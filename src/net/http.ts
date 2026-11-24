import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { Agent, fetch as undiciFetch, type Dispatcher } from "undici";
import { USER_AGENT } from "../version.js";
import { isIP } from "node:net";
import { isBlockedAddress, isLoopbackHost } from "./address-policy.js";

export interface HttpOptions {
  /** Allow loopback/private targets (local labs and tests). Off by default. */
  allowPrivate?: boolean;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Maximum response body size in bytes. */
  maxBodyBytes?: number;
}

export interface HttpRequest {
  url: string;
  method?: "GET" | "POST" | "DELETE" | "OPTIONS";
  headers?: Record<string, string>;
  /** A string is sent with Content-Length; an async iterable is streamed (chunked). */
  body?: string | AsyncIterable<Uint8Array>;
  /** Response body cap for this request only (default: the client's cap, 1 MiB). */
  maxBodyBytes?: number;
  /** Timeout for this request only (large uploads). */
  timeoutMs?: number;
  /** Redirects are never followed automatically; callers inspect them. */
}

export interface HttpResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  /** True when the body was cut at maxBodyBytes. */
  truncated: boolean;
}

export class BlockedAddressError extends Error {
  constructor(host: string, address: string) {
    super(`Refusing to connect to ${host} (${address}): private or reserved address. Use --allow-private for a local lab.`);
    this.name = "BlockedAddressError";
  }
}

export class InsecureTransportError extends Error {
  constructor(url: string) {
    super(`Refusing plain HTTP to ${url}: secrets could travel in cleartext. Plain HTTP is only allowed for loopback or private-address labs with --allow-private.`);
    this.name = "InsecureTransportError";
  }
}

/**
 * Plain HTTP is allowed only for a local lab: --allow-private and a host that
 * is a loopback name or a private/reserved IP literal. Everything else,
 * including endpoints announced by a server's metadata, must be HTTPS.
 */
export function plainHttpAllowed(url: URL, allowPrivate: boolean): boolean {
  if (!allowPrivate) return false;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return isLoopbackHost(host) || (isIP(host) !== 0 && isBlockedAddress(host));
}

/**
 * A request that got no HTTP answer. `code` is stable and machine-readable
 * (ECONNREFUSED, ENOTFOUND, ETIMEDOUT, CERT_HAS_EXPIRED, ...); the message
 * says the same in words and never contains the URL.
 */
export class NetworkError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "NetworkError";
    this.code = code;
  }
}

const NETWORK_WORDS: Record<string, string> = {
  ECONNREFUSED: "connection refused",
  ECONNRESET: "connection reset",
  ENOTFOUND: "host not found",
  EAI_AGAIN: "DNS lookup failed",
  EHOSTUNREACH: "host unreachable",
  ENETUNREACH: "network unreachable",
  ETIMEDOUT: "timed out",
  EPIPE: "connection closed while sending",
  UND_ERR_CONNECT_TIMEOUT: "connection timed out",
  UND_ERR_HEADERS_TIMEOUT: "no answer before the timeout",
  UND_ERR_BODY_TIMEOUT: "answer body timed out",
  UND_ERR_SOCKET: "connection closed",
};

/** Turn a fetch failure ("fetch failed") into its cause, with a stable code. */
export function describeNetworkError(e: unknown): NetworkError {
  if (e instanceof NetworkError) return e;
  const err = e as { name?: string; code?: unknown; message?: string; cause?: unknown };
  if (err?.name === "TimeoutError" || err?.name === "AbortError") return new NetworkError("ETIMEDOUT", "timed out");
  let node: { code?: unknown; message?: string; cause?: unknown; errors?: unknown[] } | undefined = err;
  for (let depth = 0; node && depth < 5; depth += 1) {
    const inner = Array.isArray(node.errors) && node.errors.length > 0 ? (node.errors[0] as typeof node) : undefined;
    const code = typeof node.code === "string" ? node.code : typeof inner?.code === "string" ? inner.code : undefined;
    if (code) {
      const tls = /^(?:CERT_|DEPTH_ZERO_|SELF_SIGNED_|UNABLE_TO_|ERR_TLS_|ERR_SSL_)/.test(code);
      const words = NETWORK_WORDS[code] ?? (tls ? "TLS certificate error" : "network error");
      return new NetworkError(code, `${words} (${code})`);
    }
    node = node.cause as typeof node;
  }
  return new NetworkError("EUNKNOWN", "network error");
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BODY = 1024 * 1024;

function guardedLookup(allowPrivate: boolean) {
  return (
    hostname: string,
    options: object,
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
  ): void => {
    dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err, []);
      const list = addresses as LookupAddress[];
      if (!allowPrivate) {
        const bad = list.find((a) => isBlockedAddress(a.address));
        if (bad) return callback(new BlockedAddressError(hostname, bad.address) as NodeJS.ErrnoException, []);
      }
      const all = (options as { all?: boolean }).all === true;
      if (all) return callback(null, list);
      const first = list[0];
      if (!first) return callback(new Error(`No address for ${hostname}`) as NodeJS.ErrnoException, []);
      callback(null, first.address, first.family);
    });
  };
}

/**
 * Hardened HTTP client: connect-time address policy, timeouts, capped bodies,
 * no automatic redirects, no compression, fixed user agent.
 */
export class HttpClient {
  private readonly dispatcher: Dispatcher;
  private readonly timeoutMs: number;
  private readonly maxBodyBytes: number;
  readonly allowPrivate: boolean;

  constructor(options: HttpOptions = {}) {
    this.allowPrivate = options.allowPrivate ?? false;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.dispatcher = new Agent({
      connect: { lookup: guardedLookup(this.allowPrivate), timeout: this.timeoutMs },
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
      connections: 4,
    });
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    const url = new URL(req.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error(`Unsupported URL scheme: ${url.protocol}`);
    }
    if (url.protocol === "http:" && !plainHttpAllowed(url, this.allowPrivate)) {
      throw new InsecureTransportError(`${url.origin}${url.pathname}`);
    }
    // IP-literal hosts never go through DNS lookup, so check them here.
    const literal = url.hostname.replace(/^\[|\]$/g, "");
    if (!this.allowPrivate && /^[\d.]+$|:/.test(literal) && isBlockedAddress(literal)) {
      throw new BlockedAddressError(url.hostname, literal);
    }

    const headers: Record<string, string> = {
      "user-agent": USER_AGENT,
      "accept-encoding": "identity",
      ...req.headers,
    };
    const init: Parameters<typeof undiciFetch>[1] = {
      method: req.method ?? "GET",
      headers,
      redirect: "manual",
      dispatcher: this.dispatcher,
      signal: AbortSignal.timeout(req.timeoutMs ?? this.timeoutMs),
    };
    if (typeof req.body === "string") init.body = req.body;
    else if (req.body !== undefined) {
      const source = req.body;
      init.body = ReadableStream.from(source) as unknown as NonNullable<typeof init.body>;
      (init as { duplex?: string }).duplex = "half";
    }
    let res: Awaited<ReturnType<typeof undiciFetch>>;
    try {
      res = await undiciFetch(url, init);
    } catch (e) {
      // fetch wraps connect errors as "fetch failed"; surface the policy refusal.
      const cause = (e as { cause?: unknown }).cause;
      if (cause instanceof BlockedAddressError) throw cause;
      throw describeNetworkError(e);
    }

    let read: { body: string; truncated: boolean };
    try {
      read = await this.readCapped(res.body, req.maxBodyBytes ?? this.maxBodyBytes);
    } catch (e) {
      throw describeNetworkError(e);
    }
    const { body, truncated } = read;
    const outHeaders: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      outHeaders[key] = value;
    });
    return { url: url.toString(), status: res.status, headers: outHeaders, body, truncated };
  }

  async getJson(url: string): Promise<{ response: HttpResponse; json: unknown }> {
    const response = await this.request({ url, headers: { accept: "application/json" } });
    let json: unknown = undefined;
    try {
      json = JSON.parse(response.body);
    } catch {
      json = undefined;
    }
    return { response, json };
  }

  private async readCapped(
    stream: ReadableStream<Uint8Array> | null,
    max: number,
  ): Promise<{ body: string; truncated: boolean }> {
    if (!stream) return { body: "", truncated: false };
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    let truncated = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > max) {
        chunks.push(value.subarray(0, max - size));
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
    return { body: Buffer.concat(chunks).toString("utf8"), truncated };
  }

  async close(): Promise<void> {
    await this.dispatcher.close();
  }
}
