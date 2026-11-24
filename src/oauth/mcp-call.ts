import { ScanInterruptedError, type HttpClient } from "../net/http.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * A credential for the MCP endpoint: an OAuth access token (from `login`) or
 * a static API key (`--bearer-file`). The secret only ever goes into the
 * header (or, for MAP-TOK01 only, a query parameter); it never reaches a
 * report, a log or an error message.
 */
export interface Credential {
  /** Lower-case header name. */
  header: string;
  /** Full header value, e.g. "Bearer <secret>". */
  value: string;
  /** The secret itself. */
  secret: string;
  kind: "oauth" | "static";
}

export function bearerCredential(secret: string, header = "authorization", kind: Credential["kind"] = "oauth"): Credential {
  const h = header.toLowerCase();
  return { header: h, value: h === "authorization" ? `Bearer ${secret}` : secret, secret, kind };
}

/** An Origin no legitimate client of the target uses (RFC 2606 reserved name). */
export const FOREIGN_ORIGIN = "https://attacker.mcp-authprobe.invalid";

/**
 * The two eras of MCP over HTTP. "legacy": revisions up to 2025-11-25, with
 * an `initialize` handshake, sessions and `ping`. "modern": 2026-07-28 and
 * later, stateless: every request carries its protocol version in `_meta`
 * and in the MCP-Protocol-Version and Mcp-Method headers, `server/discover`
 * replaces the handshake, and there is neither session nor `ping`.
 */
export type Era = "legacy" | "modern";
export const LEGACY_VERSION = "2025-11-25";
export const MODERN_VERSION = "2026-07-28";
/** Kept for callers of earlier versions: the legacy revision. */
export const PROTOCOL_VERSION = LEGACY_VERSION;
export const versionOf = (era: Era): string => (era === "modern" ? MODERN_VERSION : LEGACY_VERSION);

/** JSON-RPC error codes that only a modern server sends (HeaderMismatch, MissingRequiredClientCapability, UnsupportedProtocolVersion). */
export const MODERN_ERROR_CODES: readonly number[] = [-32020, -32021, -32022];

/** What is known about the revisions a server speaks. */
export interface Dialect {
  era: Era | "unknown";
  /** The revision requests are sent with. */
  version: string | null;
  /** Versions the server announced (server/discover, or an UnsupportedProtocolVersion error). */
  supportedVersions: string[];
  /** Set when the endpoint looks like the deprecated HTTP+SSE transport of 2024-11-05, which this tool does not speak. */
  transport?: "streamable-http" | "http+sse";
}

/** Side-effect-free methods the scanner sends. In the modern era "initialize" and "ping" do not exist: server/discover is sent in their place. */
export type McpMethod = "initialize" | "ping" | "server/discover" | "tools/list" | "prompts/list" | "resources/list" | "resources/templates/list";

export interface McpPostOptions {
  /** OAuth access token sent as a Bearer header (shorthand for `auth`). */
  token?: string;
  auth?: Credential;
  origin?: string;
  sessionId?: string;
  /** Era to speak (default legacy). */
  era?: Era;
  /** JSON-RPC method (default: the era's harmless opening request). Only side-effect-free methods. */
  method?: McpMethod;
  /** JSON-RPC id (default 1). */
  id?: number;
  /** Parameters of the request (a cursor); the modern `_meta` is added to them. */
  params?: Record<string, unknown>;
  /** Put the secret in this query parameter instead of the header (MAP-TOK01 only). */
  secretInQuery?: string;
  /** Raw body instead of one JSON-RPC message (MAP-BAT01, MAP-BOD01). */
  body?: string | AsyncIterable<Uint8Array>;
  /** Response body cap for this request (list methods need more than the default 1 MiB). */
  maxBodyBytes?: number;
  /** Timeout for this request (large uploads). */
  timeoutMs?: number;
}

export interface McpPostResult {
  status: number;
  /** The answer was cut at the body cap: it cannot be parsed reliably. */
  truncated?: boolean;
  sessionId: string | null;
  headers: Record<string, string>;
  body: string;
}

function initializeParams(): Record<string, unknown> {
  return { protocolVersion: LEGACY_VERSION, capabilities: {}, clientInfo: { name: TOOL_NAME, version: TOOL_VERSION } };
}

/** The per-request metadata of the modern era. */
export function modernMeta(): Record<string, unknown> {
  return {
    "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
    "io.modelcontextprotocol/clientInfo": { name: TOOL_NAME, version: TOOL_VERSION },
    "io.modelcontextprotocol/clientCapabilities": {},
  };
}

/** The method actually sent: the handshake and ping have no modern form, server/discover is the harmless request there. */
export function methodFor(era: Era, method: McpMethod | undefined): McpMethod {
  if (era === "modern") return method === undefined || method === "initialize" || method === "ping" ? "server/discover" : method;
  return method ?? "initialize";
}

/** Name of the harmless request of an era, for evidence lines: the opening one, and the one sent afterwards. */
export const helloName = (era: Era): string => (era === "modern" ? "server/discover" : "initialize");
export const noopName = (era: Era): string => (era === "modern" ? "server/discover" : "ping");

/** One JSON-RPC request of an era, as an object. */
export function rpcMessage(era: Era, method: McpMethod | undefined, id = 1, params?: Record<string, unknown>): Record<string, unknown> {
  const m = methodFor(era, method);
  if (era === "modern") return { jsonrpc: "2.0", id, method: m, params: { ...params, _meta: modernMeta() } };
  if (m === "initialize") return { jsonrpc: "2.0", id, method: m, params: initializeParams() };
  return { jsonrpc: "2.0", id, method: m, ...(params ? { params } : {}) };
}

/** The era's harmless request padded to `size` bytes, still valid JSON (MAP-BOD01). */
export function paddedNoop(era: Era, size: number): string {
  const bare = JSON.stringify(era === "modern" ? { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: { ...modernMeta(), pad: "" } } } : { jsonrpc: "2.0", id: 1, method: "ping", params: { _meta: { pad: "" } } });
  const at = bare.lastIndexOf('"pad":""') + '"pad":"'.length;
  return bare.slice(0, at) + "x".repeat(Math.max(0, size - bare.length)) + bare.slice(at);
}

/**
 * One request to the MCP endpoint. Errors never carry the URL, so a secret
 * placed in the query string cannot leak through them.
 */
export async function mcpPost(http: HttpClient, mcpUrl: string, o: McpPostOptions = {}): Promise<McpPostResult> {
  const auth = o.auth ?? (o.token ? bearerCredential(o.token) : undefined);
  const era = o.era ?? "legacy";
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  let url = mcpUrl;
  if (auth && o.secretInQuery) {
    const u = new URL(mcpUrl);
    u.searchParams.set(o.secretInQuery, auth.secret);
    url = u.toString();
  } else if (auth) {
    headers[auth.header] = auth.value;
  }
  if (o.origin) headers["origin"] = o.origin;
  const method = methodFor(era, o.method);
  if (era === "modern") {
    // 2026-07-28: both headers on every POST; they mirror the body.
    headers["mcp-protocol-version"] = MODERN_VERSION;
    headers["mcp-method"] = method;
  } else {
    // After initialize, every request carries the negotiated version (MCP 2025-06-18 and later),
    // so a server cannot refuse it, or fall back to an older revision, for that reason alone.
    if (o.sessionId || method !== "initialize" || o.body !== undefined) headers["mcp-protocol-version"] = LEGACY_VERSION;
    if (o.sessionId) headers["mcp-session-id"] = o.sessionId;
  }
  const body = o.body ?? JSON.stringify(rpcMessage(era, o.method, o.id ?? 1, o.params));
  let res;
  try {
    res = await http.request({ url, method: "POST", headers, body, ...(o.maxBodyBytes !== undefined ? { maxBodyBytes: o.maxBodyBytes } : {}), ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}) });
  } catch (e) {
    // Network errors never carry the URL; anything else is replaced when the URL holds the secret.
    if (!o.secretInQuery || e instanceof ScanInterruptedError) throw e;
    throw new Error("request failed");
  }
  return { status: res.status, sessionId: era === "modern" ? null : (res.headers["mcp-session-id"] ?? null), headers: res.headers, body: res.body, truncated: res.truncated };
}

/** Send the era's harmless opening request and return the HTTP status. */
export async function initializeStatus(http: HttpClient, mcpUrl: string, opts: { token?: string; auth?: Credential; origin?: string; era?: Era } = {}): Promise<number> {
  return (await mcpPost(http, mcpUrl, opts)).status;
}

/** Ends an MCP session (best effort). Only the legacy era has sessions. */
export async function endSession(http: HttpClient, mcpUrl: string, auth: Credential | string, sessionId: string): Promise<void> {
  const cred = typeof auth === "string" ? bearerCredential(auth) : auth;
  try {
    await http.request({ url: mcpUrl, method: "DELETE", cleanup: true, headers: { [cred.header]: cred.value, "mcp-session-id": sessionId, "mcp-protocol-version": LEGACY_VERSION } });
  } catch {
    /* best effort */
  }
}

export interface EraProbe {
  dialect: Dialect;
  /** The answer that decided (a successful opening request of the detected era), or the last one received. */
  response: McpPostResult | null;
  /** Why no era could be determined, when `dialect.era` is "unknown". */
  undetermined?: "auth_required" | "rate_limited" | "server_error" | "unsupported_version" | "not_mcp" | "request_failed";
  /** One line per request sent, for evidence. */
  trace: string[];
  /** The error of a request that got no answer. */
  error?: unknown;
}

/** The first modern JSON-RPC error of an answer, if any. */
function modernError(res: McpPostResult): { code: number; data?: unknown } | null {
  for (const m of jsonRpcMessages(res)) if (isJsonRpcError(m) && MODERN_ERROR_CODES.includes(m.error.code)) return m.error;
  return null;
}

/**
 * Find out which era a server speaks, as the 2026-07-28 specification
 * describes for a dual-era client: a modern request first; a recognized
 * modern error means a modern server; anything else that is not about
 * authentication falls back to `initialize`. A server that asks for
 * authentication first (401) reveals nothing, and neither does a rate limit.
 */
export async function detectEra(http: HttpClient, mcpUrl: string, o: { auth?: Credential; forced?: Era } = {}): Promise<EraProbe> {
  const trace: string[] = [];
  let lastError: unknown;
  const base = o.auth ? { auth: o.auth } : {};
  const send = async (era: Era): Promise<McpPostResult | null> => {
    try {
      const r = await mcpPost(http, mcpUrl, { ...base, era });
      trace.push(`${helloName(era)} (MCP ${versionOf(era)}): HTTP ${r.status}`);
      return r;
    } catch (e) {
      if (e instanceof ScanInterruptedError) throw e;
      trace.push(`${helloName(era)} (MCP ${versionOf(era)}): request failed (${(e as Error).message})`);
      lastError = e;
      return null;
    }
  };
  const unknown = (response: McpPostResult | null, undetermined: NonNullable<EraProbe["undetermined"]>, supportedVersions: string[] = []): EraProbe => ({
    dialect: { era: "unknown", version: null, supportedVersions },
    response,
    undetermined,
    trace,
    ...(lastError !== undefined ? { error: lastError } : {}),
  });
  const blocked = (r: McpPostResult): EraProbe["undetermined"] | null => {
    const cls = classifyAnswer(r.status, r.headers);
    if (cls === "rate_limited") return "rate_limited";
    if (cls === "server_error") return "server_error";
    // A modern error body on a 401/403 would be unusual; without one, the server wants authentication before it says anything.
    if ((r.status === 401 || r.status === 403) && !modernError(r)) return "auth_required";
    return null;
  };

  if (o.forced === "legacy") {
    const r = await send("legacy");
    if (!r) return unknown(null, "request_failed");
    return r.status >= 200 && r.status < 300 ? { dialect: { era: "legacy", version: LEGACY_VERSION, supportedVersions: [] }, response: r, trace } : unknown(r, blocked(r) ?? "not_mcp");
  }

  const modern = await send("modern");
  if (!modern) return unknown(null, "request_failed");
  const stop = blocked(modern);
  if (stop) return unknown(modern, stop);
  if (modern.status >= 200 && modern.status < 300) {
    for (const m of jsonRpcMessages(modern)) {
      const versions = isJsonRpcResult(m) && m.result && typeof m.result === "object" ? (m.result as { supportedVersions?: unknown }).supportedVersions : undefined;
      if (Array.isArray(versions)) {
        return { dialect: { era: "modern", version: MODERN_VERSION, supportedVersions: versions.filter((v): v is string => typeof v === "string"), transport: "streamable-http" }, response: modern, trace };
      }
    }
  }
  const err = modernError(modern);
  if (err) {
    const supported = err.code === -32022 && err.data && typeof err.data === "object" && Array.isArray((err.data as { supported?: unknown }).supported) ? ((err.data as { supported: unknown[] }).supported.filter((v) => typeof v === "string") as string[]) : [];
    // A modern server that does not speak our modern version: its legacy versions may still do.
    if (err.code === -32022 && o.forced !== "modern" && supported.some((v) => v <= LEGACY_VERSION)) {
      const legacy = await send("legacy");
      if (legacy && legacy.status >= 200 && legacy.status < 300) return { dialect: { era: "legacy", version: LEGACY_VERSION, supportedVersions: supported, transport: "streamable-http" }, response: legacy, trace };
    }
    if (err.code === -32022) return unknown(modern, "unsupported_version", supported);
    // HeaderMismatch or MissingRequiredClientCapability to a well-formed request: a modern server all the same.
    return { dialect: { era: "modern", version: MODERN_VERSION, supportedVersions: supported, transport: "streamable-http" }, response: modern, trace };
  }
  if (o.forced === "modern") return unknown(modern, "not_mcp");

  // Not a modern answer: the handshake of the earlier revisions.
  const legacy = await send("legacy");
  if (!legacy) return unknown(modern, "request_failed");
  if (legacy.status >= 200 && legacy.status < 300) return { dialect: { era: "legacy", version: LEGACY_VERSION, supportedVersions: [], transport: "streamable-http" }, response: legacy, trace };
  const legacyStop = blocked(legacy);
  if (legacyStop) return unknown(legacy, legacyStop);
  // Neither era on this URL. The deprecated HTTP+SSE transport answers a GET with an SSE stream whose first event is "endpoint".
  const probe = unknown(legacy, "not_mcp");
  if ([400, 404, 405].includes(legacy.status)) {
    try {
      const headers: Record<string, string> = { accept: "text/event-stream" };
      if (o.auth) headers[o.auth.header] = o.auth.value;
      const sse = await http.request({ url: mcpUrl, method: "GET", headers, firstChunkOnly: true, timeoutMs: 5000, maxBodyBytes: 4096 });
      trace.push(`GET with Accept: text/event-stream: HTTP ${sse.status}`);
      if (sse.status === 200 && /text\/event-stream/i.test(sse.headers["content-type"] ?? "") && /^event:\s*endpoint\s*$/m.test(sse.body)) probe.dialect.transport = "http+sse";
    } catch (e) {
      if (e instanceof ScanInterruptedError) throw e;
      /* no SSE stream: not that transport */
    }
  }
  return probe;
}

/** A JSON-RPC 2.0 error response: `jsonrpc` is "2.0" and `error.code` is a number. Any other object with an `error` key is not one. */
export function isJsonRpcError(m: unknown): m is { jsonrpc: "2.0"; id?: unknown; error: { code: number; message?: string; data?: unknown } } {
  if (typeof m !== "object" || m === null) return false;
  const o = m as { jsonrpc?: unknown; error?: unknown };
  return o.jsonrpc === "2.0" && typeof o.error === "object" && o.error !== null && typeof (o.error as { code?: unknown }).code === "number";
}

/** A JSON-RPC 2.0 success response. */
export function isJsonRpcResult(m: unknown): m is { jsonrpc: "2.0"; id?: unknown; result: unknown } {
  if (typeof m !== "object" || m === null) return false;
  const o = m as { jsonrpc?: unknown };
  return o.jsonrpc === "2.0" && "result" in o && !("error" in o);
}

export type AnswerClass = "accepted" | "refused" | "rate_limited" | "server_error" | "other";

/**
 * One classification of HTTP answers for every check: a rate limit (429, or a
 * Retry-After on an error) and a server error (5xx) say nothing about the
 * property under test, so they never count as a refusal.
 */
export function classifyAnswer(status: number, headers: Record<string, string> = {}): AnswerClass {
  if (status >= 200 && status < 300) return "accepted";
  if (status === 429 || (status >= 400 && headers["retry-after"] !== undefined)) return "rate_limited";
  if (status >= 500) return "server_error";
  if (status >= 400) return "refused";
  return "other";
}

/**
 * JSON-RPC messages in a response body: JSON, or SSE where one event may
 * spread its data over several `data:` lines (joined with newlines).
 */
export function jsonRpcMessages(res: McpPostResult): unknown[] {
  const type = (res.headers["content-type"] ?? "").toLowerCase();
  const chunks = type.includes("text/event-stream")
    ? res.body
        .split(/\r?\n\r?\n/)
        .map((event) =>
          event
            .split(/\r?\n/)
            .filter((l) => l.startsWith("data:"))
            .map((l) => l.slice(5).replace(/^ /, ""))
            .join("\n")
            .trim(),
        )
        .filter((d) => d.length > 0)
    : [res.body];
  const out: unknown[] = [];
  for (const c of chunks) {
    try {
      const v = JSON.parse(c) as unknown;
      if (Array.isArray(v)) out.push(...v);
      else out.push(v);
    } catch {
      /* not JSON */
    }
  }
  return out;
}
