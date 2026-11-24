import type { HttpClient } from "../net/http.js";
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

export const PROTOCOL_VERSION = "2025-11-25";

export interface McpPostOptions {
  /** OAuth access token sent as a Bearer header (shorthand for `auth`). */
  token?: string;
  auth?: Credential;
  origin?: string;
  sessionId?: string;
  /** JSON-RPC method (default initialize). Only side-effect-free methods. */
  method?: "initialize" | "ping";
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
  return { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: TOOL_NAME, version: TOOL_VERSION } };
}

/**
 * One request to the MCP endpoint. Errors never carry the URL, so a secret
 * placed in the query string cannot leak through them.
 */
export async function mcpPost(http: HttpClient, mcpUrl: string, o: McpPostOptions = {}): Promise<McpPostResult> {
  const auth = o.auth ?? (o.token ? bearerCredential(o.token) : undefined);
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
  const method = o.method ?? "initialize";
  // After initialize, every request carries the negotiated version (MCP 2025-06-18 and later),
  // so a server cannot refuse it, or fall back to an older revision, for that reason alone.
  if (o.sessionId || method !== "initialize" || o.body !== undefined) headers["mcp-protocol-version"] = PROTOCOL_VERSION;
  if (o.sessionId) headers["mcp-session-id"] = o.sessionId;
  const body = o.body ?? JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(method === "initialize" ? { params: initializeParams() } : {}) });
  let res;
  try {
    res = await http.request({ url, method: "POST", headers, body, ...(o.maxBodyBytes !== undefined ? { maxBodyBytes: o.maxBodyBytes } : {}), ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}) });
  } catch (e) {
    throw new Error(o.secretInQuery ? "request failed" : (e as Error).message);
  }
  return { status: res.status, sessionId: res.headers["mcp-session-id"] ?? null, headers: res.headers, body: res.body, truncated: res.truncated };
}

/** Send one MCP initialize request and return the HTTP status. */
export async function initializeStatus(http: HttpClient, mcpUrl: string, opts: { token?: string; auth?: Credential; origin?: string } = {}): Promise<number> {
  return (await mcpPost(http, mcpUrl, opts)).status;
}

/** Ends an MCP session (best effort). */
export async function endSession(http: HttpClient, mcpUrl: string, auth: Credential | string, sessionId: string): Promise<void> {
  const cred = typeof auth === "string" ? bearerCredential(auth) : auth;
  try {
    await http.request({ url: mcpUrl, method: "DELETE", headers: { [cred.header]: cred.value, "mcp-session-id": sessionId, "mcp-protocol-version": PROTOCOL_VERSION } });
  } catch {
    /* best effort */
  }
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
