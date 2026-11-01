import type { HttpClient } from "../net/http.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * Send one MCP initialize request and return the HTTP status. Used to see
 * whether a token, or an Origin, is accepted. The token is only placed in
 * the Authorization header; it never reaches a report or a log.
 */
export async function initializeStatus(http: HttpClient, mcpUrl: string, opts: { token?: string; origin?: string } = {}): Promise<number> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (opts.token) headers["authorization"] = `Bearer ${opts.token}`;
  if (opts.origin) headers["origin"] = opts.origin;
  const res = await http.request({
    url: mcpUrl,
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: TOOL_NAME, version: TOOL_VERSION } },
    }),
  });
  return res.status;
}

/** An Origin no legitimate client of the target uses (RFC 2606 reserved name). */
export const FOREIGN_ORIGIN = "https://attacker.mcp-authprobe.invalid";

export interface McpPostOptions {
  token?: string;
  origin?: string;
  sessionId?: string;
  /** JSON-RPC method (default initialize). */
  method?: "initialize" | "ping";
  /** Send the token as ?access_token= instead of the Authorization header (MAP-TOK01 only). */
  tokenInQuery?: boolean;
}

/**
 * One MCP JSON-RPC request; returns the status and the session ID the server
 * assigned, if any. Tokens never appear in the result or in error messages.
 */
export async function mcpPost(http: HttpClient, mcpUrl: string, o: McpPostOptions = {}): Promise<{ status: number; sessionId: string | null }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  let url = mcpUrl;
  if (o.token && o.tokenInQuery) {
    const u = new URL(mcpUrl);
    u.searchParams.set("access_token", o.token);
    url = u.toString();
  } else if (o.token) {
    headers["authorization"] = `Bearer ${o.token}`;
  }
  if (o.origin) headers["origin"] = o.origin;
  if (o.sessionId) {
    headers["mcp-session-id"] = o.sessionId;
    headers["mcp-protocol-version"] = "2025-11-25";
  }
  const method = o.method ?? "initialize";
  const params =
    method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: TOOL_NAME, version: TOOL_VERSION } } : undefined;
  let res;
  try {
    res = await http.request({ url, method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params ? { params } : {}) }) });
  } catch (e) {
    // Never let a URL carrying a token reach a message.
    throw new Error(o.tokenInQuery ? "request failed" : (e as Error).message);
  }
  return { status: res.status, sessionId: res.headers["mcp-session-id"] ?? null };
}

/** Ends an MCP session (best effort). */
export async function endSession(http: HttpClient, mcpUrl: string, token: string, sessionId: string): Promise<void> {
  try {
    await http.request({ url: mcpUrl, method: "DELETE", headers: { authorization: `Bearer ${token}`, "mcp-session-id": sessionId, "mcp-protocol-version": "2025-11-25" } });
  } catch {
    /* best effort */
  }
}
