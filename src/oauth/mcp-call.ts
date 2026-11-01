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
