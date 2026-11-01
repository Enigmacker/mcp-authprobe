import type { HttpClient } from "./net/http.js";
import { safeText } from "./redact.js";

/**
 * OAuth discovery for a remote MCP server, following the MCP Authorization
 * specification: 401 challenge -> Protected Resource Metadata (RFC 9728) ->
 * Authorization Server Metadata (RFC 8414 / OpenID Connect Discovery).
 *
 * Discovery is passive: it sends the requests any compliant MCP client sends
 * before logging in. It gives the active checks the endpoints they need.
 */

export interface ProtectedResourceMetadata {
  resource?: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
  [key: string]: unknown;
}

export interface AuthorizationServerMetadata {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  registration_endpoint?: string;
  revocation_endpoint?: string;
  code_challenge_methods_supported?: string[];
  grant_types_supported?: string[];
  response_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  client_id_metadata_document_supported?: boolean;
  [key: string]: unknown;
}

export interface DiscoveryResult {
  mcpUrl: string;
  challenge: { status: number; wwwAuthenticate: string | null; resourceMetadataUrl: string | null };
  prm: { url: string; metadata: ProtectedResourceMetadata } | null;
  as: { url: string; metadata: AuthorizationServerMetadata } | null;
  notes: string[];
}

/** Parse the resource_metadata parameter out of a WWW-Authenticate header. */
export function parseResourceMetadata(header: string | null): string | null {
  if (!header) return null;
  const match = /resource_metadata\s*=\s*"([^"]+)"|resource_metadata\s*=\s*([^\s,]+)/i.exec(header);
  return match?.[1] ?? match?.[2] ?? null;
}

/** Candidate PRM URLs per RFC 9728 section 3.1 (path-inserted first, then root). */
export function prmCandidates(mcpUrl: string): string[] {
  const u = new URL(mcpUrl);
  const path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
  const out = [];
  if (path) out.push(`${u.origin}/.well-known/oauth-protected-resource${path}`);
  out.push(`${u.origin}/.well-known/oauth-protected-resource`);
  return out;
}

/** Candidate AS metadata URLs per RFC 8414 section 3.1 and OIDC Discovery. */
export function asMetadataCandidates(issuer: string): string[] {
  const u = new URL(issuer);
  const path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
  if (!path) {
    return [
      `${u.origin}/.well-known/oauth-authorization-server`,
      `${u.origin}/.well-known/openid-configuration`,
    ];
  }
  return [
    `${u.origin}/.well-known/oauth-authorization-server${path}`,
    `${u.origin}/.well-known/openid-configuration${path}`,
    `${u.origin}${path}/.well-known/openid-configuration`,
  ];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function discover(mcpUrl: string, http: HttpClient): Promise<DiscoveryResult> {
  const notes: string[] = [];
  const initialize = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "mcp-authprobe", version: "0.1.0" },
    },
  };

  const res = await http.request({
    url: mcpUrl,
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify(initialize),
  });
  const wwwAuthenticate = res.headers["www-authenticate"] ?? null;
  const resourceMetadataUrl = parseResourceMetadata(wwwAuthenticate);
  if (res.status !== 401) notes.push(`MCP endpoint answered HTTP ${res.status} without credentials (expected 401).`);

  // Protected Resource Metadata
  let prm: DiscoveryResult["prm"] = null;
  const prmUrls = resourceMetadataUrl ? [resourceMetadataUrl, ...prmCandidates(mcpUrl)] : prmCandidates(mcpUrl);
  for (const url of [...new Set(prmUrls)]) {
    try {
      const { response, json } = await http.getJson(url);
      if (response.status === 200 && isObject(json)) {
        prm = { url, metadata: json as ProtectedResourceMetadata };
        break;
      }
    } catch (err) {
      notes.push(`PRM fetch failed for ${url}: ${safeText((err as Error).message)}`);
    }
  }
  if (!prm) notes.push("No Protected Resource Metadata found.");

  // Authorization Server Metadata
  let as: DiscoveryResult["as"] = null;
  const issuer = prm?.metadata.authorization_servers?.[0];
  if (issuer) {
    for (const url of asMetadataCandidates(issuer)) {
      try {
        const { response, json } = await http.getJson(url);
        if (response.status === 200 && isObject(json)) {
          as = { url, metadata: json as AuthorizationServerMetadata };
          break;
        }
      } catch (err) {
        notes.push(`AS metadata fetch failed for ${url}: ${safeText((err as Error).message)}`);
      }
    }
    if (!as) notes.push(`No authorization server metadata found for issuer ${safeText(issuer)}.`);
  }

  return { mcpUrl, challenge: { status: res.status, wwwAuthenticate, resourceMetadataUrl }, prm, as, notes };
}
