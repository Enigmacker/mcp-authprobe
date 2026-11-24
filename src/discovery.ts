import type { HttpClient } from "./net/http.js";
import { detectEra, type Dialect, type Era } from "./oauth/mcp-call.js";
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
  /**
   * Which MCP era the endpoint speaks, as far as an anonymous request can
   * tell: a server that asks for authentication first leaves it "unknown",
   * and the checks that hold a credential settle it.
   */
  protocol?: Dialect;
  /** The authorization server that was examined (its issuer identifier), and the others the resource announces. */
  issuer?: string | null;
  otherIssuers?: string[];
  /** Inconsistencies in the metadata that a client must not ignore (RFC 8414 section 3.3, RFC 9728 section 3.3). Also in `notes`. */
  warnings?: string[];
}

export interface DiscoverOptions {
  /** Era to speak instead of detecting it (--protocol legacy|modern). */
  protocol?: Era;
  /** Examine this authorization server instead of the first one announced (--issuer). It must be one of those the resource lists. */
  issuer?: string;
}

/**
 * Whether the `resource` a server announces designates the URL that was
 * asked: the same URL, or the same origin with a path that is a prefix of
 * it (a server may name its origin as its canonical resource).
 */
export function resourceMatches(announced: string, mcpUrl: string): boolean {
  let a: URL;
  let t: URL;
  try {
    a = new URL(announced);
    t = new URL(mcpUrl);
  } catch {
    return false;
  }
  if (a.origin !== t.origin || a.search !== "" || a.hash !== "") return false;
  const ap = a.pathname.replace(/\/$/, "");
  const tp = t.pathname.replace(/\/$/, "");
  return ap === tp || ap === "" || tp.startsWith(`${ap}/`);
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

export async function discover(mcpUrl: string, http: HttpClient, options: DiscoverOptions = {}): Promise<DiscoveryResult> {
  const notes: string[] = [];
  const warnings: string[] = [];
  const warn = (text: string): void => {
    warnings.push(text);
    notes.push(text);
  };

  // The request any client sends first, in the newest revision, then the earlier one.
  const probe = await detectEra(http, mcpUrl, options.protocol ? { forced: options.protocol } : {});
  const res = probe.response;
  if (!res) throw probe.error ?? new Error(probe.trace.at(-1) ?? "request failed");
  const wwwAuthenticate = res.headers["www-authenticate"] ?? null;
  const resourceMetadataUrl = parseResourceMetadata(wwwAuthenticate);
  if (res.status !== 401) notes.push(`MCP endpoint answered HTTP ${res.status} without credentials (expected 401).`);
  if (probe.dialect.era !== "unknown") notes.push(`MCP protocol: ${probe.dialect.era === "modern" ? "stateless revision" : "handshake revision"} ${probe.dialect.version}${probe.dialect.supportedVersions.length > 0 ? ` (server announces ${probe.dialect.supportedVersions.join(", ")})` : ""}.`);
  if (probe.dialect.transport === "http+sse") {
    notes.push("This URL answers like the deprecated HTTP+SSE transport of MCP 2024-11-05 (a GET opens an event stream that starts with an endpoint event). That transport is not tested by this tool: the checks of the MCP endpoint will be inconclusive. Migrate to Streamable HTTP.");
  } else if (probe.undetermined === "unsupported_version") {
    notes.push(`The server speaks MCP ${probe.dialect.supportedVersions.join(", ") || "revisions it did not name"}, none of which this version of the tool speaks.`);
  }

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
  if (prm) {
    const announced = prm.metadata.resource;
    if (typeof announced !== "string") {
      warn("The Protected Resource Metadata has no resource member (RFC 9728 requires it); the scanned URL is used as the resource.");
    } else if (!resourceMatches(announced, mcpUrl)) {
      // RFC 9728 section 3.3: a document about another resource must not be trusted for this one.
      warn(`The Protected Resource Metadata announces resource ${safeText(announced, 200)}, which is not the scanned URL (RFC 9728 section 3.3 requires them to match). The scanned URL is used as the resource parameter; a client that validates metadata would refuse this document.`);
      prm = { url: prm.url, metadata: { ...prm.metadata, resource: new URL(mcpUrl).toString() } };
    }
  }

  // Authorization Server Metadata
  let as: DiscoveryResult["as"] = null;
  const announcedServers = (Array.isArray(prm?.metadata.authorization_servers) ? prm.metadata.authorization_servers : []).filter((x): x is string => typeof x === "string");
  let issuer: string | undefined = announcedServers[0];
  if (options.issuer !== undefined) {
    if (announcedServers.includes(options.issuer)) issuer = options.issuer;
    else {
      warn(`--issuer ${safeText(options.issuer, 200)} is not one of the authorization servers this resource announces (${announcedServers.map((x) => safeText(x, 200)).join(", ") || "none"}); it was not used.`);
      issuer = undefined;
    }
  }
  const otherIssuers = announcedServers.filter((x) => x !== issuer);
  if (issuer !== undefined && otherIssuers.length > 0) {
    notes.push(`The resource announces ${announcedServers.length} authorization servers; only ${safeText(issuer, 200)} was examined. The others are not tested: ${otherIssuers.map((x) => safeText(x, 200)).join(", ")} (choose one with --issuer).`);
  }
  let candidates: string[] = [];
  if (typeof issuer === "string") {
    try {
      candidates = asMetadataCandidates(issuer);
    } catch {
      notes.push(`The authorization server issuer is not a valid URL: ${safeText(issuer)}.`);
    }
  }
  if (typeof issuer === "string" && candidates.length > 0) {
    for (const url of candidates) {
      try {
        const { response, json } = await http.getJson(url);
        if (response.status === 200 && isObject(json)) {
          // RFC 8414 section 3.3 and the MCP specification: the issuer in the document must be identical
          // to the one the URL was built from, or the document must not be used (mix-up, impersonation).
          const found = (json as AuthorizationServerMetadata).issuer;
          if (found !== issuer) {
            warn(`The metadata at ${url} names issuer ${typeof found === "string" ? safeText(found, 200) : "(none)"} instead of ${safeText(issuer, 200)}: the document was not used (RFC 8414 section 3.3).`);
            continue;
          }
          as = { url, metadata: json as AuthorizationServerMetadata };
          break;
        }
      } catch (err) {
        notes.push(`AS metadata fetch failed for ${url}: ${safeText((err as Error).message)}`);
      }
    }
    if (!as) notes.push(`No usable authorization server metadata found for issuer ${safeText(issuer)}.`);
  }
  if (as && !Array.isArray(as.metadata.code_challenge_methods_supported)) {
    notes.push("The authorization server metadata has no code_challenge_methods_supported: PKCE support is not announced. The MCP specification tells clients to refuse to proceed in that case; this tool goes on, since it tests what the server enforces.");
  }

  return {
    mcpUrl,
    challenge: { status: res.status, wwwAuthenticate, resourceMetadataUrl },
    prm,
    as,
    notes,
    protocol: probe.dialect,
    issuer: issuer ?? null,
    otherIssuers,
    warnings,
  };
}

/**
 * Scopes to request, in the order the MCP specification gives: the scope of
 * the 401 challenge when there is one, otherwise scopes_supported of the
 * Protected Resource Metadata. `offline` adds offline_access when the
 * authorization server lists it, to obtain a refresh token.
 */
export function scopesFor(d: DiscoveryResult, offline = true): string | undefined {
  const fromChallenge = /scope="([^"]+)"/i.exec(d.challenge.wwwAuthenticate ?? "")?.[1];
  const scopes = new Set((fromChallenge ?? d.prm?.metadata.scopes_supported?.join(" ") ?? "").split(/\s+/).filter(Boolean));
  const asScopes = d.as?.metadata["scopes_supported"];
  if (offline && Array.isArray(asScopes) && asScopes.includes("offline_access")) scopes.add("offline_access");
  return scopes.size > 0 ? [...scopes].join(" ") : undefined;
}
