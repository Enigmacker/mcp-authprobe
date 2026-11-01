import type { CheckDefinition, Reference } from "../types.js";

const RFC9700: Reference = {
  title: "RFC 9700 - Best Current Practice for OAuth 2.0 Security",
  url: "https://www.rfc-editor.org/rfc/rfc9700",
};
const OAUTH21: Reference = {
  title: "OAuth 2.1 (draft-ietf-oauth-v2-1)",
  url: "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/",
};
const MCP_AUTH: Reference = {
  title: "MCP specification - Authorization",
  url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
};
const MCP_SEC: Reference = {
  title: "MCP specification - Security Best Practices",
  url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
};
const RFC9728: Reference = { title: "RFC 9728 - OAuth 2.0 Protected Resource Metadata", url: "https://www.rfc-editor.org/rfc/rfc9728" };
const RFC8414: Reference = { title: "RFC 8414 - OAuth 2.0 Authorization Server Metadata", url: "https://www.rfc-editor.org/rfc/rfc8414" };

/**
 * The check catalogue. IDs are stable and never reused.
 *
 * Prefix "MAP" (mcp-authprobe) avoids clashing with mcp-posture's "MCPP".
 * Families:
 *   DSC  discovery prerequisites (passive)
 *   RTK  refresh token rotation and replay (active)
 *   RDR  redirect_uri strictness (active)
 *   THR  throttling of failed authentication (active, bounded)
 *   CSR  consent page CSRF (active, needs a browser session)
 */
export const CATALOGUE: readonly CheckDefinition[] = [
  {
    id: "MAP-DSC01",
    family: "DSC",
    title: "Authorization endpoints are discoverable",
    severity: "info",
    active: false,
    availability: "available",
    rationale:
      "Active checks need the authorization, token and registration endpoints. They are read from Protected Resource Metadata and Authorization Server Metadata, as a compliant MCP client would.",
    remediation:
      "Return 401 with a WWW-Authenticate resource_metadata parameter, publish Protected Resource Metadata listing the authorization server, and publish Authorization Server Metadata.",
    references: [MCP_AUTH, RFC9728, RFC8414],
  },
  {
    id: "MAP-RTK01",
    family: "RTK",
    title: "Refresh tokens for public clients are rotated",
    severity: "high",
    active: true,
    availability: "planned",
    rationale:
      "MCP clients are usually public clients. For them, refresh tokens must be sender-constrained or rotated on each use, so that a leaked refresh token has a short useful life.",
    remediation:
      "Issue a new refresh token on every refresh_token grant and invalidate the previous one.",
    references: [OAUTH21, RFC9700, MCP_AUTH],
  },
  {
    id: "MAP-RTK02",
    family: "RTK",
    title: "A rotated refresh token cannot be replayed",
    severity: "critical",
    active: true,
    availability: "planned",
    rationale:
      "Rotation only helps if the previous refresh token is rejected afterwards. Accepting it lets an attacker who copied it keep minting access tokens.",
    remediation: "Reject any refresh token that has already been exchanged.",
    references: [OAUTH21, RFC9700],
  },
  {
    id: "MAP-RTK03",
    family: "RTK",
    title: "Refresh token replay revokes the token family",
    severity: "high",
    active: true,
    availability: "planned",
    rationale:
      "When an already-used refresh token is presented, the server cannot tell the legitimate client from an attacker. Revoking every token descended from the same grant contains the compromise.",
    remediation: "On detected reuse, revoke the whole refresh token family and the related access tokens.",
    references: [RFC9700],
  },
  {
    id: "MAP-RDR01",
    family: "RDR",
    title: "Unregistered redirect_uri is refused at the authorization endpoint",
    severity: "critical",
    active: true,
    availability: "planned",
    rationale:
      "If the authorization endpoint redirects to a URI the client never registered, authorization codes can be delivered to an attacker.",
    remediation:
      "Compare the requested redirect_uri with the registered ones using exact string matching, and show an error page instead of redirecting when they differ.",
    references: [OAUTH21, RFC9700, MCP_SEC],
  },
  {
    id: "MAP-RDR02",
    family: "RDR",
    title: "redirect_uri matching is exact, not prefix or pattern based",
    severity: "high",
    active: true,
    availability: "planned",
    rationale:
      "Prefix, substring or pattern matching lets close variants of a registered URI through (extra path segments, different port, different case, added query). Each variant is a potential open redirect for codes.",
    remediation: "Use simple string comparison as required by OAuth 2.1, with the single loopback port exception for native clients.",
    references: [OAUTH21, RFC9700],
  },
  {
    id: "MAP-RDR03",
    family: "RDR",
    title: "Token endpoint enforces the redirect_uri used at authorization",
    severity: "medium",
    active: true,
    availability: "planned",
    rationale:
      "A token request whose redirect_uri differs from the one used in the authorization request should fail; otherwise code injection defenses are weakened.",
    remediation: "Bind the authorization code to its redirect_uri and reject mismatches at the token endpoint.",
    references: [OAUTH21],
  },
  {
    id: "MAP-RDR04",
    family: "RDR",
    title: "Dynamic client registration refuses unsafe redirect URIs",
    severity: "high",
    active: true,
    availability: "planned",
    rationale:
      "If anyone can register a client, the registration endpoint is the first line of defense: it should only accept HTTPS or loopback redirect URIs and refuse dangerous schemes.",
    remediation: "Validate redirect_uris at registration: HTTPS, loopback HTTP, or private-use schemes for native apps only.",
    references: [MCP_AUTH, OAUTH21],
  },
  {
    id: "MAP-THR01",
    family: "THR",
    title: "Repeated failed client authentication is throttled",
    severity: "medium",
    active: true,
    availability: "planned",
    rationale:
      "Without throttling, credentials and codes can be guessed at line speed. The check sends a small, capped number of failing requests with the operator's own test client and looks for rate limiting.",
    remediation: "Rate-limit failed attempts per client and per source, and answer with 429 and Retry-After.",
    references: [RFC9700],
  },
  {
    id: "MAP-CSR01",
    family: "CSR",
    title: "Consent decision is protected against cross-site request forgery",
    severity: "high",
    active: true,
    availability: "planned",
    rationale:
      "If the consent form can be submitted cross-site, a malicious page can grant access on behalf of a logged-in user (confused deputy, as described in the MCP security best practices).",
    remediation: "Protect the consent submission with an anti-CSRF token bound to the session, SameSite cookies and an Origin check.",
    references: [MCP_SEC, RFC9700],
  },
];

export function getCheck(id: string): CheckDefinition | undefined {
  return CATALOGUE.find((c) => c.id.toUpperCase() === id.toUpperCase());
}
