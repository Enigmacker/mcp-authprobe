import type { TestGrant } from "../credentials.js";
import type { HttpClient } from "../net/http.js";
import { initializeStatus } from "../oauth/mcp-call.js";
import { SAFE_DOMAIN } from "../oauth/registration.js";
import { describe as describeOutcome, refresh } from "../oauth/token-client.js";
import type { Finding } from "../types.js";
import { makeFinding } from "./finding.js";

/**
 * MAP-AUD01: a token requested for another resource must not work on this
 * MCP server. The refresh token of the test grant is used once to ask for a
 * token for an unrelated resource (RFC 8707); the authorization server must
 * refuse, or the MCP server must reject that token. Runs during `login`, and
 * during a scan given an access token (`--access-token-file`) and a grant.
 */

export interface AudienceCheckContext {
  http: HttpClient;
  target: string;
  tokenEndpoint: string;
  /** Null when no refresh token was issued. Its refreshToken is replaced by the newest one on rotation. */
  grant: TestGrant | null;
  /** Status of a request with a token issued for this server (the control), or null. */
  control: number | null;
  /** Identifiers this server may legitimately appear under in a token audience: its URL and the `resource` it announces. */
  ownAudiences?: string[];
}

/** An unrelated resource under the reserved .invalid domain: no token for it can be used anywhere. */
export const FOREIGN_RESOURCE = `https://other.${SAFE_DOMAIN}/mcp`;

const is2xx = (s: number | null): s is number => s !== null && s >= 200 && s < 300;

/** Audience of a JWT access token, read without verification (attribution only), or null. */
export function jwtAudience(token: string): string[] | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8")) as { aud?: unknown };
    if (typeof payload.aud === "string") return [payload.aud];
    if (Array.isArray(payload.aud) && payload.aud.every((a) => typeof a === "string")) return payload.aud as string[];
    return null;
  } catch {
    return null;
  }
}

export async function runAudienceCheck(c: AudienceCheckContext): Promise<Finding> {
  const { http, target, tokenEndpoint, grant, control } = c;
  const own = new Set([target, ...(c.ownAudiences ?? [])]);
  const lines = [`control, token for this server: ${control === null ? "not available" : `HTTP ${control}`}`];
  if (!is2xx(control)) {
    return makeFinding("MAP-AUD01", target, "error", "Inconclusive: the token issued for this server was not accepted by it, so audience binding cannot be judged.", lines, control === 429 ? "rate_limited" : "credential_rejected");
  }
  if (!grant) {
    return makeFinding("MAP-AUD01", target, "error", "Inconclusive: no refresh token was issued, so a token for another resource cannot be requested.", lines, "ambiguous");
  }
  const o = await refresh(http, tokenEndpoint, grant, grant.refreshToken, FOREIGN_RESOURCE);
  lines.push(`refresh token used to request a token for ${FOREIGN_RESOURCE}: ${describeOutcome(o)}`);
  if (o.refreshToken) grant.refreshToken = o.refreshToken; // rotation: keep the newest
  if (!o.accessTokenIssued) {
    // Only invalid_target says why; another refusal (scope, policy, throttling) proves nothing.
    return o.error === "invalid_target"
      ? makeFinding("MAP-AUD01", target, "pass", "The authorization server refused to issue a token for an unrelated resource (invalid_target).", lines)
      : makeFinding("MAP-AUD01", target, "error", "The request for a token for an unrelated resource was refused, but not with invalid_target; inconclusive.", lines, o.throttled ? "rate_limited" : o.status >= 500 ? "server_error" : "ambiguous");
  }
  const st = await initializeStatus(http, target, { token: o.accessToken ?? "" });
  lines.push(`that token presented to this MCP server: HTTP ${st}`);
  const aud = o.accessToken ? jwtAudience(o.accessToken) : null;
  if (aud) lines.push(`audience of that token (JWT, unverified): ${aud.join(", ")}`);
  if (st === 401 || st === 403) return makeFinding("MAP-AUD01", target, "pass", "A token issued for an unrelated resource is rejected by the MCP server.", lines);
  if (!is2xx(st)) return makeFinding("MAP-AUD01", target, "error", "Unexpected answer from the MCP server; inconclusive.", lines, st === 429 ? "rate_limited" : st >= 500 ? "server_error" : "unexpected_answer");
  if (aud && aud.includes(FOREIGN_RESOURCE) && !aud.some((a) => own.has(a))) {
    return makeFinding("MAP-AUD01", target, "fail", "The MCP server accepts a token whose audience is another resource: it does not validate the token audience.", lines);
  }
  if (aud) {
    return makeFinding(
      "MAP-AUD01",
      target,
      "error",
      "Inconclusive: the authorization server ignored the resource parameter and issued a token for this server (RFC 8707 recommends refusing with invalid_target), so the MCP server's audience validation could not be tested.",
      lines,
      "ambiguous",
    );
  }
  return makeFinding(
    "MAP-AUD01",
    target,
    "error",
    "Inconclusive: a token requested for an unrelated resource works on this server, but the token is opaque, so it cannot be told whether the authorization server ignored the resource parameter or the MCP server does not validate the audience. Check both.",
    lines,
    "ambiguous",
  );
}
