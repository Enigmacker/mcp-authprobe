import type { TestGrant } from "../credentials.js";
import type { HttpClient } from "../net/http.js";

/**
 * Minimal token endpoint client for the refresh_token grant.
 *
 * It returns only what checks need to reason about (status, OAuth error code,
 * whether a refresh token came back) plus the raw tokens kept in memory for
 * the next step. Callers must never log or report the token values.
 */
export interface RefreshOutcome {
  status: number;
  /** OAuth "error" field on failure, e.g. "invalid_grant". */
  error: string | null;
  accessTokenIssued: boolean;
  /** New refresh token, if any. In memory only. */
  refreshToken: string | null;
  /** HTTP 429 or a Retry-After header: the server is throttling. */
  throttled: boolean;
}

function formEncode(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

export async function refresh(http: HttpClient, tokenEndpoint: string, grant: TestGrant, refreshToken: string): Promise<RefreshOutcome> {
  const params: Record<string, string> = { grant_type: "refresh_token", refresh_token: refreshToken };
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };

  if (grant.authMethod === "client_secret_basic" && grant.clientSecret) {
    // RFC 6749 section 2.3.1: form-urlencode each part before base64.
    const id = encodeURIComponent(grant.clientId);
    const secret = encodeURIComponent(grant.clientSecret);
    headers["authorization"] = `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
  } else {
    params["client_id"] = grant.clientId;
    if (grant.authMethod === "client_secret_post" && grant.clientSecret) params["client_secret"] = grant.clientSecret;
  }

  const res = await http.request({ url: tokenEndpoint, method: "POST", headers, body: formEncode(params) });

  let body: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(res.body);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
  } catch {
    /* non-JSON error page */
  }
  const accessToken = body["access_token"];
  const newRefresh = body["refresh_token"];
  const error = body["error"];

  return {
    status: res.status,
    error: typeof error === "string" ? error : null,
    accessTokenIssued: res.status === 200 && typeof accessToken === "string" && accessToken.length > 0,
    refreshToken: typeof newRefresh === "string" && newRefresh.length > 0 ? newRefresh : null,
    throttled: res.status === 429 || res.headers["retry-after"] !== undefined,
  };
}

/** Human-readable, token-free description of an outcome for report evidence. */
export function describe(outcome: RefreshOutcome): string {
  if (outcome.accessTokenIssued) {
    return `HTTP ${outcome.status}, access token issued, ${outcome.refreshToken ? "new refresh token returned" : "no refresh token returned"}`;
  }
  return `HTTP ${outcome.status}${outcome.error ? `, error=${outcome.error}` : ""}${outcome.throttled ? ", throttled" : ""}`;
}
