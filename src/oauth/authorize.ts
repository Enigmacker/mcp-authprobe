import { createHash, randomBytes } from "node:crypto";
import type { HttpClient } from "../net/http.js";

/**
 * Authorization request probe.
 *
 * Sends one authorization request (code flow with PKCE S256, a random
 * state and the RFC 8707 resource) and records how the server answers,
 * without following redirects and without logging in.
 */

export type AuthorizeAnswer =
  /** The server redirected to the redirect_uri that was sent. */
  | { kind: "redirect-to-candidate"; status: number }
  /** The server redirected somewhere else, typically a login page. */
  | { kind: "redirect-elsewhere"; status: number; destination: string }
  /** No redirect: an error page, a login page or a consent page. */
  | { kind: "page"; status: number }
  /** Rate limited (429 or Retry-After) or server error (5xx): says nothing about validation. */
  | { kind: "unavailable"; status: number };

export interface AuthorizeParams {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  resource?: string;
  scope?: string;
}

function pkceChallenge(): string {
  const verifier = randomBytes(32).toString("base64url");
  return createHash("sha256").update(verifier).digest("base64url");
}

/** True when `location` points at the same origin and path as `candidate`. */
export function pointsTo(location: string, candidate: string): boolean {
  let loc: URL;
  let cand: URL;
  try {
    loc = new URL(location);
    cand = new URL(candidate);
  } catch {
    return false;
  }
  // Compare as the browser would navigate: scheme, host, port, path.
  return loc.protocol === cand.protocol && loc.host === cand.host && loc.pathname === cand.pathname && loc.username === cand.username;
}

export async function probeAuthorize(http: HttpClient, p: AuthorizeParams): Promise<AuthorizeAnswer> {
  const url = new URL(p.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", p.clientId);
  url.searchParams.set("redirect_uri", p.redirectUri);
  url.searchParams.set("state", randomBytes(16).toString("base64url"));
  url.searchParams.set("code_challenge", pkceChallenge());
  url.searchParams.set("code_challenge_method", "S256");
  if (p.resource) url.searchParams.set("resource", p.resource);
  if (p.scope) url.searchParams.set("scope", p.scope);

  const res = await http.request({ url: url.toString(), headers: { accept: "text/html,application/json" } });
  if (res.status === 429 || res.status >= 500 || res.headers["retry-after"] !== undefined) return { kind: "unavailable", status: res.status };
  const location = res.headers["location"];
  if (res.status >= 300 && res.status < 400 && location) {
    let absolute: string;
    try {
      absolute = new URL(location, url).toString();
    } catch {
      return { kind: "page", status: res.status };
    }
    if (pointsTo(absolute, p.redirectUri)) return { kind: "redirect-to-candidate", status: res.status };
    const dest = new URL(absolute);
    return { kind: "redirect-elsewhere", status: res.status, destination: `${dest.origin}${dest.pathname}` };
  }
  return { kind: "page", status: res.status };
}

/** Comparable signature: two answers with the same signature are indistinguishable. */
export function signature(a: AuthorizeAnswer): string {
  if (a.kind === "redirect-elsewhere") return `${a.kind}:${a.status}:${a.destination}`;
  return `${a.kind}:${a.status}`;
}

export function describeAnswer(a: AuthorizeAnswer): string {
  switch (a.kind) {
    case "redirect-to-candidate":
      return `HTTP ${a.status}, redirected to the redirect_uri that was sent`;
    case "redirect-elsewhere":
      return `HTTP ${a.status}, redirected to ${a.destination}`;
    case "page":
      return `HTTP ${a.status}, no redirect`;
    case "unavailable":
      return `HTTP ${a.status}, rate limited or server error`;
  }
}
