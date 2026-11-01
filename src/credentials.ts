import { readFileSync, statSync } from "node:fs";

/**
 * A test grant supplied by the operator: a client and a refresh token
 * obtained by logging in to their own server with a dedicated test account.
 *
 * Refresh token checks consume this grant: a compliant server revokes it
 * during the replay test. Never point the scanner at a grant you still need.
 *
 * File format (JSON):
 *   {
 *     "client_id": "...",
 *     "refresh_token": "...",
 *     "client_secret": "...",                       // optional, confidential clients
 *     "token_endpoint_auth_method": "none"           // "none" | "client_secret_post" | "client_secret_basic"
 *   }
 *
 * The file is read from disk only, never from the command line.
 */
export type TokenEndpointAuthMethod = "none" | "client_secret_post" | "client_secret_basic";

export interface TestGrant {
  clientId: string;
  refreshToken: string;
  clientSecret?: string;
  authMethod: TokenEndpointAuthMethod;
}

export interface LoadedGrant {
  grant: TestGrant;
  warnings: string[];
}

const AUTH_METHODS: readonly TokenEndpointAuthMethod[] = ["none", "client_secret_post", "client_secret_basic"];

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`Credentials file: "${key}" must be a non-empty string.`);
  return value.trim();
}

export function parseGrant(raw: unknown): TestGrant {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error("Credentials file: expected a JSON object.");
  const obj = raw as Record<string, unknown>;
  const clientId = requireString(obj, "client_id");
  const refreshToken = requireString(obj, "refresh_token");
  const secret = obj["client_secret"];
  const method = obj["token_endpoint_auth_method"] ?? (typeof secret === "string" ? "client_secret_post" : "none");
  if (!AUTH_METHODS.includes(method as TokenEndpointAuthMethod)) {
    throw new Error(`Credentials file: token_endpoint_auth_method must be one of ${AUTH_METHODS.join(", ")}.`);
  }
  const grant: TestGrant = { clientId, refreshToken, authMethod: method as TokenEndpointAuthMethod };
  if (method !== "none") {
    if (typeof secret !== "string" || secret === "") throw new Error(`Credentials file: "client_secret" is required for ${String(method)}.`);
    grant.clientSecret = secret;
  }
  return grant;
}

export function loadGrant(path: string): LoadedGrant {
  const warnings: string[] = [];
  if (process.platform !== "win32" && (statSync(path).mode & 0o077) !== 0) {
    warnings.push(`Credentials file ${path} is readable by other users; restrict it with chmod 600.`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    // Never echo file content: it holds secrets.
    throw new Error(`Credentials file ${path} is not valid JSON.`);
  }
  return { grant: parseGrant(raw), warnings };
}
