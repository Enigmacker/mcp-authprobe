import { closeSync, constants, fchmodSync, openSync, readFileSync, statSync, writeSync } from "node:fs";
import type { Finding } from "./types.js";

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

/**
 * A check result observed outside a scan, during `login` (for example
 * MAP-RDR03, which needs a fresh authorization code). Stored in the grant
 * file so the next scan of the same target can report it.
 */
export interface Observation extends Finding {
  observedAt: string;
}

export interface LoadedGrant {
  grant: TestGrant;
  observations: Observation[];
  warnings: string[];
}

function parseObservations(raw: unknown): Observation[] {
  if (!Array.isArray(raw)) return [];
  const statuses = new Set(["pass", "fail", "not_applicable", "error", "skipped"]);
  return raw.filter(
    (o): o is Observation =>
      typeof o === "object" &&
      o !== null &&
      typeof (o as Observation).checkId === "string" &&
      typeof (o as Observation).target === "string" &&
      typeof (o as Observation).message === "string" &&
      typeof (o as Observation).observedAt === "string" &&
      statuses.has((o as Observation).status) &&
      Array.isArray((o as Observation).evidence),
  );
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
  const observations = parseObservations((raw as Record<string, unknown> | null)?.["observations"]);
  return { grant: parseGrant(raw), observations, warnings };
}

/**
 * Write a grant file with mode 600. Refuses to follow a symbolic link and,
 * unless `overwrite` is set, to replace an existing file.
 */
export function writeGrantFile(path: string, grant: TestGrant, observations: Observation[], overwrite = false): void {
  const data: Record<string, unknown> = {
    client_id: grant.clientId,
    refresh_token: grant.refreshToken,
    token_endpoint_auth_method: grant.authMethod,
  };
  if (grant.clientSecret) data["client_secret"] = grant.clientSecret;
  if (observations.length > 0) data["observations"] = observations;

  const nofollow = constants.O_NOFOLLOW ?? 0;
  const flags = constants.O_WRONLY | constants.O_CREAT | nofollow | (overwrite ? constants.O_TRUNC : constants.O_EXCL);
  const fd = openSync(path, flags, 0o600);
  try {
    // An overwritten file keeps its old mode: force 600.
    if (process.platform !== "win32") fchmodSync(fd, 0o600);
    writeSync(fd, `${JSON.stringify(data, null, 2)}\n`);
  } finally {
    closeSync(fd);
  }
}
