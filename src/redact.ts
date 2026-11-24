/**
 * Redaction and neutralization helpers.
 *
 * Every string that reaches a report or a log goes through `safeText`, which
 * removes token-shaped values and strips control, bidi and invisible
 * characters that a hostile server could use to spoof terminal output or
 * pull-request comments.
 */

const SECRET_PATTERNS: readonly RegExp[] = [
  // JWTs
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
  // Bearer values
  /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
  // OAuth parameters carrying secrets, as whole words ("unicode: abcdef" is not a code)
  /((?<![A-Za-z0-9_])(?:access_token|refresh_token|id_token|client_secret|code_verifier|registration_access_token|password)["']?\s*[=:]\s*["']?)[^"'&\s,}]{4,}/gi,
  // An authorization code only in a query string or a JSON member ("status code: 4001" and JSON-RPC error codes are not secrets)
  /((?<![A-Za-z0-9_])code(?:=|["']\s*:\s*["']))(?!-?\d{1,6}(?![A-Za-z0-9._~+/=-]))[^"'&\s,}]{4,}/gi,
];

/**
 * Exact values to hide everywhere: every secret the scanner loads or
 * receives (static key, access and refresh tokens, client secret,
 * registration access token, ownership secret). Patterns alone miss an
 * opaque token that a server echoes in an error message.
 */
const KNOWN_SECRETS = new Set<string>();
/** Oldest values are dropped beyond this, so a long-running process (MCP mode, library) stays bounded. */
const MAX_KNOWN_SECRETS = 2000;

/** Registers a secret so that any later report or log line masks it. */
export function registerSecret(value: string | null | undefined): void {
  if (typeof value !== "string" || value.length < 8) return;
  KNOWN_SECRETS.delete(value);
  KNOWN_SECRETS.add(value);
  if (KNOWN_SECRETS.size > MAX_KNOWN_SECRETS) {
    const oldest = KNOWN_SECRETS.values().next().value;
    if (oldest !== undefined) KNOWN_SECRETS.delete(oldest);
  }
}

/** Forgets every registered secret (a long-running host can call it between unrelated scans). */
export function forgetSecrets(): void {
  KNOWN_SECRETS.clear();
}

export function redactSecrets(input: string): string {
  let out = input;
  for (const secret of KNOWN_SECRETS) if (out.includes(secret)) out = out.split(secret).join("[REDACTED]");
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match, prefix?: string) =>
      typeof prefix === "string" && match.startsWith(prefix) ? `${prefix}[REDACTED]` : "[REDACTED]",
    );
  }
  return out;
}

// C0/C1 controls (except tab and newline), bidi overrides/isolates,
// zero-width characters, BOM and Unicode tag characters.
const UNSAFE_CHARS =
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;

export function neutralize(input: string): string {
  return input.replace(UNSAFE_CHARS, (ch) => `\\u{${ch.codePointAt(0)?.toString(16) ?? "?"}}`);
}

export function safeText(input: string, maxLength = 500): string {
  const cleaned = neutralize(redactSecrets(input));
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}

/** OAuth error codes the specifications define; anything else a server puts in `error` is shown only if it looks like a code. */
const OAUTH_ERRORS = new Set([
  "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "invalid_target",
  "access_denied", "unsupported_response_type", "server_error", "temporarily_unavailable", "slow_down", "authorization_pending", "expired_token",
  "invalid_redirect_uri", "invalid_client_metadata", "invalid_token", "insufficient_scope", "login_required", "consent_required", "interaction_required",
  "too_many_requests", "invalid_dpop_proof", "use_dpop_nonce", "unsupported_token_type",
]);

/**
 * The `error` member of an OAuth error answer, safe to copy into a report: a
 * known code, or a short lower-case word. A server that puts anything else
 * there (the token it was sent, a sentence, markup) gets a description of the
 * value instead of the value.
 */
export function safeErrorCode(value: unknown): string | null {
  if (typeof value !== "string" || value === "") return null;
  if (OAUTH_ERRORS.has(value) || /^[a-z]+(?:_[a-z]+){0,5}$/.test(value) && value.length <= 40) return value;
  return `(non-standard value, ${value.length} characters)`;
}
