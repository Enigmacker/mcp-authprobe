import { bearerCredential, type Credential } from "./oauth/mcp-call.js";
import { registerSecret } from "./redact.js";
import { readSecretLine, SecretFileError } from "./secret-file.js";

/**
 * Static API key for MCP servers authenticated without OAuth (`--bearer-file`).
 * The key is read from a file, never from the command line, registered for
 * redaction everywhere, and only sent to the target once ownership of it is
 * proven.
 */

const MIN_KEY_LENGTH = 8;
const MAX_KEY_BYTES = 8 * 1024;
/** Headers a key may not be sent in: they would change the request itself. */
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "content-type", "transfer-encoding", "connection", "origin", "mcp-session-id", "mcp-protocol-version", "accept", "user-agent"]);

export class StaticKeyError extends Error {}

export function validateHeaderName(name: string): string {
  const h = name.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(h)) throw new StaticKeyError(`Invalid header name "${name.slice(0, 64)}".`);
  if (FORBIDDEN_HEADERS.has(h)) throw new StaticKeyError(`The key cannot be sent in the ${h} header.`);
  return h;
}

export function loadBearerFile(path: string, header = "authorization"): { credential: Credential; warnings: string[] } {
  return loadCredentialFile(path, header, "static");
}

/**
 * An OAuth access token for the MCP endpoint (`--access-token-file`): the
 * same file rules as a static key, but reported as a token, and always sent
 * as `Authorization: Bearer`.
 */
export function loadAccessTokenFile(path: string): { credential: Credential; warnings: string[] } {
  return loadCredentialFile(path, "authorization", "oauth");
}

function loadCredentialFile(path: string, header: string, kind: Credential["kind"]): { credential: Credential; warnings: string[] } {
  const h = validateHeaderName(header);
  const label = kind === "static" ? "key file" : "access token file";
  let loaded: { value: string; warnings: string[] };
  try {
    // Short values could not be redacted reliably and are not real keys.
    loaded = readSecretLine(path, { label, maxBytes: MAX_KEY_BYTES, minLength: MIN_KEY_LENGTH });
  } catch (e) {
    if (e instanceof SecretFileError) throw new StaticKeyError(e.message);
    throw e;
  }
  registerSecret(loaded.value);
  return { credential: bearerCredential(loaded.value, h, kind), warnings: loaded.warnings };
}
