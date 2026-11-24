import { registerSecret } from "./redact.js";
import { readSecretFile, SecretFileError } from "./secret-file.js";

/**
 * The session of a logged-in test account on the authorization server
 * (`--session-cookie-file`), for MAP-RDR01 and MAP-RDR02 on servers that
 * only validate redirect_uri after login.
 *
 * The file holds one line: the value of the Cookie header the browser sends
 * to the authorization endpoint (`name=value; name2=value2`), optionally
 * prefixed with `Cookie:`. Every value is registered for redaction; the
 * content never reaches an error message.
 */

const MAX_BYTES = 16 * 1024;
const NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// RFC 6265 cookie-octets, and the double quotes that may surround them.
const VALUE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$|^"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*"$/;

export class SessionCookieError extends Error {}

/** Parse and normalize a Cookie header value. Throws SessionCookieError without quoting the content. */
export function parseCookieHeader(text: string): string {
  const line = text.trim().replace(/^cookie\s*:\s*/i, "");
  if (!line) throw new SessionCookieError("The session cookie file is empty.");
  if (/[\r\n]/.test(line)) throw new SessionCookieError("The session cookie file must hold one line: the Cookie header value (name=value; name2=value2).");
  const pairs: string[] = [];
  for (const part of line.split(";")) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq <= 0) throw new SessionCookieError("The session cookie file must hold name=value pairs separated by semicolons.");
    const name = p.slice(0, eq).trim();
    const value = p.slice(eq + 1).trim();
    if (!NAME.test(name) || !VALUE.test(value)) throw new SessionCookieError("The session cookie file holds a cookie name or value with characters a Cookie header cannot carry.");
    pairs.push(`${name}=${value}`);
  }
  if (pairs.length === 0) throw new SessionCookieError("The session cookie file holds no cookie.");
  return pairs.join("; ");
}

export function loadSessionCookieFile(path: string): { cookie: string; warnings: string[] } {
  let loaded: { text: string; warnings: string[] };
  try {
    loaded = readSecretFile(path, { label: "session cookie file", maxBytes: MAX_BYTES });
  } catch (e) {
    if (e instanceof SecretFileError) throw new SessionCookieError(e.message);
    throw e;
  }
  const cookie = parseCookieHeader(loaded.text);
  registerSecret(cookie);
  for (const pair of cookie.split("; ")) registerSecret(pair.slice(pair.indexOf("=") + 1));
  return { cookie, warnings: loaded.warnings };
}
