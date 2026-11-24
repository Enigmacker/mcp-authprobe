import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { isLoopbackHost } from "./net/address-policy.js";
import type { HttpClient } from "./net/http.js";

/**
 * Ownership proof.
 *
 * Active checks change state on the target (they register clients, rotate
 * tokens, send failing logins). They only run against hosts whose operator
 * has published a proof derived from a secret that only the person running
 * the scan holds:
 *
 *   proof = "mcp-authprobe-verification=sha256:" + hex(sha256(host + ":" + secret))
 *
 * The proof is published either as a file at
 *   https://<host>/.well-known/mcp-authprobe.txt
 * or as a DNS TXT record on
 *   _mcp-authprobe.<host>
 *
 * Publishing a hash (not the secret) means nobody can reuse a proof they
 * found in the wild to scan someone else's server, and binding the hash to
 * the host means a proof for one host is useless on another.
 */

export const PROOF_PREFIX = "mcp-authprobe-verification=sha256:";
/**
 * Version 2 of the proof: HMAC-SHA256 keyed by the secret, over the host and
 * an optional expiry date. Both versions are accepted; version 1 proofs
 * already published keep working.
 *
 *   mcp-authprobe-verification=v2:<hex(hmac-sha256(secret, "mcp-authprobe/v2\n" + host + "\n" + exp))>[;exp=YYYY-MM-DD]
 *
 * A proof covers the whole host, whatever the port: it is fetched on port
 * 443 (or read from DNS), and says "the operator of this host agrees".
 */
export const PROOF_V2_PREFIX = "mcp-authprobe-verification=v2:";
const ANY_PREFIX = "mcp-authprobe-verification=";
export const WELL_KNOWN_PATH = "/.well-known/mcp-authprobe.txt";
export const DNS_LABEL = "_mcp-authprobe";
const MIN_SECRET_LENGTH = 32;

export interface OwnershipResult {
  host: string;
  verified: boolean;
  method: "well-known" | "dns-txt" | "loopback" | null;
  detail: string;
  /** Format of the proof that matched (1: SHA-256 of host and secret; 2: HMAC-SHA256, optional expiry). */
  proofVersion?: 1 | 2;
}

export function generateSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

export function proofFor(host: string, secret: string): string {
  const digest = createHash("sha256").update(`${normalizeHost(host)}:${secret}`).digest("hex");
  return `${PROOF_PREFIX}${digest}`;
}

/** A version 2 proof for `host`, optionally valid until the end of `expires` (YYYY-MM-DD, UTC). */
export function proofV2For(host: string, secret: string, expires?: string): string {
  if (expires !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(expires)) throw new Error("The expiry date must be YYYY-MM-DD.");
  const mac = createHmac("sha256", secret).update(`mcp-authprobe/v2\n${normalizeHost(host)}\n${expires ?? ""}`).digest("hex");
  return `${PROOF_V2_PREFIX}${mac}${expires ? `;exp=${expires}` : ""}`;
}

/**
 * Does a published line prove ownership of `host`? Returns the version that
 * matched, "expired" for a valid version 2 proof past its date, or null.
 */
export function matchProof(line: string, host: string, secret: string, now: Date = new Date()): 1 | 2 | "expired" | null {
  const candidate = line.trim();
  if (candidate.startsWith(PROOF_V2_PREFIX)) {
    const exp = /;exp=(\d{4}-\d{2}-\d{2})$/.exec(candidate)?.[1];
    if (!sameProof(candidate, proofV2For(host, secret, exp))) return null;
    if (exp !== undefined && now.getTime() > Date.parse(`${exp}T23:59:59.999Z`)) return "expired";
    return 2;
  }
  return sameProof(candidate, proofFor(host, secret)) ? 1 : null;
}

/** A warning when a secret is unlikely to be random (the proof is public: a guessable secret can be found offline). */
export function weakSecretWarning(secret: string): string | null {
  const distinct = new Set(secret).size;
  if (secret.length < MIN_SECRET_LENGTH) return `The ownership secret is too short (minimum ${MIN_SECRET_LENGTH} characters).`;
  if (distinct < 12 || /^(.{1,8})\1+$/.test(secret)) return "The ownership secret does not look random (few distinct characters, or a repeated pattern). Its proof is public: generate a secret with `mcp-authprobe ownership init`.";
  return null;
}

function sameProof(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Extract candidate proof lines from a well-known file body. */
export function proofsInText(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(ANY_PREFIX));
}

export interface VerifyOptions {
  http: HttpClient;
  /** Inject a TXT resolver for tests. */
  resolveTxtRecords?: (name: string) => Promise<string[][]>;
  /** Port to use for the well-known URL (tests and non-default ports). */
  wellKnownBaseUrl?: string;
  /**
   * Exempt loopback hosts from the proof when private addresses are allowed
   * (default true). MCP mode turns it off unless the human pinned the lab.
   */
  loopbackExempt?: boolean;
}

export async function verifyOwnership(
  host: string,
  secret: string | undefined,
  options: VerifyOptions,
): Promise<OwnershipResult> {
  const h = normalizeHost(host);

  if ((options.loopbackExempt ?? true) && options.http.allowPrivate && isLoopbackHost(h)) {
    return { host: h, verified: true, method: "loopback", detail: "Loopback target with --allow-private: local lab, proof not required." };
  }
  if (!secret) {
    return { host: h, verified: false, method: null, detail: "No ownership secret provided (MCP_AUTHPROBE_SECRET)." };
  }
  if (secret.length < MIN_SECRET_LENGTH) {
    return { host: h, verified: false, method: null, detail: `Ownership secret is too short (minimum ${MIN_SECRET_LENGTH} characters).` };
  }

  const reasons: string[] = [];
  /** The best match among published lines: a valid proof wins over an expired one. */
  const judge = (lines: string[]): 1 | 2 | "expired" | null => {
    let out: 1 | 2 | "expired" | null = null;
    for (const line of lines) {
      const m = matchProof(line, h, secret);
      if (m === 1 || m === 2) return m;
      if (m === "expired") out = "expired";
    }
    return out;
  };

  // 1. Well-known file over HTTPS (HTTP only for allowed private labs).
  const base = options.wellKnownBaseUrl ?? `https://${h}`;
  try {
    const res = await options.http.request({ url: new URL(WELL_KNOWN_PATH, base).toString() });
    if (res.status === 200) {
      const m = judge(proofsInText(res.body));
      if (m === 1 || m === 2) return { host: h, verified: true, method: "well-known", detail: `Proof found at ${WELL_KNOWN_PATH}.`, proofVersion: m };
      reasons.push(m === "expired" ? `the proof at ${WELL_KNOWN_PATH} has expired` : `${WELL_KNOWN_PATH} exists but holds no matching proof`);
    } else {
      reasons.push(`${WELL_KNOWN_PATH} returned HTTP ${res.status}`);
    }
  } catch (err) {
    reasons.push(`${WELL_KNOWN_PATH} unreachable (${(err as Error).message})`);
  }

  // 2. DNS TXT record.
  const resolver = options.resolveTxtRecords ?? resolveTxt;
  const name = `${DNS_LABEL}.${h}`;
  try {
    const records = await resolver(name);
    const m = judge(records.map((chunks) => chunks.join("")));
    if (m === 1 || m === 2) return { host: h, verified: true, method: "dns-txt", detail: `Proof found in TXT ${name}.`, proofVersion: m };
    reasons.push(m === "expired" ? `the proof in TXT ${name} has expired` : `TXT ${name} holds no matching proof`);
  } catch {
    reasons.push(`no TXT record at ${name}`);
  }

  return { host: h, verified: false, method: null, detail: `Ownership not proven: ${reasons.join("; ")}.` };
}
