import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
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
export const WELL_KNOWN_PATH = "/.well-known/mcp-authprobe.txt";
export const DNS_LABEL = "_mcp-authprobe";
const MIN_SECRET_LENGTH = 32;

export interface OwnershipResult {
  host: string;
  verified: boolean;
  method: "well-known" | "dns-txt" | "loopback" | null;
  detail: string;
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
    .filter((line) => line.startsWith(PROOF_PREFIX));
}

export interface VerifyOptions {
  http: HttpClient;
  /** Inject a TXT resolver for tests. */
  resolveTxtRecords?: (name: string) => Promise<string[][]>;
  /** Port to use for the well-known URL (tests and non-default ports). */
  wellKnownBaseUrl?: string;
}

export async function verifyOwnership(
  host: string,
  secret: string | undefined,
  options: VerifyOptions,
): Promise<OwnershipResult> {
  const h = normalizeHost(host);

  if (options.http.allowPrivate && isLoopbackHost(h)) {
    return { host: h, verified: true, method: "loopback", detail: "Loopback target with --allow-private: local lab, proof not required." };
  }
  if (!secret) {
    return { host: h, verified: false, method: null, detail: "No ownership secret provided (MCP_AUTHPROBE_SECRET)." };
  }
  if (secret.length < MIN_SECRET_LENGTH) {
    return { host: h, verified: false, method: null, detail: `Ownership secret is too short (minimum ${MIN_SECRET_LENGTH} characters).` };
  }

  const expected = proofFor(h, secret);
  const reasons: string[] = [];

  // 1. Well-known file over HTTPS (HTTP only for allowed private labs).
  const base = options.wellKnownBaseUrl ?? `https://${h}`;
  try {
    const res = await options.http.request({ url: new URL(WELL_KNOWN_PATH, base).toString() });
    if (res.status === 200) {
      if (proofsInText(res.body).some((p) => sameProof(p, expected))) {
        return { host: h, verified: true, method: "well-known", detail: `Proof found at ${WELL_KNOWN_PATH}.` };
      }
      reasons.push(`${WELL_KNOWN_PATH} exists but holds no matching proof`);
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
    if (records.map((chunks) => chunks.join("")).some((r) => sameProof(r.trim(), expected))) {
      return { host: h, verified: true, method: "dns-txt", detail: `Proof found in TXT ${name}.` };
    }
    reasons.push(`TXT ${name} holds no matching proof`);
  } catch {
    reasons.push(`no TXT record at ${name}`);
  }

  return { host: h, verified: false, method: null, detail: `Ownership not proven: ${reasons.join("; ")}.` };
}
