import { randomBytes } from "node:crypto";
import type { TestGrant } from "../credentials.js";
import type { HttpClient } from "../net/http.js";
import { deleteClient, REGISTERED_REDIRECT, registerClient, type RegisteredClient } from "../oauth/registration.js";
import { exchangeCode, refresh, type RefreshOutcome } from "../oauth/token-client.js";
import { safeText } from "../redact.js";
import type { Finding, Leftover, ReasonCode } from "../types.js";
import { makeFinding } from "./finding.js";

/**
 * MAP-THR01: are repeated failed token requests throttled?
 *
 * The check sends up to `attempts` sequential refresh_token requests, each
 * with a freshly generated random refresh token that cannot be valid, for
 * the operator's own test client, and stops at the first sign of rate
 * limiting (HTTP 429, a Retry-After header, or an OAuth slow_down /
 * temporarily_unavailable error). If the very first refresh request fails
 * with a server error or unsupported_grant_type (some servers do not
 * implement refresh), it switches once to authorization_code requests with
 * random codes, and starts counting again.
 *
 * Bounds, by design:
 *   - attempts are capped (MIN_ATTEMPTS to MAX_ATTEMPTS, default 10);
 *   - requests are sequential, never parallel;
 *   - only random values are sent: nothing is guessed, no user password or
 *     login form is ever involved;
 *   - it runs last in a scan, so throttling cannot disturb other checks.
 */

export const DEFAULT_ATTEMPTS = 10;
export const MIN_ATTEMPTS = 5;
export const MAX_ATTEMPTS = 20;

export interface ThrottleCheckContext {
  http: HttpClient;
  target: string;
  tokenEndpoint: string;
  registrationEndpoint: string | null;
  /** The operator's test grant: its client is used when present. */
  grant?: TestGrant;
  attempts?: number;
  /** Receives the temporary client when it could not be deleted. */
  leftovers?: Leftover[];
  /** A client the operator supplies: used, like the grant's client, instead of registering a temporary one. */
  client?: { clientId: string; clientSecret?: string; authMethod?: TestGrant["authMethod"] };
}

export function clampAttempts(n: number | undefined): number {
  if (n === undefined || !Number.isFinite(n)) return DEFAULT_ATTEMPTS;
  return Math.min(MAX_ATTEMPTS, Math.max(MIN_ATTEMPTS, Math.trunc(n)));
}

/** Reason codes for this file's inconclusive and skipped messages (first match wins; the default is "unexpected_answer"). */
const REASONS: ReadonlyArray<[RegExp, ReasonCode]> = [
  [/unreachable/i, "unreachable"],
  [/rate limited/i, "rate_limited"],
  [/server error/i, "server_error"],
  [/^Needs a client/, "no_client"],
];
const reasonOf = (message: string): ReasonCode | undefined => REASONS.find(([re]) => re.test(message))?.[1];

function result(status: Finding["status"], target: string, message: string, evidence: string[] = [], reason?: ReasonCode): Finding {
  return makeFinding("MAP-THR01", target, status, message, evidence, reason ?? reasonOf(message));
}

const THROTTLE_ERRORS = new Set(["slow_down", "temporarily_unavailable"]);

/** Only an explicit rate limit counts (429, a Retry-After on a 4xx, slow_down): a 5xx with Retry-After is an outage, not throttling. */
function isThrottled(o: RefreshOutcome): boolean {
  return o.status === 429 || (o.throttled && o.status >= 400 && o.status < 500) || (o.error !== null && THROTTLE_ERRORS.has(o.error));
}

export async function runThrottlingCheck(ctx: ThrottleCheckContext): Promise<Finding> {
  const { http, target, tokenEndpoint } = ctx;
  const attempts = clampAttempts(ctx.attempts);
  let temporary: RegisteredClient | null = null;

  try {
    // Use the operator's own client; otherwise a temporary one.
    let grant: TestGrant;
    if (ctx.grant) {
      grant = { ...ctx.grant };
    } else if (ctx.client) {
      grant = { clientId: ctx.client.clientId, refreshToken: "", authMethod: ctx.client.authMethod ?? (ctx.client.clientSecret ? "client_secret_post" : "none") };
      if (ctx.client.clientSecret) grant.clientSecret = ctx.client.clientSecret;
    } else if (ctx.registrationEndpoint) {
      const reg = await registerClient(http, ctx.registrationEndpoint, [REGISTERED_REDIRECT], { grantTypes: ["authorization_code", "refresh_token"] });
      if (!reg.client) {
        const limited = reg.status === 429 || reg.retryAfter ? ": the registration endpoint is rate limited, run the scan again later" : "";
        return result("error", target, `Could not register a temporary test client (HTTP ${reg.status})${limited}.`);
      }
      temporary = reg.client;
      grant = { clientId: reg.client.clientId, refreshToken: "", authMethod: reg.client.clientSecret ? "client_secret_post" : "none" };
      if (reg.client.clientSecret) grant.clientSecret = reg.client.clientSecret;
    } else {
      return result("skipped", target, "Needs a client: this authorization server offers no dynamic client registration. Pass a pre-registered client with --client-id, or a test grant with --credentials-file.");
    }

    const random = (): string => `invalid-${randomBytes(24).toString("base64url")}`;
    const viaRefresh = (): Promise<RefreshOutcome> => refresh(http, tokenEndpoint, grant, random());
    const viaCode = (): Promise<RefreshOutcome> => {
      const params: Parameters<typeof exchangeCode>[2] = { clientId: grant.clientId, code: random(), codeVerifier: randomBytes(32).toString("base64url"), redirectUri: REGISTERED_REDIRECT };
      if (grant.clientSecret) params.clientSecret = grant.clientSecret;
      return exchangeCode(http, tokenEndpoint, params);
    };
    let send = viaRefresh;
    let kind = "refresh token";
    const notes: string[] = [];
    const statusCounts = new Map<number, number>();
    for (let i = 1; i <= attempts; i += 1) {
      const outcome = await send();
      if (i === 1 && send === viaRefresh && !outcome.accessTokenIssued && (outcome.status >= 500 || outcome.error === "unsupported_grant_type")) {
        notes.push(`random refresh token: HTTP ${outcome.status}${outcome.error ? `, error=${outcome.error}` : ""}; switched to random authorization codes`);
        send = viaCode;
        kind = "authorization code";
        i = 0;
        continue;
      }
      statusCounts.set(outcome.status, (statusCounts.get(outcome.status) ?? 0) + 1);
      const tally = [...notes, [...statusCounts].map(([s, n]) => `HTTP ${s} x${n}`).join(", ")].join("; ");

      if (outcome.accessTokenIssued) {
        return result("error", target, `A random ${kind} was accepted, which should be impossible; inspect the token endpoint urgently.`, [`attempt ${i}: ${tally}`]);
      }
      if (outcome.status >= 500) {
        return result("error", target, "The token endpoint answered with a server error; the outcome is inconclusive.", [`attempt ${i}: ${tally}`]);
      }
      if (isThrottled(outcome)) {
        // Limited from the very first request: the limit was already active (an earlier scan, or a block of this address), not triggered by this check.
        const already = i === 1 ? " The endpoint was already limiting before this check sent anything: a limit exists, but its threshold was not observed (an earlier scan may have triggered it, or this address is blocked)." : "";
        return result("pass", target, `Throttling started after ${i} failed request(s).${already}`, [
          `${tally}${outcome.error ? `, last error=${outcome.error}` : ""}`,
        ]);
      }
    }
    const tally = [...notes, [...statusCounts].map(([s, n]) => `HTTP ${s} x${n}`).join(", ")].join("; ");
    return result(
      "fail",
      target,
      `No throttling after ${attempts} failed token requests (random ${kind}s) in a row. The limit may simply be higher than this test's cap; check that one exists.`,
      [tally],
    );
  } catch (err) {
    return result("error", target, `Token endpoint unreachable: ${(err as Error).message}`);
  } finally {
    if (temporary && ctx.registrationEndpoint && !(await deleteClient(http, temporary, ctx.registrationEndpoint))) {
      ctx.leftovers?.push({ kind: "client", clientId: safeText(temporary.clientId, 200), endpoint: ctx.registrationEndpoint, reason: "the server offers no RFC 7592 deletion, or refused it" });
    }
  }
}
