import type { TestGrant } from "../credentials.js";
import type { HttpClient } from "../net/http.js";
import { describe, refresh, type RefreshOutcome } from "../oauth/token-client.js";
import type { Finding, ReasonCode } from "../types.js";
import { makeFinding } from "./finding.js";

/**
 * Refresh token family: MAP-RTK01, MAP-RTK02, MAP-RTK03.
 *
 * Sequence, at most three token requests:
 *   1. refresh(R0)            -> expect a new access token and a NEW refresh token R1   (RTK01)
 *   2. refresh(R0) again      -> expect rejection, typically invalid_grant              (RTK02)
 *   3. refresh(R1)            -> expect rejection: reuse should revoke the family       (RTK03)
 *
 * Step 3 deliberately ends the test grant on a compliant server. The grant
 * must belong to a dedicated test account.
 */

export interface RefreshCheckContext {
  http: HttpClient;
  target: string;
  tokenEndpoint: string;
  grant: TestGrant;
  /**
   * Checks wanted (default: all three). Only the steps they need are sent:
   * MAP-RTK01 alone is one refresh; MAP-RTK02 adds the replay; MAP-RTK03 adds
   * the use of the newest token after the replay.
   */
  select?: (checkId: string) => boolean;
  /** RFC 8707 resource sent with every refresh (the MCP server). */
  resource?: string;
}

/** What became of the test grant, so the caller can keep the newest token. */
export interface GrantState {
  /** Token requests sent. */
  requests: number;
  /** The server returned a new refresh token. */
  rotated: boolean;
  /** The newest refresh token the scanner holds, or null when the server issued none. In memory only: never reported. */
  latestRefreshToken: string | null;
  /**
   * "valid": the newest token was not presented again and nothing revoked it, or it was just accepted;
   * "revoked": the server refused it (family revocation), the grant is spent;
   * "unknown": the sequence stopped on an inconclusive answer.
   */
  state: "valid" | "revoked" | "unknown";
}

export interface RefreshSequenceResult {
  findings: Finding[];
  grant: GrantState;
}

/** Reason codes for this file's inconclusive and skipped messages (first match wins; the default is "unexpected_answer"). */
const REASONS: ReadonlyArray<[RegExp, ReasonCode]> = [
  [/^Not selected/, "not_selected"],
  [/unreachable/i, "unreachable"],
  [/throttled/i, "rate_limited"],
  [/was not accepted/i, "credential_rejected"],
];
const reasonOf = (message: string): ReasonCode | undefined => REASONS.find(([re]) => re.test(message))?.[1];

function result(id: string, target: string, status: Finding["status"], message: string, evidence: string[], reason?: ReasonCode): Finding {
  return makeFinding(id, target, status, message, evidence, reason ?? reasonOf(message));
}

const isRejection = (o: RefreshOutcome): boolean => !o.accessTokenIssued && o.status >= 400 && o.status < 500 && !o.throttled;

const IDS = ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"] as const;

/** Returns only the findings (kept for callers of earlier versions). */
export async function runRefreshTokenChecks(ctx: RefreshCheckContext): Promise<Finding[]> {
  return (await runRefreshTokenSequence(ctx)).findings;
}

export async function runRefreshTokenSequence(ctx: RefreshCheckContext): Promise<RefreshSequenceResult> {
  const { http, target, tokenEndpoint, grant } = ctx;
  const wanted = ctx.select ?? (() => true);
  const want01 = wanted("MAP-RTK01");
  const want02 = wanted("MAP-RTK02");
  const want03 = wanted("MAP-RTK03");
  const findings: Finding[] = [];
  const r0 = grant.refreshToken;
  const state: GrantState = { requests: 0, rotated: false, latestRefreshToken: r0, state: "unknown" };
  const send = (token: string): Promise<RefreshOutcome> => {
    state.requests += 1;
    return refresh(http, tokenEndpoint, grant, token, ctx.resource);
  };
  /** A check that was not selected: nothing is reported as a result, but a request it shares is disclosed. */
  const unselected = (id: string, sent: string | null): Finding =>
    result(id, target, "skipped", sent ? `Not selected (--only/--skip): no result is reported, but ${sent}` : "Not selected (--only/--skip): not run.", []);
  const done = (): RefreshSequenceResult => {
    for (const id of IDS) if (!findings.some((f) => f.checkId === id)) findings.push(unselected(id, null));
    findings.sort((a, b) => a.checkId.localeCompare(b.checkId));
    return { findings, grant: state };
  };
  const every = (status: Finding["status"], message: string, evidence: string[]): void => {
    for (const id of IDS) if (wanted(id)) findings.push(result(id, target, status, message, evidence));
  };
  if (!want01 && !want02 && !want03) {
    state.state = "valid";
    return done();
  }

  // Step 1: a normal refresh (every check needs it).
  let first: RefreshOutcome;
  try {
    first = await send(r0);
  } catch (err) {
    every("error", `Token endpoint unreachable: ${(err as Error).message}`, []);
    return done();
  }
  const step1 = `step 1, refresh with the supplied token: ${describe(first)}`;

  if (!first.accessTokenIssued) {
    const msg = first.throttled
      ? "The token endpoint throttled the first refresh; retry later."
      : "The supplied refresh token was not accepted; supply a fresh test grant.";
    if (isRejection(first) && first.error === "invalid_grant") state.state = "revoked";
    every("error", msg, [step1]);
    return done();
  }

  const r1 = first.refreshToken;
  const rotated = r1 !== null && r1 !== r0;
  state.rotated = rotated;
  state.latestRefreshToken = r1 ?? r0;
  state.state = "valid";
  if (!want01) findings.push(unselected("MAP-RTK01", "its request (one refresh with the supplied token) was sent, because the selected refresh token checks start from it."));
  if (!rotated) {
    if (want01) {
      findings.push(
        result(
          "MAP-RTK01",
          target,
          "fail",
          r1 === null
            ? "Refresh succeeded but no new refresh token was returned: the same refresh token stays valid."
            : "Refresh succeeded but returned the same refresh token: it is not rotated.",
          [step1],
        ),
      );
    }
    // Without rotation there is no "old" token to replay: replay protection
    // cannot exist, so the next two checks do not apply. RTK01 carries the finding.
    const na = "Not applicable: refresh tokens are not rotated (see MAP-RTK01).";
    if (want02) findings.push(result("MAP-RTK02", target, "not_applicable", na, [step1]));
    if (want03) findings.push(result("MAP-RTK03", target, "not_applicable", na, [step1]));
    return done();
  }
  if (want01) findings.push(result("MAP-RTK01", target, "pass", "Refresh tokens are rotated on use.", [step1]));
  if (!want02 && !want03) return done(); // one refresh only: the newest token stays valid

  // Step 2: replay the token that was just exchanged.
  let replay: RefreshOutcome;
  try {
    replay = await send(r0);
  } catch (err) {
    const msg = `Token endpoint unreachable during replay: ${(err as Error).message}`;
    state.state = "unknown";
    if (want02) findings.push(result("MAP-RTK02", target, "error", msg, [step1]));
    if (want03) findings.push(result("MAP-RTK03", target, "error", msg, [step1]));
    return done();
  }
  const step2 = `step 2, replay of the already-used refresh token: ${describe(replay)}`;
  if (!want02) findings.push(unselected("MAP-RTK02", "its request (a replay of the used token) was sent, because MAP-RTK03 needs it."));

  if (replay.accessTokenIssued) {
    // The replay minted new tokens: the newest one is whatever came back last.
    if (replay.refreshToken) state.latestRefreshToken = replay.refreshToken;
    if (want02) findings.push(result("MAP-RTK02", target, "fail", "An already-used refresh token was accepted again: replay is possible.", [step1, step2]));
    if (want03) findings.push(result("MAP-RTK03", target, "fail", "Reuse was not detected, so the token family cannot have been revoked.", [step2]));
    return done();
  }
  if (!isRejection(replay)) {
    const msg = replay.throttled
      ? "The replay attempt was throttled; the outcome is inconclusive."
      : "The replay attempt got an unexpected response; the outcome is inconclusive.";
    state.state = "unknown";
    if (want02) findings.push(result("MAP-RTK02", target, "error", msg, [step2]));
    if (want03) findings.push(result("MAP-RTK03", target, "error", msg, [step2]));
    return done();
  }
  if (want02) findings.push(result("MAP-RTK02", target, "pass", "The already-used refresh token was rejected.", [step2]));
  // A compliant server revoked the family on that replay; without step 3 this is not known.
  state.state = "unknown";
  if (!want03) return done();

  // Step 3: is the newer token (descendant of the replayed one) revoked?
  let after: RefreshOutcome;
  try {
    after = await send(r1);
  } catch (err) {
    findings.push(result("MAP-RTK03", target, "error", `Token endpoint unreachable: ${(err as Error).message}`, [step2]));
    return done();
  }
  const step3 = `step 3, use of the newest refresh token after the replay: ${describe(after)}`;

  if (after.accessTokenIssued) {
    if (after.refreshToken) state.latestRefreshToken = after.refreshToken;
    state.state = "valid";
    findings.push(
      result(
        "MAP-RTK03",
        target,
        "fail",
        "Reuse was detected but the token family stayed valid: an attacker racing the legitimate client keeps access.",
        [step2, step3],
      ),
    );
  } else if (isRejection(after)) {
    state.state = "revoked";
    findings.push(result("MAP-RTK03", target, "pass", "Reuse revoked the whole refresh token family.", [step2, step3]));
  } else {
    findings.push(result("MAP-RTK03", target, "error", "Unexpected response after the replay; the outcome is inconclusive.", [step3]));
  }
  return done();
}
