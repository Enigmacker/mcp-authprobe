import type { TestGrant } from "../credentials.js";
import type { HttpClient } from "../net/http.js";
import { describe, refresh, type RefreshOutcome } from "../oauth/token-client.js";
import { safeText } from "../redact.js";
import type { CheckDefinition, Finding } from "../types.js";
import { CATALOGUE } from "./catalogue.js";

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
}

function def(id: string): CheckDefinition {
  const d = CATALOGUE.find((c) => c.id === id);
  if (!d) throw new Error(`Unknown check ${id}`);
  return d;
}

function result(id: string, target: string, status: Finding["status"], message: string, evidence: string[]): Finding {
  const d = def(id);
  return {
    checkId: d.id,
    title: d.title,
    severity: d.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
  };
}

const isRejection = (o: RefreshOutcome): boolean => !o.accessTokenIssued && o.status >= 400 && o.status < 500 && !o.throttled;

export async function runRefreshTokenChecks(ctx: RefreshCheckContext): Promise<Finding[]> {
  const { http, target, tokenEndpoint, grant } = ctx;
  const findings: Finding[] = [];
  const r0 = grant.refreshToken;

  // Step 1: a normal refresh.
  let first: RefreshOutcome;
  try {
    first = await refresh(http, tokenEndpoint, grant, r0);
  } catch (err) {
    const msg = `Token endpoint unreachable: ${(err as Error).message}`;
    return ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"].map((id) => result(id, target, "error", msg, []));
  }
  const step1 = `step 1, refresh with the supplied token: ${describe(first)}`;

  if (!first.accessTokenIssued) {
    const msg = first.throttled
      ? "The token endpoint throttled the first refresh; retry later."
      : "The supplied refresh token was not accepted; supply a fresh test grant.";
    return ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"].map((id) => result(id, target, "error", msg, [step1]));
  }

  const r1 = first.refreshToken;
  const rotated = r1 !== null && r1 !== r0;
  if (!rotated) {
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
    // Without rotation there is no "old" token to replay: replay protection
    // cannot exist, so the next two checks do not apply. RTK01 carries the finding.
    const na = "Not applicable: refresh tokens are not rotated (see MAP-RTK01).";
    findings.push(result("MAP-RTK02", target, "not_applicable", na, []));
    findings.push(result("MAP-RTK03", target, "not_applicable", na, []));
    return findings;
  }
  findings.push(result("MAP-RTK01", target, "pass", "Refresh tokens are rotated on use.", [step1]));

  // Step 2: replay the token that was just exchanged.
  let replay: RefreshOutcome;
  try {
    replay = await refresh(http, tokenEndpoint, grant, r0);
  } catch (err) {
    const msg = `Token endpoint unreachable during replay: ${(err as Error).message}`;
    findings.push(result("MAP-RTK02", target, "error", msg, [step1]));
    findings.push(result("MAP-RTK03", target, "error", msg, [step1]));
    return findings;
  }
  const step2 = `step 2, replay of the already-used refresh token: ${describe(replay)}`;

  if (replay.accessTokenIssued) {
    findings.push(
      result("MAP-RTK02", target, "fail", "An already-used refresh token was accepted again: replay is possible.", [step1, step2]),
    );
    findings.push(
      result("MAP-RTK03", target, "fail", "Reuse was not detected, so the token family cannot have been revoked.", [step2]),
    );
    return findings;
  }
  if (!isRejection(replay)) {
    const msg = replay.throttled
      ? "The replay attempt was throttled; the outcome is inconclusive."
      : "The replay attempt got an unexpected response; the outcome is inconclusive.";
    findings.push(result("MAP-RTK02", target, "error", msg, [step2]));
    findings.push(result("MAP-RTK03", target, "error", msg, [step2]));
    return findings;
  }
  findings.push(result("MAP-RTK02", target, "pass", "The already-used refresh token was rejected.", [step2]));

  // Step 3: is the newer token (descendant of the replayed one) revoked?
  let after: RefreshOutcome;
  try {
    after = await refresh(http, tokenEndpoint, grant, r1);
  } catch (err) {
    findings.push(result("MAP-RTK03", target, "error", `Token endpoint unreachable: ${(err as Error).message}`, [step2]));
    return findings;
  }
  const step3 = `step 3, use of the newest refresh token after the replay: ${describe(after)}`;

  if (after.accessTokenIssued) {
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
    findings.push(result("MAP-RTK03", target, "pass", "Reuse revoked the whole refresh token family.", [step2, step3]));
  } else {
    findings.push(result("MAP-RTK03", target, "error", "Unexpected response after the replay; the outcome is inconclusive.", [step3]));
  }
  return findings;
}
