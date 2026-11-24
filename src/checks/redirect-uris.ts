import { ScanInterruptedError, type HttpClient } from "../net/http.js";
import { describeAnswer, probeAuthorize, signature, type AuthorizeAnswer, type AuthorizeParams } from "../oauth/authorize.js";
import { deleteClient, REGISTERED_REDIRECT, registerClient, SAFE_DOMAIN, type RegisteredClient } from "../oauth/registration.js";
import { safeText } from "../redact.js";
import type { Finding, Leftover, ReasonCode } from "../types.js";
import { makeFinding } from "./finding.js";
import { baselineProblem, describeSessionAnswer, judgeInSession, probeInSession, type AuthorizationSession, type SessionRow } from "./redirect-session.js";

/**
 * Redirect URI family: MAP-RDR01, MAP-RDR02, MAP-RDR04.
 * (MAP-RDR03 needs an authorization code, hence a login: not run here.)
 *
 * Method for the authorization endpoint checks:
 *   1. Obtain a client whose only redirect URI is REGISTERED_REDIRECT, by
 *      dynamic registration when available.
 *   2. Baseline: one authorization request with the registered URI.
 *   3. One request per variant. A variant that gets redirected to fails the
 *      check. A variant answered differently from the baseline (typically an
 *      error page) was refused. A variant answered exactly like the baseline
 *      (typically a redirect to the login page) is inconclusive: the server
 *      may only validate after login.
 *
 * With a logged-in session (--session-cookie-file), the same requests are
 * replayed in that session instead, so that a server which only validates
 * after login can be judged: see redirect-session.ts.
 *
 * Every URI sent lives under the reserved ".invalid" domain, so even a
 * redirect could never deliver anything anywhere. Without a session no
 * redirect is followed; in a session, only those within the authorization
 * server's own origin.
 */

export const UNREGISTERED_REDIRECT = `https://elsewhere.${SAFE_DOMAIN}/callback`;

/** Close variants of the registered URI that exact string matching must refuse. */
export const NEAR_MISS_VARIANTS: ReadonlyArray<{ label: string; uri: string }> = [
  { label: "extra path segment", uri: `${REGISTERED_REDIRECT}/extra` },
  { label: "trailing slash", uri: `${REGISTERED_REDIRECT}/` },
  { label: "added query", uri: `${REGISTERED_REDIRECT}?next=1` },
  { label: "different port", uri: `https://client.${SAFE_DOMAIN}:8443/callback` },
  { label: "subdomain", uri: `https://other.client.${SAFE_DOMAIN}/callback` },
  { label: "userinfo", uri: `https://client.${SAFE_DOMAIN}@other.${SAFE_DOMAIN}/callback` },
  { label: "scheme downgrade", uri: `http://client.${SAFE_DOMAIN}/callback` },
];

/**
 * The same near misses for any registered redirect URI (a pre-registered
 * client has its own). A loopback URI gets no "different port" variant:
 * native clients may use any port there (RFC 8252), so accepting it is right.
 */
export function nearMissVariants(registered: string): Array<{ label: string; uri: string }> {
  if (registered === REGISTERED_REDIRECT) return [...NEAR_MISS_VARIANTS];
  const u = new URL(registered);
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname);
  const edit = (f: (x: URL) => void): string => {
    const x = new URL(registered);
    f(x);
    return x.toString();
  };
  const out = [
    { label: "extra path segment", uri: edit((x) => (x.pathname = `${x.pathname.replace(/\/$/, "")}/extra`)) },
    { label: "trailing slash", uri: edit((x) => (x.pathname = x.pathname.endsWith("/") ? x.pathname.replace(/\/+$/, "") || "/x" : `${x.pathname}/`)) },
    { label: "added query", uri: edit((x) => x.searchParams.set("next", "1")) },
  ];
  if (!loopback) {
    out.push({ label: "different port", uri: edit((x) => (x.port = x.port === "8443" ? "9443" : "8443")) });
    if (!/^[\d.]+$|^\[/.test(u.hostname)) out.push({ label: "subdomain", uri: edit((x) => (x.hostname = `other.${x.hostname}`)) });
  }
  out.push({ label: "userinfo", uri: `${u.protocol}//${u.host}@other.${SAFE_DOMAIN}${u.pathname}${u.search}` });
  if (u.protocol === "https:") out.push({ label: "scheme downgrade", uri: edit((x) => (x.protocol = "http:")) });
  return out;
}

/** Redirect URIs a registration endpoint should refuse for an MCP client. */
export const UNSAFE_REGISTRATIONS: ReadonlyArray<{ label: string; uri: string }> = [
  { label: "plain HTTP on a non-loopback host", uri: `http://client.${SAFE_DOMAIN}/callback` },
  { label: "javascript: scheme", uri: "javascript:void(0)" },
  { label: "data: scheme", uri: "data:text/plain,x" },
  { label: "fragment (forbidden by RFC 6749)", uri: `https://client.${SAFE_DOMAIN}/callback#fragment` },
];

export interface RedirectCheckContext {
  /** Checks to run (default: all three). Unselected checks send no request. */
  select?: (checkId: string) => boolean;
  http: HttpClient;
  target: string;
  authorizationEndpoint: string | null;
  registrationEndpoint: string | null;
  /** RFC 8707 resource to send, normally the MCP server URL. */
  resource: string;
  scope?: string;
  /** Receives the temporary clients that could not be deleted (also noted in the evidence). */
  leftovers?: Leftover[];
  /**
   * A client the operator supplies (pre-registered, or a client ID metadata
   * document), with one redirect URI registered for it: used for MAP-RDR01
   * and MAP-RDR02 instead of registering a temporary client.
   */
  client?: { clientId: string; redirectUri?: string };
  /**
   * A logged-in test account session on the authorization server: MAP-RDR01
   * and MAP-RDR02 are replayed in it. The cookie is sent to the authorization
   * endpoint's origin only and never reported.
   */
  session?: AuthorizationSession;
}

/** Reason codes for this file's inconclusive and skipped messages (first match wins; the default is "unexpected_answer"). */
const REASONS: ReadonlyArray<[RegExp, ReasonCode]> = [
  [/unreachable/i, "unreachable"],
  [/rate limited/i, "rate_limited"],
  [/server error/i, "server_error"],
  [/answered exactly like the valid one/i, "deferred_validation"],
  [/consent page was displayed/i, "deferred_validation"],
  [/session cookie was not accepted/i, "credential_rejected"],
  [/^No registration endpoint|^Needs a client/, "no_client"],
  [/^No authorization endpoint/, "no_endpoint"],
  [/was itself rejected/i, "ambiguous"],
];
const reasonOf = (message: string): ReasonCode | undefined => REASONS.find(([re]) => re.test(message))?.[1];

function result(id: string, target: string, status: Finding["status"], message: string, evidence: string[] = [], reason?: ReasonCode): Finding {
  return makeFinding(id, target, status, message, evidence, reason ?? reasonOf(message));
}

type VariantVerdict = "accepted" | "refused" | "inconclusive";

function judge(baseline: AuthorizeAnswer, answer: AuthorizeAnswer): VariantVerdict {
  if (answer.kind === "redirect-to-candidate") return "accepted";
  // A rate limit or a server error says nothing about redirect_uri validation.
  if (answer.kind === "unavailable") return "inconclusive";
  return signature(answer) === signature(baseline) ? "inconclusive" : "refused";
}

/** Summarize several variant verdicts into one finding. */
function summarize(
  id: string,
  target: string,
  rows: Array<{ label: string; verdict: VariantVerdict; detail: string }>,
  passMsg: string,
  inconclusiveMsg = "Inconclusive: some requests were answered exactly like the valid one (for example a redirect to the login page), so the server may only check redirect_uri after login.",
): Finding {
  const evidence = rows.map((r) => `${r.label}: ${r.verdict} (${r.detail})`);
  const accepted = rows.filter((r) => r.verdict === "accepted");
  if (accepted.length > 0) {
    return result(id, target, "fail", `The authorization endpoint redirected to ${accepted.length} unregistered URI(s): ${accepted.map((r) => r.label).join(", ")}.`, evidence);
  }
  if (rows.some((r) => r.verdict === "inconclusive")) {
    return result(id, target, "error", inconclusiveMsg, evidence);
  }
  return result(id, target, "pass", passMsg, evidence);
}

async function authorizationChecks(ctx: RedirectCheckContext, client: Pick<RegisteredClient, "clientId">, registered: string = REGISTERED_REDIRECT): Promise<Finding[]> {
  const { http, target } = ctx;
  const base: Omit<AuthorizeParams, "redirectUri"> = { authorizationEndpoint: ctx.authorizationEndpoint as string, clientId: client.clientId, resource: ctx.resource };
  if (ctx.scope) base.scope = ctx.scope;
  if (ctx.session) return sessionAuthorizationChecks(ctx, base, registered, ctx.session);

  const baseline = await probeAuthorize(http, { ...base, redirectUri: registered });
  const baselineLine = `baseline with the registered URI: ${describeAnswer(baseline)}`;
  if (baseline.kind === "unavailable" || (baseline.kind === "page" && baseline.status >= 400)) {
    const msg = "The baseline request with the registered redirect URI was itself rejected, so variants cannot be compared.";
    return [result("MAP-RDR01", target, "error", msg, [baselineLine]), result("MAP-RDR02", target, "error", msg, [baselineLine])];
  }

  const out: Finding[] = [];
  const wanted = ctx.select ?? (() => true);
  if (wanted("MAP-RDR01")) {
    const unregistered = await probeAuthorize(http, { ...base, redirectUri: UNREGISTERED_REDIRECT });
    const rdr01 = summarize(
      "MAP-RDR01",
      target,
      [{ label: "unrelated host", verdict: judge(baseline, unregistered), detail: describeAnswer(unregistered) }],
      "An unregistered redirect URI was refused without redirecting.",
    );
    rdr01.evidence.unshift(safeText(baselineLine));
    out.push(rdr01);
  }
  if (!wanted("MAP-RDR02")) return out;

  const rows: Array<{ label: string; verdict: VariantVerdict; detail: string }> = [];
  for (const v of nearMissVariants(registered)) {
    const answer = await probeAuthorize(http, { ...base, redirectUri: v.uri });
    rows.push({ label: v.label, verdict: judge(baseline, answer), detail: describeAnswer(answer) });
  }
  const rdr02 = summarize("MAP-RDR02", target, rows, `All ${rows.length} near-miss variants of the registered URI were refused.`);
  rdr02.evidence.unshift(safeText(baselineLine));
  out.push(rdr02);
  return out;
}

const SESSION_NOTE = "session: every request was replayed with the session cookie supplied (--session-cookie-file), sent to the authorization server only; the cookie is not reported";

/** The verdict of a set of rows judged in a session, with the message that fits what is missing. */
function summarizeSession(id: string, target: string, rows: Array<{ label: string } & SessionRow>, passMsg: string): Finding {
  const shown = rows.filter((r) => r.consentShown && r.verdict === "inconclusive");
  const msg =
    shown.length > 0
      ? `Inconclusive: the consent page was displayed for ${shown.length} unregistered URI(s) (${shown.map((r) => r.label).join(", ")}). The server may still refuse them on approval; nothing was approved. Run again with --approve-consent to find out (it grants the test client access for the test account).`
      : "Inconclusive: some requests could not be judged in the session (see the evidence).";
  const f = summarize(id, target, rows, passMsg, msg);
  if (f.status === "error" && shown.length === 0) f.reason = "ambiguous";
  const approved = rows.filter((r) => r.approved).length;
  if (approved > 0) {
    f.evidence.push(
      safeText(`consent: approved ${approved} time(s) for the test account (--approve-consent); every redirect URI sent is under the reserved .invalid domain, so no code could be delivered or used`),
    );
  }
  return f;
}

async function sessionAuthorizationChecks(ctx: RedirectCheckContext, base: Omit<AuthorizeParams, "redirectUri">, registered: string, session: AuthorizationSession): Promise<Finding[]> {
  const { http, target } = ctx;
  const wanted = ctx.select ?? (() => true);
  const baseline = await probeInSession(http, { ...base, redirectUri: registered }, session);
  const baselineLine = `baseline with the registered URI, in the session: ${describeSessionAnswer(baseline)}`;
  const problem = baselineProblem(baseline);
  if (problem) {
    const msg = problem === "rejected" ? "The baseline request with the registered redirect URI was itself rejected, so variants cannot be compared." : problem;
    const ids = ["MAP-RDR01", "MAP-RDR02"].filter((id) => wanted(id));
    return ids.map((id) => result(id, target, "error", msg, [baselineLine, SESSION_NOTE]));
  }

  const out: Finding[] = [];
  const finish = (f: Finding): Finding => {
    f.evidence.unshift(safeText(baselineLine));
    f.evidence.push(safeText(SESSION_NOTE));
    return f;
  };
  if (wanted("MAP-RDR01")) {
    const row = await judgeInSession(http, base, baseline, UNREGISTERED_REDIRECT, session);
    out.push(finish(summarizeSession("MAP-RDR01", target, [{ label: "unrelated host", ...row }], "An unregistered redirect URI was refused without redirecting, in a logged-in session.")));
  }
  if (!wanted("MAP-RDR02")) return out;
  const rows: Array<{ label: string } & SessionRow> = [];
  for (const v of nearMissVariants(registered)) rows.push({ label: v.label, ...(await judgeInSession(http, base, baseline, v.uri, session)) });
  out.push(finish(summarizeSession("MAP-RDR02", target, rows, `All ${rows.length} near-miss variants of the registered URI were refused, in a logged-in session.`)));
  return out;
}

async function registrationCheck(ctx: RedirectCheckContext, cleanup: RegisteredClient[]): Promise<Finding> {
  const { http, target } = ctx;
  const endpoint = ctx.registrationEndpoint as string;
  const evidence: string[] = [];
  const accepted: string[] = [];
  let inconclusive = 0;
  for (const u of UNSAFE_REGISTRATIONS) {
    const outcome = await registerClient(http, endpoint, [u.uri]);
    if (outcome.accepted && outcome.client) {
      accepted.push(u.label);
      cleanup.push(outcome.client);
      evidence.push(`${u.label}: ACCEPTED (HTTP ${outcome.status}, client_id ${outcome.client.clientId})`);
    } else if (outcome.status === 429 || outcome.status >= 500 || outcome.retryAfter) {
      inconclusive += 1;
      evidence.push(`${u.label}: inconclusive (HTTP ${outcome.status}, rate limited or server error)`);
    } else {
      evidence.push(`${u.label}: refused (HTTP ${outcome.status}${outcome.error ? `, error=${outcome.error}` : ""})`);
    }
  }
  if (accepted.length > 0) {
    return result("MAP-RDR04", target, "fail", `Dynamic client registration accepted ${accepted.length} unsafe redirect URI(s): ${accepted.join(", ")}.`, evidence);
  }
  if (inconclusive > 0) {
    return result("MAP-RDR04", target, "error", `Inconclusive: ${inconclusive} registration attempt(s) were rate limited or hit a server error.`, evidence);
  }
  return result("MAP-RDR04", target, "pass", `All ${UNSAFE_REGISTRATIONS.length} unsafe redirect URIs were refused at registration.`, evidence);
}

export async function runRedirectUriChecks(ctx: RedirectCheckContext): Promise<Finding[]> {
  const { http, target } = ctx;
  const findings: Finding[] = [];
  const created: RegisteredClient[] = [];

  try {
    const wanted = ctx.select ?? (() => true);
    const wants12 = wanted("MAP-RDR01") || wanted("MAP-RDR02");
    const both = (status: Finding["status"], msg: string, reason?: ReasonCode): void => {
      if (wanted("MAP-RDR01")) findings.push(result("MAP-RDR01", target, status, msg, [], reason));
      if (wanted("MAP-RDR02")) findings.push(result("MAP-RDR02", target, status, msg, [], reason));
    };
    // A supplied client comes first, as in the MCP specification: nothing is registered for RDR01/02.
    if (ctx.client && wants12) {
      if (!ctx.client.redirectUri) {
        both("skipped", "The supplied client needs one of its registered redirect URIs to compare against: pass it with --redirect-uri.", "no_client");
      } else if (!ctx.authorizationEndpoint) {
        both("skipped", "No authorization endpoint discovered.", "no_endpoint");
      } else {
        try {
          const out = await authorizationChecks(ctx, { clientId: ctx.client.clientId }, ctx.client.redirectUri);
          for (const f of out) f.evidence.push("client: supplied by the operator (--client-id), nothing was registered");
          findings.push(...out);
        } catch (err) {
          if (err instanceof ScanInterruptedError) throw err;
          both("error", `Authorization endpoint unreachable: ${(err as Error).message}`);
        }
      }
    }
    // MAP-RDR04, and the client for RDR01/02 when none is supplied, need dynamic registration.
    if (!ctx.registrationEndpoint) {
      if (!ctx.client && wants12) {
        both("skipped", "Needs a client: this authorization server offers no dynamic client registration (deprecated by MCP 2026-07-28). Pass a pre-registered client, or a client ID metadata document URL, with --client-id and one of its redirect URIs with --redirect-uri.", "no_client");
      }
      if (wanted("MAP-RDR04")) findings.push(result("MAP-RDR04", target, "not_applicable", "The authorization server does not offer dynamic client registration, which this check is about (a mechanism MCP 2026-07-28 deprecates)."));
      return findings;
    }

    let client: RegisteredClient | null = null;
    if (wants12 && !ctx.client) {
      try {
        const reg = await registerClient(http, ctx.registrationEndpoint, [REGISTERED_REDIRECT]);
        if (reg.client) {
          client = reg.client;
          created.push(reg.client);
        } else {
          const msg = `Could not register a test client (HTTP ${reg.status}${reg.error ? `, error=${reg.error}` : ""})${reg.status === 429 || reg.retryAfter ? ": the registration endpoint is rate limited, run the scan again later" : ""}.`;
          findings.push(result("MAP-RDR01", target, "error", msg), result("MAP-RDR02", target, "error", msg));
        }
      } catch (err) {
        const msg = `Registration endpoint unreachable: ${(err as Error).message}`;
        findings.push(result("MAP-RDR01", target, "error", msg), result("MAP-RDR02", target, "error", msg));
      }

      if (client) {
        if (!ctx.authorizationEndpoint) {
          const msg = "No authorization endpoint discovered.";
          findings.push(result("MAP-RDR01", target, "skipped", msg), result("MAP-RDR02", target, "skipped", msg));
        } else {
          try {
            findings.push(...(await authorizationChecks(ctx, client)));
          } catch (err) {
            const msg = `Authorization endpoint unreachable: ${(err as Error).message}`;
            findings.push(result("MAP-RDR01", target, "error", msg), result("MAP-RDR02", target, "error", msg));
          }
        }
      }
    }

    if (wanted("MAP-RDR04")) {
      try {
        findings.push(await registrationCheck(ctx, created));
      } catch (err) {
        findings.push(result("MAP-RDR04", target, "error", `Registration endpoint unreachable: ${(err as Error).message}`));
      }
    }
    return findings;
  } finally {
    // Clean up every client the scanner created; report what could not be removed.
    const leftovers: string[] = [];
    for (const c of created) {
      if (!(await deleteClient(http, c, ctx.registrationEndpoint as string))) leftovers.push(c.clientId);
    }
    for (const id of leftovers) ctx.leftovers?.push({ kind: "client", clientId: safeText(id, 200), endpoint: ctx.registrationEndpoint as string, reason: "the server offers no RFC 7592 deletion, or refused it" });
    if (leftovers.length > 0) {
      const note = `Test clients left on the server (no RFC 7592 deletion available): ${leftovers.join(", ")}. They are named "mcp-authprobe test client (safe to delete)".`;
      const target04 = findings.find((f) => f.checkId === "MAP-RDR04") ?? findings[0];
      target04?.evidence.push(safeText(note));
    }
  }
}
