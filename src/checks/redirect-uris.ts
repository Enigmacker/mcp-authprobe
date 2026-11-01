import type { HttpClient } from "../net/http.js";
import { describeAnswer, probeAuthorize, signature, type AuthorizeAnswer, type AuthorizeParams } from "../oauth/authorize.js";
import { deleteClient, REGISTERED_REDIRECT, registerClient, SAFE_DOMAIN, type RegisteredClient } from "../oauth/registration.js";
import { safeText } from "../redact.js";
import type { CheckDefinition, Finding } from "../types.js";
import { CATALOGUE } from "./catalogue.js";

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
 * Every URI sent lives under the reserved ".invalid" domain, so even a
 * redirect could never deliver anything anywhere. No redirect is followed.
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
}

function def(id: string): CheckDefinition {
  const d = CATALOGUE.find((c) => c.id === id);
  if (!d) throw new Error(`Unknown check ${id}`);
  return d;
}

function result(id: string, target: string, status: Finding["status"], message: string, evidence: string[] = []): Finding {
  const d = def(id);
  return { checkId: d.id, title: d.title, severity: d.severity, status, target, message: safeText(message), evidence: evidence.map((e) => safeText(e)) };
}

type VariantVerdict = "accepted" | "refused" | "inconclusive";

function judge(baseline: AuthorizeAnswer, answer: AuthorizeAnswer): VariantVerdict {
  if (answer.kind === "redirect-to-candidate") return "accepted";
  // A rate limit or a server error says nothing about redirect_uri validation.
  if (answer.kind === "unavailable") return "inconclusive";
  return signature(answer) === signature(baseline) ? "inconclusive" : "refused";
}

/** Summarize several variant verdicts into one finding. */
function summarize(id: string, target: string, rows: Array<{ label: string; verdict: VariantVerdict; detail: string }>, passMsg: string): Finding {
  const evidence = rows.map((r) => `${r.label}: ${r.verdict} (${r.detail})`);
  const accepted = rows.filter((r) => r.verdict === "accepted");
  if (accepted.length > 0) {
    return result(id, target, "fail", `The authorization endpoint redirected to ${accepted.length} unregistered URI(s): ${accepted.map((r) => r.label).join(", ")}.`, evidence);
  }
  if (rows.some((r) => r.verdict === "inconclusive")) {
    return result(
      id,
      target,
      "error",
      "Inconclusive: some requests were answered exactly like the valid one (for example a redirect to the login page), so the server may only check redirect_uri after login.",
      evidence,
    );
  }
  return result(id, target, "pass", passMsg, evidence);
}

async function authorizationChecks(ctx: RedirectCheckContext, client: RegisteredClient): Promise<Finding[]> {
  const { http, target } = ctx;
  const base: Omit<AuthorizeParams, "redirectUri"> = { authorizationEndpoint: ctx.authorizationEndpoint as string, clientId: client.clientId, resource: ctx.resource };
  if (ctx.scope) base.scope = ctx.scope;

  const baseline = await probeAuthorize(http, { ...base, redirectUri: REGISTERED_REDIRECT });
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
  for (const v of NEAR_MISS_VARIANTS) {
    const answer = await probeAuthorize(http, { ...base, redirectUri: v.uri });
    rows.push({ label: v.label, verdict: judge(baseline, answer), detail: describeAnswer(answer) });
  }
  const rdr02 = summarize("MAP-RDR02", target, rows, `All ${rows.length} near-miss variants of the registered URI were refused.`);
  rdr02.evidence.unshift(safeText(baselineLine));
  out.push(rdr02);
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
    // MAP-RDR04 and the client for RDR01/02 both need dynamic registration.
    if (!ctx.registrationEndpoint) {
      const msg = "No registration endpoint: these checks need dynamic client registration to create a test client.";
      findings.push(result("MAP-RDR01", target, "skipped", msg), result("MAP-RDR02", target, "skipped", msg));
      findings.push(result("MAP-RDR04", target, "not_applicable", "The authorization server does not offer dynamic client registration."));
      return findings;
    }

    const wanted = ctx.select ?? (() => true);
    let client: RegisteredClient | null = null;
    if (wanted("MAP-RDR01") || wanted("MAP-RDR02")) {
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
    if (leftovers.length > 0) {
      const note = `Test clients left on the server (no RFC 7592 deletion available): ${leftovers.join(", ")}. They are named "mcp-authprobe test client (safe to delete)".`;
      const target04 = findings.find((f) => f.checkId === "MAP-RDR04") ?? findings[0];
      target04?.evidence.push(safeText(note));
    }
  }
}
