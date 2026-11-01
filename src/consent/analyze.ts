import { parse, type HTMLElement } from "node-html-parser";
import { CATALOGUE } from "../checks/catalogue.js";
import type { HttpClient, HttpResponse } from "../net/http.js";
import { SAFE_DOMAIN } from "../oauth/registration.js";
import { safeText } from "../redact.js";
import type { Finding } from "../types.js";

/**
 * MAP-CSR01: is the consent decision protected against cross-site request
 * forgery?
 *
 * Input is a snapshot of the consent page as a logged-in test user sees it
 * (rendered HTML, URL, cookies with their raw SameSite attribute), taken by
 * the browser driver. Analysis and replay are plain HTTP, so they can be
 * tested without a browser.
 *
 * Probes, at most four form submissions with the session cookies:
 *   1. without the anti-CSRF field, foreign Origin      -> must be refused
 *   2. with the anti-CSRF field altered, foreign Origin -> must be refused
 *   3. untouched, foreign Origin                        -> informational
 *   C. untouched, the page's own Origin (control)       -> must grant
 * A "pass" requires the control to prove that the tool reproduces a real
 * grant (from probe 3 or C). Without it, a refusal could come from a badly
 * rebuilt request, so the result is inconclusive, never a pass.
 */

export const FOREIGN_ORIGIN = `https://attacker.${SAFE_DOMAIN}`;

export type SameSite = "Strict" | "Lax" | "None" | "Unspecified";

export interface SnapshotCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  /** Raw attribute as sent by the server; "Unspecified" when absent or unknown. */
  sameSite: SameSite;
}

export interface ConsentSnapshot {
  /** URL of the consent page. */
  url: string;
  /** Rendered HTML of the consent page. */
  html: string;
  /** Cookies the browser holds. Values stay in memory. */
  cookies: SnapshotCookie[];
  /** The redirect_uri registered for the test client. */
  redirectUri: string;
}

export interface FormField {
  name: string;
  value: string;
  type: string;
}

export interface ConsentForm {
  action: string;
  method: string;
  fields: FormField[];
  /** The submit control that approves, if it carries a name. */
  approve: FormField | null;
  /** Fields recognised by name as anti-CSRF tokens. */
  csrfFields: string[];
  /** Random-looking hidden fields that are not recognised by name (kept in every probe). */
  unclassified: string[];
  /**
   * Server-issued per-flow identifiers: random-looking hidden fields
   * (unclassified, or named like consent_challenge) and random-looking parts
   * of the form's URL (as in /interaction/<id>/confirm).
   */
  flowFields: string[];
  urlSecrets: string[];
}

const APPROVE =
  /\b(allow|approve|authori[sz]e|accept|consent|grant|continue|confirm|yes|agree|autoriser|accepter|valider|confirmer|erlauben|zulassen|akzeptieren|zustimmen|permitir|aceptar|autorizar|consentire|autorizza|consenti)\b/i;
const DENY =
  /\b(deny|cancel|reject|refuse|decline|no|not now|never|don'?t|do not|refuser|annuler|ne pas|ablehnen|abbrechen|verweigern|rechazar|cancelar|denegar|rifiuta|annulla)\b/i;
const CSRF_NAME = /csrf|xsrf|authenticity|_token$|^token$|form[_-]?token|request[_-]?verification|anti[_-]?forgery/i;
/** OAuth / OIDC request parameters echoed in consent forms: never anti-CSRF tokens. */
const OAUTH_PARAMS = new Set([
  "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method",
  "resource", "audience", "prompt", "response_mode", "nonce", "login_challenge", "consent_challenge",
  "request_uri", "transaction_id", "interaction_id",
]);

/** Server-issued identifiers of one authorization flow (Hydra, Keycloak, node-oidc-provider style). */
const SERVER_FLOW_PARAMS = new Set(["consent_challenge", "login_challenge", "transaction_id", "interaction_id", "request_uri"]);
/** Request parameters chosen by the client (so known to an attacker): never secrets. */
const CLIENT_PARAMS = new Set(["client_id", "redirect_uri", "state", "nonce", "code_challenge", "scope", "resource", "audience", "response_type"]);

function urlSecretsOf(action: string): string[] {
  const u = new URL(action);
  const out: string[] = [];
  for (const seg of u.pathname.split("/")) {
    const v = decodeURIComponentSafe(seg);
    if (looksRandom(v)) out.push(v);
  }
  for (const [k, v] of u.searchParams) if (!CLIENT_PARAMS.has(k.toLowerCase()) && looksRandom(v)) out.push(v);
  return out;
}

function decodeURIComponentSafe(v: string): string {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
}

function looksRandom(value: string): boolean {
  return value.length >= 16 && /^[A-Za-z0-9+/=_.:-]+$/.test(value) && new Set(value).size >= 10;
}

function controlText(el: HTMLElement): string {
  return `${el.getAttribute("name") ?? ""} ${el.getAttribute("value") ?? ""} ${el.text ?? ""} ${el.getAttribute("aria-label") ?? ""}`;
}

function isApprove(el: HTMLElement): boolean {
  const t = controlText(el);
  return APPROVE.test(t) && !DENY.test(t);
}

/** Extract the approve form of a consent page, or null when there is none. */
export function findConsentForm(html: string, pageUrl: string): ConsentForm | null {
  const root = parse(html);
  const baseHref = root.querySelector("base[href]")?.getAttribute("href");
  let base = pageUrl;
  try {
    if (baseHref) base = new URL(baseHref, pageUrl).toString();
  } catch {
    /* keep the page URL */
  }
  const candidates: Array<ConsentForm & { score: number }> = [];

  for (const form of root.querySelectorAll("form")) {
    if (form.querySelector("input[type=password]")) continue; // a login form, not consent
    const id = form.getAttribute("id");
    const outside = id ? root.querySelectorAll(`[form="${id}"]`) : [];
    const controls = (selector: string): HTMLElement[] => [...form.querySelectorAll(selector), ...outside.filter((el) => el.matches(selector))];

    const submits = [...controls("button"), ...controls("input[type=submit]")].filter((b) => (b.getAttribute("type") ?? "submit").toLowerCase() === "submit");
    if (submits.length > 0 && submits.every((s) => DENY.test(controlText(s)) && !APPROVE.test(controlText(s)))) continue;
    const approveEl = submits.find(isApprove);

    const method = (approveEl?.getAttribute("formmethod") ?? form.getAttribute("method") ?? "get").toLowerCase();
    if (method !== "post") continue;
    let action: string;
    try {
      action = new URL(approveEl?.getAttribute("formaction") ?? form.getAttribute("action") ?? pageUrl, base).toString();
    } catch {
      continue;
    }

    const fields: FormField[] = [];
    for (const input of controls("input")) {
      const name = input.getAttribute("name");
      const type = (input.getAttribute("type") ?? "text").toLowerCase();
      if (!name || ["submit", "button", "image", "reset", "file"].includes(type)) continue;
      if (type === "checkbox" || type === "radio") {
        const checked = input.getAttribute("checked") !== undefined;
        const required = input.getAttribute("required") !== undefined;
        // A required "I agree" box is what a real user ticks before approving.
        if (!checked && !(required && type === "checkbox")) continue;
        fields.push({ name, value: input.getAttribute("value") ?? "on", type });
        continue;
      }
      fields.push({ name, value: input.getAttribute("value") ?? "", type });
    }
    for (const ta of controls("textarea")) {
      const name = ta.getAttribute("name");
      if (name) fields.push({ name, value: ta.text, type: "textarea" });
    }
    for (const sel of controls("select")) {
      const name = sel.getAttribute("name");
      if (!name) continue;
      const opt = sel.querySelector("option[selected]") ?? sel.querySelector("option");
      if (opt) fields.push({ name, value: opt.getAttribute("value") ?? opt.text, type: "select" });
    }

    const approveName = approveEl?.getAttribute("name");
    const approve = approveEl && approveName ? { name: approveName, value: approveEl.getAttribute("value") ?? "", type: "submit" } : null;
    const hidden = fields.filter((f) => f.type === "hidden" && !OAUTH_PARAMS.has(f.name.toLowerCase()));
    const csrfFields = hidden.filter((f) => CSRF_NAME.test(f.name)).map((f) => f.name);
    const unclassified = hidden.filter((f) => !CSRF_NAME.test(f.name) && looksRandom(f.value)).map((f) => f.name);
    const serverFlow = fields.filter((f) => SERVER_FLOW_PARAMS.has(f.name.toLowerCase()) && looksRandom(f.value)).map((f) => f.name);
    const flowFields = [...new Set([...unclassified, ...serverFlow])];
    const urlSecrets = urlSecretsOf(action);

    const score = (approveEl ? 2 : 0) + (fields.some((f) => OAUTH_PARAMS.has(f.name.toLowerCase())) ? 1 : 0);
    candidates.push({ action, method, fields, approve, csrfFields, unclassified, flowFields, urlSecrets, score });
  }
  candidates.sort((a, b) => b.score - a.score);
  const best = candidates[0];
  if (!best) return null;
  const { score: _score, ...form } = best;
  return form;
}

function body(form: ConsentForm, mutate: (fields: FormField[]) => FormField[]): string {
  const params = new URLSearchParams();
  for (const f of mutate(form.fields)) params.append(f.name, f.value);
  if (form.approve) params.append(form.approve.name, form.approve.value);
  return params.toString();
}

/**
 * Alter a token without changing its length or alphabet, so lenient decoders
 * (hex or base64 parsers that stop at an invalid character) still see a
 * different value.
 */
export function alterToken(value: string): string {
  const chars = [...value];
  const i = chars.findIndex((c) => /[A-Za-z0-9]/.test(c));
  if (i < 0) return `${value}A`;
  const c = chars[i] as string;
  const next = (from: string, to: string): string => (c === to ? from : String.fromCharCode(c.charCodeAt(0) + 1));
  // Stay within hex digits when the value is hex.
  const isHex = /^[0-9a-fA-F]+$/.test(value);
  if (/[0-9]/.test(c)) chars[i] = next("0", "9");
  else if (/[a-z]/.test(c)) chars[i] = isHex ? (c === "f" ? "a" : next("a", "z")) : next("a", "z");
  else chars[i] = isHex ? (c === "F" ? "A" : next("A", "Z")) : next("A", "Z");
  return chars.join("");
}

// --- cookies -------------------------------------------------------------

/** RFC 6265 domain, path and secure matching; host-only cookies have no leading dot. */
export function cookieApplies(c: SnapshotCookie, url: URL): boolean {
  const host = url.hostname.toLowerCase();
  const hostOnly = !c.domain.startsWith(".");
  const domain = c.domain.replace(/^\./, "").toLowerCase();
  const domainOk = hostOnly ? host === domain : host === domain || host.endsWith(`.${domain}`);
  if (!domainOk) return false;
  const path = url.pathname || "/";
  const cp = c.path || "/";
  const pathOk = path === cp || (path.startsWith(cp) && (cp.endsWith("/") || path[cp.length] === "/"));
  if (!pathOk) return false;
  return !c.secure || url.protocol === "https:";
}

/** Browser-side defence: are the session cookies sent with the form explicitly SameSite Lax or Strict? */
export function assessCookies(snap: ConsentSnapshot, action: URL): { protective: boolean; lines: string[] } {
  const sent = snap.cookies.filter((c) => cookieApplies(c, action));
  // Session cookies are normally HttpOnly; judge those when there are any.
  const session = sent.some((c) => c.httpOnly) ? sent.filter((c) => c.httpOnly) : sent;
  const lines = sent.map((c) => `cookie ${c.name}: SameSite=${c.sameSite}${c.secure ? ", Secure" : ""}${c.httpOnly ? ", HttpOnly" : ""}`);
  const protective = session.length > 0 && session.every((c) => c.sameSite === "Lax" || c.sameSite === "Strict");
  return { protective, lines };
}

// --- probes --------------------------------------------------------------

export type ProbeVerdict = "accepted" | "refused" | "inconclusive";

/** True when a response grants consent: a redirect (or an auto-submitting page) to the redirect_uri carrying a code. */
export function grantsConsent(res: Pick<HttpResponse, "status" | "headers" | "body">, redirectUri: string, base: string): boolean {
  const red = new URL(redirectUri);
  const location = res.headers["location"];
  if (res.status >= 300 && res.status < 400 && location) {
    try {
      const loc = new URL(location, base);
      return loc.origin === red.origin && loc.pathname === red.pathname && loc.searchParams.has("code");
    } catch {
      return false;
    }
  }
  if (res.status === 200 && res.body) {
    // meta refresh, JS redirect, or response_mode=form_post page.
    const target = `${red.origin}${red.pathname}`;
    const text = res.body.replace(/&amp;/g, "&");
    return text.includes(target) && /[?&"' ]code[=" ']/.test(text.slice(text.indexOf(target)));
  }
  return false;
}

interface ProbeContext {
  http: HttpClient;
  snap: ConsentSnapshot;
  form: ConsentForm;
  allowedHosts: string[];
}

function cookieHeader(snap: ConsentSnapshot, url: URL): Record<string, string> {
  const cookies = snap.cookies.filter((c) => cookieApplies(c, url));
  return cookies.length > 0 ? { cookie: cookies.map((c) => `${c.name}=${c.value}`).join("; ") } : {};
}

async function probe(
  ctx: ProbeContext,
  payload: string,
  origin: string,
  opts: { action?: string; noCookies?: boolean } = {},
): Promise<{ verdict: ProbeVerdict; detail: string }> {
  const action = new URL(opts.action ?? ctx.form.action);
  const referer = origin === FOREIGN_ORIGIN ? `${FOREIGN_ORIGIN}/` : ctx.snap.url;
  const res = await ctx.http.request({
    url: action.toString(),
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "text/html,application/json",
      origin,
      referer,
      ...(opts.noCookies ? {} : cookieHeader(ctx.snap, action)),
    },
    body: payload,
  });
  if (grantsConsent(res, ctx.snap.redirectUri, action.toString())) return { verdict: "accepted", detail: `HTTP ${res.status}, authorization code issued to the client` };
  if (res.status === 429 || res.status >= 500 || res.headers["retry-after"] !== undefined) return { verdict: "inconclusive", detail: `HTTP ${res.status}, rate limited or server error` };
  if (res.status >= 400) return { verdict: "refused", detail: `HTTP ${res.status}` };

  const location = res.headers["location"];
  if (res.status >= 300 && res.status < 400 && location) {
    let loc: URL;
    try {
      loc = new URL(location, action);
    } catch {
      return { verdict: "inconclusive", detail: `HTTP ${res.status}, unreadable redirect` };
    }
    const red = new URL(ctx.snap.redirectUri);
    if (loc.origin === red.origin && loc.pathname === red.pathname) return { verdict: "refused", detail: `HTTP ${res.status}, redirected to the client without a code` };
    // One more hop on a proven host (e.g. an authorization server resuming the flow).
    if (ctx.allowedHosts.includes(loc.hostname.toLowerCase())) {
      const hop = await ctx.http.request({ url: loc.toString(), headers: { accept: "text/html", ...cookieHeader(ctx.snap, loc) } });
      if (grantsConsent(hop, ctx.snap.redirectUri, loc.toString())) return { verdict: "accepted", detail: `HTTP ${res.status} then ${hop.status}, authorization code issued to the client` };
      if (hop.status >= 400 && hop.status !== 429 && hop.status < 500) return { verdict: "refused", detail: `HTTP ${res.status} then ${hop.status}` };
      return { verdict: "inconclusive", detail: `HTTP ${res.status} then ${hop.status}, outcome unclear` };
    }
    return { verdict: "inconclusive", detail: `HTTP ${res.status}, redirected to an unproven host (not followed)` };
  }
  return { verdict: "inconclusive", detail: `HTTP ${res.status}, no redirect` };
}

function finding(status: Finding["status"], target: string, message: string, evidence: string[]): Finding {
  const def = CATALOGUE.find((c) => c.id === "MAP-CSR01");
  if (!def) throw new Error("MAP-CSR01 missing from catalogue");
  return { checkId: def.id, title: def.title, severity: def.severity, status, target, message: safeText(message), evidence: evidence.map((e) => safeText(e)) };
}

/**
 * @param allowedHosts hosts whose ownership is proven: probes are only sent
 *   when the consent form posts to one of them.
 */
export async function runConsentCheck(http: HttpClient, target: string, snap: ConsentSnapshot, allowedHosts: readonly string[]): Promise<Finding> {
  const allowed = allowedHosts.map((h) => h.toLowerCase());
  const form = findConsentForm(snap.html, snap.url);
  if (!form) {
    return finding("error", target, "No consent form was found on the page that was captured; make sure the consent page is displayed when you confirm.", []);
  }
  const action = new URL(form.action);
  const cookies = assessCookies(snap, action);
  if (!allowed.includes(action.hostname.toLowerCase())) {
    return finding("error", target, `The consent form posts to ${action.hostname}, whose ownership is not proven; no request was sent to it.`, cookies.lines);
  }
  const ctx: ProbeContext = { http, snap, form, allowedHosts: allowed };
  const evidence = [
    `consent form: POST ${action.origin}${action.pathname}${form.approve ? `, approve control "${form.approve.name}"` : ", no named approve control"}`,
    form.csrfFields.length > 0 ? `anti-CSRF field(s): ${form.csrfFields.join(", ")}` : "no field recognised as an anti-CSRF token",
    ...(form.unclassified.length > 0 ? [`request identifier(s) kept in every probe: ${form.unclassified.join(", ")}`] : []),
    ...cookies.lines,
  ];
  const ownOrigin = new URL(snap.url).origin;

  // 0. No named anti-CSRF token, but per-flow identifiers issued by the server
  //    (node-oidc-provider, Hydra, Keycloak style): they can play the same role.
  //    Before anything is granted (a flow is often single-use): are they checked,
  //    and are they useless without the session cookies?
  const perFlow = form.csrfFields.length === 0 && (form.flowFields.length > 0 || form.urlSecrets.length > 0);
  let flowChecked = false;
  if (perFlow) {
    const where = [...form.flowFields.map((n) => `field ${n}`), ...form.urlSecrets.map(() => "a random part of the form URL")];
    evidence.push(`per-flow identifier(s) issued by the server: ${[...new Set(where)].join(", ")}`);
    let alteredAction = form.action;
    for (const secret of form.urlSecrets) alteredAction = alteredAction.split(encodeURIComponent(secret)).join(encodeURIComponent(alterToken(secret))).split(secret).join(alterToken(secret));
    const altered = body(form, (fs) => fs.map((f) => (form.flowFields.includes(f.name) ? { ...f, value: alterToken(f.value) } : f)));
    const pa = await probe(ctx, altered, FOREIGN_ORIGIN, { action: alteredAction });
    evidence.push(`probe 0a, per-flow identifier(s) altered, foreign Origin: ${pa.verdict} (${pa.detail})`);
    if (pa.verdict === "accepted") {
      return finding("fail", target, "Consent was granted with altered per-flow identifiers and no anti-CSRF token, from a foreign Origin: nothing in the request is checked against the user's session.", evidence);
    }
    const pb = await probe(ctx, body(form, (fs) => fs), FOREIGN_ORIGIN, { noCookies: true });
    evidence.push(`probe 0b, untouched form without any cookie, foreign Origin: ${pb.verdict} (${pb.detail})`);
    if (pb.verdict === "accepted") {
      return finding("fail", target, "Consent was granted by a request carrying no cookie at all: anyone who learns the per-flow identifier can grant access on the user's behalf.", evidence);
    }
    flowChecked = pa.verdict === "refused" && pb.verdict === "refused";
  }

  // 1. Without the anti-CSRF field, from a foreign Origin.
  const p1 = await probe(ctx, body(form, (fs) => fs.filter((f) => !form.csrfFields.includes(f.name))), FOREIGN_ORIGIN);
  evidence.push(`probe 1, without anti-CSRF field, foreign Origin: ${p1.verdict} (${p1.detail})`);
  if (p1.verdict === "accepted" && flowChecked) {
    return finding(
      "error",
      target,
"Inconclusive: no anti-CSRF token, but the form carries server-issued per-flow identifiers that are checked (altered: refused) and useless without the session cookies (no cookie: refused), as with node-oidc-provider or Ory Hydra. This is safe only if they are bound to the user's own session and never leak (Referer, logs); that cannot be proven from one session, so check it.",
      evidence,
    );
  }
  if (p1.verdict === "accepted") {
    const reliance =
      form.csrfFields.length === 0 && form.unclassified.length > 0
        ? ` Protection then relies only on ${form.unclassified.join(", ")} being bound to the user's session; check that it is.`
        : "";
    const mitigation = cookies.protective
      ? " The session cookies are SameSite Lax/Strict, which blocks this from other sites in modern browsers, but not from same-site subdomains or older clients."
      : " The session cookies are not explicitly SameSite Lax/Strict, so a website can make a logged-in user grant access.";
    return finding("fail", target, `Consent was granted by a request without any anti-CSRF token, from a foreign Origin.${mitigation}${reliance}`, evidence);
  }

  // 2. Altered token, only when a token was recognised.
  let p2: { verdict: ProbeVerdict; detail: string } | null = null;
  if (form.csrfFields.length > 0) {
    p2 = await probe(ctx, body(form, (fs) => fs.map((f) => (form.csrfFields.includes(f.name) ? { ...f, value: alterToken(f.value) } : f))), FOREIGN_ORIGIN);
    evidence.push(`probe 2, altered anti-CSRF field, foreign Origin: ${p2.verdict} (${p2.detail})`);
    if (p2.verdict === "accepted") {
      return finding("fail", target, "Consent was granted with an altered anti-CSRF token: the token is present but not verified.", evidence);
    }
  }

  // 3. Untouched form, foreign Origin (informational), then the control.
  const p3 = await probe(ctx, body(form, (fs) => fs), FOREIGN_ORIGIN);
  evidence.push(`probe 3, untouched form, foreign Origin: ${p3.verdict} (${p3.detail})${p3.verdict === "accepted" ? " - Origin is not checked; the anti-CSRF token is the only server-side defence" : ""}`);
  let replayWorks = p3.verdict === "accepted";
  if (!replayWorks) {
    const control = await probe(ctx, body(form, (fs) => fs), ownOrigin);
    evidence.push(`control, untouched form, page's own Origin: ${control.verdict} (${control.detail})`);
    replayWorks = control.verdict === "accepted";
  }

  if (!replayWorks) {
    return finding(
      "error",
      target,
      "Inconclusive: the tool could not reproduce a grant even with the untouched form, so the refusals above may come from a badly rebuilt request (labels not recognised, consent sent by JavaScript, multi-step flow, single-use token).",
      evidence,
    );
  }
  const verdicts = [p1.verdict, ...(p2 ? [p2.verdict] : [])];
  if (verdicts.some((v) => v === "inconclusive")) {
    return finding("error", target, "Inconclusive: some forged submissions got an answer that is neither a grant nor a refusal.", evidence);
  }
  return finding("pass", target, "Forged consent submissions without a valid anti-CSRF token are refused, while the genuine form is accepted.", evidence);
}
