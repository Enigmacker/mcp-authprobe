import { parse, type HTMLElement } from "node-html-parser";
import { CATALOGUE } from "../checks/catalogue.js";
import { SAFE_DOMAIN } from "../oauth/registration.js";
import type { HttpClient } from "../net/http.js";
import { safeText } from "../redact.js";
import type { Finding } from "../types.js";

/**
 * MAP-CSR01: is the consent decision protected against cross-site request
 * forgery?
 *
 * Input is a snapshot of the consent page as a logged-in test user sees it
 * (rendered HTML, URL, cookies), taken by the browser driver. Analysis and
 * replay are plain HTTP, so they can be tested without a browser.
 *
 * Replay probes, all sent with the session cookies and a foreign Origin,
 * at most three POSTs, never followed:
 *   1. the approve form WITHOUT any anti-CSRF field   -> must be refused
 *   2. the approve form with the anti-CSRF field ALTERED -> must be refused
 *   3. the approve form as is, but from a foreign Origin -> informational
 * Accepted means the server redirected to the client's redirect_uri with a
 * code: consent was granted by a request a third-party site could forge.
 */

export const FOREIGN_ORIGIN = `https://attacker.${SAFE_DOMAIN}`;

export interface SnapshotCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

export interface ConsentSnapshot {
  /** URL of the consent page. */
  url: string;
  /** Rendered HTML of the consent page. */
  html: string;
  /** Cookies the browser holds for the consent page origin. Values stay in memory. */
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
  /** Names of fields that look like anti-CSRF tokens. */
  csrfFields: string[];
}

const APPROVE = /\b(allow|approve|authori[sz]e|accept|consent|grant|continue|confirm|yes|agree)\b/i;
const DENY = /\b(deny|cancel|reject|refuse|decline|no)\b/i;
const CSRF_NAME = /csrf|xsrf|authenticity|_token$|^token$|form[_-]?token|request[_-]?token|anti[_-]?forgery|__requestverificationtoken|nonce/i;
/** OAuth request parameters echoed in consent forms: never anti-CSRF tokens. */
const OAUTH_PARAMS = new Set([
  "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge",
  "code_challenge_method", "resource", "audience", "prompt", "response_mode",
]);

function looksRandom(value: string): boolean {
  return value.length >= 16 && /^[A-Za-z0-9+/=_.:-]+$/.test(value) && new Set(value).size >= 10;
}

function controlText(el: HTMLElement): string {
  return `${el.getAttribute("name") ?? ""} ${el.getAttribute("value") ?? ""} ${el.text ?? ""} ${el.getAttribute("id") ?? ""}`;
}

/** Extract the approve form of a consent page, or null when there is none. */
export function findConsentForm(html: string, pageUrl: string): ConsentForm | null {
  const root = parse(html);
  const candidates: Array<ConsentForm & { score: number }> = [];

  for (const form of root.querySelectorAll("form")) {
    const method = (form.getAttribute("method") ?? "get").toLowerCase();
    if (method !== "post") continue;
    if (form.querySelector("input[type=password]")) continue; // a login form, not consent
    let action: string;
    try {
      action = new URL(form.getAttribute("action") ?? pageUrl, pageUrl).toString();
    } catch {
      continue;
    }

    const fields: FormField[] = [];
    for (const input of form.querySelectorAll("input")) {
      const name = input.getAttribute("name");
      const type = (input.getAttribute("type") ?? "text").toLowerCase();
      if (!name || type === "submit" || type === "button" || type === "image") continue;
      if ((type === "checkbox" || type === "radio") && input.getAttribute("checked") === undefined) continue;
      fields.push({ name, value: input.getAttribute("value") ?? "", type });
    }

    const submits = [...form.querySelectorAll("button"), ...form.querySelectorAll("input[type=submit]")];
    const approveEl = submits.find((s) => APPROVE.test(controlText(s)) && !DENY.test(controlText(s)));
    const denyOnly = submits.length > 0 && submits.every((s) => DENY.test(controlText(s)));
    if (denyOnly) continue;

    const approveName = approveEl?.getAttribute("name");
    const approve = approveEl && approveName ? { name: approveName, value: approveEl.getAttribute("value") ?? "", type: "submit" } : null;

    const csrfFields = fields
      .filter((f) => f.type === "hidden" && !OAUTH_PARAMS.has(f.name.toLowerCase()) && (CSRF_NAME.test(f.name) || looksRandom(f.value)))
      .map((f) => f.name);

    const score = (approveEl ? 2 : 0) + (fields.some((f) => OAUTH_PARAMS.has(f.name.toLowerCase())) ? 1 : 0);
    candidates.push({ action, method, fields, approve, csrfFields, score });
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

export type ProbeVerdict = "accepted" | "refused" | "inconclusive";

/** True when a response grants consent: a redirect to the redirect_uri carrying a code. */
export function grantsConsent(status: number, location: string | undefined, redirectUri: string, base: string): boolean {
  if (status < 300 || status >= 400 || !location) return false;
  let loc: URL;
  let red: URL;
  try {
    loc = new URL(location, base);
    red = new URL(redirectUri);
  } catch {
    return false;
  }
  return loc.origin === red.origin && loc.pathname === red.pathname && loc.searchParams.has("code");
}

async function probe(http: HttpClient, snap: ConsentSnapshot, form: ConsentForm, payload: string): Promise<{ verdict: ProbeVerdict; detail: string }> {
  const formOrigin = new URL(form.action).origin;
  // Send only the cookies the browser would attach to this origin.
  const cookies = snap.cookies.filter((c) => {
    const host = new URL(form.action).hostname;
    const domain = c.domain.replace(/^\./, "");
    return host === domain || host.endsWith(`.${domain}`);
  });
  const res = await http.request({
    url: form.action,
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "text/html,application/json",
      origin: FOREIGN_ORIGIN,
      referer: `${FOREIGN_ORIGIN}/`,
      ...(cookies.length > 0 ? { cookie: cookies.map((c) => `${c.name}=${c.value}`).join("; ") } : {}),
    },
    body: payload,
  });
  const location = res.headers["location"];
  if (grantsConsent(res.status, location, snap.redirectUri, formOrigin)) return { verdict: "accepted", detail: `HTTP ${res.status}, redirected to the client with an authorization code` };
  if (res.status === 429 || res.status >= 500 || res.headers["retry-after"] !== undefined) return { verdict: "inconclusive", detail: `HTTP ${res.status}, rate limited or server error` };
  if (res.status >= 400) return { verdict: "refused", detail: `HTTP ${res.status}` };
  if (res.status >= 300 && location) {
    try {
      const loc = new URL(location, form.action);
      const red = new URL(snap.redirectUri);
      if (loc.origin === red.origin && loc.pathname === red.pathname) return { verdict: "refused", detail: `HTTP ${res.status}, redirected to the client with an error` };
    } catch {
      /* fall through */
    }
    return { verdict: "inconclusive", detail: `HTTP ${res.status}, redirected elsewhere` };
  }
  return { verdict: "inconclusive", detail: `HTTP ${res.status}, no redirect` };
}

/** Browser-side defence: are the session cookies of the consent origin SameSite Lax or Strict? */
export function assessCookies(snap: ConsentSnapshot): { protective: boolean; lines: string[] } {
  const host = new URL(snap.url).hostname;
  const relevant = snap.cookies.filter((c) => {
    const domain = c.domain.replace(/^\./, "");
    return host === domain || host.endsWith(`.${domain}`);
  });
  const lines = relevant.map((c) => `cookie ${c.name}: SameSite=${c.sameSite}${c.secure ? ", Secure" : ""}${c.httpOnly ? ", HttpOnly" : ""}`);
  const protective = relevant.length > 0 && relevant.every((c) => c.sameSite === "Lax" || c.sameSite === "Strict");
  return { protective, lines };
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
  const cookies = assessCookies(snap);
  const form = findConsentForm(snap.html, snap.url);
  if (!form) {
    return finding("error", target, "No consent form was found on the page that was captured; make sure the consent page is displayed when you confirm.", cookies.lines);
  }
  const actionHost = new URL(form.action).hostname.toLowerCase();
  if (!allowedHosts.map((h) => h.toLowerCase()).includes(actionHost)) {
    return finding("error", target, `The consent form posts to ${actionHost}, whose ownership is not proven; no request was sent to it.`, cookies.lines);
  }
  const evidence = [
    `consent form: POST ${new URL(form.action).origin}${new URL(form.action).pathname}`,
    form.csrfFields.length > 0 ? `anti-CSRF field(s): ${form.csrfFields.join(", ")}` : "no anti-CSRF field found in the form",
    ...cookies.lines,
  ];

  // Probe 1: no anti-CSRF field at all, foreign Origin.
  const stripped = await probe(http, snap, form, body(form, (fs) => fs.filter((f) => !form.csrfFields.includes(f.name))));
  evidence.push(`probe 1, without anti-CSRF field, foreign Origin: ${stripped.verdict} (${stripped.detail})`);
  if (stripped.verdict === "accepted") {
    const mitigation = cookies.protective
      ? " SameSite cookies block this from other sites in modern browsers, but not from same-site subdomains or older clients."
      : " The session cookies are not SameSite Lax/Strict, so any website can make a logged-in user grant access.";
    return finding("fail", target, `Consent was granted by a request without any anti-CSRF token, from a foreign Origin.${mitigation}`, evidence);
  }

  // Probe 2: altered token, only meaningful when the form has one.
  if (form.csrfFields.length > 0) {
    const altered = await probe(http, snap, form, body(form, (fs) => fs.map((f) => (form.csrfFields.includes(f.name) ? { ...f, value: `${f.value}x` } : f))));
    evidence.push(`probe 2, altered anti-CSRF field, foreign Origin: ${altered.verdict} (${altered.detail})`);
    if (altered.verdict === "accepted") {
      return finding("fail", target, "Consent was granted with an altered anti-CSRF token: the token is present but not verified.", evidence);
    }
  }

  // Probe 3: the untouched form from a foreign Origin (informational).
  const foreign = await probe(http, snap, form, body(form, (fs) => fs));
  evidence.push(`probe 3, valid form, foreign Origin: ${foreign.verdict} (${foreign.detail})${foreign.verdict === "accepted" ? " - the server does not check Origin; the anti-CSRF token is the only server-side defence" : ""}`);

  if (stripped.verdict === "refused") {
    return finding("pass", target, "Consent submissions without a valid anti-CSRF token are refused.", evidence);
  }
  return finding("error", target, "Inconclusive: the server's answers could not be classified as a grant or a refusal.", evidence);
}
