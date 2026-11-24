import { parse } from "node-html-parser";
import { findConsentForm, grantsConsent } from "../consent/analyze.js";
import type { HttpClient, HttpResponse } from "../net/http.js";
import { authorizeUrl, classifyAnswer, describeAnswer, type AuthorizeAnswer, type AuthorizeParams } from "../oauth/authorize.js";

/**
 * Redirect URI checks replayed in a logged-in session (--session-cookie-file).
 *
 * Many authorization servers send a visitor without a session to their login
 * page before they look at redirect_uri; from outside, every variant is then
 * answered like the registered URI and MAP-RDR01/02 stay inconclusive. With
 * the cookie of a logged-in test account, the same requests reach the point
 * where the server must decide:
 *
 *   - a redirect to the URI that was sent: accepted (proven);
 *   - an error page, without redirect: refused;
 *   - the consent page: the server has not refused yet, but nothing is
 *     proven. Only when the operator asks for it (--approve-consent) is the
 *     consent form submitted, once per such variant, to see where the server
 *     sends the browser. That grants the test client access for the test
 *     account: the code goes to the reserved .invalid domain and is never used.
 *
 * The cookie is sent to the origin of the authorization endpoint only, and
 * never written to a report or a log. Redirects are followed only within
 * that origin, at most MAX_HOPS times.
 */

export interface AuthorizationSession {
  /** Cookie header value of a logged-in test account on the authorization server. Never reported. */
  cookie: string;
  /** Submit the consent form when it is displayed for an unregistered URI (--approve-consent). */
  approveConsent?: boolean;
}

const MAX_HOPS = 3;

export interface SessionAnswer {
  answer: AuthorizeAnswer;
  /** The last page, when the answer is a page. Kept in memory only. */
  page?: { url: string; html: string };
  /** The page carries a consent form (a POST form with an approve control or OAuth fields, no password field). */
  consent: boolean;
  /** The page is a login page (a password field). */
  login: boolean;
  /** Same-origin redirects followed. */
  hops: number;
}

export type SessionVerdict = "accepted" | "refused" | "inconclusive";

export interface SessionRow {
  verdict: SessionVerdict;
  detail: string;
  /** The consent page was displayed for this URI and not approved. */
  consentShown?: boolean;
  /** The consent form was submitted for this URI. */
  approved?: boolean;
}

function cookieFor(session: AuthorizationSession, url: URL, origin: string): Record<string, string> {
  return url.origin === origin ? { cookie: session.cookie } : {};
}

function readPage(res: HttpResponse, url: string): Pick<SessionAnswer, "page" | "consent" | "login"> {
  const ctype = res.headers["content-type"] ?? "";
  if (!/html/i.test(ctype) && !/^\s*</.test(res.body)) return { consent: false, login: false };
  let login = false;
  try {
    login = parse(res.body).querySelector("input[type=password]") !== null;
  } catch {
    login = false;
  }
  let consent = false;
  try {
    consent = !login && findConsentForm(res.body, url) !== null;
  } catch {
    consent = false;
  }
  return { page: { url, html: res.body }, consent, login };
}

/**
 * One authorization request in the session: same-origin redirects are
 * followed (with the cookie) until the server redirects to the URI that was
 * sent, leaves its origin, or shows a page.
 */
export async function probeInSession(http: HttpClient, p: AuthorizeParams, session: AuthorizationSession): Promise<SessionAnswer> {
  const origin = new URL(p.authorizationEndpoint).origin;
  let url = authorizeUrl(p);
  for (let hops = 0; ; hops += 1) {
    const res = await http.request({ url: url.toString(), headers: { accept: "text/html,application/json", ...cookieFor(session, url, origin) } });
    const answer = classifyAnswer(res, url, p.redirectUri);
    if (answer.kind === "page") return { answer, hops, ...readPage(res, url.toString()) };
    if (answer.kind !== "redirect-elsewhere") return { answer, hops, consent: false, login: false };
    const next = new URL(res.headers["location"] as string, url);
    if (next.origin !== origin || hops >= MAX_HOPS) return { answer, hops, consent: false, login: false };
    url = next;
  }
}

export function describeSessionAnswer(a: SessionAnswer): string {
  const via = a.hops > 0 ? ` after ${a.hops} redirect(s) within the authorization server` : "";
  if (a.answer.kind === "page") {
    const what = a.login ? "a login page" : a.consent ? "a consent page" : a.answer.status >= 400 ? "an error page" : "a page without consent form";
    return `HTTP ${a.answer.status}${via}, ${what}, no redirect`;
  }
  return `${describeAnswer(a.answer)}${via}`;
}

/** Is the baseline (the registered URI, in the session) usable? Null when it is, otherwise why not. */
export function baselineProblem(b: SessionAnswer): string | null {
  if (b.answer.kind === "redirect-to-candidate") return null;
  if (b.answer.kind === "unavailable" || (b.answer.kind === "page" && b.answer.status >= 400)) return "rejected";
  if (b.login) return "The session cookie was not accepted: the request with the registered redirect URI got the login page. Log in again with the test account and refresh the cookie file.";
  if (b.answer.kind === "redirect-elsewhere") {
    return `The session cookie was not accepted, or the consent page lives on another host: the request with the registered redirect URI was redirected to ${b.answer.destination} (not followed). Log in again and refresh the cookie file.`;
  }
  return null;
}

function formBody(fields: Array<{ name: string; value: string }>, approve: { name: string; value: string } | null): string {
  const params = new URLSearchParams();
  for (const f of fields) params.append(f.name, f.value);
  if (approve) params.append(approve.name, approve.value);
  return params.toString();
}

/** Submit the consent form shown for `candidate`, and see where the server sends the browser. */
async function approve(http: HttpClient, page: { url: string; html: string }, candidate: string, session: AuthorizationSession, origin: string): Promise<SessionRow> {
  const form = findConsentForm(page.html, page.url);
  if (!form) return { verdict: "inconclusive", detail: "consent page displayed, but its form could not be read; not approved", consentShown: true };
  let url = new URL(form.action);
  if (url.origin !== origin) return { verdict: "inconclusive", detail: `consent page displayed; its form posts to ${url.origin}, another origin, so it was not submitted`, consentShown: true };
  let res = await http.request({
    url: url.toString(),
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html,application/json", origin, referer: page.url, cookie: session.cookie },
    body: formBody(form.fields, form.approve),
  });
  for (let hops = 0; ; hops += 1) {
    const answer = classifyAnswer(res, url, candidate);
    if (answer.kind === "redirect-to-candidate") return { verdict: "accepted", detail: `consent approved, then HTTP ${answer.status}, redirected to the redirect_uri that was sent`, approved: true };
    if (answer.kind === "unavailable") return { verdict: "inconclusive", detail: `consent approved, then HTTP ${answer.status}, rate limited or server error`, approved: true };
    if (answer.kind === "page") {
      if (grantsConsent(res, candidate, url.toString())) return { verdict: "accepted", detail: `consent approved, then HTTP ${res.status}, a page that sends the code to the redirect_uri that was sent`, approved: true };
      if (answer.status >= 400) return { verdict: "refused", detail: `consent approved, then HTTP ${answer.status}: refused at approval, no redirect`, approved: true };
      return { verdict: "inconclusive", detail: `consent approved, then HTTP ${answer.status}, no redirect`, approved: true };
    }
    const next = new URL(res.headers["location"] as string, url);
    if (next.origin !== origin || hops >= MAX_HOPS) {
      return { verdict: "refused", detail: `consent approved, then HTTP ${answer.status}, redirected to ${answer.destination}, not to the redirect_uri that was sent`, approved: true };
    }
    url = next;
    res = await http.request({ url: url.toString(), headers: { accept: "text/html,application/json", cookie: session.cookie } });
  }
}

/** Judge one variant, replayed in the session, against the baseline. */
export async function judgeInSession(
  http: HttpClient,
  base: Omit<AuthorizeParams, "redirectUri">,
  baseline: SessionAnswer,
  candidate: string,
  session: AuthorizationSession,
): Promise<SessionRow> {
  const origin = new URL(base.authorizationEndpoint).origin;
  const a = await probeInSession(http, { ...base, redirectUri: candidate }, session);
  const detail = `${describeSessionAnswer(a)}, in the session`;
  if (a.answer.kind === "redirect-to-candidate") return { verdict: "accepted", detail };
  if (a.answer.kind === "unavailable") return { verdict: "inconclusive", detail };
  if (a.login) return { verdict: "inconclusive", detail: `${detail}: the session was not used for this request` };
  if (a.answer.kind === "redirect-elsewhere") {
    // Another origin (not followed): it might still come back to the URI that was sent.
    return { verdict: "inconclusive", detail: `${detail} (not followed)` };
  }
  if (a.answer.status >= 400) return { verdict: "refused", detail };
  if (a.consent && a.page) {
    if (!session.approveConsent) return { verdict: "inconclusive", detail: `${detail}: the server has not refused this URI yet, which is not proof that it would redirect there (not approved)`, consentShown: true };
    return approve(http, a.page, candidate, session, origin);
  }
  // A page without consent form, where the registered URI gets a consent page or a redirect: an error shown with 200.
  if (baseline.consent || baseline.answer.kind === "redirect-to-candidate") return { verdict: "refused", detail };
  return { verdict: a.answer.status === baseline.answer.status ? "inconclusive" : "refused", detail };
}
