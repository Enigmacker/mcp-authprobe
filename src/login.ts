import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CATALOGUE, LOGIN_CHECK_IDS } from "./checks/catalogue.js";
import type { Observation, TestGrant } from "./credentials.js";
import { scopesFor, type DiscoveryResult } from "./discovery.js";
import type { ReasonCode } from "./types.js";
import type { HttpClient } from "./net/http.js";
import { jwtAudience, runAudienceCheck } from "./checks/audience.js";
import { runEndpointChecks } from "./checks/endpoint.js";
import { makeFinding } from "./checks/finding.js";
import { bearerCredential, initializeStatus, type Era } from "./oauth/mcp-call.js";
import { describe as describeOutcome, exchangeCode, refresh, type CodeExchangeOutcome } from "./oauth/token-client.js";
import { deleteClient, registerClient } from "./oauth/registration.js";
import { registerSecret, safeErrorCode, safeText } from "./redact.js";

/**
 * Interactive login to the user's own MCP server, producing a test grant.
 *
 * It behaves like a careful native MCP client (RFC 8252):
 *   - a loopback listener on 127.0.0.1 with a random port, accepting only
 *     GET /callback with the expected state, and echoing nothing back;
 *   - dynamic client registration for that loopback redirect URI;
 *   - authorization code flow with PKCE S256, random state, the RFC 8707
 *     resource, and the RFC 9207 iss check;
 *   - the browser only ever opens the discovered authorization endpoint.
 *
 * When the hosts are proven (ownership gate), it also observes MAP-RDR03:
 * before the real exchange, it presents the code with a different
 * redirect_uri, which a compliant token endpoint must refuse.
 */

/** A client the operator supplies instead of dynamic registration: pre-registered, or a client ID metadata document URL. */
export interface ClientConfig {
  clientId: string;
  /** Confidential clients only. In memory; never reported. */
  clientSecret?: string;
  authMethod?: TestGrant["authMethod"];
}

export interface LoginOptions {
  http: HttpClient;
  mcpUrl: string;
  discovery: DiscoveryResult;
  /** Opens the authorization URL (a browser in the CLI, a scripted agent in tests). */
  openUrl: (url: string) => Promise<void>;
  /** Run the login checks. Only set when ownership of every contacted host is proven. */
  probe: boolean;
  /** How long to wait for the user to finish in the browser. */
  timeoutMs?: number;
  /** Status lines for the user (stderr in the CLI). Never receives secrets. */
  log?: (line: string) => void;
  /** Use this client instead of registering one (the first choice of the MCP specification when one exists). */
  client?: ClientConfig;
  /**
   * Loopback redirect URI to listen on (http://127.0.0.1:<port>/<path>), for
   * a pre-registered native client whose redirect URI is fixed. Default: a
   * random port, which only dynamic registration can use.
   */
  redirectUri?: string;
  /**
   * Authorizations to run (default 1). With 2, when a probe spent the code
   * before MAP-RDR03 could be observed, a second authorization gives it a
   * code of its own. Each round opens the authorization page again.
   */
  rounds?: number;
}

export interface LoginResult {
  grant: TestGrant | null;
  observations: Observation[];
  notes: string[];
  /** The access token of the exchange, for a caller that goes on with it. In memory only. */
  accessToken?: string | null;
  /** How the client was obtained. */
  clientSource?: LoginState["clientSource"];
}

export class LoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoginError";
  }
}

/**
 * Everything `completeLogin` needs to finish an authorization that
 * `beginLogin` started, possibly in another process: the PKCE verifier, the
 * state, the issuer recorded for the RFC 9207 check. It holds secrets: the
 * CLI writes it with mode 600.
 */
export interface LoginState {
  version: 1;
  target: string;
  /** Issuer of the validated authorization server metadata, recorded before the user is redirected. */
  issuer: string | null;
  issParameterSupported: boolean;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint: string | null;
  clientId: string;
  clientSecret?: string;
  authMethod: TestGrant["authMethod"];
  clientSource: "pre-registered" | "metadata-document" | "dynamic-registration";
  /** RFC 7592 handle of a client registered by `beginLogin`, to delete it when no grant is kept. */
  registered?: { registrationClientUri: string | null; registrationAccessToken: string | null };
  redirectUri: string;
  state: string;
  codeVerifier: string;
  resource: string;
  scope?: string;
  createdAt: string;
}

interface CallbackParams {
  state: string | null;
  code: string | null;
  error: string | null;
  iss: string | null;
}

function equalStrings(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

interface Listener {
  redirectUri: string;
  /** Resolves with the first callback carrying this state. */
  expect: (state: string) => Promise<CallbackParams>;
  close: () => Promise<void>;
}

/** Loopback listener: accepts one GET on its path per expected state, and echoes nothing back. */
async function startCallbackListener(fixed?: string): Promise<Listener> {
  let port = 0;
  let path = "/callback";
  let host = "127.0.0.1";
  if (fixed !== undefined) {
    let u: URL;
    try {
      u = new URL(fixed);
    } catch {
      throw new LoginError("--redirect-uri is not a valid URL.");
    }
    host = u.hostname.replace(/^\[|\]$/g, "");
    if (u.protocol !== "http:" || !["127.0.0.1", "::1", "localhost"].includes(host)) {
      throw new LoginError("login can only listen on a loopback redirect URI (http://127.0.0.1:<port>/…). For a web redirect URI, use `login begin` and `login complete`.");
    }
    if (!u.port) throw new LoginError("A loopback redirect URI needs an explicit port to listen on.");
    port = Number(u.port);
    path = u.pathname;
    if (host === "localhost") host = "127.0.0.1";
  }
  let waiting: { state: string; resolve: (p: CallbackParams) => void } | null = null;
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const state = url.searchParams.get("state") ?? "";
    if (req.method !== "GET" || url.pathname !== path || !waiting || !equalStrings(state, waiting.state)) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("Unexpected request.");
      return;
    }
    const { resolve } = waiting;
    waiting = null;
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    res.end("mcp-authprobe: authorization received. You can close this tab.");
    resolve({ state, code: url.searchParams.get("code"), error: url.searchParams.get("error"), iss: url.searchParams.get("iss") });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", (e) => reject(new LoginError(`Cannot listen on ${fixed ?? "a loopback port"}: ${(e as NodeJS.ErrnoException).code ?? "error"}.`)));
    server.listen(port, host, resolve);
  });
  const bound = (server.address() as AddressInfo).port;
  return {
    redirectUri: fixed ?? `http://127.0.0.1:${bound}/callback`,
    expect: (state) =>
      new Promise<CallbackParams>((resolve) => {
        waiting = { state, resolve };
      }),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    p,
    new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new LoginError(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function observation(checkId: string, target: string, status: Observation["status"], message: string, evidence: string[], reason?: ReasonCode): Observation {
  const inferred: ReasonCode | undefined =
    reason ?? (/a request failed/i.test(message) ? "unreachable" : /^Not observed/.test(message) ? "not_observed" : /could not be told apart|issued no access token/.test(message) ? "ambiguous" : /server error/.test(message) ? "server_error" : undefined);
  return { ...makeFinding(checkId, target, status, message, evidence, inferred), source: "login", observedAt: new Date().toISOString() };
}

const isLoopbackRedirect = (uri: string): boolean => {
  try {
    const u = new URL(uri);
    return u.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname);
  } catch {
    return false;
  }
};

export interface BeginLoginOptions {
  http: HttpClient;
  mcpUrl: string;
  discovery: DiscoveryResult;
  /** Where the authorization server sends the user back. The caller serves it (a web application), or `login` listens on it. */
  redirectUri: string;
  client?: ClientConfig;
  log?: (line: string) => void;
}

/**
 * First half of a login, without any listener: obtain a client, record what
 * the second half must check, and build the authorization URL. The client is
 * chosen in the order the MCP specification gives: the one supplied
 * (pre-registered, or a client ID metadata document URL), otherwise dynamic
 * client registration when the server still offers it.
 */
export async function beginLogin(o: BeginLoginOptions): Promise<{ authorizationUrl: string; state: LoginState; notes: string[] }> {
  const { http, discovery: d } = o;
  const log = o.log ?? (() => undefined);
  const notes: string[] = [];
  const meta = d.as?.metadata;
  const target = new URL(o.mcpUrl).toString();
  const issuer = typeof meta?.issuer === "string" ? meta.issuer : null;
  const authorizationEndpoint = typeof meta?.authorization_endpoint === "string" ? meta.authorization_endpoint : null;
  const tokenEndpoint = typeof meta?.token_endpoint === "string" ? meta.token_endpoint : null;
  const registrationEndpoint = typeof meta?.registration_endpoint === "string" ? meta.registration_endpoint : null;
  if (!authorizationEndpoint || !tokenEndpoint) throw new LoginError("The authorization server does not advertise authorization and token endpoints.");

  const authUrl = new URL(authorizationEndpoint);
  if (authUrl.protocol !== "https:" && !http.allowPrivate) throw new LoginError("Refusing to open a non-https authorization endpoint.");
  const methods = meta?.code_challenge_methods_supported;
  if (Array.isArray(methods) && !methods.includes("S256")) throw new LoginError("The authorization server does not support PKCE S256.");
  if (!Array.isArray(methods)) notes.push("The authorization server does not announce code_challenge_methods_supported. The MCP specification tells clients to refuse to proceed; the login goes on with S256, to observe what the server enforces.");
  try {
    new URL(o.redirectUri);
  } catch {
    throw new LoginError("The redirect URI is not a valid URL.");
  }

  let clientId: string;
  let clientSecret: string | undefined;
  let clientSource: LoginState["clientSource"];
  let registered: LoginState["registered"];
  if (o.client) {
    clientId = o.client.clientId;
    clientSecret = o.client.clientSecret;
    const isUrl = /^https:\/\/[^/]+\/.+/.test(clientId);
    clientSource = isUrl ? "metadata-document" : "pre-registered";
    if (isUrl && meta?.client_id_metadata_document_supported !== true) {
      notes.push("The client ID is a URL (a client ID metadata document), but the authorization server does not announce client_id_metadata_document_supported: it may refuse it.");
    }
    log(`Using the supplied client ${safeText(clientId, 120)} (${isUrl ? "client ID metadata document" : "pre-registered"}).`);
  } else if (registrationEndpoint) {
    // Dynamic registration is deprecated by MCP 2026-07-28 but still the only way on many servers.
    const grantTypes = ["authorization_code", "refresh_token"];
    const applicationType = isLoopbackRedirect(o.redirectUri) ? "native" : "web";
    const reg = await registerClient(http, registrationEndpoint, [o.redirectUri], { clientName: "mcp-authprobe test login", grantTypes, applicationType });
    if (!reg.client) throw new LoginError(`Dynamic client registration failed (HTTP ${reg.status}${reg.error ? `, error=${safeText(reg.error, 80)}` : ""}).`);
    clientId = reg.client.clientId;
    clientSecret = reg.client.clientSecret ?? undefined;
    clientSource = "dynamic-registration";
    registered = { registrationClientUri: reg.client.registrationClientUri, registrationAccessToken: reg.client.registrationAccessToken };
    log(`Registered test client ${safeText(clientId, 120)}.`);
  } else {
    throw new LoginError(
      meta?.client_id_metadata_document_supported === true
        ? "The authorization server offers no dynamic client registration. It accepts client ID metadata documents: pass the URL of yours with --client-id (and its redirect URI with --redirect-uri), or a pre-registered client."
        : "The authorization server offers no dynamic client registration: pass a pre-registered client with --client-id (and --client-secret-file for a confidential client, --redirect-uri for its redirect URI).",
    );
  }

  const state = randomBytes(24).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  registerSecret(codeVerifier);
  registerSecret(clientSecret);
  const resource = d.prm?.metadata.resource ?? target;
  const scope = scopesFor(d);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", o.redirectUri);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", createHash("sha256").update(codeVerifier).digest("base64url"));
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("resource", resource);
  if (scope) authUrl.searchParams.set("scope", scope);

  const loginState: LoginState = {
    version: 1,
    target,
    issuer,
    issParameterSupported: meta?.["authorization_response_iss_parameter_supported"] === true,
    authorizationEndpoint,
    tokenEndpoint,
    registrationEndpoint,
    clientId,
    authMethod: o.client?.authMethod ?? (clientSecret ? "client_secret_post" : "none"),
    clientSource,
    redirectUri: o.redirectUri,
    state,
    codeVerifier,
    resource,
    createdAt: new Date().toISOString(),
  };
  if (clientSecret) loginState.clientSecret = clientSecret;
  if (registered) loginState.registered = registered;
  if (scope) loginState.scope = scope;
  return { authorizationUrl: authUrl.toString(), state: loginState, notes };
}

/** Check that an object read from a state file is a login state (it comes from disk: nothing is trusted). */
export function parseLoginState(raw: unknown): LoginState {
  const o = raw as Partial<LoginState> | null;
  const str = (k: keyof LoginState): boolean => typeof o?.[k] === "string" && (o[k] as string).length > 0;
  if (!o || typeof o !== "object" || o.version !== 1 || !["target", "authorizationEndpoint", "tokenEndpoint", "clientId", "redirectUri", "state", "codeVerifier", "resource"].every((k) => str(k as keyof LoginState))) {
    throw new LoginError("The state file is not a login state written by `login begin`.");
  }
  for (const k of ["target", "authorizationEndpoint", "tokenEndpoint", "redirectUri"] as const) {
    try {
      new URL(o[k] as string);
    } catch {
      throw new LoginError(`The state file holds an invalid ${k}.`);
    }
  }
  registerSecret(o.codeVerifier);
  registerSecret(o.clientSecret);
  registerSecret(o.registered?.registrationAccessToken);
  return o as LoginState;
}

function callbackParams(callback: string | URLSearchParams): CallbackParams {
  let q: URLSearchParams;
  if (typeof callback === "string") {
    try {
      q = new URL(callback).searchParams;
    } catch {
      // A bare query string ("code=…&state=…") is accepted too.
      q = new URLSearchParams(callback.replace(/^\?/, ""));
    }
  } else {
    q = callback;
  }
  return { state: q.get("state"), code: q.get("code"), error: q.get("error"), iss: q.get("iss") };
}

export interface CompleteLoginOptions {
  http: HttpClient;
  state: LoginState;
  /** The URL the authorization server sent the user back to (or its query string, or its parameters). */
  callback: string | URLSearchParams;
  /** Run the login checks. Only set when ownership of every contacted host is proven. */
  probe: boolean;
  /** Pre-exchange checks to run (default MAP-PKC01 then MAP-RDR03). */
  preProbes?: readonly string[];
  /** Run the checks that follow the exchange (endpoint checks, MAP-AUD01, MAP-COD01). Default true. */
  postProbes?: boolean;
  /** MCP era to speak to the endpoint instead of detecting it. */
  era?: Era;
  log?: (line: string) => void;
}

/**
 * Second half of a login: validate the authorization response (state, then
 * the RFC 9207 issuer, before anything else is read from it), run the login
 * checks when asked, exchange the code and return the grant.
 */
export async function completeLogin(o: CompleteLoginOptions): Promise<LoginResult> {
  const { http, state: st } = o;
  const target = st.target;
  const tokenEndpoint = st.tokenEndpoint;
  const notes: string[] = [];
  const observations: Observation[] = [];
  let keepClient = st.clientSource !== "dynamic-registration"; // only a client this login registered is ever deleted
  const cb = callbackParams(o.callback);

  try {
    if (cb.state === null || !equalStrings(cb.state, st.state)) throw new LoginError("The authorization response does not carry the expected state; it was not used.");
    // RFC 9207, as the MCP specification applies it: the issuer is checked before the code is sent anywhere,
    // and before an error is acted on or shown (an attacker's server must not get its message displayed).
    if (cb.iss !== null && st.issuer !== null && cb.iss !== st.issuer) throw new LoginError("The iss parameter does not match the discovered issuer; aborting.");
    if (cb.iss === null && st.issParameterSupported) throw new LoginError("The server announces the iss parameter but the response has none; aborting.");
    if (cb.error) throw new LoginError(`The authorization server returned error=${safeText(safeErrorCode(cb.error) ?? "", 80)}.`);
    if (!cb.code) throw new LoginError("The authorization response carried no code.");

    const exchangeParams = { clientId: st.clientId, clientSecret: st.clientSecret ?? null, code: cb.code, resource: st.resource };
    const correct = { ...exchangeParams, codeVerifier: st.codeVerifier, redirectUri: st.redirectUri };
    const mismatch = new URL(st.redirectUri);
    mismatch.pathname = `${mismatch.pathname.replace(/\/$/, "")}-mismatch`;
    let tokens: CodeExchangeOutcome | null = null;
    let tokensFromProbe = false;

    // --- Before the real exchange: refused attempts with a broken request ---
    type Verdict = "accepted" | "refused" | "inconclusive" | "not_run";
    interface ProbeResult { checkId: string; label: string; verdict: Verdict; line: string }
    const results: ProbeResult[] = [];
    const classify = (r: CodeExchangeOutcome): Verdict =>
      r.accessTokenIssued ? "accepted" : r.status >= 400 && r.status < 500 && !r.throttled ? "refused" : "inconclusive";

    if (o.probe) {
      const all: Array<{ checkId: string; label: string; params: Parameters<typeof exchangeCode>[2] }> = [
        { checkId: "MAP-PKC01", label: "code presented without a code_verifier (PKCE)", params: { ...exchangeParams, redirectUri: st.redirectUri } },
        { checkId: "MAP-PKC01", label: "code presented with a wrong code_verifier (PKCE)", params: { ...correct, codeVerifier: randomBytes(32).toString("base64url") } },
        { checkId: "MAP-RDR03", label: "code presented with a different redirect_uri", params: { ...correct, redirectUri: mismatch.toString() } },
      ];
      const order = o.preProbes ?? ["MAP-PKC01", "MAP-RDR03"];
      const preProbes = order.flatMap((id) => all.filter((p) => p.checkId === id));
      for (const p of preProbes) {
        if (tokens) {
          results.push({ checkId: p.checkId, label: p.label, verdict: "not_run", line: `${p.label}: not run, the code was already exchanged` });
          continue;
        }
        const r = await exchangeCode(http, tokenEndpoint, p.params);
        const verdict = classify(r);
        results.push({ checkId: p.checkId, label: p.label, verdict, line: `${p.label}: ${describeOutcome(r)}` });
        if (verdict === "accepted") {
          tokens = r; // the code is spent; keep these tokens as the grant
          tokensFromProbe = true;
        }
      }
    } else {
      notes.push(`${LOGIN_CHECK_IDS.join(", ")} were not observed: ownership of the contacted hosts is not proven, or --no-probe was used.`);
    }

    // --- The real exchange ---
    let codeBurnt = false;
    let exchangeFailure: string | null = null;
    if (!tokens) {
      tokens = await exchangeCode(http, tokenEndpoint, correct);
      if (!tokens.accessTokenIssued) {
        if (o.probe && tokens.error === "invalid_grant" && results.length > 0) {
          codeBurnt = true;
        } else if (o.probe && results.some((r) => r.verdict !== "not_run")) {
          // Keep what the probes observed; only the first refusal is trusted.
          codeBurnt = true;
          exchangeFailure = safeText(describeOutcome(tokens), 200);
        } else {
          throw new LoginError(`Code exchange failed: ${safeText(describeOutcome(tokens), 200)}.`);
        }
      }
    }
    if (codeBurnt) {
      // The first refusal invalidated the code: only that first result is meaningful.
      let first = true;
      for (const r of results) {
        if (r.verdict === "refused" && !first) {
          r.verdict = "inconclusive";
          r.line += " (inconclusive: the code had already been invalidated by an earlier refused attempt)";
        }
        if (r.verdict !== "not_run") first = false;
      }
    }

    const PRE_MESSAGES: Record<string, { pass: string; fail: string }> = {
      "MAP-PKC01": {
        pass: "The token endpoint refused the code without a code_verifier and with a wrong one.",
        fail: "The token endpoint exchanged a code without a valid code_verifier, so PKCE is not enforced and an intercepted code can be redeemed.",
      },
      "MAP-RDR03": {
        pass: "The token endpoint refused a code presented with a different redirect_uri.",
        fail: "The token endpoint exchanged a code presented with a redirect_uri different from the one used at authorization.",
      },
    };
    for (const checkId of ["MAP-PKC01", "MAP-RDR03"]) {
      const rs = results.filter((r) => r.checkId === checkId && r.verdict !== "not_run");
      const lines = results.filter((r) => r.checkId === checkId).map((r) => r.line);
      if (rs.length === 0) {
        if (lines.length > 0) observations.push(observation(checkId, target, "skipped", "Not observed: an earlier probe already obtained tokens with this code (see the other login checks). `login --rounds 2` gives this check a code of its own.", lines));
        continue;
      }
      const msg = PRE_MESSAGES[checkId] as { pass: string; fail: string };
      if (rs.some((r) => r.verdict === "accepted")) observations.push(observation(checkId, target, "fail", msg.fail, lines));
      else if (rs.some((r) => r.verdict === "inconclusive")) observations.push(observation(checkId, target, "error", "Inconclusive: some attempts got an unexpected answer or could not be told apart from an earlier refusal.", lines));
      else observations.push(observation(checkId, target, "pass", msg.pass, lines));
    }

    if (codeBurnt) {
      notes.push(
        exchangeFailure
          ? `The code exchange failed after the probes (${exchangeFailure}); only the first refusal is trusted. The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.`
          : "The server invalidated the code after the first refused attempt (a strict, acceptable behaviour). The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.",
      );
      return { grant: null, observations, notes, clientSource: st.clientSource };
    }
    // Without a refresh token there is no grant, but the checks that only need
    // the access token (ORG01, COD01) still run.
    const grant: TestGrant | null = tokens.refreshToken ? {
      clientId: st.clientId,
      refreshToken: tokens.refreshToken,
      authMethod: st.authMethod,
      // Bind the grant to where it came from: scans of other targets will not use it.
      target: new URL(target).toString(),
      tokenEndpoint: new URL(tokenEndpoint).toString(),
    } : null;
    if (grant && st.clientSecret) grant.clientSecret = st.clientSecret;

    if (o.probe && o.postProbes !== false) {
      await postExchangeProbes({ http, target, tokenEndpoint, grant, tokens, correct, tokensFromProbe, observations, notes, results, resource: st.resource, ...(o.era ? { era: o.era } : {}) });
      if (notes.some((n) => n.startsWith(REVOKED_NOTE))) return { grant: null, observations, notes, clientSource: st.clientSource };
    }
    if (!grant) {
      notes.push("Login succeeded but no refresh token was issued; the refresh token checks cannot run with this server configuration.");
      return { grant: null, observations, notes, accessToken: tokens.accessToken, clientSource: st.clientSource };
    }
    keepClient = true; // the grant belongs to this client
    return { grant, observations, notes, accessToken: tokens.accessToken, clientSource: st.clientSource };
  } finally {
    // Without a usable grant, a client this login registered is useless: remove it when possible.
    if (!keepClient && st.registered && st.registrationEndpoint) {
      await deleteClient(http, { clientId: st.clientId, clientSecret: null, redirectUris: [st.redirectUri], ...st.registered }, st.registrationEndpoint);
    }
  }
}

/**
 * Interactive login of a native client: a loopback listener, `beginLogin`,
 * the user's browser, then `completeLogin`.
 */
export async function login(opts: LoginOptions): Promise<LoginResult> {
  const log = opts.log ?? (() => undefined);
  const listener = await startCallbackListener(opts.redirectUri);
  const base = { http: opts.http, mcpUrl: opts.mcpUrl, discovery: opts.discovery, redirectUri: listener.redirectUri, log };
  const wait = opts.timeoutMs ?? 5 * 60_000;
  let begun: Awaited<ReturnType<typeof beginLogin>> | null = null;
  let finished = false;
  try {
    begun = await beginLogin({ ...base, ...(opts.client ? { client: opts.client } : {}) });
    log("Opening the authorization page. Log in with your dedicated TEST account.");
    const first = listener.expect(begun.state.state);
    await opts.openUrl(begun.authorizationUrl);
    const cb = await withTimeout(first, wait, "Timed out waiting for the authorization response.");
    finished = true; // from here on, completeLogin owns the cleanup of the client
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(cb)) if (v !== null) params.set(k, v);
    const result = await completeLogin({ http: opts.http, state: begun.state, callback: params, probe: opts.probe, log });
    result.notes.unshift(...begun.notes);

    // A probe that obtained tokens spent the code before MAP-RDR03 could be observed: a second code settles it.
    const unobserved = result.observations.find((x) => x.checkId === "MAP-RDR03" && x.status === "skipped");
    if (opts.probe && unobserved && (opts.rounds ?? 1) >= 2) {
      log("Second authorization, to observe MAP-RDR03 with a code of its own.");
      // The same client: the redirect URI is the one it was registered with.
      const client: ClientConfig = { clientId: begun.state.clientId, authMethod: begun.state.authMethod, ...(begun.state.clientSecret ? { clientSecret: begun.state.clientSecret } : {}) };
      const second = await beginLogin({ ...base, client });
      const again = listener.expect(second.state.state);
      await opts.openUrl(second.authorizationUrl);
      const cb2 = await withTimeout(again, wait, "Timed out waiting for the second authorization response.");
      const params2 = new URLSearchParams();
      for (const [k, v] of Object.entries(cb2)) if (v !== null) params2.set(k, v);
      const round2 = await completeLogin({ http: opts.http, state: second.state, callback: params2, probe: true, preProbes: ["MAP-RDR03"], postProbes: false, log });
      const rdr03 = round2.observations.find((x) => x.checkId === "MAP-RDR03");
      if (rdr03) {
        rdr03.evidence.push("observed with a second authorization code (--rounds 2)");
        result.observations.splice(result.observations.indexOf(unobserved), 1, rdr03);
      }
      // The newest tokens are the grant, unless the first round already lost it on purpose (revoked after a code reuse).
      if (round2.grant && result.grant) result.grant = round2.grant;
    }
    return result;
  } finally {
    await listener.close();
    // The user never came back: the client registered for this login is of no use.
    if (begun && !finished && begun.state.registered && begun.state.registrationEndpoint) {
      await deleteClient(opts.http, { clientId: begun.state.clientId, clientSecret: null, redirectUris: [begun.state.redirectUri], ...begun.state.registered }, begun.state.registrationEndpoint);
    }
  }
}

/** Open a URL in the default browser without going through a shell. */
export function openInBrowser(url: string): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return Promise.reject(new Error("Refusing to open a non-HTTP URL."));
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
        : ["xdg-open", [url]];
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd, args as string[], { stdio: "ignore", detached: true, shell: false });
      child.on("error", () => resolve()); // no browser: the URL is printed anyway
      child.unref();
    } catch {
      /* the URL is printed anyway */
    }
    resolve();
  });
}


const REVOKED_NOTE = "The server revoked the tokens after the code reuse attempt";

interface PostExchange {
  http: HttpClient;
  target: string;
  tokenEndpoint: string;
  /** Null when no refresh token was issued. */
  grant: TestGrant | null;
  tokens: CodeExchangeOutcome;
  correct: Parameters<typeof exchangeCode>[2];
  tokensFromProbe: boolean;
  observations: Observation[];
  notes: string[];
  results: Array<{ checkId: string }>;
  /** The RFC 8707 resource the tokens were requested for. */
  resource?: string;
  era?: Era;
}

const is2xx = (s: number | null): s is number => s !== null && s >= 200 && s < 300;

/**
 * Checks that need tokens: MAP-ORG01 and MAP-AUD01 (with the access token,
 * before any refresh), then MAP-COD01 (last: it may revoke the grant). Each
 * one turns a network failure into an inconclusive result, so the grant and
 * the earlier observations are never lost. The grant always keeps the newest
 * refresh token.
 */
async function postExchangeProbes(c: PostExchange): Promise<void> {
  const { http, target, tokenEndpoint, grant, tokens, observations } = c;
  const guard = async (checkId: string, run: () => Promise<void>): Promise<void> => {
    try {
      await run();
    } catch (e) {
      observations.push(observation(checkId, target, "error", `Inconclusive: a request failed (${(e as Error).message}).`, []));
    }
  };

  // Checks of the MCP endpoint with the access token, before any refresh
  // (a refresh may invalidate it): ORG01, TOK01, SES01, BAT01, BOD01, INJ01.
  let control: number | null = null;
  let era: Era | undefined = c.era;
  const accessToken = tokens.accessToken;
  if (accessToken) {
    const ep = await runEndpointChecks(http, target, bearerCredential(accessToken), c.era ? { era: c.era } : {});
    control = ep.control;
    if (ep.era) era = ep.era;
    for (const f of ep.findings) observations.push({ ...f, source: "login", observedAt: new Date().toISOString() });
  } else {
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"]) {
      observations.push(observation(id, target, "error", "Inconclusive: the token endpoint issued no access token.", []));
    }
  }

  await guard("MAP-AUD01", async () => {
    const f = await runAudienceCheck({ http, target, tokenEndpoint, grant, control, ...(era ? { era } : {}), ...(c.resource ? { ownAudiences: [c.resource] } : {}) });
    observations.push({ ...f, source: "login", observedAt: new Date().toISOString() });
  });

  // Last: a compliant server may revoke the grant here.
  await guard("MAP-COD01", async () => {
    const reuse = await exchangeCode(http, tokenEndpoint, c.correct);
    const lines = [`code presented a second time: ${describeOutcome(reuse)}`];
    if (c.tokensFromProbe) lines.unshift("the code had already been exchanged by an earlier probe");
    if (reuse.accessTokenIssued) {
      observations.push(observation("MAP-COD01", target, "fail", "The authorization code was exchanged a second time: codes are not single-use.", lines));
      if (reuse.refreshToken && grant) grant.refreshToken = reuse.refreshToken;
      return;
    }
    if (reuse.status < 400 || reuse.status >= 500 || reuse.throttled) {
      observations.push(
        observation(
          "MAP-COD01",
          target,
          "error",
          reuse.status >= 500
            ? "Inconclusive: the token endpoint crashed (server error) on the second use of the code instead of answering invalid_grant. No tokens were issued, but a clean refusal is expected."
            : "Unexpected answer to the second use of the code; inconclusive.",
          lines,
        ),
      );
      return;
    }
    // Were the tokens issued from that code revoked? (recommended)
    if (!grant) {
      // No refresh token: look at the access token instead.
      const st = accessToken ? await initializeStatus(http, target, { token: accessToken, ...(era ? { era } : {}) }) : null;
      lines.push(`access token after the reuse attempt: ${st === null ? "not available" : `HTTP ${st}`}`);
      const message =
        st !== null && (st === 401 || st === 403) && is2xx(control)
          ? "A second use of the authorization code is refused, and the access token issued from it was revoked."
          : is2xx(st)
            ? "A second use of the authorization code is refused. The access token issued from it stays valid; revoking it on reuse is recommended."
            : "A second use of the authorization code is refused. Whether the tokens issued from it were revoked is unknown.";
      observations.push(observation("MAP-COD01", target, "pass", message, lines));
      return;
    }
    const after = await refresh(http, tokenEndpoint, grant, grant.refreshToken, c.resource);
    if (after.accessTokenIssued) {
      if (after.refreshToken) grant.refreshToken = after.refreshToken;
      lines.push("newest refresh token after the reuse attempt: still valid");
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused. The tokens issued from it stay valid; revoking them on reuse is recommended.", lines));
    } else if (after.error === "invalid_grant") {
      lines.push(`newest refresh token after the reuse attempt: ${describeOutcome(after)}`);
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused, and the tokens issued from it were revoked.", lines));
      c.notes.push(`${REVOKED_NOTE} (recommended behaviour). The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.`);
    } else {
      lines.push(`newest refresh token after the reuse attempt: ${describeOutcome(after)} (unknown)`);
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused. Whether the tokens issued from it were revoked is unknown.", lines));
    }
  });
}

export { jwtAudience };
