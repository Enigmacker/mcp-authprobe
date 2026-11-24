import { runAudienceCheck } from "./checks/audience.js";
import { CATALOGUE } from "./checks/catalogue.js";
import { runEndpointChecks, runMetadataCheck, type EndpointCheckId } from "./checks/endpoint.js";
import { makeFinding, summarize } from "./checks/finding.js";
import { runRedirectUriChecks } from "./checks/redirect-uris.js";
import { runRefreshTokenSequence, type GrantState } from "./checks/refresh-tokens.js";
import { runThrottlingCheck } from "./checks/throttling.js";
import { observationSource, type Observation, type TestGrant } from "./credentials.js";
import { discover, scopesFor, type DiscoveryResult } from "./discovery.js";
import { BlockedAddressError, HttpClient, InsecureTransportError, NetworkError, ScanInterruptedError } from "./net/http.js";
import { FOREIGN_ORIGIN, helloName, initializeStatus, MODERN_VERSION, rpcMessage, versionOf, type Credential, type Era } from "./oauth/mcp-call.js";
import { normalizeHost, verifyOwnership, type OwnershipResult, type VerifyOptions } from "./ownership.js";
import type { CheckSelector } from "./selection.js";
import type { CheckStatus, DiscoverySummary, Finding, GrantReport, Leftover, ReasonCode, ScanReport } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

/** Progress of a scan, for a program that runs it (`onEvent`, or one JSON line each with --events). */
export type ScanEvent =
  | { type: "scan_started"; target: string; at: string }
  | { type: "discovery_finished"; reachable: boolean; at: string }
  | { type: "check_started"; checkId: string; at: string }
  | { type: "check_finished"; checkId: string; status: CheckStatus; reason?: ReasonCode; durationMs: number; at: string }
  | { type: "scan_finished"; complete: boolean; at: string };

export interface ScanOptions {
  /** Ownership secret; read from MCP_AUTHPROBE_SECRET by the CLI, never from argv. */
  secret?: string;
  allowPrivate?: boolean;
  timeoutMs?: number;
  /** Test grant for the refresh token checks. It is consumed by the full sequence; see `runScan` for its state afterwards. */
  grant?: TestGrant;
  /** Checks to run (from --only/--skip). Unselected checks send no request and are reported as skipped. */
  select?: CheckSelector;
  /**
   * Refuse a grant that does not name its target (MCP mode): a hand-written,
   * unbound grant could otherwise be spent on any proven server.
   */
  requireGrantBinding?: boolean;
  /** Exempt loopback labs from the ownership proof (default true; see VerifyOptions). */
  loopbackExempt?: boolean;
  /**
   * Exempt only these exact origins (MCP mode: the labs the human listed).
   * A loopback host is then exempt only if every URL the scan would contact
   * on it has one of these origins: another port of the same machine is not.
   */
  exemptOrigins?: readonly string[];
  /** With `allowPrivate`, other hosts than the target for which a private address is accepted (--allow-host). */
  allowHosts?: readonly string[];
  /** Headers sent with every request to the target origin, and nowhere else (--header-file). */
  extraHeaders?: Record<string, string>;
  /** Name of the preset the selection comes from, recorded in the report. */
  preset?: string;
  /** Failed token requests sent by MAP-THR01 (clamped to 5-20, default 10). */
  throttleAttempts?: number;
  /** Results observed during `login`, read from the grant file. */
  observations?: Observation[];
  /**
   * Oldest observation that is still reported, in milliseconds (default 24 h;
   * 0 for no limit). An older one is listed as skipped: a result observed
   * last month says little about the server today.
   */
  maxObservationAgeMs?: number;
  /**
   * Credential for the MCP endpoint: a static API key (--bearer-file) or an
   * OAuth access token (--access-token-file). Only sent to the target, and
   * only once ownership of it is proven.
   */
  credential?: Credential;
  /** Requests sent by MAP-THR02 (clamped to 10-100, default 30). */
  rateAttempts?: number;
  /** Run MAP-THR02 with an OAuth access token too (by default only with a static key: it may get the token limited). */
  rateLimitWithToken?: boolean;
  /** Wait up to this long, once, when the control request is rate limited with a Retry-After. */
  waitOnRateLimitMs?: number;
  /** Pause before every request, in milliseconds. */
  delayMs?: number;
  /** Hard cap on the number of requests of the scan. */
  maxRequests?: number;
  /** Aborting it stops the scan cleanly: temporary clients are deleted and a partial report is returned. */
  signal?: AbortSignal;
  /** Stop the scan after this many milliseconds, with a partial report. */
  deadlineMs?: number;
  /** MCP era to speak instead of detecting it: "legacy" (2025-11-25, initialize) or "modern" (2026-07-28, stateless). */
  protocol?: Era;
  /** Examine this authorization server instead of the first one the resource announces. */
  issuer?: string;
  /**
   * A client the operator supplies instead of dynamic registration (the
   * first choice of the MCP specification): pre-registered, or the URL of a
   * client ID metadata document. `redirectUri` is one of its registered
   * redirect URIs, needed by the redirect URI checks.
   */
  client?: { clientId: string; clientSecret?: string; redirectUri?: string };
  /** Called at the start and end of the scan, of discovery and of every check. Must not throw. */
  onEvent?: (event: ScanEvent) => void;
  /** Test hooks. */
  resolveTxtRecords?: VerifyOptions["resolveTxtRecords"];
  wellKnownBaseUrl?: string;
}

/** A report, and what became of the test grant (the newest refresh token is only here, never in the report). */
export interface ScanResult {
  report: ScanReport;
  grant: { latest: TestGrant | null; state: GrantState["state"] | "unused" };
}

const DAY_MS = 24 * 60 * 60 * 1000;

function dsc01(d: DiscoveryResult, staticKey: boolean): Finding {
  const missing: string[] = [];
  if (!d.prm) missing.push("Protected Resource Metadata");
  if (!d.as) missing.push("Authorization Server Metadata");
  if (d.as && !d.as.metadata.authorization_endpoint) missing.push("authorization_endpoint");
  if (d.as && !d.as.metadata.token_endpoint) missing.push("token_endpoint");
  const evidence = [
    `challenge: HTTP ${d.challenge.status}${d.challenge.resourceMetadataUrl ? `, resource_metadata=${d.challenge.resourceMetadataUrl}` : ""}`,
    ...(d.prm ? [`PRM: ${d.prm.url}`] : []),
    ...(d.as ? [`AS metadata: ${d.as.url}`] : []),
    ...d.notes,
  ];
  if (missing.length === 0) {
    const n = d.warnings?.length ?? 0;
    return makeFinding("MAP-DSC01", d.mcpUrl, "pass", n > 0 ? `Authorization endpoints discovered, with ${n} metadata inconsistenc${n === 1 ? "y" : "ies"} a strict client would refuse: see the evidence.` : "Authorization endpoints discovered.", evidence);
  }
  // A server authenticated by a static key publishes no OAuth metadata: that is expected,
  // but only when the operator says so (a plain 401 also looks like a broken OAuth setup).
  if (staticKey && !d.prm && !d.as && !d.challenge.resourceMetadataUrl) {
    return makeFinding("MAP-DSC01", d.mcpUrl, "not_applicable", "No OAuth discovery, as expected for a server authenticated by a static key (--bearer-file).", evidence);
  }
  return makeFinding("MAP-DSC01", d.mcpUrl, "fail", `Missing: ${missing.join(", ")}. Active checks cannot run.`, evidence);
}

/** Hosts that active checks would contact: the MCP host and the authorization server host. */
export function hostsToVerify(mcpUrl: string, d: DiscoveryResult | null): string[] {
  const hosts = new Set([new URL(mcpUrl).hostname]);
  for (const endpoint of [d?.as?.metadata.authorization_endpoint, d?.as?.metadata.token_endpoint, d?.as?.metadata.registration_endpoint]) {
    if (typeof endpoint === "string") {
      try {
        hosts.add(new URL(endpoint).hostname);
      } catch {
        /* malformed endpoint: reported by discovery */
      }
    }
  }
  return [...hosts];
}

/** What discovery found, for the report: URLs and capabilities, no secret. */
export function summarizeDiscovery(d: DiscoveryResult | null, era?: Era | null): DiscoverySummary {
  const meta = d?.as?.metadata;
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  const registration: DiscoverySummary["registration"] = [];
  if (typeof meta?.registration_endpoint === "string") registration.push("dcr");
  if (meta?.client_id_metadata_document_supported === true) registration.push("cimd");
  const servers = d?.prm?.metadata.authorization_servers;
  return {
    challengeStatus: d?.challenge.status ?? null,
    resourceMetadataUrl: d?.prm?.url ?? null,
    authorizationServerMetadataUrl: d?.as?.url ?? null,
    resource: str(d?.prm?.metadata.resource),
    issuer: str(meta?.issuer) ?? d?.issuer ?? null,
    authorizationServers: Array.isArray(servers) ? servers.filter((x): x is string => typeof x === "string") : [],
    authorizationEndpoint: str(meta?.authorization_endpoint),
    tokenEndpoint: str(meta?.token_endpoint),
    registrationEndpoint: str(meta?.registration_endpoint),
    registration,
    pkceMethods: Array.isArray(meta?.code_challenge_methods_supported) ? meta.code_challenge_methods_supported.filter((x): x is string => typeof x === "string") : null,
    protocol: {
      era: era ?? d?.protocol?.era ?? "unknown",
      version: era ? versionOf(era) : (d?.protocol?.version ?? null),
      supportedVersions: d?.protocol?.supportedVersions ?? [],
      ...(d?.protocol?.transport ? { transport: d.protocol.transport } : {}),
    },
    notes: d?.notes ?? [],
  };
}

const RTK_IDS = ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"];
const RDR_IDS = ["MAP-RDR01", "MAP-RDR02", "MAP-RDR04"];
/** Checks of the MCP endpoint that need a working credential. */
const ENDPOINT_IDS: readonly EndpointCheckId[] = ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"];
/** Checks that are only observed during `login` (a fresh authorization code is needed). */
const LOGIN_ONLY_IDS = ["MAP-RDR03", "MAP-PKC01", "MAP-COD01", "MAP-AUD01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01"];

/**
 * The grant usable for this target, or the reason it is not. A grant written
 * by `login` names its target and token endpoint; it is never sent elsewhere.
 */
export function grantFor(target: string, tokenEndpoint: string, options: ScanOptions): { grant: TestGrant | null; reason: string | null } {
  const g = options.grant;
  if (!g) return { grant: null, reason: "Needs a test grant: create one with `mcp-authprobe login`, then pass it with --credentials-file." };
  if (g.target === undefined) {
    if (options.requireGrantBinding) return { grant: null, reason: "The test grant does not name its target; create it with `mcp-authprobe login` so it cannot be spent on another server." };
  } else if (new URL(g.target).toString() !== new URL(target).toString()) {
    return { grant: null, reason: "The test grant belongs to another target; it was not used." };
  }
  if (g.tokenEndpoint !== undefined && new URL(g.tokenEndpoint).toString() !== new URL(tokenEndpoint).toString()) {
    return { grant: null, reason: "The test grant belongs to another token endpoint than the one discovered; it was not used." };
  }
  return { grant: g, reason: null };
}

/**
 * MAP-COR01. Passive: a CORS preflight and an ordinary request, both with a
 * foreign Origin and no credentials; only the CORS response headers are read.
 */
async function runCorsCheck(target: string, http: HttpClient, era: Era): Promise<Finding> {
    const evidence: string[] = [];
  let worst: "credentials" | "reflected" | "wildcard" | "none" = "none";
  const judge = (label: string, headers: Record<string, string>, status: number): void => {
    const acao = headers["access-control-allow-origin"];
    const acac = (headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
    evidence.push(`${label}: HTTP ${status}, Access-Control-Allow-Origin ${acao === undefined ? "absent" : `"${acao}"`}${acac ? ", Access-Control-Allow-Credentials true" : ""}`);
    const reflected = acao !== undefined && acao.toLowerCase() === FOREIGN_ORIGIN;
    if (reflected && acac) worst = "credentials";
    else if (reflected && worst !== "credentials") worst = "reflected";
    else if (acao === "*" && worst === "none") worst = "wildcard";
  };
  try {
    const pre = await http.request({
      url: target,
      method: "OPTIONS",
      headers: { origin: FOREIGN_ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": "authorization, content-type, mcp-protocol-version, mcp-method, mcp-name, mcp-session-id" },
    });
    judge("preflight (OPTIONS) from a foreign Origin", pre.headers, pre.status);
    const res = await http.request({
      url: target,
      method: "POST",
      headers: {
        origin: FOREIGN_ORIGIN,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(era === "modern" ? { "mcp-protocol-version": MODERN_VERSION, "mcp-method": "server/discover" } : {}),
      },
      body: JSON.stringify(rpcMessage(era, "ping")),
    });
    judge("request from a foreign Origin", res.headers, res.status);
  } catch (err) {
    return makeFinding("MAP-COR01", target, "error", `Request failed: ${(err as Error).message}`, evidence);
  }
  switch (worst as string) {
    case "credentials":
      return makeFinding("MAP-COR01", target, "fail", "A foreign Origin is reflected in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true: any website can call the endpoint with the user's cookies and read the answers.", evidence);
    case "reflected":
      return makeFinding("MAP-COR01", target, "pass", "A foreign Origin is reflected, but without credentials: a website cannot use the user's cookies, and bearer tokens are not sent by browsers on their own. Prefer an explicit allow-list.", evidence);
    case "wildcard":
      return makeFinding("MAP-COR01", target, "pass", "CORS allows any origin (*) without credentials, which browsers never combine with cookies.", evidence);
    default:
      return makeFinding("MAP-COR01", target, "pass", "No CORS access is granted to a foreign origin.", evidence);
  }
}

/** Everything one scan shares between its checks. */
interface Ctx {
  target: string;
  http: HttpClient;
  options: ScanOptions;
  discovery: DiscoveryResult | null;
  observations: Observation[];
  /** Whether `mcp-authprobe login` can work on this server (it needs a way to obtain a client). */
  loginPossible: boolean;
  /** The era requests are sent in: known from discovery or the credentialed checks, otherwise the newest (what discovery sent first). */
  era: Era;
  /** Whether `era` was actually observed. */
  eraKnown: boolean;
  leftovers: Leftover[];
  /** The grant as the scan leaves it. */
  grant: { latest: TestGrant | null; state: GrantState["state"] | "unused"; used: boolean; rotated: boolean };
}

const LOGIN_ADVICE = "Observed during login: run `mcp-authprobe login` with ownership proven, then scan with the grant file it writes.";
const NO_LOGIN_ADVICE = "Observed during login. This authorization server offers no dynamic client registration: give `mcp-authprobe login` a pre-registered client with --client-id (and --redirect-uri), then scan with the grant file it writes.";

/**
 * Report a result observed during `login`. The observation comes from a
 * local file, so its text is neutralized again and it is only used for the
 * exact target it was observed on, and only while it is recent enough.
 */
function fromObservation(ctx: Ctx, checkId: string): Finding {
  const { target } = ctx;
  const obs = ctx.observations.filter((o) => o.checkId === checkId && o.target === target).at(-1);
  if (!obs) return makeFinding(checkId, target, "skipped", ctx.loginPossible ? LOGIN_ADVICE : NO_LOGIN_ADVICE, [], "needs_login");
  const max = ctx.options.maxObservationAgeMs ?? DAY_MS;
  const age = Date.now() - Date.parse(obs.observedAt);
  if (max > 0 && (Number.isNaN(age) || age > max)) {
    return {
      ...makeFinding(checkId, target, "skipped", `Observed during login more than ${Math.round(max / 3_600_000)} h ago (${obs.observedAt}): too old to report. Run \`mcp-authprobe login\` again, or raise --max-observation-age.`, [], "stale_observation"),
      source: observationSource(obs),
      observedAt: obs.observedAt,
    };
  }
  const f = makeFinding(checkId, target, obs.status, obs.message, [...obs.evidence, `observed during login at ${obs.observedAt}`], obs.reason);
  return { ...f, source: observationSource(obs), observedAt: obs.observedAt };
}

const hasObservation = (ctx: Ctx, checkId: string): boolean => ctx.observations.some((o) => o.checkId === checkId && o.target === ctx.target);

/**
 * MAP-INJ01 without a credential: the result observed during `login`, or,
 * for a server that answers anonymous requests, a reading without one.
 */
async function metadataWithoutCredential(ctx: Ctx): Promise<Finding> {
  const { target, http } = ctx;
  if (hasObservation(ctx, "MAP-INJ01")) return fromObservation(ctx, "MAP-INJ01");
  const anonymous = await initializeStatus(http, target, { era: ctx.era });
  if (anonymous >= 200 && anonymous < 300) return runMetadataCheck(http, target, undefined, ctx.era);
  const how = ctx.loginPossible
    ? "run `mcp-authprobe login` (ownership proven) and scan with the grant file it writes, or pass a static key with --bearer-file or an access token with --access-token-file"
    : "pass a static key with --bearer-file or an access token with --access-token-file (or give `mcp-authprobe login` a client with --client-id: this server offers no dynamic client registration)";
  return makeFinding("MAP-INJ01", target, "skipped", `Needs a credential: ${how}.`, [`${helloName(ctx.era)} without any credential: HTTP ${anonymous}`], "needs_credential");
}

/**
 * MAP-ORG01 without a credential. Passive: two ordinary initialize requests,
 * one with a foreign Origin. Without a token most servers answer 401 before
 * looking at Origin; `login` then observes it with a valid token.
 */
async function runOriginCheck(ctx: Ctx): Promise<Finding> {
  const { target, http } = ctx;
  if (hasObservation(ctx, "MAP-ORG01")) return fromObservation(ctx, "MAP-ORG01");
  const baseline = await initializeStatus(http, target, { era: ctx.era });
  const foreign = await initializeStatus(http, target, { origin: FOREIGN_ORIGIN, era: ctx.era });
  const evidence = [`${helloName(ctx.era)} without Origin: HTTP ${baseline}`, `${helloName(ctx.era)} with Origin: ${FOREIGN_ORIGIN}: HTTP ${foreign}`];
  if (foreign === 403 && baseline !== 403) return makeFinding("MAP-ORG01", target, "pass", "A request from a foreign Origin is refused with 403.", evidence);
  if (baseline >= 200 && baseline < 300 && foreign === baseline) {
    return makeFinding("MAP-ORG01", target, "fail", "A request from a foreign Origin is processed like any other: the Origin header is not validated.", evidence);
  }
  if (baseline === 401 && foreign === 401) {
    const next = ctx.options.credential
      ? "Prove ownership of the target so the declared credential can be used, then scan again."
      : ctx.loginPossible
        ? "Run `mcp-authprobe login` (ownership proven) to observe it with a valid token, or pass a static key with --bearer-file or an access token with --access-token-file."
        : "Pass a static key with --bearer-file or an access token with --access-token-file to observe it with a credential (or give `mcp-authprobe login` a client with --client-id: this server offers no dynamic client registration).";
    return makeFinding("MAP-ORG01", target, "error", `Inconclusive: the server asks for authentication before looking at Origin. ${next}`, evidence, "needs_credential");
  }
  const reason: ReasonCode = baseline === 429 || foreign === 429 ? "rate_limited" : baseline >= 500 || foreign >= 500 ? "server_error" : "unexpected_answer";
  return makeFinding("MAP-ORG01", target, "error", "Unexpected answers; inconclusive.", evidence, reason);
}

async function runRefreshFamily(ctx: Ctx): Promise<Finding[]> {
  const { target, http, options } = ctx;
  const wanted = options.select ?? (() => true);
  const all = (status: Finding["status"], message: string, reason?: ReasonCode): Finding[] => RTK_IDS.filter(wanted).map((id) => makeFinding(id, target, status, message, [], reason));
  const tokenEndpoint = ctx.discovery?.as?.metadata.token_endpoint;
  if (typeof tokenEndpoint !== "string") return all("skipped", "No token endpoint discovered.", "no_endpoint");
  const grants = ctx.discovery?.as?.metadata.grant_types_supported;
  if (Array.isArray(grants) && !grants.includes("refresh_token")) {
    return all("not_applicable", "The authorization server does not advertise the refresh_token grant.");
  }
  const { grant, reason } = grantFor(target, tokenEndpoint, options);
  if (!grant) return all("skipped", reason ?? "No usable test grant.", "needs_grant");
  // RFC 8707: the resource goes into every token request, refreshes included.
  const resource = ctx.discovery?.prm?.metadata.resource ?? target;
  const r = await runRefreshTokenSequence({ http, target, tokenEndpoint, grant: { ...grant, refreshToken: ctx.grant.latest?.refreshToken ?? grant.refreshToken }, select: wanted, resource });
  ctx.grant.used = ctx.grant.used || r.grant.requests > 0;
  ctx.grant.rotated = ctx.grant.rotated || r.grant.rotated;
  ctx.grant.state = r.grant.state;
  ctx.grant.latest = r.grant.latestRefreshToken ? { ...grant, refreshToken: r.grant.latestRefreshToken } : null;
  return r.findings;
}

async function runThrottleFamily(ctx: Ctx): Promise<Finding> {
  const { target, http, options } = ctx;
  const meta = ctx.discovery?.as?.metadata;
  if (typeof meta?.token_endpoint !== "string") return makeFinding("MAP-THR01", target, "skipped", "No token endpoint discovered.", [], "no_endpoint");
  const c: Parameters<typeof runThrottlingCheck>[0] = {
    http,
    target,
    tokenEndpoint: meta.token_endpoint,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
    leftovers: ctx.leftovers,
    ...(options.client ? { client: { clientId: options.client.clientId, ...(options.client.clientSecret ? { clientSecret: options.client.clientSecret } : {}) } } : {}),
  };
  const { grant } = grantFor(target, meta.token_endpoint, options);
  if (grant) c.grant = grant; // otherwise a temporary client is used
  if (options.throttleAttempts !== undefined) c.attempts = options.throttleAttempts;
  return runThrottlingCheck(c);
}

async function runRedirectFamily(ctx: Ctx, select: CheckSelector): Promise<Finding[]> {
  const { target, http } = ctx;
  const meta = ctx.discovery?.as?.metadata;
  if (!meta) return RDR_IDS.filter(select).map((id) => makeFinding(id, target, "skipped", "No authorization server metadata discovered.", [], "no_endpoint"));
  // The same scope selection as `login`: the challenge first, then scopes_supported.
  const scope = ctx.discovery ? scopesFor(ctx.discovery, false) : undefined;
  const c: Parameters<typeof runRedirectUriChecks>[0] = {
    http,
    target,
    authorizationEndpoint: typeof meta.authorization_endpoint === "string" ? meta.authorization_endpoint : null,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
    resource: ctx.discovery?.prm?.metadata.resource ?? target,
    select,
    leftovers: ctx.leftovers,
    ...(ctx.options.client ? { client: { clientId: ctx.options.client.clientId, ...(ctx.options.client.redirectUri ? { redirectUri: ctx.options.client.redirectUri } : {}) } } : {}),
  };
  if (scope) c.scope = scope;
  return runRedirectUriChecks(c);
}

/**
 * MAP-AUD01 during a scan: possible when the operator supplies both an
 * access token for the server (the control) and a test grant (to ask for a
 * token for another resource). Uses one refresh; the grant keeps the newest token.
 */
async function runAudienceDuringScan(ctx: Ctx, credential: Credential, tokenEndpoint: string, grant: TestGrant): Promise<Finding> {
  const { target, http } = ctx;
  let control: number | null = null;
  try {
    control = await initializeStatus(http, target, { auth: credential, era: ctx.era });
  } catch {
    control = null;
  }
  const working: TestGrant = { ...grant, refreshToken: ctx.grant.latest?.refreshToken ?? grant.refreshToken };
  const before = working.refreshToken;
  const resource = ctx.discovery?.prm?.metadata.resource;
  const f = await runAudienceCheck({ http, target, tokenEndpoint, grant: working, control, era: ctx.era, ...(typeof resource === "string" ? { ownAudiences: [resource] } : {}) });
  if (control !== null && control >= 200 && control < 300) ctx.grant.used = true;
  if (working.refreshToken !== before) {
    ctx.grant.rotated = true;
    ctx.grant.latest = working;
    ctx.grant.state = "valid";
  }
  return f;
}

/** The scan, with what became of the test grant. `scan` returns the report alone. */
export async function runScan(mcpUrl: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const target = new URL(mcpUrl).toString();
  const emit = (e: ScanEvent): void => {
    try {
      options.onEvent?.(e);
    } catch {
      /* a listener never stops a scan */
    }
  };
  const now = (): string => new Date().toISOString();

  // One signal for the caller's abort and the deadline.
  const stop = new AbortController();
  const onAbort = (): void => stop.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  if (options.signal?.aborted) stop.abort();
  const timer = options.deadlineMs !== undefined && options.deadlineMs > 0 ? setTimeout(() => stop.abort(), options.deadlineMs) : undefined;
  timer?.unref?.();

  const httpOptions: ConstructorParameters<typeof HttpClient>[0] = {
    allowPrivate: options.allowPrivate ?? false,
    signal: stop.signal,
    // Private addresses are for the target (and the hosts the operator named), not for wherever the server's metadata points.
    privateHosts: [new URL(target).hostname, ...(options.allowHosts ?? [])],
    ...(options.extraHeaders ? { extraHeaders: { origin: new URL(target).origin, headers: options.extraHeaders } } : {}),
  };
  if (options.timeoutMs !== undefined) httpOptions.timeoutMs = options.timeoutMs;
  if (options.delayMs !== undefined) httpOptions.delayMs = options.delayMs;
  if (options.maxRequests !== undefined) httpOptions.maxRequests = options.maxRequests;
  const http = new HttpClient(httpOptions);
  const findings: Finding[] = [];
  const wanted: CheckSelector = options.select ?? (() => true);
  let complete = true;
  emit({ type: "scan_started", target, at: startedAt });

  const finish = (extra: Partial<ScanReport> & Pick<ScanReport, "ownership">, ctx: Ctx | null): ScanResult => {
    // Every check appears exactly once, in order of first appearance; unselected ones as skipped.
    const seen = new Set<string>();
    const kept: Finding[] = [];
    for (const f of findings) {
      if (seen.has(f.checkId)) continue;
      seen.add(f.checkId);
      // An unselected refresh token step whose request was shared with a selected one says so itself.
      kept.push(wanted(f.checkId) || f.reason === "not_selected" ? f : makeFinding(f.checkId, target, "skipped", "Not selected (--only/--skip): not run.", [], "not_selected"));
    }
    if (options.select || extra.reachable === false || !complete) {
      for (const def of CATALOGUE) {
        if (seen.has(def.id)) continue;
        kept.push(
          !wanted(def.id)
            ? makeFinding(def.id, target, "skipped", "Not selected (--only/--skip): not run.", [], "not_selected")
            : extra.reachable === false
              ? makeFinding(def.id, target, "skipped", "Target unreachable: not run.", [], "unreachable")
              : makeFinding(def.id, target, "error", `Not run: ${http.interrupted ?? "the scan was interrupted"}.`, [], "interrupted"),
        );
      }
    }
    const finishedAt = now();
    for (const f of kept) {
      f.source ??= "scan";
      f.observedAt ??= finishedAt;
    }
    const grantReport: GrantReport | undefined = options.grant
      ? {
          used: ctx?.grant.used ?? false,
          rotated: ctx?.grant.rotated ?? false,
          consumed: ctx?.grant.state === "revoked",
          state: ctx?.grant.used ? (ctx.grant.state as GrantReport["state"]) : "unused",
          rewritten: false,
        }
      : undefined;
    const report: ScanReport = {
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      startedAt,
      finishedAt,
      target,
      reachable: extra.reachable ?? true,
      complete,
      ownership: extra.ownership,
      findings: kept,
      summary: summarize(kept),
      discovery: summarizeDiscovery(ctx?.discovery ?? null, ctx?.eraKnown ? ctx.era : null),
      ...(options.credential ? { credential: { kind: options.credential.kind, header: options.credential.header } } : {}),
      ...(grantReport ? { grant: grantReport } : {}),
      client: {
        source: options.client
          ? /^https:\/\/[^/]+\/.+/.test(options.client.clientId)
            ? "metadata-document"
            : "pre-registered"
          : typeof ctx?.discovery?.as?.metadata.registration_endpoint === "string"
            ? "dynamic-registration"
            : "none",
      },
      leftovers: ctx?.leftovers ?? [],
      ...(options.preset ? { preset: options.preset } : {}),
    };
    emit({ type: "scan_finished", complete, at: finishedAt });
    return { report, grant: { latest: ctx?.grant.used ? ctx.grant.latest : (options.grant ?? null), state: ctx?.grant.used ? ctx.grant.state : "unused" } };
  };

  /**
   * Run one check, or a group of checks that share requests. Unselected IDs
   * are left out; an interruption or a failed request makes the selected
   * ones inconclusive without stopping the scan.
   */
  const stage = async (ids: readonly string[], run: (selected: string[]) => Promise<Finding[] | Finding>): Promise<void> => {
    const selected = ids.filter(wanted);
    if (selected.length === 0) return;
    if (http.interrupted) {
      complete = false;
      return; // listed as "not run" by finish()
    }
    const t0 = Date.now();
    for (const id of selected) emit({ type: "check_started", checkId: id, at: now() });
    let out: Finding[];
    try {
      const r = await run(selected);
      out = Array.isArray(r) ? r : [r];
    } catch (e) {
      const interrupted = e instanceof ScanInterruptedError;
      if (interrupted) complete = false;
      out = selected.map((id) => makeFinding(id, target, "error", interrupted ? `Interrupted: ${(e as Error).message}.` : `Request failed: ${(e as Error).message}`, [], interrupted ? "interrupted" : "unreachable"));
    }
    const durationMs = Date.now() - t0;
    for (const f of out) {
      f.durationMs ??= durationMs;
      findings.push(f);
      if (selected.includes(f.checkId)) emit({ type: "check_finished", checkId: f.checkId, status: f.status, ...(f.reason ? { reason: f.reason } : {}), durationMs, at: now() });
    }
  };

  try {
    let discovery: DiscoveryResult | null = null;
    try {
      discovery = await discover(target, http, { ...(options.protocol ? { protocol: options.protocol } : {}), ...(options.issuer !== undefined ? { issuer: options.issuer } : {}) });
      findings.push(dsc01(discovery, options.credential?.kind === "static"));
    } catch (err) {
      // No HTTP answer at all (or a request the address policy refuses): nothing can be tested.
      // One finding says so; a scan that could not run is never reported like a clean one.
      if (err instanceof NetworkError || err instanceof BlockedAddressError || err instanceof InsecureTransportError || err instanceof ScanInterruptedError) {
        const why = err instanceof NetworkError ? `Target unreachable: ${err.message}.` : err instanceof ScanInterruptedError ? `Interrupted: ${err.message}.` : err.message;
        findings.push(makeFinding("MAP-DSC01", target, "error", `${why} No check was run.`, [], err instanceof ScanInterruptedError ? "interrupted" : "unreachable"));
        emit({ type: "discovery_finished", reachable: false, at: now() });
        if (err instanceof ScanInterruptedError) complete = false;
        return finish({ reachable: false, ownership: { verified: false, method: null, detail: "Not checked: the target is unreachable.", hosts: [] } }, null);
      }
      findings.push(makeFinding("MAP-DSC01", target, "error", `Discovery failed: ${(err as Error).message}`, [], "unexpected_answer"));
    }
    emit({ type: "discovery_finished", reachable: true, at: now() });

    // Every host an active check would touch must be proven.
    const verifyOpts: VerifyOptions = { http, loopbackExempt: options.loopbackExempt ?? true };
    if (options.resolveTxtRecords) verifyOpts.resolveTxtRecords = options.resolveTxtRecords;
    const results: OwnershipResult[] = [];
    try {
      const contacted = [target, discovery?.as?.metadata.authorization_endpoint, discovery?.as?.metadata.token_endpoint, discovery?.as?.metadata.registration_endpoint].filter((u): u is string => typeof u === "string");
      for (const host of hostsToVerify(target, discovery)) {
        const perHost = { ...verifyOpts };
        if (options.exemptOrigins) {
          const origins = contacted.flatMap((u) => {
            try {
              const parsed = new URL(u);
              return parsed.hostname === host ? [parsed.origin] : [];
            } catch {
              return [];
            }
          });
          perHost.loopbackExempt = origins.length > 0 && origins.every((o) => (options.exemptOrigins as readonly string[]).includes(o));
        }
        if (options.wellKnownBaseUrl && host === new URL(target).hostname) perHost.wellKnownBaseUrl = options.wellKnownBaseUrl;
        results.push(await verifyOwnership(host, options.secret, perHost));
      }
    } catch (e) {
      if (!(e instanceof ScanInterruptedError)) throw e;
      complete = false;
    }
    const verified = complete && results.length > 0 && results.every((r) => r.verified);
    const ownership: ScanReport["ownership"] = {
      verified,
      method: verified ? [...new Set(results.map((r) => r.method))].join("+") : null,
      detail: results.map((r) => `${r.host}: ${r.detail}`).join(" "),
      hosts: results.map((r) => ({ host: r.host, verified: r.verified, method: r.method, detail: r.detail })),
    };
    // The proof is judged host by host: a check runs when the hosts it sends requests to are proven.
    const provenHosts = new Set(results.filter((r) => r.verified).map((r) => r.host));
    const hostOf = (u: unknown): string | null => {
      try {
        return typeof u === "string" ? normalizeHost(new URL(u).hostname) : null;
      } catch {
        return null;
      }
    };
    const mcpProven = complete && provenHosts.has(hostOf(target) ?? "");
    const asEndpoints = [discovery?.as?.metadata.authorization_endpoint, discovery?.as?.metadata.token_endpoint, discovery?.as?.metadata.registration_endpoint];
    const unprovenAsHosts = [...new Set(asEndpoints.map(hostOf).filter((h): h is string => h !== null && !provenHosts.has(h)))];
    const asProven = mcpProven && unprovenAsHosts.length === 0;

    const ctx: Ctx = {
      target,
      http,
      options,
      discovery,
      observations: options.observations ?? [],
      loginPossible: typeof discovery?.as?.metadata.registration_endpoint === "string" || !discovery?.as || options.client !== undefined,
      leftovers: [],
      grant: { latest: options.grant ?? null, state: "unused", used: false, rotated: false },
      era: options.protocol ?? (discovery?.protocol?.era === "legacy" ? "legacy" : "modern"),
      eraKnown: options.protocol !== undefined || (discovery?.protocol !== undefined && discovery.protocol.era !== "unknown"),
    };
    const credential = options.credential;

    // With a credential and ownership proven, the MCP endpoint checks run with it.
    const handled = new Set<string>();
    if (credential && mcpProven) {
      // MAP-THR02 may get the credential limited for a while: with an OAuth token it only runs on request.
      const ids = ENDPOINT_IDS.filter((id) => id !== "MAP-THR02" || credential.kind === "static" || options.rateLimitWithToken === true);
      await stage(ids, async (selected) => {
        const ep = await runEndpointChecks(http, target, credential, {
          checks: selected as EndpointCheckId[],
          ...(options.rateAttempts !== undefined ? { rateAttempts: options.rateAttempts } : {}),
          ...(options.waitOnRateLimitMs !== undefined ? { waitOnRateLimitMs: options.waitOnRateLimitMs } : {}),
          // An anonymous answer may not show the era (401 comes first): then the checks detect it with the credential.
          ...(ctx.eraKnown ? { era: ctx.era } : {}),
        });
        if (ep.era) {
          ctx.era = ep.era;
          ctx.eraKnown = true;
        }
        if (ep.supportedVersions && discovery?.protocol) discovery.protocol.supportedVersions = ep.supportedVersions;
        return ep.findings;
      });
      for (const id of ids.filter(wanted)) handled.add(id);
    }
    if (!handled.has("MAP-ORG01")) await stage(["MAP-ORG01"], () => runOriginCheck(ctx));
    await stage(["MAP-COR01"], () => runCorsCheck(target, http, ctx.era));

    const active = CATALOGUE.filter((c) => c.active);
    if (!mcpProven) {
      for (const def of active) {
        findings.push(makeFinding(def.id, target, "skipped", `Ownership of ${hostOf(target) ?? "the target"} is not proven; active check not run.`, [], "ownership_unproven"));
      }
    } else if (credential?.kind === "static" && discovery !== null && !discovery.prm && !discovery.as && !discovery.challenge.resourceMetadataUrl) {
      // No OAuth on this server: the authorization server checks do not apply.
      for (const def of active.filter((c) => !handled.has(c.id) && !(ENDPOINT_IDS as readonly string[]).includes(c.id))) {
        findings.push(makeFinding(def.id, target, "not_applicable", "The server does not use OAuth (static key declared, no authorization server discovered)."));
      }
    } else {
      // MAP-AUD01 can be judged in the scan itself given an access token (the control) and a grant.
      const tokenEndpoint = discovery?.as?.metadata.token_endpoint;
      const usable = typeof tokenEndpoint === "string" ? grantFor(target, tokenEndpoint, options).grant : null;
      // Checks that send requests to the authorization server need its host proven too; the others do not.
      const AS_IDS = [...RTK_IDS, ...RDR_IDS, "MAP-THR01"];
      if (!asProven) {
        for (const id of AS_IDS) {
          findings.push(makeFinding(id, target, "skipped", `Ownership of ${unprovenAsHosts.join(", ")} (the authorization server) is not proven: this check sends requests there and was not run. The checks of the MCP endpoint do not need that proof.`, [], "ownership_unproven"));
        }
      }
      if (asProven && credential?.kind === "oauth" && usable && typeof tokenEndpoint === "string") {
        await stage(["MAP-AUD01"], () => runAudienceDuringScan(ctx, credential, tokenEndpoint, usable));
        if (wanted("MAP-AUD01")) handled.add("MAP-AUD01");
      }
      // The refresh token checks are one sequence: only the steps the selected ones need are sent.
      if (asProven) await stage(RTK_IDS, () => runRefreshFamily(ctx));
      if (asProven) await stage(RDR_IDS, () => runRedirectFamily(ctx, wanted));
      for (const id of LOGIN_ONLY_IDS) {
        if (!handled.has(id)) findings.push(fromObservation(ctx, id));
      }
      if (!handled.has("MAP-INJ01")) await stage(["MAP-INJ01"], () => metadataWithoutCredential(ctx));
      findings.push(makeFinding("MAP-CSR01", target, "skipped", "Needs a logged-in browser session: run `mcp-authprobe consent-check` separately.", [], "needs_browser"));
      // Last on purpose: once throttled, the token endpoint may refuse other checks.
      if (asProven) await stage(["MAP-THR01"], () => runThrottleFamily(ctx));
      if (!handled.has("MAP-THR02")) {
        findings.push(
          credential?.kind === "oauth"
            ? makeFinding("MAP-THR02", target, "skipped", "Not run with an access token unless asked for, since it may get the token rate limited: select it explicitly with --only THR02 (or pass a static key with --bearer-file).", [], "not_selected")
            : makeFinding("MAP-THR02", target, "skipped", "Needs a static key: pass it with --bearer-file.", [], "needs_static_key"),
        );
      }
      for (const def of active.filter((c) => c.availability === "planned")) {
        findings.push(makeFinding(def.id, target, "skipped", "Not implemented in this version yet."));
      }
    }
    if (http.interrupted) complete = false;
    // Context for a failing MAP-ORG01 on a public server: the requirement is about DNS rebinding and browsers.
    const org = findings.find((f) => f.checkId === "MAP-ORG01" && f.status === "fail");
    const cors = findings.find((f) => f.checkId === "MAP-COR01");
    if (org && credential && new URL(target).protocol === "https:" && cors?.status === "pass") {
      org.evidence.push(
        "context: this endpoint is reached over https and authenticated by a header that a browser never adds by itself, and MAP-COR01 found no credentialed CORS access: a web page cannot use a visitor's rights here. The specification still requires 403 for an invalid Origin; the risk is highest for servers on a local network or using cookies.",
      );
    }
    return finish({ ownership }, ctx);
  } finally {
    if (timer) clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
    await http.close();
  }
}

export async function scan(mcpUrl: string, options: ScanOptions = {}): Promise<ScanReport> {
  return (await runScan(mcpUrl, options)).report;
}
