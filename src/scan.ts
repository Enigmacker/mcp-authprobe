import { CATALOGUE } from "./checks/catalogue.js";
import { runRedirectUriChecks } from "./checks/redirect-uris.js";
import { runRefreshTokenChecks } from "./checks/refresh-tokens.js";
import { runThrottlingCheck } from "./checks/throttling.js";
import type { Observation, TestGrant } from "./credentials.js";
import { discover, type DiscoveryResult } from "./discovery.js";
import { FOREIGN_ORIGIN, initializeStatus } from "./oauth/mcp-call.js";
import { HttpClient } from "./net/http.js";
import { verifyOwnership, type OwnershipResult, type VerifyOptions } from "./ownership.js";
import { safeText } from "./redact.js";
import type { CheckDefinition, Finding, ScanReport } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

export interface ScanOptions {
  /** Ownership secret; read from MCP_AUTHPROBE_SECRET by the CLI, never from argv. */
  secret?: string;
  allowPrivate?: boolean;
  timeoutMs?: number;
  /** Test grant for the refresh token checks. It is consumed by the scan. */
  grant?: TestGrant;
  /**
   * Refuse a grant that does not name its target (MCP mode): a hand-written,
   * unbound grant could otherwise be spent on any proven server.
   */
  requireGrantBinding?: boolean;
  /** Exempt loopback labs from the ownership proof (default true; see VerifyOptions). */
  loopbackExempt?: boolean;
  /** Failed token requests sent by MAP-THR01 (clamped to 5-20, default 10). */
  throttleAttempts?: number;
  /** Results observed during `login` (PKC01, RDR03, COD01, AUD01, ORG01), read from the grant file. */
  observations?: Observation[];
  /** Test hooks. */
  resolveTxtRecords?: VerifyOptions["resolveTxtRecords"];
  wellKnownBaseUrl?: string;
}

function finding(def: CheckDefinition, target: string, status: Finding["status"], message: string, evidence: string[] = []): Finding {
  return {
    checkId: def.id,
    title: def.title,
    severity: def.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
  };
}

function dsc01(def: CheckDefinition, d: DiscoveryResult): Finding {
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
  if (missing.length === 0) return finding(def, d.mcpUrl, "pass", "Authorization endpoints discovered.", evidence);
  return finding(def, d.mcpUrl, "fail", `Missing: ${missing.join(", ")}. Active checks cannot run.`, evidence);
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

const RTK_IDS = ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"];

async function runRefreshFamily(target: string, d: DiscoveryResult | null, http: HttpClient, options: ScanOptions): Promise<Finding[]> {
  const defs = RTK_IDS.map((id) => CATALOGUE.find((c) => c.id === id)).filter((c): c is CheckDefinition => c !== undefined);
  const all = (status: Finding["status"], message: string): Finding[] => defs.map((def) => finding(def, target, status, message));

  const tokenEndpoint = d?.as?.metadata.token_endpoint;
  if (typeof tokenEndpoint !== "string") return all("skipped", "No token endpoint discovered.");
  const grants = d?.as?.metadata.grant_types_supported;
  if (Array.isArray(grants) && !grants.includes("refresh_token")) {
    return all("not_applicable", "The authorization server does not advertise the refresh_token grant.");
  }
  const { grant, reason } = grantFor(target, tokenEndpoint, options);
  if (!grant) return all("skipped", reason ?? "No usable test grant.");
  return runRefreshTokenChecks({ http, target, tokenEndpoint, grant });
}

/**
 * Report a result observed during `login`. The observation comes from a
 * local file, so its text is neutralized again and it is only used for the
 * exact target it was observed on.
 */
function fromObservation(checkId: string, target: string, observations: Observation[]): Finding {
  const def = CATALOGUE.find((c) => c.id === checkId) as CheckDefinition;
  const obs = observations.filter((o) => o.checkId === checkId && o.target === target).at(-1);
  if (!obs) return finding(def, target, "skipped", "Observed during login: run `mcp-authprobe login` with ownership proven, then scan with the grant file it writes.");
  return finding(def, target, obs.status, obs.message, [...obs.evidence, `observed during login at ${obs.observedAt}`]);
}

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

async function runThrottleFamily(target: string, d: DiscoveryResult | null, http: HttpClient, options: ScanOptions): Promise<Finding> {
  const meta = d?.as?.metadata;
  const def = CATALOGUE.find((c) => c.id === "MAP-THR01") as CheckDefinition;
  if (typeof meta?.token_endpoint !== "string") return finding(def, target, "skipped", "No token endpoint discovered.");
  const ctx: Parameters<typeof runThrottlingCheck>[0] = {
    http,
    target,
    tokenEndpoint: meta.token_endpoint,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
  };
  const { grant } = grantFor(target, meta.token_endpoint, options);
  if (grant) ctx.grant = grant; // otherwise a temporary client is used
  if (options.throttleAttempts !== undefined) ctx.attempts = options.throttleAttempts;
  return runThrottlingCheck(ctx);
}

async function runRedirectFamily(target: string, d: DiscoveryResult | null, http: HttpClient): Promise<Finding[]> {
  const meta = d?.as?.metadata;
  if (!meta) {
    const defs = ["MAP-RDR01", "MAP-RDR02", "MAP-RDR04"].map((id) => CATALOGUE.find((c) => c.id === id)).filter((c): c is CheckDefinition => c !== undefined);
    return defs.map((def) => finding(def, target, "skipped", "No authorization server metadata discovered."));
  }
  const scopes = d?.prm?.metadata.scopes_supported;
  const ctx: Parameters<typeof runRedirectUriChecks>[0] = {
    http,
    target,
    authorizationEndpoint: typeof meta.authorization_endpoint === "string" ? meta.authorization_endpoint : null,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
    resource: d?.prm?.metadata.resource ?? target,
  };
  if (Array.isArray(scopes) && scopes.length > 0) ctx.scope = scopes.join(" ");
  return runRedirectUriChecks(ctx);
}

/**
 * MAP-ORG01. Passive: two ordinary initialize requests, one with a foreign
 * Origin. Without a token most servers answer 401 before looking at Origin;
 * `login` then observes it with a valid token.
 */
async function runOriginCheck(target: string, http: HttpClient, observations: Observation[]): Promise<Finding> {
  const def = CATALOGUE.find((c) => c.id === "MAP-ORG01") as CheckDefinition;
  if (observations.some((o) => o.checkId === def.id && o.target === target)) return fromObservation(def.id, target, observations);
  let baseline: number;
  let foreign: number;
  try {
    baseline = await initializeStatus(http, target);
    foreign = await initializeStatus(http, target, { origin: FOREIGN_ORIGIN });
  } catch (err) {
    return finding(def, target, "error", `Request failed: ${(err as Error).message}`);
  }
  const evidence = [`initialize without Origin: HTTP ${baseline}`, `initialize with Origin: ${FOREIGN_ORIGIN}: HTTP ${foreign}`];
  if (foreign === 403 && baseline !== 403) return finding(def, target, "pass", "A request from a foreign Origin is refused with 403.", evidence);
  if (baseline >= 200 && baseline < 300 && foreign === baseline) {
    return finding(def, target, "fail", "A request from a foreign Origin is processed like any other: the Origin header is not validated.", evidence);
  }
  if (baseline === 401 && foreign === 401) {
    return finding(def, target, "error", "Inconclusive: the server asks for authentication before looking at Origin. Run `mcp-authprobe login` (ownership proven) to observe it with a valid token.", evidence);
  }
  return finding(def, target, "error", "Unexpected answers; inconclusive.", evidence);
}

export async function scan(mcpUrl: string, options: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const target = new URL(mcpUrl).toString();
  const httpOptions: ConstructorParameters<typeof HttpClient>[0] = { allowPrivate: options.allowPrivate ?? false };
  if (options.timeoutMs !== undefined) httpOptions.timeoutMs = options.timeoutMs;
  const http = new HttpClient(httpOptions);
  const findings: Finding[] = [];

  try {
    let discovery: DiscoveryResult | null = null;
    const dscDef = CATALOGUE.find((c) => c.id === "MAP-DSC01");
    try {
      discovery = await discover(target, http);
      if (dscDef) findings.push(dsc01(dscDef, discovery));
    } catch (err) {
      if (dscDef) findings.push(finding(dscDef, target, "error", `Discovery failed: ${(err as Error).message}`));
    }

    // Every host an active check would touch must be proven.
    const verifyOpts: VerifyOptions = { http, loopbackExempt: options.loopbackExempt ?? true };
    if (options.resolveTxtRecords) verifyOpts.resolveTxtRecords = options.resolveTxtRecords;
    const results: OwnershipResult[] = [];
    for (const host of hostsToVerify(target, discovery)) {
      const perHost = { ...verifyOpts };
      if (options.wellKnownBaseUrl && host === new URL(target).hostname) perHost.wellKnownBaseUrl = options.wellKnownBaseUrl;
      results.push(await verifyOwnership(host, options.secret, perHost));
    }
    const verified = results.length > 0 && results.every((r) => r.verified);
    const ownership: ScanReport["ownership"] = {
      verified,
      method: verified ? [...new Set(results.map((r) => r.method))].join("+") : null,
      detail: results.map((r) => `${r.host}: ${r.detail}`).join(" "),
    };

    findings.push(await runOriginCheck(target, http, options.observations ?? []));

    const active = CATALOGUE.filter((c) => c.active);
    if (!verified) {
      for (const def of active) {
        findings.push(finding(def, target, "skipped", "Ownership of every contacted host is not proven; active check not run."));
      }
    } else {
      findings.push(...(await runRefreshFamily(target, discovery, http, options)));
      findings.push(...(await runRedirectFamily(target, discovery, http)));
      for (const id of ["MAP-RDR03", "MAP-PKC01", "MAP-COD01", "MAP-AUD01"]) {
        findings.push(fromObservation(id, target, options.observations ?? []));
      }
      const csr = CATALOGUE.find((c) => c.id === "MAP-CSR01") as CheckDefinition;
      findings.push(finding(csr, target, "skipped", "Needs a logged-in browser session: run `mcp-authprobe consent-check` separately."));
      // Last on purpose: once throttled, the token endpoint may refuse other checks.
      findings.push(await runThrottleFamily(target, discovery, http, options));
      for (const def of active.filter((c) => c.availability === "planned")) {
        findings.push(finding(def, target, "skipped", "Not implemented in this version yet."));
      }
    }

    return {
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      startedAt,
      finishedAt: new Date().toISOString(),
      target,
      ownership,
      findings,
    };
  } finally {
    await http.close();
  }
}
