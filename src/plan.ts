import { CATALOGUE } from "./checks/catalogue.js";
import type { Observation } from "./credentials.js";
import { discover } from "./discovery.js";
import { HttpClient } from "./net/http.js";
import { normalizeHost, verifyOwnership } from "./ownership.js";
import { grantFor, hostsToVerify, summarizeDiscovery, type ScanOptions } from "./scan.js";
import type { DiscoverySummary, HostOwnership, ReasonCode } from "./types.js";

/**
 * `mcp-authprobe plan`: what a scan with these options would do, without
 * doing it. Only discovery and the ownership lookups are sent (the read-only
 * requests of any scan); no active request, no token, no client.
 */

export interface PlanEntry {
  checkId: string;
  title: string;
  active: boolean;
  /** Whether the scan would send this check's requests. */
  runs: boolean;
  /** When it would not: why, as the reason code the scan would report, and in words. */
  reason?: ReasonCode;
  explanation: string;
  /** Upper bound of the requests it sends, and what they do on the server. */
  requests: string;
  effects: string;
}

export interface ScanPlan {
  target: string;
  reachable: boolean;
  ownership: HostOwnership[];
  discovery: DiscoverySummary;
  entries: PlanEntry[];
}

const COST: Record<string, [string, string]> = {
  "MAP-DSC01": ["up to 7", "none: the requests any client sends before logging in"],
  "MAP-ORG01": ["2 without a credential, 6 with one", "none"],
  "MAP-COR01": ["2", "none"],
  "MAP-RTK01": ["1 token request", "rotates the test grant's refresh token"],
  "MAP-RTK02": ["1 more token request", "replays a used refresh token: a compliant server revokes the grant"],
  "MAP-RTK03": ["1 more token request", "ends the test grant on a compliant server"],
  "MAP-RDR01": ["2 authorization requests (and 1 registration without --client-id)", "a temporary client, deleted afterwards, unless one is supplied"],
  "MAP-RDR02": ["8 authorization requests", "none beyond the client of MAP-RDR01"],
  "MAP-RDR04": ["4 registrations", "temporary clients if the server accepts them, deleted afterwards"],
  "MAP-THR01": ["5 to 20 failed token requests", "may get the test client throttled for a while"],
  "MAP-TOK01": ["5", "none"],
  "MAP-SES01": ["3, plus a DELETE", "opens and ends one session (MCP 2025-11-25 only)"],
  "MAP-BAT01": ["3", "none: harmless requests only"],
  "MAP-BOD01": ["4, two of them 6 MiB", "12 MiB of upload"],
  "MAP-INJ01": ["up to 42 (lists are paged)", "none: only list methods, nothing is called"],
  "MAP-THR02": ["10 to 100 in a row", "may get the credential rate limited for a while"],
};

export async function planScan(mcpUrl: string, options: ScanOptions = {}): Promise<ScanPlan> {
  const target = new URL(mcpUrl).toString();
  const http = new HttpClient({
    allowPrivate: options.allowPrivate ?? false,
    privateHosts: [new URL(target).hostname, ...(options.allowHosts ?? [])],
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.extraHeaders ? { extraHeaders: { origin: new URL(target).origin, headers: options.extraHeaders } } : {}),
  });
  const wanted = options.select ?? (() => true);
  const entry = (checkId: string, runs: boolean, explanation: string, reason?: ReasonCode): PlanEntry => {
    const def = CATALOGUE.find((c) => c.id === checkId);
    if (!def) throw new Error(`Unknown check ${checkId}`);
    const [requests, effects] = COST[checkId] ?? ["none", "none"];
    return { checkId, title: def.title, active: def.active, runs, explanation, requests: runs ? requests : "none", effects: runs ? effects : "none", ...(reason ? { reason } : {}) };
  };
  try {
    let discovery;
    try {
      discovery = await discover(target, http, { ...(options.protocol ? { protocol: options.protocol } : {}), ...(options.issuer !== undefined ? { issuer: options.issuer } : {}) });
    } catch (e) {
      return {
        target,
        reachable: false,
        ownership: [],
        discovery: summarizeDiscovery(null),
        entries: CATALOGUE.map((c) => entry(c.id, false, `The target is unreachable (${(e as Error).message}): nothing would run.`, "unreachable")),
      };
    }
    const ownership: HostOwnership[] = [];
    for (const host of hostsToVerify(target, discovery)) {
      const r = await verifyOwnership(host, options.secret, { http, loopbackExempt: options.loopbackExempt ?? true, ...(options.resolveTxtRecords ? { resolveTxtRecords: options.resolveTxtRecords } : {}) });
      ownership.push({ host: r.host, verified: r.verified, method: r.method, detail: r.detail });
    }
    const proven = new Set(ownership.filter((o) => o.verified).map((o) => o.host));
    const hostOf = (u: unknown): string | null => {
      try {
        return typeof u === "string" ? normalizeHost(new URL(u).hostname) : null;
      } catch {
        return null;
      }
    };
    const meta = discovery.as?.metadata;
    const mcpHost = hostOf(target) ?? "";
    const mcpProven = proven.has(mcpHost);
    const unprovenAs = [...new Set([meta?.authorization_endpoint, meta?.token_endpoint, meta?.registration_endpoint].map(hostOf).filter((h): h is string => h !== null && !proven.has(h)))];
    const asProven = mcpProven && unprovenAs.length === 0;
    const cred = options.credential;
    const noOAuth = cred?.kind === "static" && !discovery.prm && !discovery.as && !discovery.challenge.resourceMetadataUrl;
    const dcr = typeof meta?.registration_endpoint === "string";
    const tokenEndpoint = typeof meta?.token_endpoint === "string" ? meta.token_endpoint : null;
    const grant = tokenEndpoint ? grantFor(target, tokenEndpoint, options) : { grant: null, reason: "No token endpoint discovered." };
    const observed = (id: string): Observation | undefined => (options.observations ?? []).filter((o) => o.checkId === id && o.target === target).at(-1);
    const maxAge = options.maxObservationAgeMs ?? 24 * 60 * 60 * 1000;
    const fromLogin = (id: string): PlanEntry => {
      const o = observed(id);
      if (!o) return entry(id, false, options.client || dcr ? "Observed during login: run `mcp-authprobe login`, then scan with the grant file." : "Observed during login, which needs a client here: pass --client-id to `mcp-authprobe login`.", "needs_login");
      if (maxAge > 0 && Date.now() - Date.parse(o.observedAt) > maxAge) return entry(id, false, `The result observed during login at ${o.observedAt} is too old to be reported.`, "stale_observation");
      return entry(id, false, `Reported from the login of ${o.observedAt} (${o.status}); the scan sends nothing for it.`);
    };
    const unproven = (id: string, host: string): PlanEntry => entry(id, false, `Ownership of ${host} is not proven: publish the proof first (\`mcp-authprobe ownership proof ${host}\`).`, "ownership_unproven");
    const endpointIds = ["MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"];

    const entries = CATALOGUE.map((c): PlanEntry => {
      const id = c.id;
      if (!wanted(id)) return entry(id, false, "Not selected (--only, --skip, --rtk or --preset).", "not_selected");
      if (id === "MAP-DSC01") return entry(id, true, "Runs in every scan.");
      if (id === "MAP-COR01") return entry(id, true, "Runs in every scan, without a credential.");
      if (id === "MAP-ORG01") return entry(id, true, cred && mcpProven ? "Runs with the credential." : observed(id) ? "Reported from the login results." : "Runs without a credential; inconclusive when the server asks for one first.");
      if (!mcpProven) return unproven(id, mcpHost);
      if (endpointIds.includes(id)) {
        if (cred) return entry(id, true, `Runs with the ${cred.kind === "static" ? "static key" : "access token"}.`);
        if (id === "MAP-INJ01" && !observed(id)) return entry(id, discovery.challenge.status >= 200 && discovery.challenge.status < 300, discovery.challenge.status >= 200 && discovery.challenge.status < 300 ? "The server answers without a credential: its metadata is read anonymously." : "Needs a credential: --bearer-file, --access-token-file, or a login.", "needs_credential");
        return fromLogin(id);
      }
      if (id === "MAP-THR02") {
        if (cred?.kind === "static") return entry(id, true, "Runs with the static key, last.");
        if (cred?.kind === "oauth") return options.rateLimitWithToken ? entry(id, true, "Runs with the access token, as asked.") : entry(id, false, "With an access token it only runs when named: --only THR02.", "not_selected");
        return entry(id, false, "Needs a static key (--bearer-file).", "needs_static_key");
      }
      if (noOAuth) return entry(id, false, "Not applicable: the server uses a static key and publishes no OAuth metadata.");
      if (id === "MAP-CSR01") return entry(id, false, "Needs a browser session: run `mcp-authprobe consent-check`.", "needs_browser");
      if (id === "MAP-AUD01") {
        if (cred?.kind === "oauth" && grant.grant && asProven) return entry(id, true, "Runs in the scan: the access token is the control, one refresh asks for a token for another resource.");
        return fromLogin(id);
      }
      if (["MAP-PKC01", "MAP-RDR03", "MAP-COD01"].includes(id)) return fromLogin(id);
      if (!asProven) return unproven(id, unprovenAs.join(", "));
      if (id.startsWith("MAP-RTK")) return grant.grant ? entry(id, true, "Runs with the test grant.") : entry(id, false, grant.reason ?? "Needs a test grant.", tokenEndpoint ? "needs_grant" : "no_endpoint");
      if (id === "MAP-RDR01" || id === "MAP-RDR02") {
        if (options.client) return options.client.redirectUri ? entry(id, true, "Runs with the supplied client; nothing is registered.") : entry(id, false, "The supplied client needs --redirect-uri.", "no_client");
        return dcr ? entry(id, true, "Runs with a temporary client from dynamic registration.") : entry(id, false, "The server offers no dynamic registration: pass --client-id and --redirect-uri.", "no_client");
      }
      if (id === "MAP-RDR04") return dcr ? entry(id, true, "Runs against the registration endpoint.") : entry(id, false, "Not applicable: the server offers no dynamic registration.");
      if (id === "MAP-THR01") {
        if (!tokenEndpoint) return entry(id, false, "No token endpoint discovered.", "no_endpoint");
        return grant.grant || options.client || dcr ? entry(id, true, "Runs last, with the test client.") : entry(id, false, "Needs a client: --client-id, or a test grant.", "no_client");
      }
      return entry(id, false, "Not run by a scan.");
    });
    return { target, reachable: true, ownership, discovery: summarizeDiscovery(discovery), entries };
  } finally {
    await http.close();
  }
}

/** The plan as text, for the terminal. */
export function planToText(plan: ScanPlan): string {
  const lines = [plan.target];
  if (!plan.reachable) lines.push("  The target is unreachable: nothing would run.");
  for (const o of plan.ownership) lines.push(`  ownership of ${o.host}: ${o.verified ? `proven (${o.method})` : "NOT proven"}`);
  const p = plan.discovery.protocol;
  if (plan.reachable) lines.push(`  MCP revision: ${p.era === "unknown" ? "not known yet (the server asks for a credential first)" : `${p.version} (${p.era})`}; client registration offered: ${plan.discovery.registration.join(", ") || "none"}`);
  lines.push("");
  for (const e of plan.entries) {
    lines.push(`  ${e.runs ? "runs  " : "no    "} ${e.checkId.padEnd(10)} ${e.explanation}`);
    if (e.runs) lines.push(`             requests: ${e.requests}; effect: ${e.effects}`);
  }
  const n = plan.entries.filter((e) => e.runs).length;
  lines.push("", `  ${n} of ${plan.entries.length} checks would send requests. Nothing was sent beyond discovery and the ownership lookups.`);
  return `${lines.join("\n")}\n`;
}
