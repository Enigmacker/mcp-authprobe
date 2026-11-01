import { CATALOGUE } from "./checks/catalogue.js";
import { discover, type DiscoveryResult } from "./discovery.js";
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
    const verifyOpts: VerifyOptions = { http };
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

    for (const def of CATALOGUE.filter((c) => c.active)) {
      if (!verified) {
        findings.push(finding(def, target, "skipped", "Ownership of every contacted host is not proven; active check not run."));
      } else if (def.availability === "planned") {
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
