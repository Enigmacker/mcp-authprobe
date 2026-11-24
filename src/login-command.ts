import { existsSync } from "node:fs";
import { LOGIN_CHECK_IDS } from "./checks/catalogue.js";
import { loadGrant, writeGrantFile, type Observation } from "./credentials.js";
import { discover } from "./discovery.js";
import { login, LoginError, openInBrowser } from "./login.js";
import { summarize } from "./checks/finding.js";
import { EXIT } from "./exit.js";
import { BlockedAddressError, HttpClient, InsecureTransportError, NetworkError } from "./net/http.js";
import { toJson } from "./report/json.js";
import type { ScanReport } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";
import { writeFileSync } from "node:fs";
import { verifyOwnership } from "./ownership.js";
import { safeText } from "./redact.js";
import { hostsToVerify } from "./scan.js";

export interface LoginCommandOptions {
  mcpUrl: string;
  out: string;
  force: boolean;
  probe: boolean;
  browser: boolean;
  allowPrivate: boolean;
  secret: string | undefined;
  /** Replaces the browser (tests). */
  openUrl?: (url: string) => Promise<void>;
  timeoutMs?: number;
  /** Per-request timeout in milliseconds (--timeout). */
  requestTimeoutMs?: number;
  /** Write the results as a report, without any token (--json). */
  json?: string;
}

// Everything printed here may contain server-controlled text: neutralize it.
const err = (t: string): void => {
  process.stderr.write(`${safeText(t, 4000)}\n`);
};

/** `mcp-authprobe login`: everything goes to stderr; tokens are only written to the grant file. */
export async function runLoginCommand(o: LoginCommandOptions): Promise<number> {
  const startedAt = new Date().toISOString();
  const http = new HttpClient({ allowPrivate: o.allowPrivate, ...(o.requestTimeoutMs !== undefined ? { timeoutMs: o.requestTimeoutMs } : {}) });
  try {
    const discovery = await discover(o.mcpUrl, http);
    let probe = false;
    if (o.probe) {
      const results = [];
      for (const host of hostsToVerify(o.mcpUrl, discovery)) results.push(await verifyOwnership(host, o.secret, { http }));
      probe = results.every((r) => r.verified);
      if (!probe) err(`Ownership not proven for every host: the login checks (${LOGIN_CHECK_IDS.join(", ")}) will not be observed.`);
    }

    const result = await login({
      http,
      mcpUrl: o.mcpUrl,
      discovery,
      probe,
      log: err,
      ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      openUrl:
        o.openUrl ??
        (async (url) => {
          err(`\nAuthorization URL (open it if no browser appears):\n${url}\n`);
          if (o.browser) await openInBrowser(url);
        }),
    });

    for (const ob of result.observations) err(`${ob.checkId}: ${ob.status} - ${ob.message}`);
    for (const n of result.notes) err(`Note: ${n}`);

    // Overwriting a file of the same target: keep the results this login did not observe
    // (after a strict server forced a second login with --no-probe).
    let observations: Observation[] = result.observations;
    if (o.force && existsSync(o.out)) {
      try {
        const target = new URL(o.mcpUrl).toString();
        const fresh = new Set(observations.map((x) => x.checkId));
        const kept = loadGrant(o.out).observations.filter((x) => x.target === target && !fresh.has(x.checkId));
        if (kept.length > 0) err(`Keeping earlier results from ${o.out}: ${kept.map((x) => x.checkId).join(", ")}.`);
        observations = [...kept, ...observations];
      } catch {
        /* unreadable or not ours: replaced */
      }
    }
    if (o.json) {
      // The results alone, in the report format: nothing here is secret, unlike the grant file.
      const report: ScanReport = {
        tool: { name: TOOL_NAME, version: TOOL_VERSION },
        startedAt,
        finishedAt: new Date().toISOString(),
        target: new URL(o.mcpUrl).toString(),
        reachable: true,
        ownership: { verified: probe, method: null, detail: probe ? "Ownership proven: the login checks were observed." : "Ownership not proven, or --no-probe: the login checks were not observed." },
        findings: result.observations,
        summary: summarize(result.observations),
      };
      try {
        writeFileSync(o.json, toJson(report));
      } catch (e) {
        err(`Could not write ${o.json}: ${(e as Error).message}`);
      }
    }
    if (!result.grant && observations.length === 0) return EXIT.error;

    try {
      writeGrantFile(o.out, result.grant, observations, o.force);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      err(code === "EEXIST" ? `${o.out} already exists; use --force to overwrite it.` : `Could not write ${o.out}: ${(e as Error).message}`);
      return EXIT.usage;
    }
    if (!result.grant) {
      err(`Results written to ${o.out} (no test grant). Run login again with --no-probe --force --out ${o.out}: these results are kept.`);
      return EXIT.noGrant;
    }
    err(`Test grant written to ${o.out} (mode 600). It is consumed by the refresh token checks: scan with --credentials-file ${o.out}.`);
    return EXIT.ok;
  } catch (e) {
    err(e instanceof LoginError ? `Login failed: ${e.message}` : `Login failed: ${(e as Error).message}`);
    return e instanceof NetworkError || e instanceof BlockedAddressError || e instanceof InsecureTransportError ? EXIT.unreachable : EXIT.error;
  } finally {
    await http.close();
  }
}
