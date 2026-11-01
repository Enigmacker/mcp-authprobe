import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { runConsentCheck } from "./consent/analyze.js";
import { BrowserUnavailableError, CaptureAbortedError, captureConsentSnapshot } from "./consent/browser.js";
import { CATALOGUE } from "./checks/catalogue.js";
import { discover } from "./discovery.js";
import { HttpClient } from "./net/http.js";
import { deleteClient, registerClient, type RegisteredClient } from "./oauth/registration.js";
import { verifyOwnership } from "./ownership.js";
import { safeText } from "./redact.js";
import { toJson } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import { toSarif } from "./report/sarif.js";
import { toTable } from "./report/table.js";
import { hostsToVerify } from "./scan.js";
import { severityAtLeast, type Finding, type ScanReport, type Severity } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

export interface ConsentCommandOptions {
  mcpUrl: string;
  allowPrivate: boolean;
  secret: string | undefined;
  browser?: string;
  browserPath?: string;
  failOn: Severity;
  json?: string;
  sarif?: string;
  markdown?: string;
}

const err = (t: string): void => {
  process.stderr.write(`${safeText(t, 4000)}\n`);
};

/**
 * Wait for Enter. Rejects (and releases stdin, so the process can exit) when
 * the signal aborts, on Ctrl-C at the prompt, or when stdin closes.
 */
export function waitForEnter(
  prompt: string,
  signal: AbortSignal,
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input, output });
    let done = false;
    const finish = (error?: Error): void => {
      if (done) return;
      done = true;
      signal.removeEventListener("abort", onAbort);
      rl.close();
      if (error) reject(error);
      else resolve();
    };
    const onAbort = (): void => finish(signal.reason instanceof Error ? signal.reason : new Error("Aborted."));
    signal.addEventListener("abort", onAbort, { once: true });
    rl.on("SIGINT", () => finish(new CaptureAbortedError("Interrupted.")));
    rl.on("close", () => finish(new CaptureAbortedError("Input closed before the consent page was confirmed.")));
    rl.question(prompt, () => finish());
  });
}

/** `mcp-authprobe consent-check`: MAP-CSR01 with a real browser session. Returns an exit code. */
export async function runConsentCommand(o: ConsentCommandOptions): Promise<number> {
  const http = new HttpClient({ allowPrivate: o.allowPrivate });
  const startedAt = new Date().toISOString();
  const target = new URL(o.mcpUrl).toString();
  let client: RegisteredClient | null = null;
  let registrationEndpoint: string | null = null;
  let sink: Server | null = null;
  try {
    const d = await discover(target, http);
    const meta = d.as?.metadata;
    if (typeof meta?.authorization_endpoint !== "string") {
      err("No authorization endpoint discovered; nothing to check.");
      return 3;
    }
    registrationEndpoint = typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null;
    if (!registrationEndpoint) {
      err("The consent check needs dynamic client registration to create a test client.");
      return 3;
    }

    // Ownership gate: every host the check contacts must be proven.
    const hosts = hostsToVerify(target, d);
    const results = [];
    for (const h of hosts) results.push(await verifyOwnership(h, o.secret, { http }));
    const unproven = results.filter((r) => !r.verified);
    if (unproven.length > 0) {
      for (const r of unproven) err(`Not verified: ${r.host}: ${r.detail}`);
      err("The consent check is active: it only runs when ownership of every contacted host is proven.");
      return 1;
    }

    // Ctrl-C anywhere during the capture aborts it; cleanup below still runs.
    const interrupt = new AbortController();
    const onSigint = (): void => interrupt.abort(new CaptureAbortedError("Interrupted."));
    process.once("SIGINT", onSigint);

    let capture;
    try {
      const captureOpts: Parameters<typeof captureConsentSnapshot>[0] = {
        signal: interrupt.signal,
        // Runs once the browser is up: nothing is registered if it cannot start.
        prepare: async () => {
          // Own the loopback redirect URI, so a code (if consent is given by
          // mistake) is never received by another local process. It is discarded.
          sink = createServer((_req, res) => {
            res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
            res.end("mcp-authprobe: received and discarded. The consent check needs the consent page itself; you can close this tab.");
          });
          await new Promise<void>((resolve) => (sink as Server).listen(0, "127.0.0.1", resolve));
          const redirectUri = `http://127.0.0.1:${((sink as Server).address() as AddressInfo).port}/callback`;
          const reg = await registerClient(http, registrationEndpoint as string, [redirectUri], { clientName: "mcp-authprobe consent check (safe to delete)" });
          if (!reg.client) throw new Error(`Dynamic client registration failed (HTTP ${reg.status}).`);
          client = reg.client;

          const auth = new URL(meta.authorization_endpoint as string);
          auth.searchParams.set("response_type", "code");
          auth.searchParams.set("client_id", client.clientId);
          auth.searchParams.set("redirect_uri", redirectUri);
          auth.searchParams.set("state", randomBytes(16).toString("base64url"));
          auth.searchParams.set("code_challenge", createHash("sha256").update(randomBytes(32).toString("base64url")).digest("base64url"));
          auth.searchParams.set("code_challenge_method", "S256");
          auth.searchParams.set("resource", d.prm?.metadata.resource ?? target);
          const scopes = d.prm?.metadata.scopes_supported;
          if (Array.isArray(scopes) && scopes.length > 0) auth.searchParams.set("scope", scopes.join(" "));

          err("A browser window opens on your authorization server.");
          err("1. Log in with your dedicated TEST account.");
          err('2. When the consent page ("Allow ...?") is displayed, do NOT click anything.');
          return { authorizationUrl: auth.toString(), redirectUri };
        },
        waitForConsentPage: (_page, signal) => waitForEnter("3. Come back here and press Enter. ", signal),
      };
      if (o.browser) captureOpts.channel = o.browser;
      if (o.browserPath) captureOpts.executablePath = o.browserPath;
      capture = await captureConsentSnapshot(captureOpts);
    } finally {
      process.removeListener("SIGINT", onSigint);
    }

    let finding: Finding;
    const def = CATALOGUE.find((c) => c.id === "MAP-CSR01");
    if (!def) throw new Error("MAP-CSR01 missing from catalogue");
    if (capture.kind === "redirected") {
      finding = {
        checkId: def.id,
        title: def.title,
        severity: def.severity,
        status: "error",
        target,
        message: "The browser was sent back to the client before the consent page was captured: either the server granted access without asking for consent, or Allow was clicked. Run again and stop on the consent page.",
        evidence: [],
      };
    } else {
      finding = await runConsentCheck(http, target, capture.snapshot, hosts);
    }

    const report: ScanReport = {
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      startedAt,
      finishedAt: new Date().toISOString(),
      target,
      ownership: { verified: true, method: [...new Set(results.map((r) => r.method))].join("+"), detail: results.map((r) => `${r.host}: ${r.detail}`).join(" ") },
      findings: [finding],
    };
    process.stdout.write(toTable(report));
    if (o.json) writeFileSync(o.json, toJson(report));
    if (o.sarif) writeFileSync(o.sarif, toSarif(report));
    if (o.markdown) writeFileSync(o.markdown, toMarkdown(report));
    if (finding.status === "fail" && severityAtLeast(finding.severity, o.failOn)) return 1;
    return finding.status === "error" ? 3 : 0;
  } catch (e) {
    err(e instanceof BrowserUnavailableError || e instanceof CaptureAbortedError ? e.message : `Consent check failed: ${(e as Error).message}`);
    return e instanceof BrowserUnavailableError ? 2 : 3;
  } finally {
    if (client && registrationEndpoint) await deleteClient(http, client, registrationEndpoint);
    if (sink) {
      sink.closeAllConnections();
      await new Promise<void>((resolve) => (sink as Server).close(() => resolve()));
    }
    await http.close();
  }
}
