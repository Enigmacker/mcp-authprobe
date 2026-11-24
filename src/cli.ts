#!/usr/bin/env node
import { accessSync, appendFileSync, constants as fsConstants, realpathSync, statSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CATALOGUE, getCheck, LOGIN_CHECK_IDS } from "./checks/catalogue.js";
import { LAB_PROFILES } from "./lab/profiles.js";
import { isBlockedAddress } from "./net/address-policy.js";
import { loadGrant, writeGrantFile, type LoadedGrant } from "./credentials.js";
import { EXIT, exitCodeFor } from "./exit.js";
import { HttpClient, plainHttpAllowed } from "./net/http.js";
import { registerSecret, safeText } from "./redact.js";
import { DNS_LABEL, generateSecret, proofFor, proofV2For, verifyOwnership, weakSecretWarning, WELL_KNOWN_PATH } from "./ownership.js";
import { deleteClient, pendingClients, setClientJournal } from "./oauth/registration.js";
import { planScan, planToText } from "./plan.js";
import { StaticKeyError, validateHeaderName } from "./static-key.js";
import { toJson } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import { toSarif } from "./report/sarif.js";
import { colorWanted, toTable } from "./report/table.js";
import { runScan, type ScanEvent } from "./scan.js";
import { readSecretFile, readSecretLine, SecretFileError } from "./secret-file.js";
import { parseSelection, resolveChecks } from "./selection.js";
import { loadAccessTokenFile, loadBearerFile } from "./static-key.js";
import { loadPostureReport, postureSection, type LoadedPosture } from "./posture.js";
import { REASON_CODES, type Severity } from "./types.js";
import { REPORT_SCHEMA } from "./report/json.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

const SECRET_ENV = "MCP_AUTHPROBE_SECRET";

export { EXIT };
/** Returned by main() when a long-running server was started: do not exit. */
export const KEEP_RUNNING = -1;

const HELP = `${TOOL_NAME} ${TOOL_VERSION}
Active authorization testing for remote MCP servers you own.

Usage:
  ${TOOL_NAME} scan <mcp-url> [options]
  ${TOOL_NAME} plan <mcp-url> [options]    Say what a scan with these options would run,
                                           and why not the rest; sends discovery only
  ${TOOL_NAME} ownership init <host>       Create a secret and the proof to publish
  ${TOOL_NAME} ownership proof <host>      Print the proof for <host> from your secret
  ${TOOL_NAME} ownership verify <host>     Check that the proof is published
  ${TOOL_NAME} checks list [--json]        List every check
  ${TOOL_NAME} capabilities [--json]       What this version supports (for programs)
  ${TOOL_NAME} checks show <id>            Explain one check
  ${TOOL_NAME} login <mcp-url> --out <file> Log in with a test account and save a test grant
  ${TOOL_NAME} login begin <mcp-url> --state-file <file> --redirect-uri <uri>
  ${TOOL_NAME} login complete --state-file <file> --callback-file <file> --out <file>
                                           The same login in two steps, for an application
                                           that receives the redirect itself (no listener)
  ${TOOL_NAME} consent-check <mcp-url>     MAP-CSR01: consent CSRF, in a real browser
  ${TOOL_NAME} cleanup --journal <file>    Delete test clients a killed scan left behind
  ${TOOL_NAME} mcp                         Run as an MCP server over stdio
  ${TOOL_NAME} lab [--profile <name>] [--port 8787]
                                           Run a local practice server (loopback only)

Scan options:
  --json <file>         Write the JSON report ("-" writes it to standard output
                        instead of the table)
  --quiet               Do not print the table
  --sarif <file>        Write a SARIF 2.1.0 report
  --markdown <file>     Write a Markdown report
  --fail-on <severity>  Exit 1 on a failing check at or above this severity (default: high)
  --allow-private       Allow loopback/private addresses (local labs only), for the
                        scanned host
  --allow-host <host>   With --allow-private, also for this host (an authorization
                        server on another private address); repeatable
  --preset <name>       passive: discovery, anonymous Origin and CORS only, no
                        credential used; standard: everything but the 12 MiB uploads
                        (MAP-BOD01) and the request burst (MAP-THR02); intrusive:
                        everything (the default)
  --header-file <file>  Extra headers for requests to the scanned origin only, one
                        "Name: value" per line (a gateway token in front of the server)
  --journal <file>      Record the temporary clients registered, so that
                        "cleanup --journal" can delete them after a killed scan
  --timeout <ms>        Per-request timeout (default: 10000)
  --secret-file <file>  Read the ownership secret from a file instead of ${SECRET_ENV}
  --throttle-attempts <n>
                        Failed token requests sent by MAP-THR01 (5-20, default 10)
  --verbose             Show every evidence line (default: failing checks only)
  --posture-report <file>
                        Merge an mcp-posture JSON report for the same URL: what the
                        server announces next to what it enforces
  --only <list>         Run only these checks: IDs (MAP-RDR01 or RDR01) or families (RDR),
                        comma-separated; the others are reported as skipped
  --skip <list>         Do not run these checks (same syntax; wins over --only)
  --credentials-file <file>
                        Test grant (JSON: client_id, refresh_token, optional
                        client_secret) for the refresh token checks. The full
                        sequence consumes the grant: use a dedicated test account.
                        When the grant is still valid afterwards, the file is
                        rewritten with the newest refresh token.
  --credentials-out <file>
                        Write the newest grant there instead of rewriting the input
  --rtk <mode>          Refresh token checks: destructive (default, RTK01-03: the
                        grant is revoked on a compliant server), rotate-only
                        (RTK01, one refresh: the grant stays usable) or off
  --max-observation-age <hours>
                        Oldest login result still reported (default 24; 0: no limit)
  --bearer-file <file>  Static API key for a server authenticated without OAuth
                        (one line, mode 600). Never put the key on the command line.
  --access-token-file <file>
                        OAuth access token for the MCP endpoint checks (one line,
                        mode 600), when your application already holds one. With
                        --credentials-file, MAP-AUD01 is judged in the scan too.
  --bearer-header <name>
                        Header for the key (default: Authorization, sent as Bearer;
                        any other header gets the key as is, e.g. X-API-Key)
  --rate-attempts <n>   Requests sent by MAP-THR02 with the key (10-100, default 30)
  --fail-on-inconclusive <true|false>
                        Exit 3 when a check is inconclusive (default: true)
  --protocol <era>      MCP revision to speak: auto (default: 2026-07-28 first, then
                        the initialize handshake of 2025-11-25), modern or legacy
  --client-id <id>      Use this OAuth client instead of dynamic registration: a
                        pre-registered client, or the https URL of a client ID
                        metadata document
  --client-secret-file <file>
                        Its secret, for a confidential client (one line, mode 600)
  --redirect-uri <uri>  One of its registered redirect URIs (MAP-RDR01, MAP-RDR02)
  --issuer <url>        Examine this authorization server when the resource
                        announces several (default: the first one)
  --wait-on-rate-limit <seconds>
                        When the credential is rate limited and the server gives a
                        Retry-After of at most this long, wait once and go on
  --delay-ms <ms>       Pause before every request (a gentler scan)
  --max-requests <n>    Stop after this many requests, with a partial report
  --deadline <seconds>  Stop after this long, with a partial report
  --events <file>       Append one JSON line per event (scan and check start and
                        end) to this file; "-" writes them to standard error

Consent check options (needs the optional playwright-core package and Chrome or Edge):
  --client-id, --redirect-uri
                        A pre-registered client and its loopback redirect URI,
                        instead of dynamic registration
  --browser <channel>   chrome (default), msedge or chromium
  --browser-path <exe>  Use this browser executable instead
  --json, --sarif, --markdown, --fail-on, --allow-private, --secret-file  as for scan

Login options:
  --out <file>          Where to write the test grant (mode 600, never overwritten without --force)
  --force               Overwrite an existing grant file
  --no-probe            Do not observe the login checks
                        (${LOGIN_CHECK_IDS.slice(0, 5).map((id) => id.slice(4)).join(", ")},
                        ${LOGIN_CHECK_IDS.slice(5).map((id) => id.slice(4)).join(", ")})
  --no-browser          Print the authorization URL instead of opening a browser
  --json <file>         Write the login results as a report, without any token
  --client-id, --client-secret-file
                        A pre-registered client (or client ID metadata document URL)
                        instead of dynamic registration
  --redirect-uri <uri>  Loopback redirect URI to listen on, for a client whose
                        redirect URI is fixed (http://127.0.0.1:<port>/callback);
                        with "login begin", the redirect URI of your application
  --rounds <n>          1 (default) or 2: a second authorization gives MAP-RDR03 a
                        code of its own when a probe spent the first one
  --state-file <file>   login begin writes it (mode 600), login complete reads it
  --callback-file <file>
                        File holding the URL the user was sent back to (or its query
                        string). --callback-url <url> takes it from the command
                        line, where other local users can see the code
  --protocol, --issuer  as for scan
  --allow-private, --secret-file, --timeout  as for scan

Lab options:
  --profile <name>      One of (default: vulnerable):
${Object.entries(LAB_PROFILES).map(([name, p]) => `                        ${name}: ${p.description}`).join("\n")}
  --auto-approve        Approve every valid authorization request at once, without the
                        login and consent pages: for scripts and CI (not for consent-check)
  --port <n>            Port on 127.0.0.1 (default: 8787; 0 picks a free port)
  --host <address>      127.0.0.1 (default) or ::1; nothing else is accepted

Exit codes:
  0  no failing check at or above --fail-on (login: a test grant was written)
  1  failing checks at or above --fail-on (ownership verify: proof not found)
  2  usage error, nothing was sent
  3  inconclusive checks, unless --fail-on-inconclusive false (login: it failed)
  4  the target is unreachable, or the scan could not run or was interrupted;
     --fail-on-inconclusive never silences it
  5  login wrote its results but no test grant

Ownership options:
  --expires <YYYY-MM-DD>
                        With "ownership proof": a proof that stops being accepted
                        after that day

The ownership secret is read from ${SECRET_ENV} or --secret-file, never from
the command line, so it does not end up in shell history or process lists.

Only scan servers you own or are explicitly authorized to test.
`;

/** The ownership secret, from --secret-file (read like every secret file) or the environment. Throws SecretFileError. */
function readSecret(secretFile: string | undefined): string | undefined {
  let value: string | undefined;
  if (secretFile) {
    const loaded = readSecretLine(secretFile, { label: "ownership secret file", maxBytes: 8 * 1024, followLinks: true });
    for (const w of loaded.warnings) err(`warning: ${w}\n`);
    value = loaded.value;
  } else {
    value = process.env[SECRET_ENV]?.trim();
  }
  if (!value) return undefined;
  registerSecret(value);
  return value;
}

/** --client-id, --client-secret-file and --redirect-uri, or a message for a usage error. */
function clientOptions(values: Values): { client?: { clientId: string; clientSecret?: string; redirectUri?: string }; error?: string } {
  const id = values["client-id"];
  const redirectUri = values["redirect-uri"];
  if (values["client-secret-file"] && !id) return { error: "--client-secret-file needs --client-id" };
  if (redirectUri !== undefined) {
    try {
      const u = new URL(redirectUri);
      if (u.hash) return { error: "--redirect-uri must not contain a fragment" };
    } catch {
      return { error: "--redirect-uri is not a valid URL" };
    }
  }
  if (!id) return {};
  if (/[\s\u0000-\u001f]/.test(id) || id.length > 2048) return { error: "--client-id is not a valid client identifier" };
  const client: { clientId: string; clientSecret?: string; redirectUri?: string } = { clientId: id };
  if (values["client-secret-file"]) {
    const loaded = readSecretLine(values["client-secret-file"], { label: "client secret file", maxBytes: 8 * 1024 });
    for (const w of loaded.warnings) err(`warning: ${w}\n`);
    registerSecret(loaded.value);
    client.clientSecret = loaded.value;
  }
  if (redirectUri !== undefined) client.redirectUri = redirectUri;
  return { client };
}

/** Extra headers from --header-file: "Name: value" lines, for the scanned origin only. Values are masked in reports. */
function readHeaderFile(path: string): Record<string, string> {
  const { text, warnings } = readSecretFile(path, { label: "header file", maxBytes: 16 * 1024, followLinks: true });
  for (const w of warnings) err(`warning: ${w}\n`);
  const headers: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const at = line.indexOf(":");
    const value = at > 0 ? line.slice(at + 1).trim() : "";
    if (at <= 0 || !value || /[\u0000-\u001f\u007f]/.test(value)) throw new SecretFileError(`${path}: every line must be "Name: value".`);
    const name = validateHeaderName(line.slice(0, at));
    registerSecret(value);
    headers[name] = value;
  }
  if (Object.keys(headers).length > 20) throw new SecretFileError(`${path}: at most 20 headers.`);
  return headers;
}

/** What the presets select. "intrusive" is everything, and the default. */
export const PRESETS: Record<string, { description: string; select: (id: string) => boolean; credential: boolean }> = {
  passive: { description: "discovery, anonymous Origin and CORS only; no credential is used", select: (id) => ["MAP-DSC01", "MAP-ORG01", "MAP-COR01"].includes(id), credential: false },
  standard: { description: "everything but the 12 MiB uploads (MAP-BOD01) and the request burst (MAP-THR02)", select: (id) => id !== "MAP-BOD01" && id !== "MAP-THR02", credential: true },
  intrusive: { description: "everything (the default)", select: () => true, credential: true },
};

/** --protocol as an era, undefined for auto, or null when invalid. */
function parseProtocol(value: string | undefined): "legacy" | "modern" | undefined | null {
  if (value === undefined || value === "auto") return undefined;
  return value === "legacy" || value === "modern" ? value : null;
}

/** A non-negative number option, undefined when absent, or null when invalid. */
function parseNumber(value: string | undefined, o: { min?: number; max?: number; integer?: boolean } = {}): number | undefined | null {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n < (o.min ?? 0) || n > (o.max ?? Number.MAX_SAFE_INTEGER) || (o.integer && !Number.isInteger(n))) return null;
  return n;
}

/** What this version supports, for a program that drives it. */
export function capabilities(): Record<string, unknown> {
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    reportSchema: REPORT_SCHEMA,
    mcpProtocol: { eras: ["modern", "legacy"], versions: ["2026-07-28", "2025-11-25"], detection: "auto" },
    clientRegistration: ["pre-registered", "metadata-document", "dynamic-registration"],
    checks: CATALOGUE.map((c) => c.id),
    reasonCodes: REASON_CODES,
    exitCodes: EXIT,
    labProfiles: Object.keys(LAB_PROFILES),
    presets: Object.fromEntries(Object.entries(PRESETS).map(([k, v]) => [k, v.description])),
    ownershipProofs: ["v1 (sha256)", "v2 (hmac-sha256, optional expiry)"],
    commands: ["scan", "plan", "login", "login begin", "login complete", "consent-check", "ownership", "checks", "capabilities", "cleanup", "lab", "mcp"],
    credentials: ["bearer-file", "access-token-file", "credentials-file", "client-id", "client-secret-file"],
    login: ["interactive", "begin", "complete"],
    reports: ["json", "sarif", "markdown", "events"],
  };
}

/**
 * Why a target cannot be scanned with these options, or null. Checked before
 * any request, so a configuration mistake is a usage error (exit 2) and not a
 * list of inconclusive results.
 */
export function targetProblem(url: URL, allowPrivate: boolean): string | null {
  if (url.protocol !== "https:" && url.protocol !== "http:") return `Unsupported URL scheme ${url.protocol} (use https).`;
  if (url.username || url.password) return "URLs with embedded credentials are refused.";
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (url.protocol === "http:" && !plainHttpAllowed(url, allowPrivate)) {
    return allowPrivate
      ? `Plain http is only accepted for a loopback or private-address lab; ${url.host} is neither. Use https.`
      : `Plain http is refused: secrets could travel in cleartext. Use https, or --allow-private for a lab on a loopback or private address.`;
  }
  if (!allowPrivate && (isIP(host) !== 0 ? isBlockedAddress(host) : host === "localhost" || host.endsWith(".localhost"))) {
    return `${url.host} is a loopback, private or reserved address: pass --allow-private to scan a local lab.`;
  }
  return null;
}

/** Why a report file could not be written, or null: found before the scan, not after it consumed a test grant. */
function outputProblem(option: string, file: string): string | null {
  if (file === "-") return null;
  const dir = dirname(resolvePath(file));
  try {
    if (!statSync(dir).isDirectory()) return `--${option}: ${dir} is not a directory.`;
    accessSync(dir, fsConstants.W_OK);
  } catch (e) {
    return `--${option}: cannot write to ${dir} (${(e as NodeJS.ErrnoException).code ?? "error"}).`;
  }
  try {
    if (statSync(resolvePath(file)).isDirectory()) return `--${option}: ${file} is a directory.`;
  } catch {
    /* does not exist yet: fine */
  }
  return null;
}

/** --timeout as milliseconds, undefined when absent, or null when invalid. */
function parseTimeout(value: string | undefined): number | undefined | null {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function out(text: string): void {
  process.stdout.write(text);
}

function err(text: string): void {
  process.stderr.write(text);
}

const CLI_OPTIONS = {
      json: { type: "string" },
      quiet: { type: "boolean", default: false },
      "auto-approve": { type: "boolean", default: false },
      "client-id": { type: "string" },
      "client-secret-file": { type: "string" },
      "redirect-uri": { type: "string" },
      protocol: { type: "string" },
      issuer: { type: "string" },
      rounds: { type: "string" },
      "state-file": { type: "string" },
      "callback-url": { type: "string" },
      "callback-file": { type: "string" },
      "keep-state": { type: "boolean", default: false },
      "allow-host": { type: "string", multiple: true },
      "header-file": { type: "string" },
      preset: { type: "string" },
      journal: { type: "string" },
      expires: { type: "string" },
      "credentials-out": { type: "string" },
      rtk: { type: "string" },
      "max-observation-age": { type: "string" },
      "access-token-file": { type: "string" },
      "wait-on-rate-limit": { type: "string" },
      "delay-ms": { type: "string" },
      "max-requests": { type: "string" },
      deadline: { type: "string" },
      events: { type: "string" },
      sarif: { type: "string" },
      markdown: { type: "string" },
      "fail-on": { type: "string", default: "high" },
      "allow-private": { type: "boolean", default: false },
      timeout: { type: "string" },
      "secret-file": { type: "string" },
      "credentials-file": { type: "string" },
      out: { type: "string" },
      "throttle-attempts": { type: "string" },
      only: { type: "string" },
      "bearer-file": { type: "string" },
      "bearer-header": { type: "string" },
      "rate-attempts": { type: "string" },
      "fail-on-inconclusive": { type: "string" },
      "posture-report": { type: "string" },
      skip: { type: "string" },
      browser: { type: "string" },
      "browser-path": { type: "string" },
      force: { type: "boolean", default: false },
      "no-probe": { type: "boolean", default: false },
      "no-browser": { type: "boolean", default: false },
      verbose: { type: "boolean", default: false },
      profile: { type: "string", default: "vulnerable" },
      port: { type: "string", default: "8787" },
      host: { type: "string", default: "127.0.0.1" },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    } as const;

const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export async function main(argv: string[]): Promise<number> {
  // `checks list --json` and `capabilities --json` take no file: the JSON goes to standard output.
  const first = argv.find((a) => !a.startsWith("-"));
  const args = first === "checks" || first === "capabilities" ? argv.map((a, i) => (a === "--json" && (argv[i + 1] === undefined || argv[i + 1]?.startsWith("--")) ? "--json=-" : a)) : argv;
  const { values, positionals } = parseCli(args);

  if (values.version) {
    out(`${TOOL_VERSION}\n`);
    return EXIT.ok;
  }
  const [command, sub, arg] = positionals;
  if (values.help || !command) {
    out(HELP);
    return values.help ? EXIT.ok : EXIT.usage;
  }
  try {
    return await dispatch(command, sub, arg, values);
  } catch (e) {
    // A secret file that cannot be read is a usage error, whatever the command.
    if (e instanceof SecretFileError || e instanceof StaticKeyError) {
      err(`${e.message}\n`);
      return EXIT.usage;
    }
    throw e;
  }
}

type Values = ReturnType<typeof parseCli>["values"];

function parseCli(argv: string[]) {
  return parseArgs({ args: argv, allowPositionals: true, strict: true, options: CLI_OPTIONS });
}

async function dispatch(command: string, sub: string | undefined, arg: string | undefined, values: Values): Promise<number> {
  if (command === "cleanup") {
    if (!values.journal) {
      err("cleanup needs --journal <file>, the journal a scan wrote with --journal.\n");
      return EXIT.usage;
    }
    const text = readSecretFile(values.journal, { label: "journal", maxBytes: 4 * 1024 * 1024, followLinks: true }).text;
    const pending = pendingClients(text);
    if (pending.length === 0) {
      out("Nothing to clean up: every client in the journal was deleted.\n");
      return EXIT.ok;
    }
    // Each client is deleted with its own management token, at the endpoint that issued it: what the scan itself would have done.
    const http = new HttpClient({ allowPrivate: values["allow-private"] });
    let left = 0;
    try {
      setClientJournal(values.journal);
      for (const c of pending) {
        const ok = await deleteClient(http, { clientId: c.clientId, clientSecret: null, redirectUris: [], registrationClientUri: c.registrationClientUri, registrationAccessToken: c.registrationAccessToken }, c.registrationEndpoint);
        if (!ok) left += 1;
        out(`${ok ? "deleted" : "NOT deleted"}  ${safeText(c.clientId, 120)}  (${safeText(c.registrationEndpoint, 200)})\n`);
      }
    } finally {
      setClientJournal(null);
      await http.close();
    }
    if (left > 0) err(`${left} client(s) could not be deleted (no RFC 7592 deletion, or the server refused): remove them by hand; they are named "mcp-authprobe test client (safe to delete)".\n`);
    return left > 0 ? EXIT.findings : EXIT.ok;
  }

  if (command === "capabilities") {
    out(values.json !== undefined || sub === "--json" ? `${JSON.stringify(capabilities(), null, 2)}\n` : `${TOOL_NAME} ${TOOL_VERSION}\nreport schema: ${REPORT_SCHEMA}\nchecks: ${CATALOGUE.length}\nlab profiles: ${Object.keys(LAB_PROFILES).join(", ")}\nUse --json for the full, machine-readable description.\n`);
    return EXIT.ok;
  }

  if (command === "mcp") {
    const { startStdioServer } = await import("./mcp-server.js");
    await startStdioServer();
    return KEEP_RUNNING;
  }

  if (command === "lab") {
    const { LabUsageError, startLab } = await import("./lab-command.js");
    try {
      const { lab, banner } = await startLab({ profile: values.profile, port: values.port, host: values.host, autoApprove: values["auto-approve"] });
      err(banner);
      const stop = (): void => {
        void lab.close().finally(() => process.exit(EXIT.ok));
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      return KEEP_RUNNING;
    } catch (e) {
      err(`${(e as Error).message}\n`);
      return e instanceof LabUsageError ? EXIT.usage : EXIT.error;
    }
  }

  if (command === "checks") {
    if (sub === "list" && values.json !== undefined) {
      out(`${JSON.stringify(CATALOGUE, null, 2)}\n`);
      return EXIT.ok;
    }
    if (sub === "list") {
      for (const c of CATALOGUE) {
        out(`${c.id.padEnd(10)} ${c.severity.padEnd(8)} ${(c.active ? "active" : "passive").padEnd(7)} ${c.availability.padEnd(9)} ${c.title}\n`);
      }
      return EXIT.ok;
    }
    if (sub === "show" && arg) {
      const c = getCheck(arg);
      if (!c) {
        err(`Unknown check: ${arg}\n`);
        return EXIT.usage;
      }
      out(
        `${c.id}: ${c.title}\nSeverity: ${c.severity}  Mode: ${c.active ? "active" : "passive"}  Status: ${c.availability}\nApplies to: MCP ${c.appliesTo.join(", ")}\nRuns with: ${c.runsWith.replace(/`/g, "")}\n\nWhy:\n  ${c.rationale}\n\nFix:\n  ${c.remediation}\n\nReferences:\n${c.references.map((r) => `  - ${r.title}: ${r.url}`).join("\n")}\n`,
      );
      return EXIT.ok;
    }
  }

  if (command === "ownership" && arg) {
    if (sub === "init") {
      const secret = generateSecret();
      out(
        [
          `Secret (store it in a password manager or CI secret, then export it as ${SECRET_ENV}):`,
          ``,
          `  ${secret}`,
          ``,
          `Publish ONE of the following for ${arg}:`,
          ``,
          `  File  https://${arg}${WELL_KNOWN_PATH} containing the line:`,
          `        ${proofV2For(arg, secret)}`,
          ``,
          `  DNS   TXT record on ${DNS_LABEL}.${arg} with the value:`,
          `        ${proofV2For(arg, secret)}`,
          ``,
          `The proof covers the whole host ${arg}, on any port. Versions before 0.13 need the`,
          `earlier format instead (both lines may be published side by side):`,
          `        ${proofFor(arg, secret)}`,
          ``,
          `Repeat "ownership proof <host>" for the authorization server host if it differs.`,
          ``,
        ].join("\n"),
      );
      return EXIT.ok;
    }
    const secret = readSecret(values["secret-file"]);
    if (sub === "proof") {
      if (!secret) {
        err(`Set ${SECRET_ENV} or pass --secret-file.\n`);
        return EXIT.usage;
      }
      const weak = weakSecretWarning(secret);
      if (weak) err(`warning: ${weak}\n`);
      try {
        out(`${proofV2For(arg, secret, values.expires)}\n`);
      } catch (e) {
        err(`--expires: ${(e as Error).message}\n`);
        return EXIT.usage;
      }
      // Versions before 0.13 only know the first format; it stays accepted.
      if (!values.expires) err(`Earlier format, for versions before 0.13 (both may be published): ${proofFor(arg, secret)}\n`);
      return EXIT.ok;
    }
    if (sub === "verify") {
      const t = parseTimeout(values.timeout);
      if (t === null) {
        err(`--timeout must be a positive number of milliseconds\n`);
        return EXIT.usage;
      }
      const http = new HttpClient({ allowPrivate: values["allow-private"], ...(t !== undefined ? { timeoutMs: t } : {}) });
      try {
        const result = await verifyOwnership(arg, secret, { http });
        out(`${result.verified ? "verified" : "NOT verified"}: ${result.detail}${result.proofVersion ? ` (proof format v${result.proofVersion})` : ""}\n`);
        return result.verified ? EXIT.ok : EXIT.findings;
      } finally {
        await http.close();
      }
    }
  }

  if (command === "consent-check" && sub) {
    let url: URL;
    try {
      url = new URL(sub);
    } catch {
      err(`Not a URL: ${sub}\n`);
      return EXIT.usage;
    }
    const failOn = values["fail-on"] as Severity;
    if (!SEVERITIES.includes(failOn)) {
      err(`--fail-on must be one of ${SEVERITIES.join(", ")}\n`);
      return EXIT.usage;
    }
    const problem = targetProblem(url, values["allow-private"]);
    const timeoutMs = parseTimeout(values.timeout);
    if (problem || timeoutMs === null) {
      err(`${problem ?? "--timeout must be a positive number of milliseconds"}\n`);
      return EXIT.usage;
    }
    for (const [option, file] of [["json", values.json], ["sarif", values.sarif], ["markdown", values.markdown]] as const) {
      const p = file ? outputProblem(option, file) : null;
      if (p) {
        err(`${p}\n`);
        return EXIT.usage;
      }
    }
    const { runConsentCommand } = await import("./consent-command.js");
    const o: Parameters<typeof runConsentCommand>[0] = {
      mcpUrl: url.toString(),
      allowPrivate: values["allow-private"],
      secret: readSecret(values["secret-file"]),
      failOn,
    };
    if (timeoutMs !== undefined) o.requestTimeoutMs = timeoutMs;
    const supplied = clientOptions(values);
    if (supplied.error) {
      err(`${supplied.error}\n`);
      return EXIT.usage;
    }
    if (supplied.client) o.client = supplied.client;
    if (values["allow-host"]) o.allowHosts = values["allow-host"];
    if (values.browser) o.browser = values.browser;
    if (values["browser-path"]) o.browserPath = values["browser-path"];
    if (values.json) o.json = values.json;
    if (values.sarif) o.sarif = values.sarif;
    if (values.markdown) o.markdown = values.markdown;
    return runConsentCommand(o);
  }

  if (command === "login" && sub) {
    const protocol = parseProtocol(values.protocol);
    const timeoutMs = parseTimeout(values.timeout);
    if (protocol === null || timeoutMs === null) {
      err(`${protocol === null ? "--protocol must be auto, legacy or modern" : "--timeout must be a positive number of milliseconds"}\n`);
      return EXIT.usage;
    }
    const supplied = clientOptions(values);
    if (supplied.error) {
      err(`${supplied.error}\n`);
      return EXIT.usage;
    }
    const client = supplied.client ? { clientId: supplied.client.clientId, ...(supplied.client.clientSecret ? { clientSecret: supplied.client.clientSecret } : {}) } : undefined;
    const common = {
      allowPrivate: values["allow-private"],
      ...(values["allow-host"] ? { allowHosts: values["allow-host"] } : {}),
      ...(timeoutMs !== undefined ? { requestTimeoutMs: timeoutMs } : {}),
      ...(protocol ? { protocol } : {}),
    };
    const { runLoginBegin, runLoginCommand, runLoginComplete } = await import("./login-command.js");

    if (sub === "complete") {
      if (!values["state-file"] || !values.out) {
        err("login complete needs --state-file <file> and --out <file>.\n");
        return EXIT.usage;
      }
      if ((values["callback-url"] === undefined) === (values["callback-file"] === undefined)) {
        err("login complete needs the URL the user was sent back to: --callback-file <file> (preferred) or --callback-url <url>.\n");
        return EXIT.usage;
      }
      // The callback carries the authorization code: read from a file, it never shows in process listings.
      const callback = values["callback-file"] ? readSecretFile(values["callback-file"], { label: "callback file", maxBytes: 16 * 1024, followLinks: true }).text.trim() : (values["callback-url"] as string);
      return runLoginComplete({
        ...common,
        stateFile: values["state-file"],
        callback,
        out: values.out,
        force: values.force,
        probe: !values["no-probe"],
        secret: readSecret(values["secret-file"]),
        keepState: values["keep-state"],
        ...(values.json ? { json: values.json } : {}),
      });
    }

    const target = sub === "begin" ? arg : sub;
    let url: URL;
    try {
      url = new URL(target ?? "");
    } catch {
      err(`Not a URL: ${target ?? "(missing)"}\n`);
      return EXIT.usage;
    }
    const problem = targetProblem(url, values["allow-private"]);
    if (problem) {
      err(`${problem}\n`);
      return EXIT.usage;
    }
    if (sub === "begin") {
      if (!values["state-file"] || !values["redirect-uri"]) {
        err("login begin needs --state-file <file> and --redirect-uri <uri> (the redirect URI of your application).\n");
        return EXIT.usage;
      }
      return runLoginBegin({
        ...common,
        mcpUrl: url.toString(),
        stateFile: values["state-file"],
        redirectUri: values["redirect-uri"],
        force: values.force,
        ...(client ? { client } : {}),
        ...(values.issuer !== undefined ? { issuer: values.issuer } : {}),
        print: (line) => out(`${line}\n`),
      });
    }
    if (!values.out) {
      err("login needs --out <file> for the test grant.\n");
      return EXIT.usage;
    }
    const rounds = parseNumber(values.rounds, { min: 1, max: 2, integer: true });
    if (rounds === null) {
      err("--rounds must be 1 or 2\n");
      return EXIT.usage;
    }
    return runLoginCommand({
      ...common,
      mcpUrl: url.toString(),
      out: values.out,
      ...(values.json ? { json: values.json } : {}),
      force: values.force,
      probe: !values["no-probe"],
      browser: !values["no-browser"],
      secret: readSecret(values["secret-file"]),
      ...(client ? { client } : {}),
      ...(values["redirect-uri"] ? { redirectUri: values["redirect-uri"] } : {}),
      ...(rounds !== undefined ? { rounds } : {}),
      ...(values.issuer !== undefined ? { issuer: values.issuer } : {}),
    });
  }

  if ((command === "scan" || command === "plan") && sub) {
    const failOn = values["fail-on"] as Severity;
    if (!SEVERITIES.includes(failOn)) {
      err(`--fail-on must be one of ${SEVERITIES.join(", ")}\n`);
      return EXIT.usage;
    }
    let url: URL;
    try {
      url = new URL(sub);
    } catch {
      err(`Not a URL: ${sub}\n`);
      return EXIT.usage;
    }
    const timeoutMs = parseTimeout(values.timeout);
    if (timeoutMs === null) {
      err(`--timeout must be a positive number of milliseconds\n`);
      return EXIT.usage;
    }
    const problem = targetProblem(url, values["allow-private"]);
    if (problem) {
      err(`${problem}\n`);
      return EXIT.usage;
    }
    for (const [option, file] of [["json", values.json], ["sarif", values.sarif], ["markdown", values.markdown]] as const) {
      const p = file ? outputProblem(option, file) : null;
      if (p) {
        err(`${p}\n`);
        return EXIT.usage;
      }
    }

    const options: Parameters<typeof runScan>[1] = { allowPrivate: values["allow-private"] };
    if (values["allow-host"]) options.allowHosts = values["allow-host"];
    if (values["header-file"]) options.extraHeaders = readHeaderFile(values["header-file"]);
    const preset = values.preset === undefined ? undefined : PRESETS[values.preset];
    if (values.preset !== undefined && !preset) {
      err(`--preset must be one of ${Object.keys(PRESETS).join(", ")}\n`);
      return EXIT.usage;
    }
    if (values.preset !== undefined) options.preset = values.preset;
    let select: ReturnType<typeof parseSelection>;
    try {
      select = parseSelection(values.only, values.skip);
      // MAP-THR02 with an OAuth token only when it is named: it may get the token limited.
      if (values.only !== undefined && resolveChecks(values.only).has("MAP-THR02") && /(^|,)\s*(MAP-)?THR(02)?\s*(,|$)/i.test(values.only)) options.rateLimitWithToken = true;
    } catch (e) {
      err(`${(e as Error).message}\n`);
      return EXIT.usage;
    }
    const protocol = parseProtocol(values.protocol);
    if (protocol === null) {
      err("--protocol must be auto, legacy or modern\n");
      return EXIT.usage;
    }
    if (protocol) options.protocol = protocol;
    if (values.issuer !== undefined) options.issuer = values.issuer;
    const supplied = clientOptions(values);
    if (supplied.error) {
      err(`${supplied.error}\n`);
      return EXIT.usage;
    }
    if (supplied.client) options.client = supplied.client;
    const rtk = values.rtk ?? "destructive";
    if (!["destructive", "rotate-only", "off"].includes(rtk)) {
      err("--rtk must be destructive, rotate-only or off\n");
      return EXIT.usage;
    }
    if (rtk !== "destructive") {
      const inner = select;
      const dropped = rtk === "off" ? ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"] : ["MAP-RTK02", "MAP-RTK03"];
      select = (id) => !dropped.includes(id) && (inner ? inner(id) : true);
    }
    if (preset && values.preset !== "intrusive") {
      const inner = select;
      select = (id) => preset.select(id) && (inner ? inner(id) : true);
    }
    if (select) options.select = select;
    const secret = readSecret(values["secret-file"]);
    if (secret) options.secret = secret;
    if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
    const numbers: Array<[string, keyof typeof options, Parameters<typeof parseNumber>[1], number, string]> = [
      ["throttle-attempts", "throttleAttempts", { min: 5, max: 20, integer: true }, 1, "an integer between 5 and 20"],
      ["rate-attempts", "rateAttempts", { min: 10, max: 100, integer: true }, 1, "an integer between 10 and 100"],
      ["max-observation-age", "maxObservationAgeMs", { min: 0 }, 3_600_000, "a number of hours (0 for no limit)"],
      ["wait-on-rate-limit", "waitOnRateLimitMs", { min: 0, max: 600 }, 1000, "a number of seconds between 0 and 600"],
      ["delay-ms", "delayMs", { min: 0, max: 60_000 }, 1, "a number of milliseconds between 0 and 60000"],
      ["max-requests", "maxRequests", { min: 1, integer: true }, 1, "a positive integer"],
      ["deadline", "deadlineMs", { min: 1 }, 1000, "a positive number of seconds"],
    ];
    for (const [flag, key, bounds, factor, expected] of numbers) {
      const n = parseNumber(values[flag as keyof Values] as string | undefined, bounds);
      if (n === null) {
        err(`--${flag} must be ${expected}\n`);
        return EXIT.usage;
      }
      if (n !== undefined) (options as Record<string, unknown>)[key] = n * factor;
    }
    if (values["bearer-header"] !== undefined && !values["bearer-file"]) {
      err("--bearer-header needs --bearer-file\n");
      return EXIT.usage;
    }
    if (values["bearer-file"] && values["access-token-file"]) {
      err("Pass either --bearer-file (a static key) or --access-token-file (an OAuth access token), not both.\n");
      return EXIT.usage;
    }
    if ((values["bearer-file"] || values["access-token-file"]) && preset?.credential === false) {
      err(`warning: --preset ${values.preset} uses no credential: the key or token was not read.\n`);
    } else if (values["bearer-file"] || values["access-token-file"]) {
      try {
        const loaded = values["bearer-file"] ? loadBearerFile(values["bearer-file"], values["bearer-header"]) : loadAccessTokenFile(values["access-token-file"] as string);
        for (const w of loaded.warnings) err(`warning: ${w}\n`);
        options.credential = loaded.credential;
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
    }
    let failOnInconclusive = true;
    if (values["fail-on-inconclusive"] !== undefined) {
      const v = values["fail-on-inconclusive"].toLowerCase();
      if (!["true", "false", "yes", "no", "1", "0"].includes(v)) {
        err("--fail-on-inconclusive must be true or false\n");
        return EXIT.usage;
      }
      failOnInconclusive = ["true", "yes", "1"].includes(v);
    }
    let loadedGrant: LoadedGrant | null = null;
    if (values["credentials-out"] && !values["credentials-file"]) {
      err("--credentials-out needs --credentials-file\n");
      return EXIT.usage;
    }
    if (values["credentials-file"]) {
      try {
        loadedGrant = loadGrant(values["credentials-file"]);
        for (const w of loadedGrant.warnings) err(`warning: ${w}\n`);
        if (loadedGrant.grant) options.grant = loadedGrant.grant;
        options.observations = loadedGrant.observations;
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
      const p = values["credentials-out"] ? outputProblem("credentials-out", values["credentials-out"]) : null;
      if (p) {
        err(`${p}\n`);
        return EXIT.usage;
      }
    }

    let posture: LoadedPosture | null = null;
    if (values["posture-report"]) {
      try {
        posture = loadPostureReport(values["posture-report"], url.toString());
        for (const w of posture.warnings) err(`warning: ${w}\n`);
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
    }

    if (command === "plan") {
      const plan = await planScan(url.toString(), options);
      out(values.json === "-" ? `${JSON.stringify(plan, null, 2)}\n` : planToText(plan));
      if (values.json && values.json !== "-") writeFileSync(values.json, `${JSON.stringify(plan, null, 2)}\n`);
      return plan.reachable ? EXIT.ok : EXIT.unreachable;
    }

    if (values.journal) {
      const p = outputProblem("journal", values.journal);
      if (p) {
        err(`${p}\n`);
        return EXIT.usage;
      }
      setClientJournal(values.journal);
    }
    if (values.events) {
      const p = outputProblem("events", values.events);
      if (p) {
        err(`${p}\n`);
        return EXIT.usage;
      }
      const file = values.events;
      options.onEvent = (e: ScanEvent): void => {
        const line = `${JSON.stringify(e)}\n`;
        if (file === "-") err(line);
        else appendFileSync(file, line);
      };
    }

    // SIGTERM or Ctrl-C stops the scan cleanly: temporary clients are deleted and a partial report is written.
    const stop = new AbortController();
    let signals = 0;
    const onSignal = (): void => {
      signals += 1;
      if (signals > 1) process.exit(130);
      err("Interrupted: cleaning up and writing a partial report (again to stop at once).\n");
      stop.abort();
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    options.signal = stop.signal;

    let result;
    try {
      result = await runScan(url.toString(), options);
    } catch (e) {
      err(`Scan failed: ${(e as Error).message}\n`);
      return EXIT.unreachable;
    } finally {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      setClientJournal(null);
    }
    const report = result.report;
    if (posture) report.posture = postureSection(report.findings, posture);

    // Keep the grant usable: when the server did not revoke it, the newest refresh token replaces the old one.
    if (loadedGrant?.grant && result.grant.latest && result.grant.state !== "revoked" && result.grant.state !== "unused") {
      const target = values["credentials-out"] ?? (values["credentials-file"] as string);
      if (result.grant.latest.refreshToken !== loadedGrant.grant.refreshToken || values["credentials-out"]) {
        try {
          writeGrantFile(target, result.grant.latest, loadedGrant.observations, true);
          if (report.grant) report.grant.rewritten = true;
        } catch (e) {
          err(`warning: could not write the newest refresh token to ${target}: ${(e as Error).message}\n`);
        }
      }
    }

    const code = exitCodeFor(report, { failOn, failOnInconclusive });
    if (report.summary) report.summary.exitCode = code;
    const jsonToStdout = values.json === "-";
    if (!values.quiet && !jsonToStdout) out(toTable(report, { color: colorWanted(), verbose: values.verbose }));
    if (jsonToStdout) out(toJson(report));
    else if (values.json) writeFileSync(values.json, toJson(report));
    if (values.sarif) writeFileSync(values.sarif, toSarif(report));
    if (values.markdown) writeFileSync(values.markdown, toMarkdown(report));
    return code;
  }

  err(HELP);
  return EXIT.usage;
}

function isEntryPoint(): boolean {
  const script = process.argv[1];
  if (!script) return false;
  try {
    // Resolve npm's bin symlink before comparing with this module's path.
    return realpathSync(script) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main(process.argv.slice(2)).then(
    (code) => {
      if (code !== KEEP_RUNNING) process.exitCode = code;
    },
    (e: unknown) => {
      err(`${(e as Error).message}\n`);
      process.exitCode = EXIT.usage;
    },
  );
}
