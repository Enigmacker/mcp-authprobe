import { existsSync, unlinkSync } from "node:fs";
import { LOGIN_CHECK_IDS } from "./checks/catalogue.js";
import { loadGrant, writeGrantFile, type Observation } from "./credentials.js";
import { discover } from "./discovery.js";
import { beginLogin, completeLogin, login, LoginError, openInBrowser, parseLoginState, type ClientConfig, type LoginResult, type LoginState } from "./login.js";
import type { Era } from "./oauth/mcp-call.js";
import { deleteClient } from "./oauth/registration.js";
import { readSecretFile, SecretFileError, writeSecretFile } from "./secret-file.js";
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
  /** A supplied client instead of dynamic registration (--client-id, --client-secret-file). */
  client?: ClientConfig;
  /** Loopback redirect URI to listen on (--redirect-uri). */
  redirectUri?: string;
  /** Authorizations to run (--rounds). */
  rounds?: number;
  protocol?: Era;
  issuer?: string;
}

// Everything printed here may contain server-controlled text: neutralize it.
const err = (t: string): void => {
  process.stderr.write(`${safeText(t, 4000)}\n`);
};

const httpFor = (o: { allowPrivate: boolean; requestTimeoutMs?: number }): HttpClient =>
  new HttpClient({ allowPrivate: o.allowPrivate, ...(o.requestTimeoutMs !== undefined ? { timeoutMs: o.requestTimeoutMs } : {}) });

const failure = (e: unknown): number => {
  err(`Login failed: ${(e as Error).message}`);
  return e instanceof NetworkError || e instanceof BlockedAddressError || e instanceof InsecureTransportError ? EXIT.unreachable : EXIT.error;
};

/** The login checks only run when every host they contact is proven. */
async function proven(http: HttpClient, hosts: string[], secret: string | undefined): Promise<boolean> {
  const results = [];
  for (const host of hosts) results.push(await verifyOwnership(host, secret, { http }));
  const ok = results.every((r) => r.verified);
  if (!ok) err(`Ownership not proven for every host: the login checks (${LOGIN_CHECK_IDS.join(", ")}) will not be observed.`);
  return ok;
}

/** Print the results, write the grant file (and the JSON report), and choose the exit code. */
function finish(o: { mcpUrl: string; out: string; force: boolean; json?: string }, result: LoginResult, probe: boolean, startedAt: string): number {
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
      ...(result.clientSource ? { client: { source: result.clientSource } } : {}),
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
  err(`Test grant written to ${o.out} (mode 600). The full refresh token sequence consumes it: scan with --credentials-file ${o.out}.`);
  return EXIT.ok;
}

/** `mcp-authprobe login`: everything goes to stderr; tokens are only written to the grant file. */
export async function runLoginCommand(o: LoginCommandOptions): Promise<number> {
  const startedAt = new Date().toISOString();
  const http = httpFor(o);
  try {
    const discovery = await discover(o.mcpUrl, http, { ...(o.protocol ? { protocol: o.protocol } : {}), ...(o.issuer !== undefined ? { issuer: o.issuer } : {}) });
    for (const w of discovery.warnings ?? []) err(`Note: ${w}`);
    const probe = o.probe ? await proven(http, hostsToVerify(o.mcpUrl, discovery), o.secret) : false;
    const result = await login({
      http,
      mcpUrl: o.mcpUrl,
      discovery,
      probe,
      log: err,
      ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      ...(o.client ? { client: o.client } : {}),
      ...(o.redirectUri ? { redirectUri: o.redirectUri } : {}),
      ...(o.rounds !== undefined ? { rounds: o.rounds } : {}),
      openUrl:
        o.openUrl ??
        (async (url) => {
          err(`\nAuthorization URL (open it if no browser appears):\n${url}\n`);
          if (o.browser) await openInBrowser(url);
        }),
    });
    return finish(o, result, probe, startedAt);
  } catch (e) {
    return failure(e);
  } finally {
    await http.close();
  }
}

export interface LoginBeginOptions {
  mcpUrl: string;
  /** Where the state is written (mode 600): the PKCE verifier, the state, the expected issuer. */
  stateFile: string;
  /** Redirect URI of the application that will receive the authorization response. */
  redirectUri: string;
  client?: ClientConfig;
  force: boolean;
  allowPrivate: boolean;
  requestTimeoutMs?: number;
  protocol?: Era;
  issuer?: string;
  /** Receives the authorization URL (standard output in the CLI). */
  print: (line: string) => void;
}

/**
 * `mcp-authprobe login begin`: the first half of a login for an application
 * that receives the redirect itself (a web application, a program driving
 * the tool). Prints the authorization URL; nothing listens.
 */
export async function runLoginBegin(o: LoginBeginOptions): Promise<number> {
  const http = httpFor(o);
  try {
    const discovery = await discover(o.mcpUrl, http, { ...(o.protocol ? { protocol: o.protocol } : {}), ...(o.issuer !== undefined ? { issuer: o.issuer } : {}) });
    for (const w of discovery.warnings ?? []) err(`Note: ${w}`);
    const begun = await beginLogin({ http, mcpUrl: o.mcpUrl, discovery, redirectUri: o.redirectUri, log: err, ...(o.client ? { client: o.client } : {}) });
    for (const n of begun.notes) err(`Note: ${n}`);
    try {
      writeSecretFile(o.stateFile, `${JSON.stringify(begun.state, null, 2)}\n`, o.force);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      err(code === "EEXIST" ? `${o.stateFile} already exists; use --force to overwrite it.` : `Could not write ${o.stateFile}: ${(e as Error).message}`);
      // A client registered for nothing is removed.
      if (begun.state.registered && begun.state.registrationEndpoint) {
        await deleteClient(http, { clientId: begun.state.clientId, clientSecret: null, redirectUris: [o.redirectUri], ...begun.state.registered }, begun.state.registrationEndpoint);
      }
      return EXIT.usage;
    }
    err(`State written to ${o.stateFile} (mode 600). Send the user to the URL below, then run \`mcp-authprobe login complete --state-file ${o.stateFile} --callback-file <file holding the URL they came back to> --out <grant file>\`.`);
    o.print(begun.authorizationUrl);
    return EXIT.ok;
  } catch (e) {
    return failure(e);
  } finally {
    await http.close();
  }
}

export interface LoginCompleteOptions {
  stateFile: string;
  /** The URL the user was sent back to, with its query string (or the query string alone). */
  callback: string;
  out: string;
  force: boolean;
  probe: boolean;
  allowPrivate: boolean;
  secret: string | undefined;
  requestTimeoutMs?: number;
  json?: string;
  protocol?: Era;
  /** Keep the state file (default: it is deleted, its code verifier is of no further use). */
  keepState?: boolean;
}

/** `mcp-authprobe login complete`: validate the authorization response, run the login checks, write the grant. */
export async function runLoginComplete(o: LoginCompleteOptions): Promise<number> {
  const startedAt = new Date().toISOString();
  let state: LoginState;
  try {
    state = parseLoginState(JSON.parse(readSecretFile(o.stateFile, { label: "state file", maxBytes: 64 * 1024 }).text));
  } catch (e) {
    err(e instanceof LoginError || e instanceof SecretFileError ? e.message : `The state file ${o.stateFile} is not valid JSON.`);
    return EXIT.usage;
  }
  const http = httpFor(o);
  try {
    const hosts = [...new Set([state.target, state.authorizationEndpoint, state.tokenEndpoint, ...(state.registrationEndpoint ? [state.registrationEndpoint] : [])].map((u) => new URL(u).hostname))];
    const probe = o.probe ? await proven(http, hosts, o.secret) : false;
    const result = await completeLogin({ http, state, callback: o.callback, probe, log: err, ...(o.protocol ? { era: o.protocol } : {}) });
    const code = finish({ mcpUrl: state.target, out: o.out, force: o.force, ...(o.json ? { json: o.json } : {}) }, result, probe, startedAt);
    // The code is spent and the verifier with it: the state is of no further use.
    if (!o.keepState) {
      try {
        unlinkSync(o.stateFile);
      } catch {
        /* already gone */
      }
    }
    return code;
  } catch (e) {
    return failure(e);
  } finally {
    await http.close();
  }
}
