import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CATALOGUE } from "./checks/catalogue.js";
import type { Observation, TestGrant } from "./credentials.js";
import type { DiscoveryResult } from "./discovery.js";
import type { HttpClient } from "./net/http.js";
import { describe as describeOutcome, exchangeCode, type CodeExchangeOutcome } from "./oauth/token-client.js";
import { deleteClient, registerClient, type RegisteredClient } from "./oauth/registration.js";
import { safeText } from "./redact.js";

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

export interface LoginOptions {
  http: HttpClient;
  mcpUrl: string;
  discovery: DiscoveryResult;
  /** Opens the authorization URL (a browser in the CLI, a scripted agent in tests). */
  openUrl: (url: string) => Promise<void>;
  /** Run the MAP-RDR03 probe. Only set when ownership of every contacted host is proven. */
  probeRedirectBinding: boolean;
  /** How long to wait for the user to finish in the browser. */
  timeoutMs?: number;
  /** Status lines for the user (stderr in the CLI). Never receives secrets. */
  log?: (line: string) => void;
}

export interface LoginResult {
  grant: TestGrant | null;
  observations: Observation[];
  notes: string[];
}

export class LoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoginError";
  }
}

interface CallbackParams {
  code: string | null;
  error: string | null;
  iss: string | null;
}

function equalStrings(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Loopback listener that resolves with the first callback carrying the right state. */
async function startCallbackListener(expectedState: string): Promise<{ redirectUri: string; mismatchUri: string; result: Promise<CallbackParams>; close: () => Promise<void> }> {
  let resolveResult!: (p: CallbackParams) => void;
  const result = new Promise<CallbackParams>((resolve) => {
    resolveResult = resolve;
  });
  let done = false;

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const state = url.searchParams.get("state") ?? "";
    if (req.method !== "GET" || url.pathname !== "/callback" || done || !equalStrings(state, expectedState)) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("Unexpected request.");
      return;
    }
    done = true;
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    res.end("mcp-authprobe: authorization received. You can close this tab.");
    resolveResult({ code: url.searchParams.get("code"), error: url.searchParams.get("error"), iss: url.searchParams.get("iss") });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    redirectUri: `http://127.0.0.1:${port}/callback`,
    mismatchUri: `http://127.0.0.1:${port}/callback-mismatch`,
    result,
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

function observation(checkId: string, target: string, status: Observation["status"], message: string, evidence: string[]): Observation {
  const def = CATALOGUE.find((c) => c.id === checkId);
  if (!def) throw new Error(`Unknown check ${checkId}`);
  return {
    checkId,
    title: def.title,
    severity: def.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
    observedAt: new Date().toISOString(),
  };
}

function scopesFor(d: DiscoveryResult): string | undefined {
  const fromChallenge = /scope="([^"]+)"/i.exec(d.challenge.wwwAuthenticate ?? "")?.[1];
  const scopes = new Set((fromChallenge ?? d.prm?.metadata.scopes_supported?.join(" ") ?? "").split(/\s+/).filter(Boolean));
  // Ask for a refresh token where the server models it as a scope.
  const asScopes = d.as?.metadata["scopes_supported"];
  if (Array.isArray(asScopes) && asScopes.includes("offline_access")) scopes.add("offline_access");
  return scopes.size > 0 ? [...scopes].join(" ") : undefined;
}

export async function login(opts: LoginOptions): Promise<LoginResult> {
  const { http, discovery: d } = opts;
  const log = opts.log ?? (() => undefined);
  const meta = d.as?.metadata;
  const target = opts.mcpUrl;
  const issuer = typeof meta?.issuer === "string" ? meta.issuer : null;
  const authorizationEndpoint = typeof meta?.authorization_endpoint === "string" ? meta.authorization_endpoint : null;
  const tokenEndpoint = typeof meta?.token_endpoint === "string" ? meta.token_endpoint : null;
  const registrationEndpoint = typeof meta?.registration_endpoint === "string" ? meta.registration_endpoint : null;
  if (!authorizationEndpoint || !tokenEndpoint) throw new LoginError("The authorization server does not advertise authorization and token endpoints.");
  if (!registrationEndpoint) throw new LoginError("The authorization server does not offer dynamic client registration; pre-registered clients are not supported yet.");

  const authUrl = new URL(authorizationEndpoint);
  if (authUrl.protocol !== "https:" && !http.allowPrivate) throw new LoginError("Refusing to open a non-https authorization endpoint.");
  const methods = meta?.code_challenge_methods_supported;
  if (Array.isArray(methods) && !methods.includes("S256")) throw new LoginError("The authorization server does not support PKCE S256.");

  const state = randomBytes(24).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const listener = await startCallbackListener(state);
  const notes: string[] = [];
  const observations: Observation[] = [];
  let registered: RegisteredClient | null = null;
  let keepClient = false;

  try {
    const reg = await registerClient(http, registrationEndpoint, [listener.redirectUri], {
      clientName: "mcp-authprobe test login",
      grantTypes: ["authorization_code", "refresh_token"],
    });
    if (!reg.client) throw new LoginError(`Dynamic client registration failed (HTTP ${reg.status}${reg.error ? `, error=${reg.error}` : ""}).`);
    const client = reg.client;
    registered = client;
    log(`Registered test client ${client.clientId}.`);

    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", client.clientId);
    authUrl.searchParams.set("redirect_uri", listener.redirectUri);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    const resource = d.prm?.metadata.resource ?? target;
    authUrl.searchParams.set("resource", resource);
    const scope = scopesFor(d);
    if (scope) authUrl.searchParams.set("scope", scope);

    log("Opening the authorization page. Log in with your dedicated TEST account.");
    await opts.openUrl(authUrl.toString());
    const cb = await withTimeout(listener.result, opts.timeoutMs ?? 5 * 60_000, "Timed out waiting for the authorization response.");

    if (cb.error) throw new LoginError(`The authorization server returned error=${safeText(cb.error, 80)}.`);
    if (!cb.code) throw new LoginError("The authorization response carried no code.");
    // RFC 9207: reject a response from another issuer (mix-up attacks).
    if (cb.iss !== null && issuer !== null && cb.iss !== issuer) throw new LoginError("The iss parameter does not match the discovered issuer; aborting.");
    if (cb.iss === null && meta?.["authorization_response_iss_parameter_supported"] === true) {
      throw new LoginError("The server announces the iss parameter but the response has none; aborting.");
    }

    const exchangeParams = { clientId: client.clientId, clientSecret: client.clientSecret, code: cb.code, codeVerifier: verifier, resource };
    let tokens: CodeExchangeOutcome | null = null;

    if (opts.probeRedirectBinding) {
      const probe = await exchangeCode(http, tokenEndpoint, { ...exchangeParams, redirectUri: listener.mismatchUri });
      const line = `code presented with a different redirect_uri: ${describeOutcome(probe)}`;
      if (probe.accessTokenIssued) {
        observations.push(observation("MAP-RDR03", target, "fail", "The token endpoint exchanged a code presented with a redirect_uri different from the one used at authorization.", [line]));
        tokens = probe; // the code is spent; keep these tokens as the grant
      } else if (probe.status >= 400 && probe.status < 500 && !probe.throttled) {
        observations.push(observation("MAP-RDR03", target, "pass", "The token endpoint refused a code presented with a different redirect_uri.", [line]));
      } else {
        observations.push(observation("MAP-RDR03", target, "error", "Unexpected answer to the mismatched exchange; inconclusive.", [line]));
      }
    } else {
      notes.push("MAP-RDR03 was not observed: ownership of the contacted hosts is not proven.");
    }

    if (!tokens) {
      tokens = await exchangeCode(http, tokenEndpoint, { ...exchangeParams, redirectUri: listener.redirectUri });
      if (!tokens.accessTokenIssued) {
        if (opts.probeRedirectBinding && tokens.error === "invalid_grant") {
          notes.push(
            "The server invalidated the code after the refused attempt (a strict, acceptable behaviour). Run login again with --no-probe to obtain a test grant.",
          );
          return { grant: null, observations, notes };
        }
        throw new LoginError(`Code exchange failed: ${describeOutcome(tokens)}.`);
      }
    }
    if (!tokens.refreshToken) {
      notes.push("Login succeeded but no refresh token was issued; the refresh token checks cannot run with this server configuration.");
      return { grant: null, observations, notes };
    }

    const grant: TestGrant = {
      clientId: client.clientId,
      refreshToken: tokens.refreshToken,
      authMethod: client.clientSecret ? "client_secret_post" : "none",
    };
    if (client.clientSecret) grant.clientSecret = client.clientSecret;
    keepClient = true; // the grant belongs to this client
    return { grant, observations, notes };
  } finally {
    await listener.close();
    // Without a usable grant the client is useless: remove it when possible.
    if (registered && !keepClient) await deleteClient(http, registered, registrationEndpoint);
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
