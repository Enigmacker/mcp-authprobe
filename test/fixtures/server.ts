import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * Local fixture: a minimal MCP resource server and authorization server on
 * 127.0.0.1. It never leaves the machine. Behaviour is switched by options
 * so tests can model compliant and misconfigured servers.
 */
export interface TokenBehaviour {
  /** Issue a new refresh token on each refresh (default true). */
  rotate?: boolean;
  /** When rotating, still return the old refresh token (broken rotation). */
  returnSameRefresh?: boolean;
  /** Reject a refresh token that was already exchanged (default true). */
  rejectReplay?: boolean;
  /** On detected replay, revoke every token of the family (default true). */
  revokeFamily?: boolean;
  /** Confidential client secret; when set, client authentication is required. */
  clientSecret?: string;
  /** Answer every token request with 429 (throttling). */
  throttle?: boolean;
  /** Bind authorization codes to their redirect_uri at the token endpoint (default true). */
  bindRedirect?: boolean;
  /** Invalidate a code after any failed exchange attempt (default false). */
  consumeCodeOnFailure?: boolean;
  /** Answer 429 once this many failed token requests have been seen. */
  rateLimitAfter?: number;
  /** Signal throttling with an OAuth slow_down error in a 400 instead of 429. */
  rateLimitStyle?: "429" | "slow_down";
  /** Answer every token request with 503 and Retry-After (outage). */
  outage?: boolean;
}

export interface AuthorizationBehaviour {
  /**
   * How the authorization endpoint matches redirect_uri:
   * "exact" (compliant), "prefix" (string prefix), "any" (no check),
   * "deferred" (no check before login: indistinguishable from outside).
   */
  match?: "exact" | "prefix" | "any" | "deferred";
  /**
   * What a valid request without a session gets: "login" (redirect to the
   * login page) or "error-redirect" (redirect to redirect_uri with
   * error=login_required, as with prompt=none).
   */
  noSession?: "login" | "error-redirect" | "auto-approve";
  /** Include the RFC 9207 iss parameter in authorization responses (default true). */
  issInResponse?: boolean;
  /** Registration policy: "strict" refuses unsafe redirect URIs, "lax" accepts anything. */
  registration?: "strict" | "lax" | "disabled";
  /** Offer RFC 7592 deletion of registered clients (default true). */
  management?: boolean;
  /** Answer 429 to authorize and register requests once this many have been seen. */
  rateLimitAfter?: number;
}

/** Consent page behaviour, for MAP-CSR01. */
export interface ConsentBehaviour {
  /**
   * "token": a per-session anti-CSRF token is required (compliant);
   * "none": no token, any POST with the session cookie grants consent;
   * "unverified": a token is rendered but never checked;
   * "origin": no token, but a foreign Origin is refused.
   */
  csrf?: "token" | "none" | "unverified" | "origin";
  /** SameSite attribute of the session cookie (default Lax). */
  sameSite?: "Lax" | "Strict" | "None";
}

export interface FixtureOptions {
  /** Send WWW-Authenticate with resource_metadata on 401 (default true). */
  challenge?: boolean;
  /** Serve Protected Resource Metadata (default true). */
  prm?: boolean;
  /** Serve Authorization Server Metadata (default true). */
  asMetadata?: boolean;
  /** Body of /.well-known/mcp-authprobe.txt, or null for 404. */
  ownershipFile?: string | null;
  /** Answer the MCP endpoint without credentials (misconfiguration). */
  anonymous?: boolean;
  tokens?: TokenBehaviour;
  authorization?: AuthorizationBehaviour;
  /** Serve a login page and a consent page at /authorize (enables MAP-CSR01 tests). */
  consent?: ConsentBehaviour;
  /**
   * Address to listen on and to advertise in URLs (default 127.0.0.1).
   * A non-loopback local address lets tests exercise the ownership gate.
   */
  host?: string;
}

export interface Fixture {
  baseUrl: string;
  mcpUrl: string;
  requests: Array<{ method: string; path: string }>;
  /** Create a fresh grant and return its refresh token. */
  issueRefreshToken(clientId?: string): string;
  /** Number of token requests received so far. */
  tokenRequests(): number;
  /** Client IDs currently registered through dynamic registration. */
  registeredClients(): string[];
  /** Create a logged-in session and return its cookie value (consent mode). */
  issueSession(): string;
  /** Number of consents granted so far (consent mode). */
  consentsGranted(): number;
  close(): Promise<void>;
}

interface RefreshRecord {
  family: string;
  clientId: string;
  used: boolean;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

const newToken = (prefix: string): string => `${prefix}_${randomBytes(16).toString("hex")}`;

export async function startFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const opts = { challenge: true, prm: true, asMetadata: true, ownershipFile: null, anonymous: false, ...options };
  let failures = 0;
  const tok: Required<Omit<TokenBehaviour, "clientSecret" | "rateLimitAfter">> & { clientSecret?: string; rateLimitAfter?: number } = {
    rotate: true,
    returnSameRefresh: false,
    rejectReplay: true,
    revokeFamily: true,
    throttle: false,
    bindRedirect: true,
    consumeCodeOnFailure: false,
    rateLimitStyle: "429",
    outage: false,
    ...options.tokens,
  };
  let authzRequests = 0;
  const authz: Required<Omit<AuthorizationBehaviour, "rateLimitAfter">> & { rateLimitAfter?: number } = { match: "exact", noSession: "login", registration: "strict", management: true, issInResponse: true, ...options.authorization };
  const codes = new Map<string, { clientId: string; redirectUri: string; challenge: string; used: boolean }>();
  const clients = new Map<string, { redirectUris: string[]; managementToken: string }>();
  const requests: Fixture["requests"] = [];
  const refreshTokens = new Map<string, RefreshRecord>();
  const revokedFamilies = new Set<string>();
  let tokenCount = 0;
  let base = "";

  function tokenEndpoint(req: IncomingMessage, body: string, res: ServerResponse): void {
    tokenCount += 1;
    if (tok.throttle) return json(res, 429, { error: "slow_down" }, { "retry-after": "30" });
    if (tok.outage) return json(res, 503, { error: "temporarily_down" }, { "retry-after": "30" });
    if (tok.rateLimitAfter !== undefined && failures >= tok.rateLimitAfter) {
      return tok.rateLimitStyle === "429" ? json(res, 429, { error: "too_many_requests" }, { "retry-after": "60" }) : json(res, 400, { error: "slow_down" });
    }

    const form = new URLSearchParams(body);
    let clientId = form.get("client_id");
    let secret = form.get("client_secret");
    const basic = /^Basic\s+(.+)$/i.exec(req.headers.authorization ?? "");
    if (basic?.[1]) {
      const [id, sec] = Buffer.from(basic[1], "base64").toString("utf8").split(":");
      clientId = decodeURIComponent(id ?? "");
      secret = decodeURIComponent(sec ?? "");
    }
    if (tok.clientSecret !== undefined && secret !== tok.clientSecret) return json(res, 401, { error: "invalid_client" });
    if (form.get("grant_type") === "authorization_code") {
      const code = codes.get(form.get("code") ?? "");
      if (!code || code.used || code.clientId !== clientId) return json(res, 400, { error: "invalid_grant" });
      const verifier = form.get("code_verifier") ?? "";
      const fail = (): void => {
        if (tok.consumeCodeOnFailure) code.used = true;
        json(res, 400, { error: "invalid_grant" });
      };
      if (createHash("sha256").update(verifier).digest("base64url") !== code.challenge) return fail();
      if (tok.bindRedirect && form.get("redirect_uri") !== code.redirectUri) return fail();
      code.used = true;
      const refreshOut = newToken("rt");
      refreshTokens.set(refreshOut, { family: newToken("fam"), clientId: code.clientId, used: false });
      return json(res, 200, { access_token: newToken("at"), token_type: "Bearer", expires_in: 3600, refresh_token: refreshOut });
    }
    if (form.get("grant_type") !== "refresh_token") return json(res, 400, { error: "unsupported_grant_type" });

    const presented = form.get("refresh_token") ?? "";
    const record = refreshTokens.get(presented);
    if (!record || record.clientId !== clientId || revokedFamilies.has(record.family)) {
      failures += 1;
      return json(res, 400, { error: "invalid_grant" });
    }
    if (record.used && tok.rejectReplay) {
      if (tok.revokeFamily) revokedFamilies.add(record.family);
      return json(res, 400, { error: "invalid_grant", error_description: "refresh token reuse detected" });
    }

    let refreshOut = presented;
    if (tok.rotate) {
      record.used = true;
      if (!tok.returnSameRefresh) {
        refreshOut = newToken("rt");
        refreshTokens.set(refreshOut, { family: record.family, clientId: record.clientId, used: false });
      }
    }
    return json(res, 200, { access_token: newToken("at"), token_type: "Bearer", expires_in: 3600, refresh_token: refreshOut });
  }

  function safeRedirect(uri: string): boolean {
    let u: URL;
    try {
      u = new URL(uri);
    } catch {
      return false;
    }
    if (u.hash) return false;
    if (u.protocol === "https:") return true;
    return u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  }

  function registerEndpoint(body: string, res: ServerResponse): void {
    if (authz.registration === "disabled") return json(res, 404, { error: "not_found" });
    let meta: { redirect_uris?: unknown };
    try {
      meta = JSON.parse(body) as { redirect_uris?: unknown };
    } catch {
      return json(res, 400, { error: "invalid_client_metadata" });
    }
    const uris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris.filter((u): u is string => typeof u === "string") : [];
    if (uris.length === 0) return json(res, 400, { error: "invalid_redirect_uri" });
    if (authz.registration === "strict" && !uris.every(safeRedirect)) return json(res, 400, { error: "invalid_redirect_uri" });
    const clientId = newToken("client");
    const managementToken = newToken("rat");
    clients.set(clientId, { redirectUris: uris, managementToken });
    const body201: Record<string, unknown> = { client_id: clientId, redirect_uris: uris, token_endpoint_auth_method: "none" };
    if (authz.management) {
      body201["registration_client_uri"] = `${base}/register/${clientId}`;
      body201["registration_access_token"] = managementToken;
    }
    return json(res, 201, body201);
  }

  function manageEndpoint(req: IncomingMessage, clientId: string, res: ServerResponse): void {
    const c = clients.get(clientId);
    if (!c || req.headers.authorization !== `Bearer ${c.managementToken}`) return json(res, 401, { error: "invalid_token" });
    if (req.method === "DELETE") {
      clients.delete(clientId);
      res.writeHead(204);
      res.end();
      return;
    }
    return json(res, 405, { error: "method_not_allowed" });
  }

  // --- consent mode -------------------------------------------------------
  const sessions = new Map<string, string>(); // sid -> csrf token
  let granted = 0;
  const consentOpts = { csrf: "token" as const, sameSite: "Lax" as const, ...options.consent };

  function cookieOf(req: IncomingMessage, name: string): string | null {
    const header = req.headers.cookie ?? "";
    for (const part of header.split(";")) {
      const [k, ...v] = part.trim().split("=");
      if (k === name) return v.join("=");
    }
    return null;
  }

  function newSession(): string {
    const sid = newToken("sid");
    sessions.set(sid, newToken("csrf"));
    return sid;
  }

  function sessionCookie(sid: string): string {
    return `sid=${sid}; Path=/; HttpOnly; SameSite=${consentOpts.sameSite}${consentOpts.sameSite === "None" ? "; Secure" : ""}`;
  }

  const esc = (v: string): string => v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

  function consentAuthorize(req: IncomingMessage, url: URL, res: ServerResponse): void {
    const sid = cookieOf(req, "sid");
    const csrf = sid ? sessions.get(sid) : undefined;
    if (!sid || csrf === undefined) {
      res.writeHead(302, { location: `${base}/login?return=${encodeURIComponent(url.pathname + url.search)}` });
      res.end();
      return;
    }
    const q = url.searchParams;
    const client = clients.get(q.get("client_id") ?? "");
    if (!client || !client.redirectUris.includes(q.get("redirect_uri") ?? "")) return json(res, 400, { error: "invalid_request" });
    const hidden = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "resource", "scope"]
      .map((k) => `<input type="hidden" name="${k}" value="${esc(q.get(k) ?? "")}">`)
      .join("");
    const token = consentOpts.csrf === "token" || consentOpts.csrf === "unverified" ? `<input type="hidden" name="csrf_token" value="${esc(csrf)}">` : "";
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><title>Consent</title><h1>Allow test client?</h1>
<form method="post" action="/consent">${hidden}${token}
<button type="submit" name="decision" value="deny">Deny</button>
<button type="submit" name="decision" value="allow">Allow</button></form>`);
  }

  function consentSubmit(req: IncomingMessage, body: string, res: ServerResponse): void {
    const sid = cookieOf(req, "sid");
    const csrf = sid ? sessions.get(sid) : undefined;
    if (!sid || csrf === undefined) return json(res, 401, { error: "login_required" });
    const form = new URLSearchParams(body);
    if (consentOpts.csrf === "token" && form.get("csrf_token") !== csrf) return json(res, 403, { error: "invalid_csrf_token" });
    if (consentOpts.csrf === "origin" && req.headers.origin !== undefined && req.headers.origin !== base) return json(res, 403, { error: "bad_origin" });
    const redirectUri = form.get("redirect_uri") ?? "";
    const client = clients.get(form.get("client_id") ?? "");
    if (!client || !client.redirectUris.includes(redirectUri)) return json(res, 400, { error: "invalid_request" });
    const back = new URL(redirectUri);
    back.searchParams.set("state", form.get("state") ?? "");
    if (form.get("decision") !== "allow") {
      back.searchParams.set("error", "access_denied");
    } else {
      granted += 1;
      const code = newToken("code");
      codes.set(code, { clientId: form.get("client_id") ?? "", redirectUri, challenge: form.get("code_challenge") ?? "", used: false });
      back.searchParams.set("code", code);
    }
    res.writeHead(302, { location: back.toString() });
    res.end();
  }

  function loginPage(req: IncomingMessage, url: URL, body: string, res: ServerResponse): void {
    const ret = url.searchParams.get("return") ?? "/";
    if (req.method === "POST") {
      const form = new URLSearchParams(body);
      if (form.get("username") !== "test" || form.get("password") !== "test") return json(res, 401, { error: "bad_credentials" });
      const sid = newSession();
      res.writeHead(302, { location: ret.startsWith("/") ? ret : "/", "set-cookie": sessionCookie(sid) });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><title>Login</title><form method="post" action="/login?return=${encodeURIComponent(ret)}">
<input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>`);
  }

  function authorizeEndpoint(url: URL, res: ServerResponse): void {
    const q = url.searchParams;
    const client = clients.get(q.get("client_id") ?? "");
    const redirectUri = q.get("redirect_uri") ?? "";
    const login = (): void => {
      res.writeHead(302, { location: `${base}/login?session=${randomBytes(4).toString("hex")}` });
      res.end();
    };
    if (authz.match === "deferred") return login();
    if (!client) return json(res, 400, { error: "invalid_client" });
    const ok =
      authz.match === "any" ||
      (authz.match === "exact" && client.redirectUris.includes(redirectUri)) ||
      (authz.match === "prefix" && client.redirectUris.some((r) => redirectUri.startsWith(r)));
    if (!ok) return json(res, 400, { error: "invalid_request", error_description: "redirect_uri mismatch" });
    if (q.get("code_challenge_method") !== "S256" || !q.get("code_challenge")) return json(res, 400, { error: "invalid_request" });
    if (authz.noSession === "login") return login();
    if (authz.noSession === "auto-approve") {
      const code = newToken("code");
      codes.set(code, { clientId: q.get("client_id") ?? "", redirectUri, challenge: q.get("code_challenge") ?? "", used: false });
      const back = new URL(redirectUri);
      back.searchParams.set("code", code);
      back.searchParams.set("state", q.get("state") ?? "");
      if (authz.issInResponse) back.searchParams.set("iss", base);
      res.writeHead(302, { location: back.toString() });
      res.end();
      return;
    }
    const target = new URL(redirectUri);
    target.searchParams.set("error", "login_required");
    target.searchParams.set("state", q.get("state") ?? "");
    res.writeHead(302, { location: target.toString() });
    res.end();
  }

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://fixture").pathname;
    requests.push({ method: req.method ?? "GET", path });

    void readBody(req).then((body) => {
      if (path === "/mcp") {
        if (opts.anonymous) {
          return json(res, 200, { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "fixture", version: "0" } } });
        }
        const headers: Record<string, string> = opts.challenge
          ? { "www-authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp", scope="mcp"` }
          : {};
        return json(res, 401, { error: "unauthorized" }, headers);
      }
      if (path === "/.well-known/oauth-protected-resource/mcp" && opts.prm) {
        return json(res, 200, { resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: ["mcp"] });
      }
      if (path === "/.well-known/oauth-authorization-server" && opts.asMetadata) {
        return json(res, 200, {
          issuer: base,
          authorization_endpoint: `${base}/authorize`,
          token_endpoint: `${base}/token`,
          ...(authz.registration === "disabled" ? {} : { registration_endpoint: `${base}/register` }),
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: authz.issInResponse,
          token_endpoint_auth_methods_supported: tok.clientSecret ? ["client_secret_post", "client_secret_basic"] : ["none"],
        });
      }
      if (path === "/token" && req.method === "POST") return tokenEndpoint(req, body, res);
      if ((path === "/register" && req.method === "POST") || path === "/authorize") {
        authzRequests += 1;
        if (authz.rateLimitAfter !== undefined && authzRequests > authz.rateLimitAfter) {
          return json(res, 429, { error: "too_many_requests" }, { "retry-after": "60" });
        }
      }
      if (path === "/register" && req.method === "POST") return registerEndpoint(body, res);
      if (path.startsWith("/register/")) return manageEndpoint(req, path.slice("/register/".length), res);
      if (options.consent && path === "/authorize" && req.method === "GET") return consentAuthorize(req, new URL(req.url ?? "/", base), res);
      if (options.consent && path === "/consent" && req.method === "POST") return consentSubmit(req, body, res);
      if (options.consent && path === "/login") return loginPage(req, new URL(req.url ?? "/", base), body, res);
      if (path === "/authorize" && req.method === "GET") return authorizeEndpoint(new URL(req.url ?? "/", base), res);
      if (path === "/.well-known/mcp-authprobe.txt" && opts.ownershipFile !== null) {
        res.writeHead(200, { "content-type": "text/plain" });
        return res.end(opts.ownershipFile);
      }
      json(res, 404, { error: "not_found" });
    });
  });

  const host = options.host ?? "127.0.0.1";
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const { port } = server.address() as AddressInfo;
  base = `http://${host.includes(":") ? `[${host}]` : host}:${port}`;

  return {
    baseUrl: base,
    mcpUrl: `${base}/mcp`,
    requests,
    issueRefreshToken(clientId = "test-client") {
      const token = newToken("rt");
      refreshTokens.set(token, { family: newToken("fam"), clientId, used: false });
      return token;
    },
    tokenRequests: () => tokenCount,
    registeredClients: () => [...clients.keys()],
    issueSession: () => newSession(),
    consentsGranted: () => granted,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
