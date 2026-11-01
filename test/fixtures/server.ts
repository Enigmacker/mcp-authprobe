import { randomBytes } from "node:crypto";
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
}

export interface Fixture {
  baseUrl: string;
  mcpUrl: string;
  requests: Array<{ method: string; path: string }>;
  /** Create a fresh grant and return its refresh token. */
  issueRefreshToken(clientId?: string): string;
  /** Number of token requests received so far. */
  tokenRequests(): number;
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
  const tok: Required<Omit<TokenBehaviour, "clientSecret">> & { clientSecret?: string } = {
    rotate: true,
    returnSameRefresh: false,
    rejectReplay: true,
    revokeFamily: true,
    throttle: false,
    ...options.tokens,
  };
  const requests: Fixture["requests"] = [];
  const refreshTokens = new Map<string, RefreshRecord>();
  const revokedFamilies = new Set<string>();
  let tokenCount = 0;
  let base = "";

  function tokenEndpoint(req: IncomingMessage, body: string, res: ServerResponse): void {
    tokenCount += 1;
    if (tok.throttle) return json(res, 429, { error: "slow_down" }, { "retry-after": "30" });

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
    if (form.get("grant_type") !== "refresh_token") return json(res, 400, { error: "unsupported_grant_type" });

    const presented = form.get("refresh_token") ?? "";
    const record = refreshTokens.get(presented);
    if (!record || record.clientId !== clientId || revokedFamilies.has(record.family)) {
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
          registration_endpoint: `${base}/register`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: tok.clientSecret ? ["client_secret_post", "client_secret_basic"] : ["none"],
        });
      }
      if (path === "/token" && req.method === "POST") return tokenEndpoint(req, body, res);
      if (path === "/.well-known/mcp-authprobe.txt" && opts.ownershipFile !== null) {
        res.writeHead(200, { "content-type": "text/plain" });
        return res.end(opts.ownershipFile);
      }
      json(res, 404, { error: "not_found" });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;

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
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
