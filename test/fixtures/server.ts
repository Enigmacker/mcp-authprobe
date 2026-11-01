import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * Local fixture: a minimal MCP resource server and authorization server
 * metadata on 127.0.0.1. It never leaves the machine. Behaviour is switched
 * by options so tests can model compliant and misconfigured servers.
 */
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
}

export interface Fixture {
  baseUrl: string;
  mcpUrl: string;
  requests: Array<{ method: string; path: string }>;
  close(): Promise<void>;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export async function startFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const opts = { challenge: true, prm: true, asMetadata: true, ownershipFile: null, anonymous: false, ...options };
  const requests: Fixture["requests"] = [];
  let base = "";

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://fixture").pathname;
    requests.push({ method: req.method ?? "GET", path });
    req.resume();

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
        token_endpoint_auth_methods_supported: ["none"],
      });
    }
    if (path === "/.well-known/mcp-authprobe.txt" && opts.ownershipFile !== null) {
      res.writeHead(200, { "content-type": "text/plain" });
      return res.end(opts.ownershipFile);
    }
    json(res, 404, { error: "not_found" });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;

  return {
    baseUrl: base,
    mcpUrl: `${base}/mcp`,
    requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
