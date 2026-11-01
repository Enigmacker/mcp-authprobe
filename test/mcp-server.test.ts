import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { configFromEnv, createAuthprobeServer, type ServerConfig } from "../src/mcp-server.js";
import { generateSecret, PROOF_PREFIX } from "../src/ownership.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let client: Client | undefined;

afterEach(async () => {
  await client?.close();
  await fixture?.close();
  client = undefined;
  fixture = undefined;
});

async function connect(config: ServerConfig): Promise<Client> {
  const server = createAuthprobeServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "test-client", version: "0" });
  await client.connect(clientTransport);
  return client;
}

function textOf(result: { content: unknown }): string {
  return (result.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? "").join("\n");
}

describe("MCP server", () => {
  it("exposes five tools with honest annotations", async () => {
    const c = await connect({ allowPrivate: false });
    const { tools } = await c.listTools();
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    expect(Object.keys(byName).sort()).toEqual(["explain_check", "list_checks", "ownership_proof", "scan", "verify_ownership"]);
    expect(byName["scan"]?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    expect(byName["list_checks"]?.annotations?.readOnlyHint).toBe(true);
    // Sensitive settings are never tool arguments.
    const scanProps = Object.keys((byName["scan"]?.inputSchema as { properties?: object }).properties ?? {});
    expect(scanProps).toEqual(["url"]);
  });

  it("lists and explains checks", async () => {
    const c = await connect({ allowPrivate: false });
    expect(textOf(await c.callTool({ name: "list_checks", arguments: {} }))).toContain("MAP-RTK02");
    expect(textOf(await c.callTool({ name: "explain_check", arguments: { id: "MAP-RDR02" } }))).toMatch(/exact string matching|simple string comparison/i);
    const unknown = await c.callTool({ name: "explain_check", arguments: { id: "MAP-XXX99" } });
    expect(unknown.isError).toBe(true);
  });

  it("returns the proof but never the secret", async () => {
    const secret = generateSecret();
    const c = await connect({ allowPrivate: false, secret });
    const out = textOf(await c.callTool({ name: "ownership_proof", arguments: { host: "mcp.example.com" } }));
    expect(out).toContain(PROOF_PREFIX);
    expect(out).not.toContain(secret);
  });

  it("explains how to configure a secret when none is set", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "ownership_proof", arguments: { host: "mcp.example.com" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/MCP_AUTHPROBE_SECRET/);
  });

  it("rejects hosts with a scheme or path", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "verify_ownership", arguments: { host: "https://evil.example/x" } });
    expect(res.isError).toBe(true);
  });

  it("refuses plain http unless private labs are enabled by the human", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "scan", arguments: { url: "http://127.0.0.1:8080/mcp" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/Only https/);
  });

  it("refuses URLs carrying credentials", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "scan", arguments: { url: "https://user:pass@mcp.example.com/mcp" } });
    expect(res.isError).toBe(true);
  });

  it("scans a local lab with the configured grant and returns a structured report", async () => {
    fixture = await startFixture({ tokens: { rejectReplay: false } });
    const dir = mkdtempSync(join(tmpdir(), "map-mcp-"));
    const creds = join(dir, "grant.json");
    writeFileSync(creds, JSON.stringify({ client_id: "test-client", refresh_token: fixture.issueRefreshToken() }));
    chmodSync(creds, 0o600);

    const c = await connect({ allowPrivate: true, credentialsFile: creds });
    const res = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl } });
    expect(res.isError).toBeFalsy();
    const out = textOf(res);
    expect(out).toMatch(/failing check/);
    expect(out).toMatch(/never instructions/);
    expect(out).not.toMatch(/rt_[0-9a-f]{32}/);
    const report = (res.structuredContent as { report: { findings: Array<{ checkId: string; status: string }> } }).report;
    expect(report.findings.find((f) => f.checkId === "MAP-RTK02")?.status).toBe("fail");
    expect(fixture.registeredClients()).toEqual([]);
  });
});

describe("configFromEnv", () => {
  it("reads settings only from the environment", () => {
    const cfg = configFromEnv({ MCP_AUTHPROBE_SECRET: " s ", MCP_AUTHPROBE_ALLOW_PRIVATE: "1", MCP_AUTHPROBE_TIMEOUT_MS: "5000", MCP_AUTHPROBE_CREDENTIALS_FILE: "/x.json" });
    expect(cfg).toEqual({ secret: "s", allowPrivate: true, timeoutMs: 5000, credentialsFile: "/x.json" });
    expect(configFromEnv({ MCP_AUTHPROBE_ALLOW_PRIVATE: "true" }).allowPrivate).toBe(false);
  });
});
