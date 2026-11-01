import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CATALOGUE } from "../src/checks/catalogue.js";
import { main, EXIT } from "../src/cli.js";
import { toJson } from "../src/report/json.js";
import { toMarkdown } from "../src/report/markdown.js";
import { toSarif } from "../src/report/sarif.js";
import { hostsToVerify, scan } from "../src/scan.js";
import type { ScanReport } from "../src/types.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

describe("catalogue", () => {
  it("has unique, well-formed IDs", () => {
    const ids = CATALOGUE.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const c of CATALOGUE) {
      expect(c.id).toMatch(/^MAP-[A-Z]{3}\d{2}$/);
      expect(c.id.slice(4, 7)).toBe(c.family);
      expect(c.references.length).toBeGreaterThan(0);
    }
  });
});

describe("scan", () => {
  it("discovers a compliant loopback lab and treats it as owned", async () => {
    fixture = await startFixture();
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    expect(report.ownership.verified).toBe(true);
    expect(report.findings.find((f) => f.checkId === "MAP-DSC01")?.status).toBe("pass");
  });

  it("skips every active check when ownership is not proven", async () => {
    fixture = await startFixture();
    // Without --allow-private the loopback fixture cannot even be contacted.
    const report = await scan(fixture.mcpUrl, {});
    expect(report.ownership.verified).toBe(false);
    const active = report.findings.filter((f) => CATALOGUE.find((c) => c.id === f.checkId)?.active);
    expect(active.length).toBeGreaterThan(0);
    expect(active.every((f) => f.status === "skipped")).toBe(true);
    expect(report.findings.find((f) => f.checkId === "MAP-DSC01")?.status).toBe("error");
  });

  it("fails discovery when metadata is missing", async () => {
    fixture = await startFixture({ prm: false, challenge: false });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    const dsc = report.findings.find((f) => f.checkId === "MAP-DSC01");
    expect(dsc?.status).toBe("fail");
    expect(dsc?.message).toMatch(/Protected Resource Metadata/);
  });

  it("runs the refresh token checks when a test grant is supplied", async () => {
    fixture = await startFixture({ tokens: { revokeFamily: false } });
    const grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" as const };
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, grant });
    const status = (id: string) => report.findings.find((f) => f.checkId === id)?.status;
    expect([status("MAP-RTK01"), status("MAP-RTK02"), status("MAP-RTK03")]).toEqual(["pass", "pass", "fail"]);
  });

  it("skips the refresh token checks without a test grant, sending no token request", async () => {
    fixture = await startFixture();
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    const rtk = report.findings.filter((f) => f.checkId.startsWith("MAP-RTK"));
    expect(rtk).toHaveLength(3);
    expect(rtk.every((f) => f.status === "skipped" && /credentials-file/.test(f.message))).toBe(true);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it("never sends a token request when ownership is not proven", async () => {
    fixture = await startFixture();
    const grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" as const };
    await scan(fixture.mcpUrl, { grant });
    expect(fixture.tokenRequests()).toBe(0);
  });

  it("asks for proof on the authorization server host too", () => {
    const hosts = hostsToVerify("https://mcp.example.com/mcp", {
      mcpUrl: "https://mcp.example.com/mcp",
      challenge: { status: 401, wwwAuthenticate: null, resourceMetadataUrl: null },
      prm: null,
      as: { url: "x", metadata: { authorization_endpoint: "https://auth.example.net/authorize", token_endpoint: "https://auth.example.net/token" } },
      notes: [],
    });
    expect(hosts).toEqual(["mcp.example.com", "auth.example.net"]);
  });
});

const sample: ScanReport = {
  tool: { name: "mcp-authprobe", version: "test" },
  startedAt: "2026-11-01T00:00:00.000Z",
  finishedAt: "2026-11-01T00:00:01.000Z",
  target: "https://mcp.example.com/mcp",
  ownership: { verified: true, method: "well-known", detail: "ok" },
  findings: [
    { checkId: "MAP-RTK02", title: "t", severity: "critical", status: "fail", target: "https://mcp.example.com/mcp", message: "replay | accepted", evidence: ["e1"] },
    { checkId: "MAP-DSC01", title: "t", severity: "info", status: "pass", target: "https://mcp.example.com/mcp", message: "ok", evidence: [] },
  ],
};

describe("reports", () => {
  it("JSON carries a schema tag", () => {
    expect(JSON.parse(toJson(sample)).schema).toBe("mcp-authprobe/report/v1");
  });

  it("SARIF lists every rule and only failures as results", () => {
    const sarif = JSON.parse(toSarif(sample));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(CATALOGUE.length);
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0]).toMatchObject({ ruleId: "MAP-RTK02", level: "error" });
  });

  it("Markdown escapes table cells and lists failures first", () => {
    const md = toMarkdown(sample);
    expect(md).toContain("replay \\| accepted");
    expect(md.indexOf("MAP-RTK02")).toBeLessThan(md.indexOf("MAP-DSC01"));
  });
});

describe("cli", () => {
  it("returns usage errors with code 2", async () => {
    expect(await main(["scan", "not a url"])).toBe(EXIT.usage);
    expect(await main(["scan", "https://x.example", "--fail-on", "extreme"])).toBe(EXIT.usage);
    expect(await main(["checks", "show", "MAP-XXX99"])).toBe(EXIT.usage);
  });

  it("lists checks", async () => {
    expect(await main(["checks", "list"])).toBe(EXIT.ok);
  });

  it("exits 0 on a clean lab scan", async () => {
    fixture = await startFixture();
    expect(await main(["scan", fixture.mcpUrl, "--allow-private"])).toBe(EXIT.ok);
  });

  it("exits 1 when a refresh token can be replayed", async () => {
    fixture = await startFixture({ tokens: { rejectReplay: false } });
    const dir = mkdtempSync(join(tmpdir(), "map-cli-"));
    const creds = join(dir, "creds.json");
    writeFileSync(creds, JSON.stringify({ client_id: "test-client", refresh_token: fixture.issueRefreshToken() }), { mode: 0o600 });
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--credentials-file", creds])).toBe(EXIT.findings);
  });

  it("rejects an unreadable credentials file as a usage error", async () => {
    expect(await main(["scan", "https://x.example/mcp", "--credentials-file", "/nonexistent/creds.json"])).toBe(EXIT.usage);
  });
});
