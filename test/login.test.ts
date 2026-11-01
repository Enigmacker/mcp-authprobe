import { lstatSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadGrant, writeGrantFile, type TestGrant } from "../src/credentials.js";
import { discover } from "../src/discovery.js";
import { login, LoginError, type LoginResult } from "../src/login.js";
import { HttpClient } from "../src/net/http.js";
import { scan } from "../src/scan.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

/** A scripted "browser": follows the authorization redirect back to the loopback listener. */
function browser(tamper?: (location: URL) => void) {
  return async (url: string): Promise<void> => {
    const res = await fetch(url, { redirect: "manual" });
    const location = res.headers.get("location");
    if (!location) return;
    const back = new URL(location);
    tamper?.(back);
    await fetch(back, { redirect: "manual" });
  };
}

async function runLogin(
  options: FixtureOptions,
  extra: { probe?: boolean; tamper?: (l: URL) => void; timeoutMs?: number } = {},
): Promise<LoginResult> {
  fixture = await startFixture({ authorization: { noSession: "auto-approve" }, ...options });
  http = new HttpClient({ allowPrivate: true });
  const discovery = await discover(fixture.mcpUrl, http);
  return login({
    http,
    mcpUrl: fixture.mcpUrl,
    discovery,
    openUrl: browser(extra.tamper),
    probeRedirectBinding: extra.probe ?? true,
    timeoutMs: extra.timeoutMs ?? 5000,
  });
}

describe("login", () => {
  it("obtains a working test grant and observes MAP-RDR03 as passing", async () => {
    const result = await runLogin({});
    expect(result.grant).toMatchObject({ authMethod: "none", target: (fixture as Fixture).mcpUrl, tokenEndpoint: `${(fixture as Fixture).baseUrl}/token` });
    expect(result.observations.map((o) => [o.checkId, o.status])).toEqual([["MAP-RDR03", "pass"]]);

    // The grant and observation feed a full scan.
    const report = await scan((fixture as Fixture).mcpUrl, { allowPrivate: true, grant: result.grant as TestGrant, observations: result.observations });
    const status = (id: string) => report.findings.find((f) => f.checkId === id)?.status;
    expect([status("MAP-RTK01"), status("MAP-RTK02"), status("MAP-RTK03"), status("MAP-RDR03")]).toEqual(["pass", "pass", "pass", "pass"]);
    expect(report.findings.find((f) => f.checkId === "MAP-RDR03")?.evidence.at(-1)).toMatch(/observed during login/);
  });

  it("flags a token endpoint that ignores redirect_uri, and keeps the tokens it issued", async () => {
    const result = await runLogin({ tokens: { bindRedirect: false } });
    expect(result.observations[0]).toMatchObject({ checkId: "MAP-RDR03", status: "fail" });
    expect(result.grant).not.toBeNull();
  });

  it("explains a strict server that burns the code after a refused attempt, and removes the client", async () => {
    const result = await runLogin({ tokens: { consumeCodeOnFailure: true } });
    expect(result.observations[0]?.status).toBe("pass");
    expect(result.grant).toBeNull();
    expect(result.notes.join(" ")).toMatch(/--no-probe/);
    expect((fixture as Fixture).registeredClients()).toEqual([]);
  });

  it("skips the probe when ownership is not proven", async () => {
    const result = await runLogin({}, { probe: false });
    expect(result.observations).toEqual([]);
    expect(result.grant).not.toBeNull();
    expect(result.notes.join(" ")).toMatch(/not proven/);
  });

  it("aborts on an issuer mismatch (RFC 9207)", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.set("iss", "https://other.example") })).rejects.toThrow(/iss parameter does not match/);
    expect((fixture as Fixture).registeredClients()).toEqual([]);
  });

  it("aborts when an announced iss is missing", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.delete("iss") })).rejects.toThrow(/has none/);
  });

  it("ignores callbacks with a wrong state and times out", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.set("state", "forged"), timeoutMs: 500 })).rejects.toBeInstanceOf(LoginError);
  });

  it("never prints tokens in notes or observations", async () => {
    const result = await runLogin({});
    const text = JSON.stringify({ o: result.observations, n: result.notes });
    expect(text).not.toMatch(/(rt|at|code)_[0-9a-f]{32}/);
  });
});

describe("grant file", () => {
  const grant: TestGrant = { clientId: "c", refreshToken: "r", authMethod: "none" };

  it("is written with mode 600, round-trips with observations, and is never silently overwritten", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "grant.json");
    const obs = [{ checkId: "MAP-RDR03", title: "t", severity: "medium" as const, status: "pass" as const, target: "https://x.example/mcp", message: "m", evidence: [], observedAt: "2026-11-01T00:00:00Z" }];
    writeGrantFile(path, grant, obs);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
    const loaded = loadGrant(path);
    expect(loaded.grant).toEqual(grant);
    expect(loaded.observations).toEqual(obs);
    expect(() => writeGrantFile(path, grant, [])).toThrow(/EEXIST/);
    writeGrantFile(path, { ...grant, refreshToken: "r2" }, [], true);
    expect(JSON.parse(readFileSync(path, "utf8")).refresh_token).toBe("r2");
  });

  it("restores mode 600 when overwriting a permissive file", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "grant.json");
    writeFileSync(path, "{}", { mode: 0o644 });
    writeGrantFile(path, grant, [], true);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it.skipIf(process.platform === "win32")("refuses to write through a symbolic link", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "keep me");
    const link = join(dir, "grant.json");
    symlinkSync(victim, link);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(() => writeGrantFile(link, grant, [], true)).toThrow();
    expect(readFileSync(victim, "utf8")).toBe("keep me");
  });

  it("ignores malformed observations", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "g.json");
    writeFileSync(path, JSON.stringify({ client_id: "c", refresh_token: "r", observations: [{ checkId: "MAP-RDR03", status: "pwned" }, 42] }), { mode: 0o600 });
    expect(loadGrant(path).observations).toEqual([]);
  });
});
