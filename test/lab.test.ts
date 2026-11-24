import { afterEach, describe, expect, it } from "vitest";
import type { TestGrant } from "../src/credentials.js";
import { discover } from "../src/discovery.js";
import { LabUsageError, startLab } from "../src/lab-command.js";
import { connect } from "node:net";
import { startFixture, type Fixture } from "../src/lab/server.js";
import { login } from "../src/login.js";
import { bearerCredential } from "../src/oauth/mcp-call.js";
import { HttpClient } from "../src/net/http.js";
import { scan } from "../src/scan.js";

let lab: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await lab?.close();
  await http?.close();
  lab = undefined;
  http = undefined;
});

/** A scripted user: logs in with test / test and clicks Allow on the consent page. */
async function user(authorizationUrl: string): Promise<void> {
  const first = await fetch(authorizationUrl, { redirect: "manual" });
  const loginUrl = new URL(first.headers.get("location") ?? "", authorizationUrl);
  const logged = await fetch(loginUrl, { method: "POST", redirect: "manual", body: new URLSearchParams({ username: "test", password: "test" }) });
  const cookie = (logged.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
  const page = await (await fetch(authorizationUrl, { headers: { cookie } })).text();
  const form = new URLSearchParams();
  for (const m of page.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) form.set(m[1] as string, (m[2] as string).replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&amp;/g, "&"));
  form.set("decision", "allow");
  const consent = await fetch(new URL("/consent", authorizationUrl), { method: "POST", redirect: "manual", headers: { cookie }, body: form });
  await fetch(consent.headers.get("location") ?? "", { redirect: "manual" });
}

async function runLab(profile: string) {
  const started = await startLab({ profile, port: 0, host: "127.0.0.1" });
  lab = started.lab;
  http = new HttpClient({ allowPrivate: true });
  const discovery = await discover(lab.mcpUrl, http);
  const result = await login({ http, mcpUrl: lab.mcpUrl, discovery, openUrl: user, probe: true, timeoutMs: 5000 });
  const report = await scan(lab.mcpUrl, { allowPrivate: true, grant: result.grant as TestGrant, observations: result.observations, throttleAttempts: 10 });
  const status = Object.fromEntries(report.findings.map((f) => [f.checkId, f.status]));
  return { started, result, status };
}

describe("lab", () => {
  it("refuses a non-loopback address, an unknown profile and a bad port", async () => {
    await expect(startLab({ profile: "vulnerable", port: 0, host: "0.0.0.0" })).rejects.toBeInstanceOf(LabUsageError);
    await expect(startLab({ profile: "nope", port: 0, host: "127.0.0.1" })).rejects.toThrow(/Unknown profile/);
    await expect(startLab({ profile: "secure", port: 70000, host: "127.0.0.1" })).rejects.toThrow(/--port/);
  });

  it("accepts only literal loopback addresses and decimal ports", async () => {
    for (const host of ["localhost", "foo.localhost", "127.0.0.2", "::ffff:127.0.0.1"]) {
      await expect(startLab({ profile: "secure", port: 0, host })).rejects.toBeInstanceOf(LabUsageError);
    }
    for (const port of ["", " 0x10 ", "1e3", "8787abc", "-1"]) {
      await expect(startLab({ profile: "secure", port, host: "127.0.0.1" })).rejects.toThrow(/--port/);
    }
    await expect(startFixture({ host: "0.0.0.0" })).rejects.toThrow(/only listens/);
    const started = await startLab({ profile: "secure", port: "0", host: "[::1]" }).catch((e: Error) => e);
    if (started instanceof Error) expect(started.message).toMatch(/EADDRNOTAVAIL|EAFNOSUPPORT/); // no IPv6 here
    else await started.lab.close();
  });

  it("survives malformed requests", async () => {
    const started = await startLab({ profile: "vulnerable", port: 0, host: "127.0.0.1" });
    lab = started.lab;
    const { port } = new URL(lab.baseUrl);
    const raw = (text: string): Promise<string> =>
      new Promise((resolve) => {
        const sock = connect(Number(port), "127.0.0.1", () => sock.end(text));
        let out = "";
        sock.on("data", (d) => (out += d.toString()));
        sock.on("close", () => resolve(out));
        sock.on("error", () => resolve(out));
      });
    expect(await raw("GET http://[bad/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")).toMatch(/^HTTP\/1\.1 400/);
    const basic = Buffer.from("%zz:x").toString("base64");
    expect((await fetch(`${lab.baseUrl}/token`, { method: "POST", headers: { authorization: `Basic ${basic}` }, body: "grant_type=refresh_token" })).status).toBe(400);
    const reg = (await (await fetch(`${lab.baseUrl}/register`, { method: "POST", body: JSON.stringify({ redirect_uris: ["x"] }) })).json()) as { client_id: string };
    const sid = lab.issueSession();
    const consent = await fetch(`${lab.baseUrl}/consent`, { method: "POST", headers: { cookie: `sid=${sid}` }, body: new URLSearchParams({ client_id: reg.client_id, redirect_uri: "x", decision: "allow" }) });
    expect(consent.status).toBe(400);
    expect((await fetch(`${lab.baseUrl}/register`, { method: "POST", body: "x".repeat(100_000) }).catch(() => null))?.status ?? 413).toBe(413);
    expect((await fetch(lab.mcpUrl, { method: "POST" })).status).toBe(401); // still alive
  });

  it("vulnerable: login and scan report the planted flaws", async () => {
    const { started, result, status } = await runLab("vulnerable");
    expect(started.banner).toMatch(/test \/ test/);
    expect(result.grant).not.toBeNull();
    expect(status).toMatchObject({
      "MAP-DSC01": "pass",
      "MAP-RTK01": "pass",
      "MAP-RTK02": "fail",
      "MAP-RDR02": "error",
      "MAP-RDR04": "fail",
      "MAP-PKC01": "fail",
      "MAP-AUD01": "fail",
      "MAP-ORG01": "fail",
      "MAP-TOK01": "fail",
      "MAP-SES01": "fail",
      "MAP-COR01": "fail",
      "MAP-THR01": "fail",
      "MAP-INJ01": "fail",
    });
  });

  it("secure: every check passes, is not applicable, or needs the browser", async () => {
    const { result, status } = await runLab("secure");
    expect(result.grant).not.toBeNull();
    const notPassing = Object.entries(status).filter(([, s]) => s !== "pass" && s !== "not_applicable");
    // CSR01 needs the browser; THR02 needs a static key (OAuth profile).
    expect(notPassing.sort()).toEqual([["MAP-CSR01", "skipped"], ["MAP-THR02", "skipped"]]);
  });

  it.each([
    ["static-bearer", "fail"],
    ["static-bearer-secure", "pass"],
  ] as const)("%s: a scan with the printed key reports the expected results", async (profile, expected) => {
    const started = await startLab({ profile, port: 0, host: "127.0.0.1" });
    lab = started.lab;
    const key = /API key for this run: (\S+)/.exec(started.banner)?.[1] as string;
    expect(key).toMatch(/^lab_/);
    const report = await scan(lab.mcpUrl, { allowPrivate: true, credential: bearerCredential(key, "authorization", "static") });
    const status = Object.fromEntries(report.findings.map((f) => [f.checkId, f.status]));
    expect(status["MAP-DSC01"]).toBe("not_applicable");
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"]) expect([id, status[id]]).toEqual([id, expected]);
    expect(status["MAP-COR01"]).toBe(expected);
  });
});

describe("lab profiles for MCP 2026-07-28 and pre-registered clients", () => {
  const modernHeaders = { "content-type": "application/json", "mcp-protocol-version": "2026-07-28" };
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "t", version: "0" }, "io.modelcontextprotocol/clientCapabilities": {} };
  const post = (url: string, headers: Record<string, string>, body: unknown): Promise<Response> => fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  let lab: Awaited<ReturnType<typeof startLab>>["lab"] | undefined;
  afterEach(async () => {
    await lab?.close();
    lab = undefined;
  });

  it("modern: speaks 2026-07-28 only, as the specification describes", async () => {
    ({ lab } = await startLab({ profile: "modern", port: 0, host: "127.0.0.1" }));
    const { startFixture } = await import("../src/lab/server.js");
    await lab.close();
    lab = await startFixture({ anonymous: true, mcp: { protocol: "modern", sessions: false, metadata: "clean" } });
    const url = lab.mcpUrl;
    // A legacy client: no required header.
    const legacy = await post(url, { "content-type": "application/json" }, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    expect(legacy.status).toBe(400);
    const legacyBody = (await legacy.json()) as { error: { code: number; message: string } };
    expect(legacyBody.error.code).toBe(-32020);
    expect(legacyBody.error.message).toContain("2026-07-28");
    // server/discover
    const ok = await post(url, { ...modernHeaders, "mcp-method": "server/discover" }, { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("mcp-session-id")).toBeNull();
    expect(((await ok.json()) as { result: { supportedVersions: string[]; resultType: string } }).result).toMatchObject({ supportedVersions: ["2026-07-28"], resultType: "complete" });
    // Header and body disagree.
    expect((await post(url, { ...modernHeaders, "mcp-method": "tools/list" }, { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } })).status).toBe(400);
    // Removed and unknown methods.
    const ping = await post(url, { ...modernHeaders, "mcp-method": "ping" }, { jsonrpc: "2.0", id: 1, method: "ping", params: { _meta: meta } });
    expect(ping.status).toBe(404);
    expect(((await ping.json()) as { error: { code: number } }).error.code).toBe(-32601);
    // Unsupported version.
    const old = await post(url, { "content-type": "application/json", "mcp-protocol-version": "2025-11-25", "mcp-method": "server/discover" }, { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: { ...meta, "io.modelcontextprotocol/protocolVersion": "2025-11-25" } } });
    expect(old.status).toBe(400);
    expect(((await old.json()) as { error: { code: number; data: { supported: string[] } } }).error).toMatchObject({ code: -32022, data: { supported: ["2026-07-28"] } });
    // No GET stream, no session to end.
    expect((await fetch(url)).status).toBe(405);
    expect((await fetch(url, { method: "DELETE" })).status).toBe(405);
  });

  it("dual: answers initialize with a session and server/discover without one", async () => {
    const { startFixture } = await import("../src/lab/server.js");
    lab = await startFixture({ anonymous: true, mcp: { protocol: "dual" } });
    const init = await post(lab.mcpUrl, { "content-type": "application/json" }, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).not.toBeNull();
    const discover = await post(lab.mcpUrl, { ...modernHeaders, "mcp-method": "server/discover" }, { jsonrpc: "2.0", id: 2, method: "server/discover", params: { _meta: meta } });
    expect(discover.headers.get("mcp-session-id")).toBeNull();
    expect(((await discover.json()) as { result: { supportedVersions: string[] } }).result.supportedVersions).toEqual(["2026-07-28", "2025-11-25"]);
  });

  it("preregistered: no registration endpoint, one client that works", async () => {
    let banner: string;
    ({ lab, banner } = await startLab({ profile: "preregistered", port: 0, host: "127.0.0.1", autoApprove: true }));
    expect(banner).toContain("lab-preregistered-client");
    const as = (await (await fetch(`${lab.baseUrl}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(as["registration_endpoint"]).toBeUndefined();
    expect((await fetch(`${lab.baseUrl}/register`, { method: "POST", body: "{}" })).status).toBe(404);
    const authorize = new URL(`${lab.baseUrl}/authorize`);
    for (const [k, v] of Object.entries({ response_type: "code", client_id: "lab-preregistered-client", redirect_uri: "https://app.mcp-authprobe.invalid/oauth/callback", state: "s", code_challenge: "c".repeat(43), code_challenge_method: "S256" })) authorize.searchParams.set(k, v);
    const res = await fetch(authorize, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location") as string).searchParams.get("code")).toMatch(/^code_/);
    authorize.searchParams.set("redirect_uri", "https://elsewhere.mcp-authprobe.invalid/callback");
    expect((await fetch(authorize, { redirect: "manual" })).status).toBe(400);
    expect(lab.registeredClients()).toEqual([]);
  });

  it("the limit on failed token requests is per client and lifts after its window", async () => {
    const { startFixture } = await import("../src/lab/server.js");
    lab = await startFixture({ tokens: { rateLimitAfter: 2, rateLimitWindowMs: 150 } });
    const attempt = async (client: string): Promise<number> =>
      (await fetch(`${lab!.baseUrl}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "nope", client_id: client }) })).status;
    expect([await attempt("a"), await attempt("a"), await attempt("a")]).toEqual([400, 400, 429]);
    expect(await attempt("b")).toBe(400);
    await new Promise((r) => setTimeout(r, 200));
    expect(await attempt("a")).toBe(400);
  });
});
