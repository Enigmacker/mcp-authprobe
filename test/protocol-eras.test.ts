import { mkdtempSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { loadGrant } from "../src/credentials.js";
import { discover, resourceMatches } from "../src/discovery.js";
import { LAB_CLIENT, LAB_PROFILES } from "../src/lab/profiles.js";
import { beginLogin, completeLogin, login, LoginError } from "../src/login.js";
import { HttpClient } from "../src/net/http.js";
import { bearerCredential, detectEra, methodFor, paddedNoop, rpcMessage } from "../src/oauth/mcp-call.js";
import { registerClient } from "../src/oauth/registration.js";
import { nearMissVariants, NEAR_MISS_VARIANTS } from "../src/checks/redirect-uris.js";
import { scan } from "../src/scan.js";
import type { Finding, ScanReport } from "../src/types.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixtures/server.js";

const KEY = "sk_era_0123456789abcdef";
let fixture: Fixture | undefined;
let http: HttpClient | undefined;
let server: Server | undefined;
afterEach(async () => {
  await fixture?.close();
  await http?.close();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  fixture = undefined;
  http = undefined;
  server = undefined;
});

const by = (r: ScanReport): Record<string, Finding> => Object.fromEntries(r.findings.map((f) => [f.checkId, f]));
const cred = bearerCredential(KEY, "authorization", "static");
const keyServer = (mcp: NonNullable<FixtureOptions["mcp"]>, extra: FixtureOptions = {}): FixtureOptions => ({ prm: false, asMetadata: false, challenge: "bearer", staticKey: { value: KEY }, ...extra, mcp });
const ENDPOINT = ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"];
const dir = (): string => mkdtempSync(join(tmpdir(), "map-era-"));

/** A scripted "browser" for a lab with --auto-approve: fetches the authorization URL and returns where it was sent back to. */
async function approve(url: string): Promise<string> {
  const res = await fetch(url, { redirect: "manual" });
  const location = res.headers.get("location");
  if (!location) throw new Error(`no redirect (HTTP ${res.status})`);
  return location;
}
const browser = async (url: string): Promise<void> => {
  await fetch(await approve(url), { redirect: "manual" });
};

describe("MCP 2026-07-28 (stateless) and 2025-11-25 (handshake)", () => {
  it("builds requests of each era as the specifications describe", () => {
    expect(rpcMessage("legacy", "ping")).toEqual({ jsonrpc: "2.0", id: 1, method: "ping" });
    const modern = rpcMessage("modern", "ping", 7) as { method: string; params: { _meta: Record<string, unknown> } };
    expect(modern.method).toBe("server/discover");
    expect(modern.params._meta["io.modelcontextprotocol/protocolVersion"]).toBe("2026-07-28");
    expect(modern.params._meta["io.modelcontextprotocol/clientInfo"]).toMatchObject({ name: "mcp-authprobe" });
    expect(modern.params._meta["io.modelcontextprotocol/clientCapabilities"]).toEqual({});
    expect(methodFor("modern", "initialize")).toBe("server/discover");
    expect(methodFor("modern", "tools/list")).toBe("tools/list");
    expect(methodFor("legacy", undefined)).toBe("initialize");
    for (const era of ["legacy", "modern"] as const) {
      const padded = paddedNoop(era, 4096);
      expect(padded).toHaveLength(4096);
      expect((JSON.parse(padded) as { method: string }).method).toBe(era === "modern" ? "server/discover" : "ping");
    }
  });

  it("passes every key check on a compliant 2026-07-28-only server, without initialize, ping or DELETE", async () => {
    fixture = await startFixture(keyServer({ protocol: "modern", sessions: false, metadata: "clean", rateLimit: 25 }));
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred });
    const f = by(report);
    expect(report.discovery?.protocol).toMatchObject({ era: "modern", version: "2026-07-28", supportedVersions: ["2026-07-28"] });
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"]) expect(f[id]?.status, id).toBe("pass");
    expect(f["MAP-SES01"]?.status).toBe("not_applicable");
    expect(f["MAP-SES01"]?.message).toMatch(/2026-07-28.*no protocol session/);
    expect(f["MAP-ORG01"]?.evidence.join(" ")).toMatch(/server\/discover/);
    const methods = new Set(fixture.mcpMethods());
    expect(methods.has("initialize")).toBe(false);
    expect(methods.has("ping")).toBe(false);
    expect(methods.has("notifications/initialized")).toBe(false);
    expect(fixture.requests.some((r) => r.method === "DELETE")).toBe(false);
  });

  it("finds the same flaws on a vulnerable 2026-07-28-only server", async () => {
    fixture = await startFixture(keyServer({ protocol: "modern", sessions: false, metadata: "poisoned", validateOrigin: false, acceptQueryToken: true, batch: true }, { maxBodyBytes: 16 * 1024 * 1024 }));
    const f = by(await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred }));
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"]) expect(f[id]?.status, id).toBe("fail");
  });

  it("prefers the modern era on a dual server, and keeps the handshake on a legacy one", async () => {
    fixture = await startFixture(keyServer({ protocol: "dual", metadata: "clean" }));
    const dual = await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred, select: (id) => ENDPOINT.includes(id) });
    expect(dual.discovery?.protocol.era).toBe("modern");
    expect(by(dual)["MAP-SES01"]?.status).toBe("not_applicable");
    const forced = await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred, protocol: "legacy", select: (id) => ENDPOINT.includes(id) });
    expect(forced.discovery?.protocol.era).toBe("legacy");
    expect(by(forced)["MAP-SES01"]?.status).toBe("pass");
    await fixture.close();
    fixture = await startFixture(keyServer({ metadata: "clean" }));
    const legacy = await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred, select: (id) => ENDPOINT.includes(id) });
    expect(legacy.discovery?.protocol).toMatchObject({ era: "legacy", version: "2025-11-25" });
    for (const id of ENDPOINT) expect(by(legacy)[id]?.status, id).toBe("pass");
  });

  it("does not blame the key when it is the protocol that is refused", async () => {
    fixture = await startFixture(keyServer({ protocol: "modern", sessions: false }));
    const f = by(await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred, protocol: "legacy", select: (id) => ENDPOINT.includes(id) }));
    // Forcing the handshake on a server that only speaks 2026-07-28: what 0.10 did to every such server.
    expect(f["MAP-TOK01"]?.status).toBe("error");
    expect(f["MAP-TOK01"]?.message).not.toMatch(/did not accept the key/);
  });

  it("detects the era anonymously only when the server answers anonymously", async () => {
    http = new HttpClient({ allowPrivate: true });
    fixture = await startFixture({ anonymous: true, mcp: { protocol: "modern", sessions: false } });
    expect((await detectEra(http, fixture.mcpUrl)).dialect.era).toBe("modern");
    await fixture.close();
    fixture = await startFixture({ mcp: { protocol: "modern", sessions: false } });
    const protectedServer = await detectEra(http, fixture.mcpUrl);
    expect(protectedServer.dialect.era).toBe("unknown");
    expect(protectedServer.undetermined).toBe("auth_required");
    // Discovery still gets its 401 challenge and the metadata.
    const d = await discover(fixture.mcpUrl, http);
    expect(d.challenge.status).toBe(401);
    expect(d.as?.metadata.token_endpoint).toBe(`${fixture.baseUrl}/token`);
  });

  it("names the deprecated HTTP+SSE transport instead of blaming the credential", async () => {
    server = createServer((req, res) => {
      req.resume();
      if (req.url !== "/sse") return void res.writeHead(404).end();
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: endpoint\ndata: /messages?sessionId=1\n\n");
        return; // the stream stays open, as on a real server
      }
      res.writeHead(405).end();
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/sse`;
    const report = await scan(url, { allowPrivate: true, credential: cred, select: (id) => ["MAP-DSC01", "MAP-TOK01"].includes(id) });
    expect(report.discovery?.protocol.transport).toBe("http+sse");
    expect(report.discovery?.notes.join(" ")).toMatch(/deprecated HTTP\+SSE transport/);
    expect(by(report)["MAP-TOK01"]).toMatchObject({ status: "error", reason: "protocol_unsupported" });
    expect(by(report)["MAP-TOK01"]?.message).toMatch(/HTTP\+SSE/);
    server.closeAllConnections();
  });

  it("login observes its ten checks on a 2026-07-28-only server", async () => {
    fixture = await startFixture({ ...LAB_PROFILES.modern.options, consent: undefined as never, authorization: { match: "exact", registration: "strict", noSession: "auto-approve" } } as FixtureOptions);
    http = new HttpClient({ allowPrivate: true });
    const result = await login({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), openUrl: browser, probe: true, timeoutMs: 5000 });
    const status = Object.fromEntries(result.observations.map((o) => [o.checkId, o.status]));
    expect(status).toMatchObject({ "MAP-PKC01": "pass", "MAP-RDR03": "pass", "MAP-ORG01": "pass", "MAP-TOK01": "pass", "MAP-SES01": "not_applicable", "MAP-BAT01": "pass", "MAP-BOD01": "pass", "MAP-INJ01": "pass", "MAP-AUD01": "pass", "MAP-COD01": "pass" });
    expect(new Set(fixture.mcpMethods()).has("initialize")).toBe(false);
  });
});

describe("clients without dynamic registration", () => {
  const prereg = (extra: Partial<NonNullable<FixtureOptions["authorization"]>> = {}, tokens: FixtureOptions["tokens"] = { rateLimitAfter: 5 }): FixtureOptions => ({
    tokens,
    authorization: { match: "exact", registration: "disabled", noSession: "auto-approve", clients: [{ clientId: LAB_CLIENT.clientId, redirectUris: [...LAB_CLIENT.redirectUris, "http://127.0.0.1:29871/callback"] }], ...extra },
  });

  it("says what to pass when the server offers no registration, and runs the checks once a client is supplied", async () => {
    fixture = await startFixture(prereg());
    const without = await scan(fixture.mcpUrl, { allowPrivate: true });
    const f = by(without);
    expect(without.discovery?.registration).toEqual([]);
    expect(without.client?.source).toBe("none");
    for (const id of ["MAP-RDR01", "MAP-RDR02", "MAP-THR01"]) expect(f[id]).toMatchObject({ status: "skipped", reason: "no_client" });
    expect(f["MAP-RDR01"]?.message).toMatch(/--client-id/);
    expect(f["MAP-PKC01"]?.message).toMatch(/--client-id/);
    expect(f["MAP-PKC01"]?.message).not.toMatch(/run `mcp-authprobe login` with ownership proven/);
    expect(f["MAP-RDR04"]?.status).toBe("not_applicable");

    const withClient = await scan(fixture.mcpUrl, { allowPrivate: true, client: { clientId: LAB_CLIENT.clientId, redirectUri: LAB_CLIENT.redirectUris[0] } });
    const g = by(withClient);
    expect(withClient.client?.source).toBe("pre-registered");
    expect(g["MAP-RDR01"]?.status).toBe("pass");
    expect(g["MAP-RDR02"]?.status).toBe("pass");
    expect(g["MAP-THR01"]?.status).toBe("pass");
    expect(fixture.registeredClients()).toEqual([]);
    expect(fixture.requests.some((r) => r.path === "/register")).toBe(false);
  });

  it("finds prefix matching with a supplied client whose redirect URI is the operator's own", async () => {
    fixture = await startFixture(prereg({ match: "prefix", noSession: "error-redirect" }));
    const f = by(await scan(fixture.mcpUrl, { allowPrivate: true, client: { clientId: LAB_CLIENT.clientId, redirectUri: LAB_CLIENT.redirectUris[1] }, select: (id) => id.startsWith("MAP-RDR0") }));
    expect(f["MAP-RDR01"]?.status).toBe("pass");
    expect(f["MAP-RDR02"]?.status).toBe("fail");
  });

  it("derives near misses from any registered redirect URI", () => {
    expect(nearMissVariants("https://client.mcp-authprobe.invalid/callback")).toEqual([...NEAR_MISS_VARIANTS]);
    const web = Object.fromEntries(nearMissVariants("https://app.example.com/oauth/cb").map((v) => [v.label, v.uri]));
    expect(web).toMatchObject({
      "extra path segment": "https://app.example.com/oauth/cb/extra",
      "trailing slash": "https://app.example.com/oauth/cb/",
      "added query": "https://app.example.com/oauth/cb?next=1",
      "different port": "https://app.example.com:8443/oauth/cb",
      subdomain: "https://other.app.example.com/oauth/cb",
      userinfo: "https://app.example.com@other.mcp-authprobe.invalid/oauth/cb",
      "scheme downgrade": "http://app.example.com/oauth/cb",
    });
    const loopback = nearMissVariants("http://127.0.0.1:8765/callback").map((v) => v.label);
    expect(loopback).not.toContain("different port");
    expect(loopback).not.toContain("scheme downgrade");
  });

  it("login uses a supplied client on a fixed loopback redirect URI", async () => {
    fixture = await startFixture(prereg());
    http = new HttpClient({ allowPrivate: true });
    const result = await login({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), openUrl: browser, probe: true, timeoutMs: 5000, client: { clientId: LAB_CLIENT.clientId }, redirectUri: "http://127.0.0.1:29871/callback" });
    expect(result.clientSource).toBe("pre-registered");
    expect(result.grant?.clientId).toBe(LAB_CLIENT.clientId);
    expect(result.observations.find((o) => o.checkId === "MAP-PKC01")?.status).toBe("pass");
    await expect(login({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), openUrl: browser, probe: false, timeoutMs: 2000 })).rejects.toThrow(/--client-id/);
    await expect(login({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), openUrl: browser, probe: false, client: { clientId: LAB_CLIENT.clientId }, redirectUri: "https://app.example.com/cb" })).rejects.toThrow(/login begin/);
  });

  it("login in two steps, for a web application: no listener, the four code checks observed", async () => {
    fixture = await startFixture(prereg());
    http = new HttpClient({ allowPrivate: true });
    const discovery = await discover(fixture.mcpUrl, http);
    const begun = await beginLogin({ http, mcpUrl: fixture.mcpUrl, discovery, redirectUri: LAB_CLIENT.redirectUris[1], client: { clientId: LAB_CLIENT.clientId } });
    expect(begun.state).toMatchObject({ clientSource: "pre-registered", issuer: fixture.baseUrl, redirectUri: LAB_CLIENT.redirectUris[1] });
    const callback = await approve(begun.authorizationUrl);
    expect(callback.startsWith(LAB_CLIENT.redirectUris[1])).toBe(true);
    const result = await completeLogin({ http, state: begun.state, callback, probe: true });
    const status = Object.fromEntries(result.observations.map((o) => [o.checkId, o.status]));
    expect(status).toMatchObject({ "MAP-PKC01": "pass", "MAP-RDR03": "pass", "MAP-COD01": "pass", "MAP-AUD01": "pass" });
    expect(result.grant?.refreshToken).toMatch(/^rt_/);
    expect(result.observations.every((o) => o.source === "login")).toBe(true);
  });

  it("validates state, then the issuer, before it looks at anything else in the response", async () => {
    fixture = await startFixture(prereg());
    http = new HttpClient({ allowPrivate: true });
    const discovery = await discover(fixture.mcpUrl, http);
    const begin = () => beginLogin({ http: http!, mcpUrl: fixture!.mcpUrl, discovery, redirectUri: LAB_CLIENT.redirectUris[1], client: { clientId: LAB_CLIENT.clientId } });
    const a = await begin();
    await expect(completeLogin({ http, state: a.state, callback: `https://x/cb?code=abc&state=wrong&iss=${fixture.baseUrl}`, probe: false })).rejects.toThrow(/expected state/);
    // An error from another issuer is neither acted on nor shown.
    const hostile = `${LAB_CLIENT.redirectUris[1]}?error=please_call_this_number&state=${a.state.state}&iss=https://evil.example`;
    const e = await completeLogin({ http, state: a.state, callback: hostile, probe: false }).catch((x: unknown) => x as Error);
    expect(e).toBeInstanceOf(LoginError);
    expect((e as Error).message).toMatch(/iss parameter does not match/);
    expect((e as Error).message).not.toMatch(/please_call/);
    await expect(completeLogin({ http, state: a.state, callback: `?code=abc&state=${a.state.state}`, probe: false })).rejects.toThrow(/response has none/);
    await expect(completeLogin({ http, state: a.state, callback: `?error=access_denied&state=${a.state.state}&iss=${fixture.baseUrl}`, probe: false })).rejects.toThrow(/error=access_denied/);
  });

  it("the CLI does the two steps through a state file, and a callback file", async () => {
    fixture = await startFixture(prereg());
    const d = dir();
    const stateFile = join(d, "state.json");
    const out = join(d, "grant.json");
    const lines: string[] = [];
    const write = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => (lines.push(String(chunk)), true)) as typeof process.stdout.write;
    let code: number;
    try {
      code = await main(["login", "begin", fixture.mcpUrl, "--allow-private", "--client-id", LAB_CLIENT.clientId, "--redirect-uri", LAB_CLIENT.redirectUris[1], "--state-file", stateFile]);
    } finally {
      process.stdout.write = write;
    }
    expect(code).toBe(0);
    expect(statSync(stateFile).mode & 0o777).toBe(0o600);
    const authorizationUrl = lines.join("").trim();
    expect(authorizationUrl.startsWith(`${fixture.baseUrl}/authorize?`)).toBe(true);
    const callbackFile = join(d, "callback");
    writeFileSync(callbackFile, `${await approve(authorizationUrl)}\n`, { mode: 0o600 });
    const report = join(d, "login.json");
    expect(await main(["login", "complete", "--allow-private", "--state-file", stateFile, "--callback-file", callbackFile, "--out", out, "--json", report])).toBe(0);
    expect(loadGrant(out).grant?.clientId).toBe(LAB_CLIENT.clientId);
    expect(loadGrant(out).observations.map((o) => o.checkId)).toEqual(expect.arrayContaining(["MAP-PKC01", "MAP-RDR03", "MAP-COD01", "MAP-AUD01"]));
    expect(existsSync(stateFile)).toBe(false);
    const r = JSON.parse(readFileSync(report, "utf8")) as ScanReport;
    expect(r.client?.source).toBe("pre-registered");
    expect(JSON.stringify(r)).not.toMatch(/rt_[0-9a-f]{8}/);
    // Usage errors.
    expect(await main(["login", "begin", fixture.mcpUrl, "--allow-private"])).toBe(2);
    expect(await main(["login", "complete", "--state-file", stateFile, "--out", out])).toBe(2);
    expect(await main(["login", "complete", "--state-file", join(d, "missing"), "--callback-url", "https://x/cb?code=1", "--out", out])).toBe(2);
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--protocol", "future"])).toBe(2);
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--client-secret-file", callbackFile])).toBe(2);
  });

  it("a client ID metadata document URL is passed through as the client ID", async () => {
    const url = "https://client.mcp-authprobe.invalid/client-metadata.json";
    fixture = await startFixture({ authorization: { registration: "disabled", noSession: "auto-approve", clientIdMetadataDocuments: true, clients: [{ clientId: url, redirectUris: ["https://client.mcp-authprobe.invalid/callback"] }] } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, client: { clientId: url, redirectUri: "https://client.mcp-authprobe.invalid/callback" }, select: (id) => id === "MAP-RDR01" });
    expect(report.discovery?.registration).toEqual(["cimd"]);
    expect(report.client?.source).toBe("metadata-document");
    expect(by(report)["MAP-RDR01"]?.status).toBe("pass");
  });

  it("--rounds 2 gives MAP-RDR03 a code of its own when PKCE is not enforced", async () => {
    fixture = await startFixture({ tokens: { pkce: "optional", bindRedirect: false }, authorization: { noSession: "auto-approve" } });
    http = new HttpClient({ allowPrivate: true });
    const discovery = await discover(fixture.mcpUrl, http);
    const one = await login({ http, mcpUrl: fixture.mcpUrl, discovery, openUrl: browser, probe: true, timeoutMs: 5000 });
    expect(one.observations.find((o) => o.checkId === "MAP-RDR03")).toMatchObject({ status: "skipped", reason: "not_observed" });
    const two = await login({ http, mcpUrl: fixture.mcpUrl, discovery, openUrl: browser, probe: true, timeoutMs: 5000, rounds: 2 });
    expect(two.observations.find((o) => o.checkId === "MAP-PKC01")?.status).toBe("fail");
    expect(two.observations.find((o) => o.checkId === "MAP-RDR03")?.status).toBe("fail");
    expect(two.observations.filter((o) => o.checkId === "MAP-RDR03")).toHaveLength(1);
    expect(two.grant).not.toBeNull();
  });
});

describe("what the client sends and validates", () => {
  it("dynamic registration carries application_type: native for loopback, web otherwise", async () => {
    fixture = await startFixture({ authorization: { noSession: "auto-approve" } });
    http = new HttpClient({ allowPrivate: true });
    await login({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), openUrl: browser, probe: false, timeoutMs: 5000 });
    await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-RDR01" });
    const types = fixture.registrationBodies().map((b) => b["application_type"]);
    expect(types).toEqual(["native", "web"]);
  });

  it("retries a registration once without application_type when the server rejects the field", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString("utf8")));
      req.on("end", () => {
        const json = JSON.parse(body) as Record<string, unknown>;
        bodies.push(json);
        if ("application_type" in json) return void res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid_client_metadata", error_description: "unknown field application_type" }));
        res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify({ client_id: "c1", redirect_uris: json["redirect_uris"] }));
      });
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    http = new HttpClient({ allowPrivate: true });
    const out = await registerClient(http, `http://127.0.0.1:${(server.address() as AddressInfo).port}/register`, ["http://127.0.0.1:1234/callback"], { applicationType: "native" });
    expect(out.client?.clientId).toBe("c1");
    expect(bodies.map((b) => b["application_type"])).toEqual(["native", undefined]);
  });

  it("sends resource with every refresh of the refresh token checks", async () => {
    fixture = await startFixture();
    const grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" as const };
    await scan(fixture.mcpUrl, { allowPrivate: true, grant, select: (id) => id.startsWith("MAP-RTK") });
    const params = fixture.tokenRequestParams();
    expect(params).toHaveLength(3);
    for (const p of params) expect(p).toContain("resource");
  });

  it("does not use authorization server metadata whose issuer differs", async () => {
    fixture = await startFixture({ asOverrides: { issuer: "https://honest.example" } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" });
    const dsc = by(report)["MAP-DSC01"];
    expect(dsc?.status).toBe("fail");
    expect(dsc?.evidence.join(" ")).toMatch(/names issuer https:\/\/honest\.example instead of .*the document was not used/);
    expect(report.discovery?.tokenEndpoint).toBeNull();
  });

  it("remarks a resource that is not the scanned URL, and does not send it as the resource parameter", async () => {
    fixture = await startFixture({ prmOverrides: { resource: "https://other.example/mcp" } });
    http = new HttpClient({ allowPrivate: true });
    const d = await discover(fixture.mcpUrl, http);
    expect(d.warnings?.[0]).toMatch(/announces resource https:\/\/other\.example\/mcp, which is not the scanned URL/);
    expect(d.prm?.metadata.resource).toBe(fixture.mcpUrl);
    const dsc = by(await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" }))["MAP-DSC01"];
    expect(dsc?.status).toBe("pass");
    expect(dsc?.message).toMatch(/1 metadata inconsistency/);
    // The same server reached under another name of the loopback: the announced resource is another origin.
    const viaName = by(await scan(fixture.mcpUrl.replace("127.0.0.1", "localhost"), { allowPrivate: true, select: (id) => id === "MAP-DSC01" }))["MAP-DSC01"];
    expect(viaName?.message).toMatch(/metadata inconsistency/);
    expect(resourceMatches("https://mcp.example.com", "https://mcp.example.com/mcp")).toBe(true);
    expect(resourceMatches("https://mcp.example.com/mcp", "https://mcp.example.com/mcp/")).toBe(true);
    expect(resourceMatches("https://mcp.example.com/other", "https://mcp.example.com/mcp")).toBe(false);
    expect(resourceMatches("https://mcp.example.com/mc", "https://mcp.example.com/mcp")).toBe(false);
  });

  it("lists every announced authorization server and lets one be chosen", async () => {
    fixture = await startFixture({});
    const base = fixture.baseUrl;
    await fixture.close();
    fixture = await startFixture({ port: Number(new URL(base).port), prmOverrides: { authorization_servers: [base, "https://second.example"] } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" });
    expect(report.discovery?.authorizationServers).toEqual([base, "https://second.example"]);
    expect(report.discovery?.notes.join(" ")).toMatch(/announces 2 authorization servers; only .* was examined.*--issuer/);
    const wrong = await scan(fixture.mcpUrl, { allowPrivate: true, issuer: "https://not-announced.example", select: (id) => id === "MAP-DSC01" });
    expect(by(wrong)["MAP-DSC01"]?.status).toBe("fail");
    expect(wrong.discovery?.notes.join(" ")).toMatch(/is not one of the authorization servers this resource announces/);
  });

  it("notes an authorization server that does not announce its PKCE methods", async () => {
    fixture = await startFixture({ authorization: { hidePkceMethods: true } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" });
    expect(report.discovery?.pkceMethods).toBeNull();
    expect(report.discovery?.notes.join(" ")).toMatch(/no code_challenge_methods_supported/);
  });
});
