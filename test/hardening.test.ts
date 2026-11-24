import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CATALOGUE } from "../src/checks/catalogue.js";
import { main, PRESETS } from "../src/cli.js";
import { completeLogin, beginLogin } from "../src/login.js";
import { discover } from "../src/discovery.js";
import { BlockedAddressError, HttpClient } from "../src/net/http.js";
import { pendingClients, registerClient, setClientJournal } from "../src/oauth/registration.js";
import { matchProof, proofFor, proofV2For, verifyOwnership, weakSecretWarning } from "../src/ownership.js";
import { planScan, planToText } from "../src/plan.js";
import { toSarif } from "../src/report/sarif.js";
import { configFromEnv, createAuthprobeServer } from "../src/mcp-server.js";
import { bearerCredential } from "../src/oauth/mcp-call.js";
import { scan } from "../src/scan.js";
import type { Finding, ScanReport } from "../src/types.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let other: Fixture | undefined;
let http: HttpClient | undefined;
let server: Server | undefined;
afterEach(async () => {
  await fixture?.close();
  await other?.close();
  await http?.close();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  fixture = other = undefined;
  http = undefined;
  server = undefined;
  setClientJournal(null);
});

const SECRET = "s3cr3t-with-enough-entropy-0123456789-abcdef";
const KEY = "sk_hard_0123456789abcdef";
const by = (r: ScanReport): Record<string, Finding> => Object.fromEntries(r.findings.map((f) => [f.checkId, f]));
const dir = (): string => mkdtempSync(join(tmpdir(), "map-hard-"));

describe("ownership proof, version 2", () => {
  it("is an HMAC of the host, accepted next to the first format", () => {
    const v1 = proofFor("mcp.example.com", SECRET);
    const v2 = proofV2For("mcp.example.com", SECRET);
    expect(v2).toMatch(/^mcp-authprobe-verification=v2:[0-9a-f]{64}$/);
    expect(matchProof(v1, "mcp.example.com", SECRET)).toBe(1);
    expect(matchProof(v2, "MCP.example.com.", SECRET)).toBe(2);
    expect(matchProof(v2, "other.example.com", SECRET)).toBeNull();
    expect(matchProof(v2, "mcp.example.com", `${SECRET}x`)).toBeNull();
  });

  it("can expire, and the date cannot be moved without the secret", () => {
    const p = proofV2For("mcp.example.com", SECRET, "2026-12-31");
    expect(p).toMatch(/;exp=2026-12-31$/);
    expect(matchProof(p, "mcp.example.com", SECRET, new Date("2026-12-31T12:00:00Z"))).toBe(2);
    expect(matchProof(p, "mcp.example.com", SECRET, new Date("2027-01-01T00:00:01Z"))).toBe("expired");
    expect(matchProof(p.replace("2026-12-31", "2099-12-31"), "mcp.example.com", SECRET)).toBeNull();
    expect(() => proofV2For("mcp.example.com", SECRET, "tomorrow")).toThrow();
  });

  it("is verified from the well-known file in either format, and an expired one says so", async () => {
    http = new HttpClient({ allowPrivate: true });
    const check = async (body: string) => {
      fixture = await startFixture({ ownershipFile: body });
      const r = await verifyOwnership("127.0.0.1", SECRET, { http: http!, loopbackExempt: false, wellKnownBaseUrl: fixture.baseUrl, resolveTxtRecords: async () => [] });
      await fixture.close();
      fixture = undefined;
      return r;
    };
    expect(await check(`${proofFor("127.0.0.1", SECRET)}\n`)).toMatchObject({ verified: true, proofVersion: 1 });
    expect(await check(`# comment\n${proofV2For("127.0.0.1", SECRET)}\n`)).toMatchObject({ verified: true, proofVersion: 2 });
    const expired = await check(`${proofV2For("127.0.0.1", SECRET, "2020-01-01")}\n`);
    expect(expired.verified).toBe(false);
    expect(expired.detail).toMatch(/has expired/);
  });

  it("warns about a secret that does not look random", () => {
    expect(weakSecretWarning("a".repeat(40))).toMatch(/does not look random/);
    expect(weakSecretWarning("abcabcabcabcabcabcabcabcabcabcabcabc")).toMatch(/does not look random/);
    expect(weakSecretWarning(SECRET)).toBeNull();
  });
});

describe("proof host by host", () => {
  /** An MCP server whose authorization server is on another host name of the loopback. */
  async function twoHosts(): Promise<{ mcpUrl: string; as: Fixture } | null> {
    try {
      // A second address of the loopback (every 127.x.y.z is one on Linux; not configured everywhere).
      other = await startFixture({ host: "127.0.0.2", unsafeAllowNonLoopback: true, tokens: { rateLimitAfter: 5 } });
    } catch {
      return null;
    }
    const asBase = other.baseUrl;
    fixture = await startFixture({ staticKey: { value: KEY }, prmOverrides: { authorization_servers: [asBase] }, mcp: { metadata: "clean", sessions: false } });
    return { mcpUrl: fixture.mcpUrl, as: other };
  }

  it("runs the MCP endpoint checks when only the MCP host is proven, and no request reaches the authorization server", async () => {
    const hosts = await twoHosts();
    if (!hosts) return; // no second loopback address on this machine
    const { mcpUrl, as } = hosts;
    const proof = proofV2For("127.0.0.1", SECRET);
    await fixture!.close();
    const port = Number(new URL(mcpUrl).port);
    fixture = await startFixture({ port, staticKey: { value: KEY }, prmOverrides: { authorization_servers: [as.baseUrl] }, ownershipFile: proof, mcp: { metadata: "clean", sessions: false } });
    const before = as.requests.length;
    const report = await scan(mcpUrl, {
      allowPrivate: true,
      allowHosts: ["127.0.0.2"],
      loopbackExempt: false,
      secret: SECRET,
      wellKnownBaseUrl: fixture.baseUrl,
      resolveTxtRecords: async () => [],
      credential: bearerCredential(KEY, "authorization", "static"),
      select: (id) => !["MAP-THR02", "MAP-BOD01"].includes(id),
    });
    const f = by(report);
    expect(report.ownership.verified).toBe(false);
    expect(report.ownership.hosts?.map((h) => [h.host, h.verified])).toEqual([["127.0.0.1", true], ["127.0.0.2", false]]);
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01", "MAP-INJ01"]) expect(f[id]?.status, id).toBe("pass");
    for (const id of ["MAP-RDR01", "MAP-RDR02", "MAP-RDR04", "MAP-THR01", "MAP-RTK01"]) {
      expect(f[id], id).toMatchObject({ status: "skipped", reason: "ownership_unproven" });
      expect(f[id]?.message).toMatch(/127\.0\.0\.2 \(the authorization server\) is not proven/);
    }
    // Only read-only metadata and proof lookups reached the authorization server: nothing active.
    const active = as.requests.slice(before).filter((r) => ["/register", "/authorize", "/token"].includes(r.path));
    expect(active).toEqual([]);
  });

  it("login observes the endpoint checks but not the token endpoint ones when only the MCP host is proven", async () => {
    fixture = await startFixture({ authorization: { noSession: "auto-approve" }, mcp: { metadata: "clean" } });
    http = new HttpClient({ allowPrivate: true });
    const begun = await beginLogin({ http, mcpUrl: fixture.mcpUrl, discovery: await discover(fixture.mcpUrl, http), redirectUri: "https://app.mcp-authprobe.invalid/cb" });
    const callback = (await fetch(begun.authorizationUrl, { redirect: "manual" })).headers.get("location") as string;
    const tokenRequestsBefore = fixture.tokenRequests();
    const result = await completeLogin({ http, state: begun.state, callback, probe: { authorizationServer: false, endpoint: true } });
    const ids = result.observations.map((o) => o.checkId);
    expect(ids).toEqual(expect.arrayContaining(["MAP-ORG01", "MAP-TOK01", "MAP-INJ01"]));
    for (const id of ["MAP-PKC01", "MAP-RDR03", "MAP-COD01", "MAP-AUD01"]) expect(ids).not.toContain(id);
    // One token request only: the real exchange.
    expect(fixture.tokenRequests() - tokenRequestsBefore).toBe(1);
    expect(result.grant).not.toBeNull();
  });
});

describe("private addresses are for the scanned host", () => {
  it("does not follow metadata to another private host unless it was named", async () => {
    http = new HttpClient({ allowPrivate: true, privateHosts: ["127.0.0.1"] });
    await expect(http.request({ url: "http://10.255.255.1:9/x", timeoutMs: 500 })).rejects.toBeInstanceOf(BlockedAddressError);
    // Every name of the loopback is the same machine.
    expect(http.privateAllowedFor("localhost")).toBe(true);
    expect(http.privateAllowedFor("[::1]")).toBe(true);
    expect(http.privateAllowedFor("10.0.0.5")).toBe(false);
    http.allowPrivateHost("10.0.0.5");
    expect(http.privateAllowedFor("10.0.0.5")).toBe(true);
    // Without the list, --allow-private applies to every host, as before (library callers).
    const open = new HttpClient({ allowPrivate: true });
    expect(open.privateAllowedFor("10.0.0.5")).toBe(true);
    await open.close();
  });

  it("a server cannot send the scan to an internal address through its metadata", async () => {
    let hits = 0;
    server = createServer((_req, res) => {
      hits += 1;
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    // The "internal service" is reached under a private address that is not the scanned host.
    fixture = await startFixture({ prmOverrides: { authorization_servers: ["http://10.255.255.1:9"] } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01", timeoutMs: 800 });
    expect(report.discovery?.notes.join(" ")).toMatch(/AS metadata fetch failed.*private or reserved address/);
    expect(hits).toBe(0);
  });
});

describe("presets, plan, journal, headers", () => {
  it("presets select what they say, and the default stays everything", () => {
    const ids = CATALOGUE.map((c) => c.id);
    expect(ids.filter(PRESETS["passive"]!.select)).toEqual(["MAP-DSC01", "MAP-ORG01", "MAP-COR01"].sort((a, b) => ids.indexOf(a) - ids.indexOf(b)));
    expect(ids.filter((id) => !PRESETS["standard"]!.select(id)).sort()).toEqual(["MAP-BOD01", "MAP-THR02"]);
    expect(ids.every(PRESETS["intrusive"]!.select)).toBe(true);
  });

  it("--preset passive uses no credential and sends nothing active", async () => {
    fixture = await startFixture({ staticKey: { value: KEY } });
    const d = dir();
    writeFileSync(join(d, "k"), `${KEY}\n`, { mode: 0o600 });
    const out = join(d, "r.json");
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--preset", "passive", "--bearer-file", join(d, "k"), "--quiet", "--json", out, "--fail-on-inconclusive", "false"])).toBe(0);
    const r = JSON.parse(readFileSync(out, "utf8")) as ScanReport;
    expect(r.preset).toBe("passive");
    expect(r.credential).toBeUndefined();
    expect(r.findings.filter((f) => f.reason !== "not_selected").map((f) => f.checkId).sort()).toEqual(["MAP-COR01", "MAP-DSC01", "MAP-ORG01"]);
    expect(fixture.requests.some((x) => ["/register", "/authorize", "/token"].includes(x.path))).toBe(false);
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--preset", "reckless"])).toBe(2);
  });

  it("plan says what a scan would run, and agrees with the scan", async () => {
    fixture = await startFixture({ tokens: { rateLimitAfter: 5 } });
    const grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" as const };
    const options = { allowPrivate: true, grant };
    const requestsBefore = fixture.requests.length;
    const plan = await planScan(fixture.mcpUrl, options);
    // Only discovery: nothing was registered, authorized or exchanged.
    expect(fixture.requests.slice(requestsBefore).some((r) => ["/register", "/authorize", "/token"].includes(r.path))).toBe(false);
    expect(plan.entries).toHaveLength(CATALOGUE.length);
    const report = await scan(fixture.mcpUrl, options);
    for (const e of plan.entries) {
      const f = by(report)[e.checkId] as Finding;
      const ran = f.source === "scan" && f.status !== "skipped" && f.status !== "not_applicable";
      expect(e.runs, e.checkId).toBe(ran);
      if (!e.runs && f.reason) expect(e.reason, e.checkId).toBe(f.reason);
    }
    expect(planToText(plan)).toMatch(/of 21 checks would send requests/);
    expect(await main(["plan", fixture.mcpUrl, "--allow-private", "--json", "-"])).toBe(0);
  });

  it("plan agrees with the scan without registration, without proof and with a key", async () => {
    fixture = await startFixture({ authorization: { registration: "disabled" } });
    const cases = [
      { allowPrivate: true },
      { allowPrivate: true, loopbackExempt: false, resolveTxtRecords: async () => [] as string[][] },
      { allowPrivate: true, client: { clientId: "x", redirectUri: "https://client.mcp-authprobe.invalid/callback" }, select: (id: string) => id !== "MAP-THR01" },
    ];
    for (const options of cases) {
      const plan = await planScan(fixture.mcpUrl, options);
      const report = await scan(fixture.mcpUrl, options);
      for (const e of plan.entries) {
        const f = by(report)[e.checkId] as Finding;
        expect(e.runs, `${e.checkId} ${JSON.stringify(Object.keys(options))}`).toBe(f.status !== "skipped" && f.status !== "not_applicable");
      }
    }
  });

  it("the journal lists what a killed scan left, and cleanup deletes it", async () => {
    fixture = await startFixture();
    const journal = join(dir(), "clients.jsonl");
    setClientJournal(journal);
    http = new HttpClient({ allowPrivate: true });
    await registerClient(http, `${fixture.baseUrl}/register`, ["https://client.mcp-authprobe.invalid/callback"]);
    await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-RDR01" });
    setClientJournal(null);
    const pending = pendingClients(readFileSync(journal, "utf8"));
    expect(pending).toHaveLength(1); // the scan deleted its own; the first one was "left by a killed scan"
    expect(fixture.registeredClients()).toEqual([pending[0]?.clientId]);
    expect(await main(["cleanup", "--journal", journal, "--allow-private"])).toBe(0);
    expect(fixture.registeredClients()).toEqual([]);
    expect(pendingClients(readFileSync(journal, "utf8"))).toEqual([]);
    expect(await main(["cleanup"])).toBe(2);
  });

  it("--header-file sends its headers to the scanned origin only", async () => {
    const seen: Array<{ port: number; value: string | undefined }> = [];
    const listen = async (): Promise<{ s: Server; port: number }> => {
      const s = createServer((req, res) => {
        req.resume();
        seen.push({ port: (s.address() as AddressInfo).port, value: req.headers["x-gateway-token"] as string | undefined });
        res.writeHead(404).end();
      });
      await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
      return { s, port: (s.address() as AddressInfo).port };
    };
    const a = await listen();
    const b = await listen();
    server = a.s;
    const client = new HttpClient({ allowPrivate: true, extraHeaders: { origin: `http://127.0.0.1:${a.port}`, headers: { "x-gateway-token": "gw_0123456789" } } });
    await client.request({ url: `http://127.0.0.1:${a.port}/mcp` });
    await client.request({ url: `http://127.0.0.1:${b.port}/token` });
    await client.close();
    await new Promise<void>((r) => b.s.close(() => r()));
    expect(seen).toEqual([{ port: a.port, value: "gw_0123456789" }, { port: b.port, value: undefined }]);
    const d = dir();
    writeFileSync(join(d, "h"), "not a header line\n", { mode: 0o600 });
    expect(await main(["scan", "https://mcp.example.com/mcp", "--header-file", join(d, "h")])).toBe(2);
    writeFileSync(join(d, "h2"), "Host: evil\n", { mode: 0o600 });
    expect(await main(["scan", "https://mcp.example.com/mcp", "--header-file", join(d, "h2")])).toBe(2);
  });

  it("SARIF results carry a fingerprint that is stable for a check and a target", () => {
    const report = (target: string): ScanReport => ({
      tool: { name: "mcp-authprobe", version: "t" }, startedAt: "a", finishedAt: "b", target, ownership: { verified: true, method: null, detail: "" },
      findings: [{ checkId: "MAP-RTK02", title: "t", severity: "critical", status: "fail", target, message: "m", evidence: [] }],
    });
    const fp = (t: string): string => (JSON.parse(toSarif(report(t))) as { runs: Array<{ results: Array<{ partialFingerprints: Record<string, string> }> }> }).runs[0]!.results[0]!.partialFingerprints["mcpAuthprobe/v1"]!;
    expect(fp("https://a.example/mcp")).toBe(fp("https://a.example/mcp"));
    expect(fp("https://a.example/mcp")).not.toBe(fp("https://b.example/mcp"));
    expect(fp("https://a.example/mcp")).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("MCP mode", () => {
  it("exempts a lab by its exact origin, not the whole loopback", async () => {
    fixture = await startFixture();
    const exact = await scan(fixture.mcpUrl, { allowPrivate: true, loopbackExempt: true, exemptOrigins: [fixture.baseUrl], select: (id) => id === "MAP-DSC01" });
    expect(exact.ownership.verified).toBe(true);
    const otherPort = await scan(fixture.mcpUrl, { allowPrivate: true, loopbackExempt: true, exemptOrigins: ["http://127.0.0.1:1"], resolveTxtRecords: async () => [], select: (id) => id === "MAP-DSC01" });
    expect(otherPort.ownership.verified).toBe(false);
  });

  it("reads the host allow-list and the client from the environment", () => {
    const config = configFromEnv({ MCP_AUTHPROBE_ALLOWED_HOSTS: "mcp.example.com, Staging.example.com", MCP_AUTHPROBE_CLIENT_ID: "my-client", MCP_AUTHPROBE_REDIRECT_URI: "https://app.example.com/cb", MCP_AUTHPROBE_PROTOCOL: "modern" });
    expect(config.allowedHosts).toEqual(["mcp.example.com", "staging.example.com"]);
    expect(config.client).toEqual({ clientId: "my-client", redirectUri: "https://app.example.com/cb" });
    expect(config.protocol).toBe("modern");
    expect(createAuthprobeServer(config)).toBeDefined();
  });
});
