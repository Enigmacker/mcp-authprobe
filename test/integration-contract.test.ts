import { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { announcedRateLimit, retryAfterSeconds, runEndpointChecks } from "../src/checks/endpoint.js";
import { capabilities, main } from "../src/cli.js";
import { loadGrant, writeGrantFile } from "../src/credentials.js";
import { EXIT, exitCodeFor } from "../src/exit.js";
import * as library from "../src/index.js";
import { HttpClient } from "../src/net/http.js";
import { bearerCredential } from "../src/oauth/mcp-call.js";
import { toJson } from "../src/report/json.js";
import { runScan, scan, type ScanEvent } from "../src/scan.js";
import { readSecretFile, readSecretLine, SecretFileError, writeSecretFile } from "../src/secret-file.js";
import { loadAccessTokenFile } from "../src/static-key.js";
import { REASON_CODES, type Finding, type ScanReport } from "../src/types.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixtures/server.js";

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

const dir = (): string => mkdtempSync(join(tmpdir(), "map-contract-"));
const read = (p: string): string => readFileSync(new URL(p, import.meta.url), "utf8");

/** A small JSON Schema validator: the subset the report schema uses. Returns the list of violations. */
export function validate(schema: Record<string, unknown>, value: unknown, path = "$"): string[] {
  const errors: string[] = [];
  const typeOf = (v: unknown): string => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
  if ("const" in schema && value !== schema["const"]) errors.push(`${path}: expected ${JSON.stringify(schema["const"])}`);
  if (Array.isArray(schema["enum"]) && !schema["enum"].includes(value)) errors.push(`${path}: ${JSON.stringify(value)} is not one of the allowed values`);
  if (schema["type"] !== undefined) {
    const types = Array.isArray(schema["type"]) ? (schema["type"] as string[]) : [schema["type"] as string];
    const t = typeOf(value);
    if (!types.includes(t) && !(t === "integer" && types.includes("number"))) errors.push(`${path}: expected ${types.join(" or ")}, got ${t}`);
  }
  if (typeof schema["pattern"] === "string" && typeof value === "string" && !new RegExp(schema["pattern"]).test(value)) errors.push(`${path}: does not match ${schema["pattern"]}`);
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const key of (schema["required"] as string[] | undefined) ?? []) if (!(key in obj)) errors.push(`${path}: missing ${key}`);
    const props = (schema["properties"] ?? {}) as Record<string, Record<string, unknown>>;
    for (const [key, sub] of Object.entries(props)) if (key in obj && obj[key] !== undefined) errors.push(...validate(sub, obj[key], `${path}.${key}`));
  }
  if (Array.isArray(value) && schema["items"]) value.forEach((v, i) => errors.push(...validate(schema["items"] as Record<string, unknown>, v, `${path}[${i}]`)));
  return errors;
}

const SCHEMA = JSON.parse(read("../schema/report.schema.json")) as Record<string, unknown>;
const asJson = (r: ScanReport): unknown => JSON.parse(toJson(r));
const by = (r: ScanReport): Record<string, Finding> => Object.fromEntries(r.findings.map((f) => [f.checkId, f]));

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

describe("report contract", () => {
  it("every report validates against the published schema", async () => {
    fixture = await startFixture();
    const grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" as const };
    const reports = [
      await scan(fixture.mcpUrl, { allowPrivate: true, grant }),
      await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" }),
      await scan(fixture.mcpUrl, {}),
      await scan(`http://127.0.0.1:${await freePort()}/mcp`, { allowPrivate: true }),
    ];
    for (const r of reports) expect(validate(SCHEMA, asJson(r))).toEqual([]);
    expect(validate(SCHEMA, { schema: "mcp-authprobe/report/v1" }).length).toBeGreaterThan(0);
  });

  it("an 0.10 report (without the added fields) is still valid", () => {
    const old = { schema: "mcp-authprobe/report/v1", tool: { name: "mcp-authprobe", version: "0.10.1" }, startedAt: "x", finishedAt: "y", target: "https://mcp.example.com/mcp", ownership: { verified: true, method: "well-known", detail: "ok" }, findings: [{ checkId: "MAP-DSC01", title: "t", severity: "info", status: "pass", target: "t", message: "m", evidence: [] }] };
    expect(validate(SCHEMA, old)).toEqual([]);
  });

  it("the schema lists every reason code and status", () => {
    const finding = ((SCHEMA["properties"] as Record<string, { items: { properties: Record<string, { enum: string[] }> } }>)["findings"] as { items: { properties: Record<string, { enum: string[] }> } }).items.properties;
    expect([...(finding["reason"] as { enum: string[] }).enum].sort()).toEqual([...REASON_CODES].sort());
  });

  it("carries a summary, the discovery, per-host ownership and a reason for everything that did not run", async () => {
    fixture = await startFixture();
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    expect(report.summary?.total).toBe(report.findings.length);
    expect(report.summary?.judged).toBe(report.findings.filter((f) => f.status === "pass" || f.status === "fail").length);
    expect(report.summary?.coverage).toBeGreaterThan(0);
    expect(report.discovery).toMatchObject({ issuer: fixture.baseUrl, tokenEndpoint: `${fixture.baseUrl}/token`, registration: ["dcr"], resource: fixture.mcpUrl });
    expect(report.ownership.hosts).toEqual([{ host: "127.0.0.1", verified: true, method: "loopback", detail: expect.any(String) }]);
    for (const f of report.findings) {
      expect(f.family).toBe(f.checkId.slice(4, 7));
      expect(typeof f.active).toBe("boolean");
      expect(f.source).toBeDefined();
      if (f.status === "skipped" || f.status === "error") expect(REASON_CODES).toContain(f.reason);
    }
    const f = by(report);
    expect(f["MAP-RTK01"]?.reason).toBe("needs_grant");
    expect(f["MAP-PKC01"]?.reason).toBe("needs_login");
    expect(f["MAP-CSR01"]?.reason).toBe("needs_browser");
    expect(f["MAP-THR02"]?.reason).toBe("needs_static_key");
    expect(report.leftovers).toEqual([]);
  });

  it("names not_selected, ownership_unproven and unreachable", async () => {
    fixture = await startFixture();
    expect(by(await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-DSC01" }))["MAP-RDR01"]?.reason).toBe("not_selected");
    expect(by(await scan(fixture.mcpUrl, { allowPrivate: true, loopbackExempt: false, resolveTxtRecords: async () => [] }))["MAP-RDR01"]?.reason).toBe("ownership_unproven");
    const down = await scan(`http://127.0.0.1:${await freePort()}/mcp`, { allowPrivate: true });
    expect(by(down)["MAP-DSC01"]?.reason).toBe("unreachable");
    expect(by(down)["MAP-RDR01"]?.reason).toBe("unreachable");
    expect(down.summary?.coverage).toBe(0);
  });

  it("lists a temporary client it could not delete", async () => {
    fixture = await startFixture({ authorization: { management: false } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id === "MAP-RDR01" });
    expect(report.leftovers).toHaveLength(1);
    expect(report.leftovers?.[0]).toMatchObject({ kind: "client", endpoint: `${fixture.baseUrl}/register` });
  });

  it("emits one start and one end event per check that ran", async () => {
    fixture = await startFixture();
    const events: ScanEvent[] = [];
    await scan(fixture.mcpUrl, { allowPrivate: true, select: (id) => id.startsWith("MAP-RDR0") || id === "MAP-COR01", onEvent: (e) => events.push(e) });
    expect(events[0]?.type).toBe("scan_started");
    expect(events.at(-1)?.type).toBe("scan_finished");
    const started = events.filter((e) => e.type === "check_started").map((e) => (e as { checkId: string }).checkId).sort();
    const finished = events.filter((e) => e.type === "check_finished").map((e) => (e as { checkId: string }).checkId).sort();
    expect(started).toEqual(["MAP-COR01", "MAP-RDR01", "MAP-RDR02", "MAP-RDR04"]);
    expect(finished).toEqual(started);
  });
});

describe("exit codes", () => {
  const report = (findings: Array<Partial<Finding>>, extra: Partial<ScanReport> = {}): ScanReport => ({
    tool: { name: "t", version: "0" }, startedAt: "", finishedAt: "", target: "", ownership: { verified: true, method: null, detail: "" },
    findings: findings.map((f) => ({ checkId: "MAP-DSC01", title: "", severity: "high", status: "pass", target: "", message: "", evidence: [], ...f }) as Finding), ...extra,
  });

  it("separates failing, inconclusive and unreachable", () => {
    expect(exitCodeFor(report([{}]))).toBe(0);
    expect(exitCodeFor(report([{ status: "fail" }]))).toBe(1);
    expect(exitCodeFor(report([{ status: "fail", severity: "low" }]))).toBe(0);
    expect(exitCodeFor(report([{ status: "error" }]))).toBe(3);
    expect(exitCodeFor(report([{ status: "error" }]), { failOnInconclusive: false })).toBe(0);
    expect(exitCodeFor(report([{ status: "error" }], { reachable: false }), { failOnInconclusive: false })).toBe(4);
    expect(exitCodeFor(report([{}], { complete: false }), { failOnInconclusive: false })).toBe(4);
    expect(EXIT).toMatchObject({ ok: 0, findings: 1, usage: 2, error: 3, unreachable: 4, noGrant: 5 });
  });

  it("an unreachable target exits 4 whatever --fail-on-inconclusive says, and the report says so", async () => {
    const d = dir();
    const url = `http://127.0.0.1:${await freePort()}/mcp`;
    expect(await main(["scan", url, "--allow-private", "--fail-on-inconclusive", "false", "--quiet", "--json", join(d, "r.json")])).toBe(4);
    const r = JSON.parse(readFileSync(join(d, "r.json"), "utf8")) as ScanReport;
    expect(r.reachable).toBe(false);
    expect(r.summary?.exitCode).toBe(4);
    expect(await main(["login", url, "--allow-private", "--no-browser", "--out", join(d, "g.json")])).toBe(4);
  });

  it("a deadline or a request budget gives a partial report and exit 4", async () => {
    fixture = await startFixture();
    const r = await scan(fixture.mcpUrl, { allowPrivate: true, maxRequests: 6 });
    expect(r.complete).toBe(false);
    expect(r.findings.some((f) => f.reason === "interrupted")).toBe(true);
    expect(r.findings).toHaveLength(library.CATALOGUE.length);
    expect(fixture.registeredClients()).toEqual([]);
    expect(exitCodeFor(r, { failOnInconclusive: false })).toBe(4);
    const aborted = new AbortController();
    aborted.abort();
    expect((await scan(fixture.mcpUrl, { allowPrivate: true, signal: aborted.signal })).complete).toBe(false);
  });

  it("deletes its temporary client when it is interrupted in the middle of the redirect checks", async () => {
    fixture = await startFixture();
    const stop = new AbortController();
    const r = await scan(fixture.mcpUrl, {
      allowPrivate: true,
      select: (id) => id === "MAP-RDR02",
      signal: stop.signal,
      onEvent: (e) => {
        if (e.type === "check_started") setTimeout(() => stop.abort(), 15);
      },
      delayMs: 20,
    });
    expect(r.complete).toBe(false);
    expect(fixture.registeredClients()).toEqual([]);
  });
});

describe("OAuth access token (--access-token-file)", () => {
  const secure: FixtureOptions = { authorization: { noSession: "auto-approve" } };

  /** A token obtained the way a web application would: its own redirect URI, no loopback listener. */
  async function accessToken(f: Fixture): Promise<{ access: string; refresh: string; clientId: string }> {
    const reg = (await (await fetch(`${f.baseUrl}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://app.example.invalid/cb"] }) })).json()) as { client_id: string };
    const verifier = "v".repeat(43);
    const { createHash } = await import("node:crypto");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = new URL(`${f.baseUrl}/authorize`);
    for (const [k, v] of Object.entries({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://app.example.invalid/cb", state: "s", code_challenge: challenge, code_challenge_method: "S256" })) authorize.searchParams.set(k, v);
    const location = (await fetch(authorize, { redirect: "manual" })).headers.get("location") as string;
    const code = new URL(location).searchParams.get("code") as string;
    const tokens = (await (await fetch(`${f.baseUrl}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "https://app.example.invalid/cb", client_id: reg.client_id, code_verifier: verifier }) })).json()) as { access_token: string; refresh_token: string };
    return { access: tokens.access_token, refresh: tokens.refresh_token, clientId: reg.client_id };
  }

  it("runs the endpoint checks as a token, without the per-key rate limit check", async () => {
    fixture = await startFixture(secure);
    const t = await accessToken(fixture);
    const d = dir();
    writeFileSync(join(d, "at"), `${t.access}\n`, { mode: 0o600 });
    const { credential } = loadAccessTokenFile(join(d, "at"));
    expect(credential.kind).toBe("oauth");
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential, select: (id) => !id.startsWith("MAP-THR01") });
    const f = by(report);
    expect(report.credential).toEqual({ kind: "oauth", header: "authorization" });
    expect(f["MAP-TOK01"]?.status).toBe("pass");
    expect(f["MAP-ORG01"]?.message).toMatch(/valid token/);
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"]) expect(f[id]?.message).not.toMatch(/the key|static key/);
    expect(f["MAP-DSC01"]?.status).toBe("pass");
    expect(f["MAP-THR02"]?.status).toBe("skipped");
    expect(f["MAP-THR02"]?.message).toMatch(/--only THR02/);
    expect(JSON.stringify(report)).not.toContain(t.access);
  });

  it("runs MAP-THR02 with a token when asked, and MAP-AUD01 when a grant comes with it", async () => {
    fixture = await startFixture({ ...secure, mcp: { checkAudience: false } });
    const t = await accessToken(fixture);
    const grant = { clientId: t.clientId, refreshToken: t.refresh, authMethod: "none" as const };
    const result = await runScan(fixture.mcpUrl, { allowPrivate: true, credential: bearerCredential(t.access), grant, rateLimitWithToken: true, select: (id) => ["MAP-THR02", "MAP-AUD01"].includes(id) });
    const f = by(result.report);
    expect(f["MAP-THR02"]?.status).toBe("fail");
    expect(f["MAP-AUD01"]?.status).toBe("fail");
    expect(f["MAP-AUD01"]?.source).toBe("scan");
    // One refresh was spent on MAP-AUD01: the grant holds the newest token and is still valid.
    expect(result.grant.state).toBe("valid");
    expect(result.grant.latest?.refreshToken).not.toBe(t.refresh);
    expect(result.report.grant).toMatchObject({ used: true, rotated: true, consumed: false });
  });

  it("says when the token expired during the scan", async () => {
    let calls = 0;
    const s = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        calls += 1;
        if (calls <= 2) return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
        res.writeHead(401, { "www-authenticate": "Bearer" }).end();
      });
    });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
    const url = `http://127.0.0.1:${(s.address() as AddressInfo).port}/mcp`;
    const http = new HttpClient({ allowPrivate: true });
    try {
      const { findings } = await runEndpointChecks(http, url, bearerCredential("at_0123456789abcdef"), { checks: ["MAP-ORG01"] });
      expect(findings[0]?.reason).toBe("credential_expired");
    } finally {
      await http.close();
      await new Promise<void>((r) => s.close(() => r()));
    }
  });

  it("refuses a key and a token together, and a token on the command line is not an option", async () => {
    expect(await main(["scan", "https://mcp.example.com/mcp", "--bearer-file", "a", "--access-token-file", "b"])).toBe(EXIT.usage);
    expect(await main(["scan", "https://mcp.example.com/mcp", "--access-token-file", "/nonexistent/at"])).toBe(EXIT.usage);
  });
});

describe("a rate-limited credential", () => {
  const limited: FixtureOptions = { prm: false, asMetadata: false, challenge: "bearer", staticKey: { value: "sk_limited_0123456789" }, mcp: { rateLimit: 2, sessions: false } };
  const cred = bearerCredential("sk_limited_0123456789", "authorization", "static");

  it("is reported as rate_limited with the Retry-After, not as a rejected key", async () => {
    fixture = await startFixture(limited);
    for (let i = 0; i < 3; i += 1) await fetch(fixture.mcpUrl, { method: "POST", headers: { authorization: "Bearer sk_limited_0123456789", "content-type": "application/json" }, body: "{}" });
    const http = new HttpClient({ allowPrivate: true });
    try {
      const r = await runEndpointChecks(http, fixture.mcpUrl, cred, { checks: ["MAP-TOK01", "MAP-BAT01"] });
      expect(r.retryAfterSeconds).toBe(60);
      for (const f of r.findings) {
        expect(f.reason).toBe("rate_limited");
        expect(f.message).toMatch(/rate limiting it \(HTTP 429, Retry-After 60 s\)/);
        expect(f.message).not.toMatch(/did not accept/);
      }
    } finally {
      await http.close();
    }
  });

  it("MAP-THR02 counts the requests the scan already made with the key", async () => {
    fixture = await startFixture({ ...limited, mcp: { rateLimit: 20, sessions: false } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential: cred });
    const thr = by(report)["MAP-THR02"];
    expect(thr?.status).toBe("pass");
    expect(thr?.message).toMatch(/requests sent with this key since the scan started/);
    expect(thr?.message).toMatch(/about 60 s/);
  });

  it("reads Retry-After and announced rate limits", () => {
    expect(retryAfterSeconds({ "retry-after": "30" })).toBe(30);
    expect(retryAfterSeconds({})).toBeNull();
    expect(announcedRateLimit({ "x-ratelimit-limit": "100", "x-ratelimit-remaining": "42" })).toEqual({ limit: 100, remaining: 42 });
    expect(announcedRateLimit({ "ratelimit-limit": "60", "ratelimit-remaining": "7" })).toEqual({ limit: 60, remaining: 7 });
    expect(announcedRateLimit({ ratelimit: '"default";r=50;t=30', "ratelimit-policy": '"default";q=100;w=60' })).toEqual({ limit: 100, remaining: 50 });
    expect(announcedRateLimit({ "content-type": "application/json" })).toBeNull();
  });
});

describe("the test grant survives what does not revoke it", () => {
  const cli = async (options: FixtureOptions, args: string[]) => {
    fixture = await startFixture(options);
    const d = dir();
    const file = join(d, "grant.json");
    const first = fixture.issueRefreshToken();
    writeGrantFile(file, { clientId: "test-client", refreshToken: first, authMethod: "none", target: fixture.mcpUrl }, []);
    const out = join(d, "report.json");
    const code = await main(["scan", fixture.mcpUrl, "--allow-private", "--credentials-file", file, "--quiet", "--json", out, "--skip", "THR,RDR", ...args]);
    return { code, file, first, d, report: JSON.parse(readFileSync(out, "utf8")) as ScanReport, requests: fixture.tokenRequests() };
  };

  it("--rtk rotate-only sends one refresh and rewrites the file with the newest token, twice in a row", async () => {
    const r = await cli({}, ["--rtk", "rotate-only"]);
    expect(r.requests).toBe(1);
    const after = loadGrant(r.file).grant;
    expect(after?.refreshToken).not.toBe(r.first);
    expect(statSync(r.file).mode & 0o777).toBe(0o600);
    expect(r.report.grant).toEqual({ used: true, rotated: true, consumed: false, state: "valid", rewritten: true });
    expect(readdirSync(r.d).filter((n) => n.endsWith(".tmp"))).toEqual([]);
    // The same file works again: the grant was not lost.
    expect(await main(["scan", fixture!.mcpUrl, "--allow-private", "--credentials-file", r.file, "--quiet", "--rtk", "rotate-only", "--skip", "THR,RDR"])).toBe(0);
    expect(loadGrant(r.file).grant?.refreshToken).not.toBe(after?.refreshToken);
  });

  it("keeps the newest token when the server accepts the replay (the grant is still valid)", async () => {
    const r = await cli({ tokens: { rejectReplay: false } }, []);
    expect(r.code).toBe(1);
    expect(r.report.grant).toMatchObject({ consumed: false, rewritten: true });
    const latest = loadGrant(r.file).grant?.refreshToken as string;
    const res = await fetch(`${fixture!.baseUrl}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: latest, client_id: "test-client" }) });
    expect(res.status).toBe(200);
  });

  it("says the grant is consumed after the full sequence on a compliant server, and leaves the file alone", async () => {
    const r = await cli({}, []);
    expect(r.code).toBe(0);
    expect(r.report.grant).toEqual({ used: true, rotated: true, consumed: true, state: "revoked", rewritten: false });
    expect(loadGrant(r.file).grant?.refreshToken).toBe(r.first);
  });

  it("--rtk off leaves the grant untouched; --credentials-out writes elsewhere", async () => {
    const off = await cli({}, ["--rtk", "off"]);
    expect(off.requests).toBe(0);
    expect(off.report.grant).toMatchObject({ used: false, state: "unused", rewritten: false });
    await fixture?.close();
    const elsewhere = join(dir(), "new.json");
    const r = await cli({}, ["--rtk", "rotate-only", "--credentials-out", elsewhere]);
    expect(loadGrant(r.file).grant?.refreshToken).toBe(r.first);
    expect(loadGrant(elsewhere).grant?.refreshToken).not.toBe(r.first);
    expect(await main(["scan", "https://mcp.example.com/mcp", "--rtk", "sometimes"])).toBe(EXIT.usage);
  });
});

describe("secret files", () => {
  it("writes atomically, with mode 600, never through a link, never over a file by accident", () => {
    const d = dir();
    const file = join(d, "s.json");
    writeSecretFile(file, "one\n", false);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(() => writeSecretFile(file, "two\n", false)).toThrow(/EEXIST/);
    writeFileSync(file, "old\n", { mode: 0o644 });
    writeSecretFile(file, "two\n", true);
    expect(readFileSync(file, "utf8")).toBe("two\n");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(d)).toEqual(["s.json"]);
    const victim = join(d, "victim");
    writeFileSync(victim, "keep");
    symlinkSync(victim, join(d, "link"));
    expect(() => writeSecretFile(join(d, "link"), "x", true)).toThrow(/ELOOP/);
    expect(readFileSync(victim, "utf8")).toBe("keep");
  });

  it("reads every secret file the same way", async () => {
    const d = dir();
    const file = join(d, "secret");
    writeFileSync(file, "a".repeat(40), { mode: 0o644 });
    expect(readSecretLine(file, { label: "secret", maxBytes: 1024 }).warnings[0]).toMatch(/readable by other users/);
    expect(() => readSecretFile(file, { label: "secret", maxBytes: 8 })).toThrow(SecretFileError);
    expect(() => readSecretFile(d, { label: "secret", maxBytes: 1024 })).toThrow(SecretFileError);
    symlinkSync(file, join(d, "link"));
    expect(() => readSecretFile(join(d, "link"), { label: "secret", maxBytes: 1024 })).toThrow(/symbolic link/);
    expect(readSecretFile(join(d, "link"), { label: "secret", maxBytes: 1024, followLinks: true }).text).toHaveLength(40);
    // The ownership secret goes through the same reader: a missing or oversized file is a usage error.
    expect(await main(["ownership", "proof", "mcp.example.com", "--secret-file", join(d, "missing")])).toBe(EXIT.usage);
    writeFileSync(join(d, "big"), "x".repeat(9000));
    expect(await main(["scan", "https://mcp.example.com/mcp", "--secret-file", join(d, "big")])).toBe(EXIT.usage);
    expect(existsSync(join(d, "big"))).toBe(true);
  });
});

describe("login results in a scan", () => {
  const obs = (observedAt: string) => ({ checkId: "MAP-PKC01", title: "t", severity: "high" as const, status: "pass" as const, target: "", message: "The token endpoint refused the code.", evidence: [], observedAt });

  it("carry their source and date, and are not reported when too old", async () => {
    fixture = await startFixture();
    const fresh = { ...obs(new Date().toISOString()), target: fixture.mcpUrl };
    const old = { ...obs("2026-01-01T00:00:00.000Z"), target: fixture.mcpUrl };
    const only = (id: string): boolean => id === "MAP-PKC01";
    const a = by(await scan(fixture.mcpUrl, { allowPrivate: true, observations: [fresh], select: only }))["MAP-PKC01"];
    expect(a).toMatchObject({ status: "pass", source: "login", observedAt: fresh.observedAt });
    const b = by(await scan(fixture.mcpUrl, { allowPrivate: true, observations: [old], select: only }))["MAP-PKC01"];
    expect(b).toMatchObject({ status: "skipped", reason: "stale_observation", source: "login", observedAt: old.observedAt });
    const c = by(await scan(fixture.mcpUrl, { allowPrivate: true, observations: [old], select: only, maxObservationAgeMs: 0 }))["MAP-PKC01"];
    expect(c?.status).toBe("pass");
  });
});

describe("library and machine-readable output", () => {
  it("exports what an integrator needs to build scan options", () => {
    for (const name of ["scan", "runScan", "discover", "login", "bearerCredential", "loadBearerFile", "loadAccessTokenFile", "parseSelection", "loadGrant", "writeGrantFile", "runEndpointChecks", "runRedirectUriChecks", "runThrottlingCheck", "runRefreshTokenSequence", "exitCodeFor", "EXIT", "toJson", "toSarif", "toMarkdown", "REPORT_SCHEMA", "REASON_CODES"]) {
      expect(library, name).toHaveProperty(name);
    }
    const pkg = JSON.parse(read("../package.json")) as { exports: Record<string, unknown>; files: string[] };
    expect(Object.keys(pkg.exports)).toEqual(expect.arrayContaining([".", "./lab", "./schema/report.schema.json", "./package.json"]));
    expect(pkg.files).toContain("schema");
  });

  it("describes itself to a program", async () => {
    const c = capabilities() as { checks: string[]; reasonCodes: string[]; exitCodes: Record<string, number>; reportSchema: string };
    expect(c.checks).toHaveLength(library.CATALOGUE.length);
    expect(c.reasonCodes).toEqual(REASON_CODES);
    expect(c.exitCodes["unreachable"]).toBe(4);
    expect(c.reportSchema).toBe("mcp-authprobe/report/v1");
    expect(await main(["capabilities", "--json"])).toBe(0);
    expect(await main(["checks", "list", "--json"])).toBe(0);
  });

  it("writes one JSON line per event with --events", async () => {
    fixture = await startFixture();
    const file = join(dir(), "events.ndjson");
    expect(await main(["scan", fixture.mcpUrl, "--allow-private", "--only", "DSC,COR", "--quiet", "--events", file])).toBe(0);
    const events = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { type: string });
    expect(events.map((e) => e.type)).toEqual(["scan_started", "discovery_finished", "check_started", "check_finished", "scan_finished"]);
  });
});
