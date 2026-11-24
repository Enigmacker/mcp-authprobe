import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { runRedirectUriChecks } from "../src/checks/redirect-uris.js";
import { HttpClient } from "../src/net/http.js";
import { safeText } from "../src/redact.js";
import { loadSessionCookieFile, parseCookieHeader, SessionCookieError } from "../src/session-cookie.js";
import type { Finding, ScanReport } from "../src/types.js";
import { startFixture, type AuthorizationBehaviour, type ConsentBehaviour, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

interface Run {
  byId: Record<string, Finding>;
  fx: Fixture;
  cookie: string;
}

/** A consent-mode authorization server; the checks run in a session unless `cookie` is null. */
async function run(authorization: AuthorizationBehaviour, consent: ConsentBehaviour, o: { cookie?: string | null; approve?: boolean } = {}): Promise<Run> {
  fixture = await startFixture({ authorization, consent });
  http = new HttpClient({ allowPrivate: true });
  const cookie = o.cookie === undefined ? `sid=${fixture.issueSession()}` : (o.cookie ?? "");
  const all = await runRedirectUriChecks({
    http,
    target: fixture.mcpUrl,
    authorizationEndpoint: `${fixture.baseUrl}/authorize`,
    registrationEndpoint: `${fixture.baseUrl}/register`,
    resource: fixture.mcpUrl,
    scope: "mcp",
    select: (id) => id !== "MAP-RDR04",
    ...(o.cookie === null ? {} : { session: { cookie, ...(o.approve ? { approveConsent: true } : {}) } }),
  });
  return { byId: Object.fromEntries(all.map((f) => [f.checkId, f])), fx: fixture, cookie };
}

/** The server most often met: login first, then redirect_uri, then the consent page. */
const LOGIN_FIRST: AuthorizationBehaviour = { validateAfterLogin: true };

describe("redirect URI checks in a logged-in session", () => {
  it("are inconclusive without a session on a server that logs in first (the case they solve)", async () => {
    const { byId } = await run(LOGIN_FIRST, {}, { cookie: null });
    expect(byId["MAP-RDR02"]).toMatchObject({ status: "error", reason: "deferred_validation" });
  });

  it("pass on a sound server: error page for every variant, consent page for the registered URI", async () => {
    const { byId, fx, cookie } = await run(LOGIN_FIRST, {});
    expect(byId["MAP-RDR01"]?.status).toBe("pass");
    const rdr02 = byId["MAP-RDR02"];
    expect(rdr02?.status).toBe("pass");
    expect(rdr02?.message).toMatch(/logged-in session/);
    expect(rdr02?.evidence[0]).toMatch(/baseline .* in the session: HTTP 200, a consent page/);
    expect(rdr02?.evidence.some((e) => /^subdomain: refused \(HTTP 400, an error page/.test(e))).toBe(true);
    expect(rdr02?.evidence.at(-1)).toMatch(/cookie is not reported/);
    expect(fx.consentsGranted()).toBe(0);
    // The cookie never reaches a finding.
    const sid = cookie.slice("sid=".length);
    expect(JSON.stringify(byId)).not.toContain(sid);
  });

  it("report a cookie the server does not accept, not a verdict", async () => {
    const { byId } = await run(LOGIN_FIRST, {}, { cookie: "sid=expired-or-made-up-value" });
    for (const id of ["MAP-RDR01", "MAP-RDR02"]) {
      expect(byId[id]).toMatchObject({ status: "error", reason: "credential_rejected" });
      expect(byId[id]?.message).toMatch(/login page/);
    }
  });

  it("prove the failure when the session redirects to unregistered URIs", async () => {
    const { byId } = await run({ ...LOGIN_FIRST, match: "prefix" }, { skipConsent: true });
    expect(byId["MAP-RDR01"]?.status).toBe("pass");
    const rdr02 = byId["MAP-RDR02"];
    expect(rdr02?.status).toBe("fail");
    expect(rdr02?.message).toMatch(/3 unregistered/);
    expect(rdr02?.evidence.some((e) => /^extra path segment: accepted \(HTTP 302, redirected to the redirect_uri that was sent, in the session\)/.test(e))).toBe(true);
    expect(rdr02?.evidence.some((e) => /^different port: refused/.test(e))).toBe(true);
  });

  it("never turn a consent page into a verdict, and approve nothing, without --approve-consent", async () => {
    const { byId, fx } = await run({ match: "deferred" }, {});
    for (const id of ["MAP-RDR01", "MAP-RDR02"]) {
      expect(byId[id]).toMatchObject({ status: "error", reason: "deferred_validation" });
      expect(byId[id]?.message).toMatch(/consent page was displayed .*--approve-consent/);
    }
    expect(fx.consentsGranted()).toBe(0);
  });

  it("prove the failure by approving when asked to (--approve-consent)", async () => {
    const { byId, fx } = await run({ match: "deferred" }, {}, { approve: true });
    expect(byId["MAP-RDR01"]?.status).toBe("fail");
    const rdr02 = byId["MAP-RDR02"];
    expect(rdr02?.status).toBe("fail");
    expect(rdr02?.message).toMatch(/7 unregistered/);
    expect(rdr02?.evidence.some((e) => /consent approved, then HTTP 302, redirected to the redirect_uri that was sent/.test(e))).toBe(true);
    expect(rdr02?.evidence.some((e) => /approved 7 time\(s\) for the test account/.test(e))).toBe(true);
    expect(fx.consentsGranted()).toBe(8);
  });

  it("pass when the consent page is shown for any URI but approval refuses the unregistered ones", async () => {
    const shown = await run(LOGIN_FIRST, { checkRedirectAt: "approval" });
    expect(shown.byId["MAP-RDR02"]).toMatchObject({ status: "error", reason: "deferred_validation" });
    await fixture?.close();
    await http?.close();
    const { byId, fx } = await run(LOGIN_FIRST, { checkRedirectAt: "approval" }, { approve: true });
    expect(byId["MAP-RDR01"]?.status).toBe("pass");
    expect(byId["MAP-RDR02"]?.status).toBe("pass");
    expect(byId["MAP-RDR02"]?.evidence.some((e) => /refused at approval/.test(e))).toBe(true);
    expect(fx.consentsGranted()).toBe(0);
  });

  it("send the approval with the page's anti-CSRF token", async () => {
    const { byId } = await run({ match: "deferred" }, { csrf: "token" }, { approve: true });
    expect(byId["MAP-RDR02"]?.status).toBe("fail");
  });
});

describe("session cookie file", () => {
  const dir = (): string => mkdtempSync(join(tmpdir(), "authprobe-session-"));

  it("normalizes a Cookie header value, with or without the header name", () => {
    expect(parseCookieHeader("Cookie: a=1;b=2 ;  c=\"x\"\n")).toBe('a=1; b=2; c="x"');
    expect(parseCookieHeader("sid=abc")).toBe("sid=abc");
  });

  it("refuses what is not a Cookie header, without quoting it", () => {
    for (const bad of ["", "novalue", "a=1\nb=2", "a=b c", "bad name=1", "a=\u0001"]) {
      expect(() => parseCookieHeader(bad)).toThrow(SessionCookieError);
    }
    try {
      parseCookieHeader("secret-session-value-123 oops");
    } catch (e) {
      expect((e as Error).message).not.toContain("secret-session-value-123");
    }
  });

  it("registers every value for redaction", () => {
    const d = dir();
    writeFileSync(join(d, "c"), "sid=opaque-session-value-4242; theme=dark\n", { mode: 0o600 });
    const { cookie, warnings } = loadSessionCookieFile(join(d, "c"));
    expect(cookie).toBe("sid=opaque-session-value-4242; theme=dark");
    expect(warnings).toEqual([]);
    expect(safeText("echo opaque-session-value-4242")).toBe("echo [REDACTED]");
  });

  it("--approve-consent needs --session-cookie-file, and a bad file is a usage error", async () => {
    expect(await main(["scan", "https://mcp.example.com/mcp", "--approve-consent"])).toBe(2);
    const d = dir();
    writeFileSync(join(d, "c"), "not a cookie\n", { mode: 0o600 });
    expect(await main(["scan", "https://mcp.example.com/mcp", "--session-cookie-file", join(d, "c")])).toBe(2);
  });

  it("a scan replays RDR01/RDR02 in the session and keeps the cookie out of every report", async () => {
    fixture = await startFixture({ authorization: LOGIN_FIRST, consent: {} });
    const d = dir();
    const sid = fixture.issueSession();
    writeFileSync(join(d, "c"), `sid=${sid}\n`, { mode: 0o600 });
    const out = join(d, "r.json");
    const md = join(d, "r.md");
    const sarif = join(d, "r.sarif");
    const events = join(d, "e.jsonl");
    await main([
      "scan", fixture.mcpUrl, "--allow-private", "--only", "RDR01,RDR02", "--session-cookie-file", join(d, "c"),
      "--quiet", "--json", out, "--markdown", md, "--sarif", sarif, "--events", events, "--verbose",
    ]);
    const r = JSON.parse(readFileSync(out, "utf8")) as ScanReport;
    const byId = Object.fromEntries(r.findings.map((f) => [f.checkId, f]));
    expect(byId["MAP-RDR01"]?.status).toBe("pass");
    expect(byId["MAP-RDR02"]?.status).toBe("pass");
    for (const file of [out, md, sarif, events]) expect(readFileSync(file, "utf8")).not.toContain(sid);
  });
});
