import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runRefreshTokenChecks } from "../src/checks/refresh-tokens.js";
import { loadGrant, parseGrant, type TestGrant } from "../src/credentials.js";
import { HttpClient } from "../src/net/http.js";
import type { Finding } from "../src/types.js";
import { startFixture, type Fixture, type TokenBehaviour } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

async function run(tokens: TokenBehaviour = {}, grantOverride: Partial<TestGrant> = {}): Promise<{ byId: Record<string, Finding>; all: Finding[]; fx: Fixture }> {
  fixture = await startFixture({ tokens });
  http = new HttpClient({ allowPrivate: true });
  const grant: TestGrant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none", ...grantOverride };
  const all = await runRefreshTokenChecks({ http, target: fixture.mcpUrl, tokenEndpoint: `${fixture.baseUrl}/token`, grant });
  const byId = Object.fromEntries(all.map((f) => [f.checkId, f]));
  return { byId, all, fx: fixture };
}

const statuses = (byId: Record<string, Finding>): Record<string, string> =>
  Object.fromEntries(Object.entries(byId).map(([k, v]) => [k, v.status]));

describe("refresh token checks", () => {
  it("pass on a compliant server, in at most three requests", async () => {
    const { byId, fx } = await run();
    expect(statuses(byId)).toEqual({ "MAP-RTK01": "pass", "MAP-RTK02": "pass", "MAP-RTK03": "pass" });
    expect(fx.tokenRequests()).toBe(3);
  });

  it("flag missing rotation and mark replay checks not applicable", async () => {
    const { byId, fx } = await run({ rotate: false });
    expect(statuses(byId)).toEqual({ "MAP-RTK01": "fail", "MAP-RTK02": "not_applicable", "MAP-RTK03": "not_applicable" });
    expect(byId["MAP-RTK01"]?.message).toMatch(/same refresh token/);
    expect(fx.tokenRequests()).toBe(1);
  });

  it("flag a server that returns the same refresh token", async () => {
    const { byId } = await run({ returnSameRefresh: true });
    expect(byId["MAP-RTK01"]?.status).toBe("fail");
  });

  it("flag accepted replay", async () => {
    const { byId } = await run({ rejectReplay: false });
    expect(statuses(byId)).toEqual({ "MAP-RTK01": "pass", "MAP-RTK02": "fail", "MAP-RTK03": "fail" });
  });

  it("flag replay detection without family revocation", async () => {
    const { byId } = await run({ revokeFamily: false });
    expect(statuses(byId)).toEqual({ "MAP-RTK01": "pass", "MAP-RTK02": "pass", "MAP-RTK03": "fail" });
  });

  it("report errors, not passes, when the grant is not accepted", async () => {
    const { byId, fx } = await run({}, { refreshToken: "rt_unknown" });
    expect(Object.values(byId).every((f) => f.status === "error")).toBe(true);
    expect(fx.tokenRequests()).toBe(1);
  });

  it("report errors when throttled", async () => {
    const { byId } = await run({ throttle: true });
    expect(Object.values(byId).every((f) => f.status === "error")).toBe(true);
    expect(byId["MAP-RTK01"]?.message).toMatch(/throttled/);
  });

  it("authenticate confidential clients with client_secret_post and client_secret_basic", async () => {
    for (const authMethod of ["client_secret_post", "client_secret_basic"] as const) {
      const { byId } = await run({ clientSecret: "s3cret:with/special" }, { authMethod, clientSecret: "s3cret:with/special" });
      expect(byId["MAP-RTK03"]?.status).toBe("pass");
      await fixture?.close();
      await http?.close();
      fixture = undefined;
      http = undefined;
    }
  });

  it("never leak token values in findings", async () => {
    const { all } = await run();
    const text = JSON.stringify(all);
    expect(text).not.toMatch(/rt_[0-9a-f]{32}/);
    expect(text).not.toMatch(/at_[0-9a-f]{32}/);
  });
});

describe("credentials file", () => {
  it("parses public and confidential grants", () => {
    expect(parseGrant({ client_id: "c", refresh_token: "r" })).toEqual({ clientId: "c", refreshToken: "r", authMethod: "none" });
    expect(parseGrant({ client_id: "c", refresh_token: "r", client_secret: "s" })).toMatchObject({ authMethod: "client_secret_post", clientSecret: "s" });
  });

  it("rejects incomplete or inconsistent files", () => {
    expect(() => parseGrant({ client_id: "c" })).toThrow(/refresh_token/);
    expect(() => parseGrant({ client_id: "c", refresh_token: "r", token_endpoint_auth_method: "client_secret_basic" })).toThrow(/client_secret/);
    expect(() => parseGrant({ client_id: "c", refresh_token: "r", token_endpoint_auth_method: "private_key_jwt" })).toThrow(/must be one of/);
    expect(() => parseGrant([])).toThrow(/JSON object/);
  });

  it("warns about permissive file modes and never echoes invalid content", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-creds-"));
    const good = join(dir, "good.json");
    writeFileSync(good, JSON.stringify({ client_id: "c", refresh_token: "r" }));
    chmodSync(good, 0o644);
    expect(loadGrant(good).warnings.length).toBe(process.platform === "win32" ? 0 : 1);
    chmodSync(good, 0o600);
    expect(loadGrant(good).warnings).toEqual([]);

    const bad = join(dir, "bad.json");
    writeFileSync(bad, "refresh_token=supersecretvalue");
    expect(() => loadGrant(bad)).toThrow(/not valid JSON/);
    try {
      loadGrant(bad);
    } catch (e) {
      expect((e as Error).message).not.toContain("supersecretvalue");
    }
  });
});
