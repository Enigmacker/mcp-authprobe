import { afterEach, describe, expect, it } from "vitest";
import { clampAttempts, MAX_ATTEMPTS, runThrottlingCheck } from "../src/checks/throttling.js";
import type { TestGrant } from "../src/credentials.js";
import { HttpClient } from "../src/net/http.js";
import { scan } from "../src/scan.js";
import { startFixture, type Fixture, type TokenBehaviour } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

async function run(tokens: TokenBehaviour, opts: { attempts?: number; withGrant?: boolean; registration?: boolean } = {}) {
  fixture = await startFixture({ tokens, authorization: { registration: opts.registration === false ? "disabled" : "strict" } });
  http = new HttpClient({ allowPrivate: true });
  const ctx: Parameters<typeof runThrottlingCheck>[0] = {
    http,
    target: fixture.mcpUrl,
    tokenEndpoint: `${fixture.baseUrl}/token`,
    registrationEndpoint: opts.registration === false ? null : `${fixture.baseUrl}/register`,
  };
  if (opts.withGrant) ctx.grant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" } satisfies TestGrant;
  if (opts.attempts !== undefined) ctx.attempts = opts.attempts;
  return { finding: await runThrottlingCheck(ctx), fx: fixture };
}

describe("clampAttempts", () => {
  it("keeps the number of requests within 5-20, default 10", () => {
    expect(clampAttempts(undefined)).toBe(10);
    expect(clampAttempts(1)).toBe(5);
    expect(clampAttempts(1000)).toBe(MAX_ATTEMPTS);
    expect(clampAttempts(Number.NaN)).toBe(10);
    expect(clampAttempts(7.9)).toBe(7);
  });
});

describe("MAP-THR01", () => {
  it("passes and stops as soon as throttling starts (429)", async () => {
    const { finding, fx } = await run({ rateLimitAfter: 3 });
    expect(finding.status).toBe("pass");
    expect(finding.message).toMatch(/after 4 failed/);
    expect(fx.tokenRequests()).toBe(4);
  });

  it("recognizes an OAuth slow_down error as throttling", async () => {
    const { finding } = await run({ rateLimitAfter: 2, rateLimitStyle: "slow_down" });
    expect(finding.status).toBe("pass");
  });

  it("fails after the capped number of attempts without throttling", async () => {
    const { finding, fx } = await run({}, { attempts: 6 });
    expect(finding.status).toBe("fail");
    expect(fx.tokenRequests()).toBe(6);
    expect(finding.evidence[0]).toBe("HTTP 400 x6");
  });

  it("never sends more than the hard cap, whatever is asked", async () => {
    const { fx } = await run({}, { attempts: 500 });
    expect(fx.tokenRequests()).toBe(MAX_ATTEMPTS);
  });

  it("uses a temporary client when no grant is supplied, and deletes it", async () => {
    const { finding, fx } = await run({ rateLimitAfter: 2 });
    expect(finding.status).toBe("pass");
    expect(fx.registeredClients()).toEqual([]);
  });

  it("skips without a grant and without registration", async () => {
    const { finding, fx } = await run({}, { registration: false });
    expect(finding.status).toBe("skipped");
    expect(fx.tokenRequests()).toBe(0);
  });

  it("does not consume the operator's real refresh token", async () => {
    fixture = await startFixture({});
    http = new HttpClient({ allowPrivate: true });
    const real = fixture.issueRefreshToken();
    await runThrottlingCheck({ http, target: fixture.mcpUrl, tokenEndpoint: `${fixture.baseUrl}/token`, registrationEndpoint: null, grant: { clientId: "test-client", refreshToken: real, authMethod: "none" }, attempts: 5 });
    const res = await fetch(`${fixture.baseUrl}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: real, client_id: "test-client" }),
    });
    expect(res.status).toBe(200);
  });
});

describe("scan ordering", () => {
  it("runs the throttling check after the refresh token checks, so they are not disturbed", async () => {
    fixture = await startFixture({ tokens: { rateLimitAfter: 4 } });
    const grant: TestGrant = { clientId: "test-client", refreshToken: fixture.issueRefreshToken(), authMethod: "none" };
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, grant });
    const status = (id: string) => report.findings.find((f) => f.checkId === id)?.status;
    expect([status("MAP-RTK01"), status("MAP-RTK02"), status("MAP-RTK03"), status("MAP-THR01")]).toEqual(["pass", "pass", "pass", "pass"]);
    expect(report.findings.at(-1)?.checkId).not.toBe("MAP-RTK03");
  });
});
