import { afterEach, describe, expect, it } from "vitest";
import { NEAR_MISS_VARIANTS, runRedirectUriChecks, UNSAFE_REGISTRATIONS } from "../src/checks/redirect-uris.js";
import { HttpClient } from "../src/net/http.js";
import { pointsTo } from "../src/oauth/authorize.js";
import { deleteClient, SAFE_DOMAIN } from "../src/oauth/registration.js";
import type { Finding } from "../src/types.js";
import { startFixture, type AuthorizationBehaviour, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

async function run(authorization: AuthorizationBehaviour = {}): Promise<{ byId: Record<string, Finding>; fx: Fixture }> {
  fixture = await startFixture({ authorization });
  http = new HttpClient({ allowPrivate: true });
  const reg = authorization.registration === "disabled" ? null : `${fixture.baseUrl}/register`;
  const all = await runRedirectUriChecks({
    http,
    target: fixture.mcpUrl,
    authorizationEndpoint: `${fixture.baseUrl}/authorize`,
    registrationEndpoint: reg,
    resource: fixture.mcpUrl,
    scope: "mcp",
  });
  return { byId: Object.fromEntries(all.map((f) => [f.checkId, f])), fx: fixture };
}

const statuses = (byId: Record<string, Finding>): Record<string, string> =>
  Object.fromEntries(Object.entries(byId).map(([k, v]) => [k, v.status]));

describe("pointsTo", () => {
  it("compares scheme, host, port, path and userinfo, ignoring query", () => {
    const r = `https://client.${SAFE_DOMAIN}/callback`;
    expect(pointsTo(`${r}?code=x&state=y`, r)).toBe(true);
    expect(pointsTo(`${r}/extra?code=x`, r)).toBe(false);
    expect(pointsTo(`https://client.${SAFE_DOMAIN}:8443/callback`, r)).toBe(false);
    expect(pointsTo(`http://client.${SAFE_DOMAIN}/callback`, r)).toBe(false);
    expect(pointsTo("not a url", r)).toBe(false);
  });
});

describe("variants", () => {
  it("only ever use the reserved .invalid domain or inert schemes", () => {
    for (const v of [...NEAR_MISS_VARIANTS, ...UNSAFE_REGISTRATIONS]) {
      const u = new URL(v.uri);
      if (u.protocol === "https:" || u.protocol === "http:") expect(u.hostname.endsWith(".invalid")).toBe(true);
      else expect(["javascript:", "data:"]).toContain(u.protocol);
    }
  });
});

describe("redirect URI checks", () => {
  it("pass on a compliant server and clean up every test client", async () => {
    const { byId, fx } = await run();
    expect(statuses(byId)).toEqual({ "MAP-RDR01": "pass", "MAP-RDR02": "pass", "MAP-RDR04": "pass" });
    expect(fx.registeredClients()).toEqual([]);
  });

  it("flag prefix matching on the extra path, trailing slash and query variants only", async () => {
    const { byId } = await run({ match: "prefix", noSession: "error-redirect" });
    expect(byId["MAP-RDR01"]?.status).toBe("pass");
    const rdr02 = byId["MAP-RDR02"];
    expect(rdr02?.status).toBe("fail");
    expect(rdr02?.message).toMatch(/3 unregistered/);
    expect(rdr02?.evidence.some((e) => e.startsWith("subdomain: refused"))).toBe(true);
  });

  it("flag a server that redirects to any URI", async () => {
    const { byId } = await run({ match: "any", noSession: "error-redirect" });
    expect(byId["MAP-RDR01"]?.status).toBe("fail");
    expect(byId["MAP-RDR02"]?.status).toBe("fail");
  });

  it("report inconclusive, not pass, when validation is deferred until login", async () => {
    const { byId } = await run({ match: "deferred" });
    expect(byId["MAP-RDR01"]?.status).toBe("error");
    expect(byId["MAP-RDR02"]?.status).toBe("error");
    expect(byId["MAP-RDR02"]?.message).toMatch(/Inconclusive/);
  });

  it("flag lax registration and delete the accepted clients", async () => {
    const { byId, fx } = await run({ registration: "lax" });
    expect(byId["MAP-RDR04"]?.status).toBe("fail");
    expect(byId["MAP-RDR04"]?.message).toMatch(/4 unsafe/);
    expect(fx.registeredClients()).toEqual([]);
  });

  it("report clients it could not delete", async () => {
    const { byId, fx } = await run({ registration: "lax", management: false });
    expect(fx.registeredClients().length).toBe(5);
    expect(byId["MAP-RDR04"]?.evidence.some((e) => e.includes("left on the server"))).toBe(true);
  });

  it("skip without dynamic registration", async () => {
    const { byId } = await run({ registration: "disabled" });
    expect(statuses(byId)).toEqual({ "MAP-RDR01": "skipped", "MAP-RDR02": "skipped", "MAP-RDR04": "not_applicable" });
  });

  it("never follow a management URI to another origin", async () => {
    http = new HttpClient({ allowPrivate: true });
    const deleted = await deleteClient(
      http,
      { clientId: "c", clientSecret: null, redirectUris: [], registrationClientUri: "https://elsewhere.example/register/c", registrationAccessToken: "t" },
      "http://127.0.0.1:9/register",
    );
    expect(deleted).toBe(false);
  });
});
