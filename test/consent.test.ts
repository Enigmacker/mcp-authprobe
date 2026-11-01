import { existsSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { findConsentForm, grantsConsent, runConsentCheck, type ConsentSnapshot } from "../src/consent/analyze.js";
import { captureConsentSnapshot } from "../src/consent/browser.js";
import { HttpClient } from "../src/net/http.js";
import { startFixture, type ConsentBehaviour, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

const REDIRECT = "http://127.0.0.1:59999/callback";

async function registerClient(fx: Fixture): Promise<string> {
  const res = await fetch(`${fx.baseUrl}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT] }),
  });
  return ((await res.json()) as { client_id: string }).client_id;
}

function authorizeUrl(fx: Fixture, clientId: string): string {
  const u = new URL(`${fx.baseUrl}/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", REDIRECT);
  u.searchParams.set("state", "st");
  u.searchParams.set("code_challenge", "cc");
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

/** What the browser driver would capture, built over plain HTTP. */
async function snapshot(consent: ConsentBehaviour): Promise<ConsentSnapshot> {
  fixture = await startFixture({ consent });
  const clientId = await registerClient(fixture);
  const sid = fixture.issueSession();
  const url = authorizeUrl(fixture, clientId);
  const html = await (await fetch(url, { headers: { cookie: `sid=${sid}` } })).text();
  return {
    url,
    html,
    redirectUri: REDIRECT,
    cookies: [{ name: "sid", value: sid, domain: "127.0.0.1", path: "/", secure: false, httpOnly: true, sameSite: consent.sameSite ?? "Lax" }],
  };
}

async function check(consent: ConsentBehaviour, allowed = ["127.0.0.1"]) {
  const snap = await snapshot(consent);
  http = new HttpClient({ allowPrivate: true });
  return runConsentCheck(http, (fixture as Fixture).mcpUrl, snap, allowed);
}

describe("findConsentForm", () => {
  const page = (inner: string) => `<html><body>${inner}</body></html>`;

  it("picks the approve control, detects the anti-CSRF field and ignores OAuth parameters", () => {
    const form = findConsentForm(
      page(`<form method="post" action="/consent">
        <input type="hidden" name="state" value="aaaaaaaaaaaaaaaaaaaaaaaa1234567890">
        <input type="hidden" name="client_id" value="c">
        <input type="hidden" name="_csrf" value="t">
        <button name="d" value="deny">Deny</button><button name="d" value="allow">Allow access</button></form>`),
      "https://as.example/authorize",
    );
    expect(form?.action).toBe("https://as.example/consent");
    expect(form?.approve).toEqual({ name: "d", value: "allow", type: "submit" });
    expect(form?.csrfFields).toEqual(["_csrf"]);
  });

  it("treats an unnamed random hidden value as an anti-CSRF token", () => {
    const form = findConsentForm(page(`<form method="post"><input type="hidden" name="x" value="Zq8Lw3Pn5Rt7Yv9Bc2Df"><button>Authorize</button></form>`), "https://as.example/a");
    expect(form?.csrfFields).toEqual(["x"]);
  });

  it("ignores login forms, GET forms and deny-only forms", () => {
    expect(findConsentForm(page(`<form method="post"><input name="u"><input type="password" name="p"><button>Log in</button></form>`), "https://as.example/")).toBeNull();
    expect(findConsentForm(page(`<form method="get"><button>Allow</button></form>`), "https://as.example/")).toBeNull();
    expect(findConsentForm(page(`<form method="post"><button>Cancel</button></form>`), "https://as.example/")).toBeNull();
  });
});

describe("grantsConsent", () => {
  it("requires a redirect to the redirect URI carrying a code", () => {
    expect(grantsConsent(302, `${REDIRECT}?code=x&state=s`, REDIRECT, "https://as.example")).toBe(true);
    expect(grantsConsent(302, `${REDIRECT}?error=access_denied`, REDIRECT, "https://as.example")).toBe(false);
    expect(grantsConsent(302, "https://as.example/login", REDIRECT, "https://as.example")).toBe(false);
    expect(grantsConsent(200, undefined, REDIRECT, "https://as.example")).toBe(false);
  });
});

describe("MAP-CSR01 replay", () => {
  it("passes when a per-session anti-CSRF token is required", async () => {
    const f = await check({ csrf: "token" });
    expect(f.status).toBe("pass");
    expect(f.evidence.some((e) => e.includes("anti-CSRF field(s): csrf_token"))).toBe(true);
  });

  it("fails when any POST with the session cookie grants consent", async () => {
    const f = await check({ csrf: "none", sameSite: "None" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/not SameSite Lax\/Strict/);
  });

  it("fails when the token is rendered but never verified", async () => {
    const f = await check({ csrf: "unverified" });
    expect(f.status).toBe("fail");
  });

  it("mentions the SameSite mitigation when cookies are Lax", async () => {
    const f = await check({ csrf: "none", sameSite: "Lax" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/same-site subdomains/);
  });

  it("passes when a foreign Origin is refused even without a token", async () => {
    const f = await check({ csrf: "origin" });
    expect(f.status).toBe("pass");
  });

  it("sends nothing when the form posts to an unproven host", async () => {
    const f = await check({ csrf: "none" }, ["other.example"]);
    expect(f.status).toBe("error");
    expect((fixture as Fixture).consentsGranted()).toBe(0);
    expect((fixture as Fixture).requests.filter((r) => r.path === "/consent")).toEqual([]);
  });

  it("never reports cookie values or tokens", async () => {
    const f = await check({ csrf: "token" });
    expect(JSON.stringify(f)).not.toMatch(/(sid|csrf)_[0-9a-f]{32}/);
  });
});

// Real browser, headless: runs where Chrome and playwright-core are installed.
const chromeAvailable = ["/opt/google/chrome/chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].some((p) => existsSync(p));

describe.skipIf(!chromeAvailable)("browser driver (real Chrome)", () => {
  async function login(page: any): Promise<void> {
    await page.fill("input[name=username]", "test");
    await page.fill("input[name=password]", "test");
    await page.click("button[type=submit]");
  }

  it("captures the consent page with its cookies and finds a compliant server", async () => {
    fixture = await startFixture({ consent: { csrf: "token", sameSite: "Strict" } });
    const clientId = await registerClient(fixture);
    const result = await captureConsentSnapshot({
      authorizationUrl: authorizeUrl(fixture, clientId),
      redirectUri: REDIRECT,
      headless: true,
      waitForConsentPage: async (page: any) => {
        await login(page);
        await page.waitForSelector("button[value=allow]");
      },
    });
    expect(result.kind).toBe("snapshot");
    if (result.kind !== "snapshot") return;
    expect(result.snapshot.cookies.find((c) => c.name === "sid")?.sameSite).toBe("Strict");
    http = new HttpClient({ allowPrivate: true });
    const f = await runConsentCheck(http, fixture.mcpUrl, result.snapshot, ["127.0.0.1"]);
    expect(f.status).toBe("pass");
  }, 60_000);

  it("reports a redirect when Allow is clicked, and intercepts it", async () => {
    fixture = await startFixture({ consent: { csrf: "token" } });
    const clientId = await registerClient(fixture);
    const result = await captureConsentSnapshot({
      authorizationUrl: authorizeUrl(fixture, clientId),
      redirectUri: REDIRECT,
      headless: true,
      waitForConsentPage: async (page: any) => {
        await login(page);
        await page.click("button[value=allow]");
        await page.waitForURL(/callback/);
      },
    });
    expect(result.kind).toBe("redirected");
  }, 60_000);
});
