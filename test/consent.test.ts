import { existsSync } from "node:fs";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { alterToken, cookieApplies, findConsentForm, grantsConsent, runConsentCheck, type ConsentSnapshot, type SnapshotCookie } from "../src/consent/analyze.js";
import { captureConsentSnapshot, sameSiteOf } from "../src/consent/browser.js";
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
  const sameSite = consent.sameSite === "unset" || consent.sameSite === undefined ? (consent.sameSite === "unset" ? "Unspecified" : "Lax") : consent.sameSite;
  return {
    url,
    html,
    redirectUri: REDIRECT,
    cookies: [{ name: "sid", value: sid, domain: "127.0.0.1", path: "/", secure: false, httpOnly: true, sameSite }],
  };
}

async function check(consent: ConsentBehaviour, allowed = ["127.0.0.1"]) {
  const snap = await snapshot(consent);
  http = new HttpClient({ allowPrivate: true });
  return runConsentCheck(http, (fixture as Fixture).mcpUrl, snap, allowed);
}

describe("findConsentForm", () => {
  const page = (inner: string) => `<html><body>${inner}</body></html>`;

  it("picks the approve control, recognises the anti-CSRF field by name, and keeps OAuth parameters", () => {
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

  it("does not take \"Don't allow\" for the approve button (review finding)", () => {
    const form = findConsentForm(page(`<form method="post"><button name="d" value="no">Don't allow</button><button name="d" value="yes">Allow</button></form>`), "https://as.example/a");
    expect(form?.approve?.value).toBe("yes");
  });

  it("recognises French labels (review finding)", () => {
    const form = findConsentForm(page(`<form method="post"><button name="d" value="n">Refuser</button><button name="d" value="o">Autoriser</button></form>`), "https://as.example/a");
    expect(form?.approve?.value).toBe("o");
  });

  it("keeps random request identifiers instead of treating them as CSRF tokens (review finding)", () => {
    const form = findConsentForm(
      page(`<form method="post"><input type="hidden" name="consent_challenge" value="Zq8Lw3Pn5Rt7Yv9Bc2Df"><input type="hidden" name="x" value="Ab3Cd5Ef7Gh9Jk2Lm4Np"><button>Authorize</button></form>`),
      "https://as.example/a",
    );
    expect(form?.csrfFields).toEqual([]);
    expect(form?.unclassified).toEqual(["x"]);
    expect(form?.fields.map((f) => f.name)).toEqual(["consent_challenge", "x"]);
  });

  it("honours formaction, base href, required checkboxes, selects and textareas", () => {
    const form = findConsentForm(
      `<html><head><base href="https://as.example/app/"></head><body><form id="f" method="post" action="ignored">
        <input type="checkbox" name="agree" value="yes" required>
        <input type="checkbox" name="newsletter" value="1">
        <select name="scope_choice"><option value="a">A</option><option value="b" selected>B</option></select>
        <textarea name="note">hi</textarea>
        <button name="d" value="allow" formaction="approve">Allow</button></form>
        <input form="f" type="hidden" name="extra" value="1"></body></html>`,
      "https://as.example/consent",
    );
    expect(form?.action).toBe("https://as.example/app/approve");
    expect(form?.fields).toEqual([
      { name: "agree", value: "yes", type: "checkbox" },
      { name: "extra", value: "1", type: "hidden" },
      { name: "note", value: "hi", type: "textarea" },
      { name: "scope_choice", value: "b", type: "select" },
    ]);
  });

  it("ignores login forms, GET forms and deny-only forms", () => {
    expect(findConsentForm(page(`<form method="post"><input name="u"><input type="password" name="p"><button>Log in</button></form>`), "https://as.example/")).toBeNull();
    expect(findConsentForm(page(`<form method="get"><button>Allow</button></form>`), "https://as.example/")).toBeNull();
    expect(findConsentForm(page(`<form method="post"><button>Cancel</button></form>`), "https://as.example/")).toBeNull();
  });
});

describe("helpers", () => {
  it("alterToken changes the value within its alphabet, keeping its length (review finding)", () => {
    for (const v of ["deadbeef", "DEADBEEF", "9f00", "abc-123_XYZ", "zzz", "Z9"]) {
      const a = alterToken(v);
      expect(a).not.toBe(v);
      expect(a.length).toBe(v.length);
    }
    expect(alterToken("f0")).toMatch(/^[0-9a-f]+$/);
    expect(Buffer.from(alterToken("deadbeef"), "hex").equals(Buffer.from("deadbeef", "hex"))).toBe(false);
  });

  it("grantsConsent recognises redirects and auto-submitting pages carrying a code", () => {
    const h = (status: number, location?: string, body = "") => ({ status, headers: location ? { location } : {}, body });
    expect(grantsConsent(h(302, `${REDIRECT}?code=x&state=s`), REDIRECT, "https://as.example")).toBe(true);
    expect(grantsConsent(h(302, `${REDIRECT}?error=access_denied`), REDIRECT, "https://as.example")).toBe(false);
    expect(grantsConsent(h(302, "https://as.example/login"), REDIRECT, "https://as.example")).toBe(false);
    expect(grantsConsent(h(200, undefined, `<meta http-equiv="refresh" content="0;url=${REDIRECT}?code=abc&amp;state=s">`), REDIRECT, "https://as.example")).toBe(true);
    expect(grantsConsent(h(200, undefined, `<form action="${REDIRECT}"><input name="code" value="x"></form>`), REDIRECT, "https://as.example")).toBe(true);
    expect(grantsConsent(h(200, undefined, "<p>Access denied</p>"), REDIRECT, "https://as.example")).toBe(false);
  });

  it("matches cookies like a browser: host-only, domain, path, secure (review finding)", () => {
    const c = (o: Partial<SnapshotCookie>): SnapshotCookie => ({ name: "s", value: "v", domain: "as.example", path: "/", secure: false, httpOnly: true, sameSite: "Lax", ...o });
    expect(cookieApplies(c({}), new URL("https://as.example/consent"))).toBe(true);
    expect(cookieApplies(c({}), new URL("https://sub.as.example/consent"))).toBe(false);
    expect(cookieApplies(c({ domain: ".as.example" }), new URL("https://sub.as.example/consent"))).toBe(true);
    expect(cookieApplies(c({ path: "/oauth" }), new URL("https://as.example/consent"))).toBe(false);
    expect(cookieApplies(c({ path: "/oauth" }), new URL("https://as.example/oauth/consent"))).toBe(true);
    expect(cookieApplies(c({ path: "/oauth" }), new URL("https://as.example/oauthx"))).toBe(false);
    expect(cookieApplies(c({ secure: true }), new URL("http://as.example/consent"))).toBe(false);
  });

  it("reads the raw SameSite attribute (review finding)", () => {
    expect(sameSiteOf("sid=1; Path=/; HttpOnly")).toEqual({ name: "sid", sameSite: "Unspecified" });
    expect(sameSiteOf("sid=1; SameSite=strict")).toEqual({ name: "sid", sameSite: "Strict" });
    expect(sameSiteOf("a=b; samesite=None; Secure")).toEqual({ name: "a", sameSite: "None" });
  });
});

describe("MAP-CSR01 replay", () => {
  it("passes when a per-session anti-CSRF token is required, with a working control", async () => {
    const f = await check({ csrf: "token" });
    expect(f.status).toBe("pass");
    expect(f.evidence.some((e) => e.includes("anti-CSRF field(s): csrf_token"))).toBe(true);
  });

  it("fails when any POST with the session cookie grants consent", async () => {
    const f = await check({ csrf: "none", sameSite: "None" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/not explicitly SameSite/);
  });

  it("fails when the token is rendered but never verified", async () => {
    expect((await check({ csrf: "unverified" })).status).toBe("fail");
  });

  it("does not call an unspecified SameSite protective (review finding)", async () => {
    const f = await check({ csrf: "none", sameSite: "unset" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/not explicitly SameSite/);
  });

  it("mentions the SameSite mitigation when cookies are explicitly Lax", async () => {
    const f = await check({ csrf: "none", sameSite: "Lax" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/same-site subdomains/);
  });

  it("passes when a foreign Origin is refused even without a token", async () => {
    expect((await check({ csrf: "origin" })).status).toBe("pass");
  });

  it("fails with \"Don't allow\" before \"Allow\" on an unprotected server (review finding)", async () => {
    expect((await check({ csrf: "none", labels: "dont-allow" })).status).toBe("fail");
  });

  it("fails with French labels on an unprotected server (review finding)", async () => {
    expect((await check({ csrf: "none", labels: "fr" })).status).toBe("fail");
  });

  it("fails with a required checkbox on an unprotected server (review finding)", async () => {
    expect((await check({ csrf: "none", requireCheckbox: true })).status).toBe("fail");
  });

  it("is inconclusive, never a pass, when the consent is sent by JavaScript (review finding)", async () => {
    const f = await check({ csrf: "none", spa: true });
    expect(f.status).toBe("error");
    expect(f.message).toMatch(/could not reproduce a grant/);
  });

  it("fails when only the presence of the token is checked and the grant goes through a resume URL (review finding)", async () => {
    const f = await check({ csrf: "presence", resume: true });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/altered anti-CSRF token/);
  });

  it("fails when only a request identifier stands between a website and the grant (review finding)", async () => {
    const f = await check({ csrf: "none", challenge: true });
    expect(f.status).toBe("fail");
  });

  it("does not fail a server that verifies a hex token with a lenient decoder (review finding)", async () => {
    expect((await check({ csrf: "hex" })).status).toBe("pass");
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

  async function capture(consent: ConsentBehaviour, script: (page: any) => Promise<void>, extra: { signal?: AbortSignal; timeoutMs?: number } = {}) {
    fixture = await startFixture({ consent });
    const fx = fixture;
    let registered = false;
    const result = await captureConsentSnapshot({
      headless: true,
      prepare: async () => {
        registered = true;
        return { authorizationUrl: authorizeUrl(fx, await registerClient(fx)), redirectUri: REDIRECT };
      },
      waitForConsentPage: async (page) => script(page),
      ...extra,
    });
    return { result, registered };
  }

  it("captures the consent page with raw cookie attributes and finds a compliant server", async () => {
    const { result } = await capture({ csrf: "token", sameSite: "Strict" }, async (page) => {
      await login(page);
      await page.waitForSelector("button[value=allow]");
    });
    expect(result.kind).toBe("snapshot");
    if (result.kind !== "snapshot") return;
    expect(result.snapshot.cookies.find((c) => c.name === "sid")?.sameSite).toBe("Strict");
    http = new HttpClient({ allowPrivate: true });
    expect((await runConsentCheck(http, (fixture as Fixture).mcpUrl, result.snapshot, ["127.0.0.1"])).status).toBe("pass");
  }, 60_000);

  it("reports a missing SameSite attribute as Unspecified, not Lax (review finding)", async () => {
    const { result } = await capture({ csrf: "token", sameSite: "unset" }, async (page) => {
      await login(page);
      await page.waitForSelector("button[value=allow]");
    });
    expect(result.kind === "snapshot" && result.snapshot.cookies.find((c) => c.name === "sid")?.sameSite).toBe("Unspecified");
  }, 60_000);

  it("reports a redirect when Allow is clicked", async () => {
    const { result } = await capture({ csrf: "token" }, async (page) => {
      await login(page);
      // The callback URL has no listener here: wait for the request, not for a page load.
      await Promise.all([page.waitForRequest(/callback/), page.click("button[value=allow]")]);
    });
    expect(result.kind).toBe("redirected");
  }, 60_000);

  it("stops waiting and closes the browser on abort (review finding)", async () => {
    const ac = new AbortController();
    const started = Date.now();
    await expect(
      capture({ csrf: "token" }, async (page) => {
        setTimeout(() => ac.abort(), 200);
        await page.waitForTimeout(60_000); // a user who never presses Enter
      }, { signal: ac.signal }),
    ).rejects.toThrow(/Interrupted/);
    expect(Date.now() - started).toBeLessThan(20_000);
  }, 60_000);

  it("stops waiting when the user closes the page (review finding)", async () => {
    await expect(
      capture({ csrf: "token" }, async (page) => {
        setTimeout(() => void page.close(), 200);
        await new Promise(() => undefined); // never resolves on its own
      }),
    ).rejects.toThrow(/closed/);
  }, 60_000);

  it("times out instead of hanging", async () => {
    await expect(capture({ csrf: "token" }, async () => new Promise(() => undefined), { timeoutMs: 1_500 })).rejects.toThrow(/Timed out/);
  }, 60_000);
});

describe("browser unavailable", () => {
  it("registers nothing when the browser cannot start (review finding)", async () => {
    fixture = await startFixture({ consent: {} });
    let prepared = false;
    await expect(
      captureConsentSnapshot({
        executablePath: "/nonexistent/chrome",
        headless: true,
        prepare: async () => {
          prepared = true;
          return { authorizationUrl: "http://127.0.0.1/", redirectUri: REDIRECT };
        },
        waitForConsentPage: async () => undefined,
      }),
    ).rejects.toThrow(/Could not start the browser/);
    expect(prepared).toBe(false);
  });
});

describe("waitForEnter", () => {
  const sink = () => new PassThrough();

  it("resolves on Enter", async () => {
    const { waitForEnter } = await import("../src/consent-command.js");
    const input = new PassThrough();
    const p = waitForEnter("> ", new AbortController().signal, input, sink());
    input.write("\n");
    await expect(p).resolves.toBeUndefined();
  });

  it("rejects and releases the input on abort (review finding)", async () => {
    const { waitForEnter } = await import("../src/consent-command.js");
    const input = new PassThrough();
    const ac = new AbortController();
    const p = waitForEnter("> ", ac.signal, input, sink());
    ac.abort(new Error("Timed out waiting for the consent page."));
    await expect(p).rejects.toThrow(/Timed out/);
  });

  it("rejects when the input closes (review finding)", async () => {
    const { waitForEnter } = await import("../src/consent-command.js");
    const input = new PassThrough();
    const p = waitForEnter("> ", new AbortController().signal, input, sink());
    input.end();
    await expect(p).rejects.toThrow(/closed/);
  });
});

describe("MAP-CSR01 with per-flow identifiers (node-oidc-provider style)", () => {
  it("is inconclusive, not failing, when a session-bound flow id in the form URL is the only protection", async () => {
    const f = await check({ csrf: "none", flowUrl: "bound" });
    expect(f.status).toBe("error");
    expect(f.message).toMatch(/per-flow identifiers/);
    expect(f.evidence.join("\n")).toMatch(/probe 0a, per-flow identifier\(s\) altered, foreign Origin: refused/);
    expect(f.evidence.join("\n")).toMatch(/probe 0b, untouched form without any cookie, foreign Origin: refused/);
  });

  it("fails when the flow id grants consent without any cookie", async () => {
    const f = await check({ csrf: "none", flowUrl: "unbound" });
    expect(f.status).toBe("fail");
    expect(f.message).toMatch(/no cookie at all/);
  });

  it("still passes a real anti-CSRF token next to a flow id", async () => {
    expect((await check({ csrf: "token", flowUrl: "bound" })).status).not.toBe("fail");
  });

  it("fails a flow id that is not checked (consent_challenge only required to be present)", async () => {
    const f = await check({ csrf: "none", challenge: true });
    expect(f.status).toBe("fail");
  });
});

