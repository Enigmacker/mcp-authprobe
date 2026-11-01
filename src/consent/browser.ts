import type { ConsentSnapshot, SnapshotCookie } from "./analyze.js";

/**
 * Browser driver for MAP-CSR01, built on the optional `playwright-core`
 * dependency and the Chrome (or Edge) already installed on the machine:
 * no browser is downloaded.
 *
 * The user logs in with a test account and stops on the consent page; the
 * driver never clicks anything. A navigation to the client's redirect URI
 * (auto-approval, or a click on Allow) is detected and reported; the caller
 * owns the loopback listener behind that URI, so a code is never delivered
 * to any other process.
 */

export interface CaptureOptions {
  authorizationUrl: string;
  redirectUri: string;
  /** "chrome" (default), "msedge" or "chromium"; ignored with executablePath. */
  channel?: string;
  executablePath?: string;
  headless?: boolean;
  /**
   * Resolves when the consent page is displayed (the user pressing Enter in
   * the CLI, a scripted helper in tests). Receives the page for scripting.
   */
  waitForConsentPage: (page: unknown) => Promise<void>;
  timeoutMs?: number;
}

export type CaptureResult =
  | { kind: "snapshot"; snapshot: ConsentSnapshot }
  /** The browser reached the redirect URI before the consent page was captured. */
  | { kind: "redirected" };

export class BrowserUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserUnavailableError";
  }
}

interface PwCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

async function loadPlaywright(): Promise<{ chromium: { launch: (o: Record<string, unknown>) => Promise<any> } }> {
  try {
    const name = "playwright-core"; // kept in a variable: optional peer dependency
    return (await import(name)) as { chromium: { launch: (o: Record<string, unknown>) => Promise<any> } };
  } catch {
    throw new BrowserUnavailableError(
      "The consent check needs the optional package playwright-core. Run it with: npx -p mcp-authprobe -p playwright-core mcp-authprobe consent-check <mcp-url>",
    );
  }
}

export async function captureConsentSnapshot(o: CaptureOptions): Promise<CaptureResult> {
  const { chromium } = await loadPlaywright();
  const launchOptions: Record<string, unknown> = { headless: o.headless ?? false };
  if (o.executablePath) launchOptions["executablePath"] = o.executablePath;
  else launchOptions["channel"] = o.channel ?? "chrome";

  let browser: any;
  try {
    browser = await chromium.launch(launchOptions);
  } catch (e) {
    throw new BrowserUnavailableError(
      `Could not start the browser (${(e as Error).message.split("\n")[0]}). Install Google Chrome, or pass --browser msedge, or --browser-path <executable>.`,
    );
  }

  try {
    const context = await browser.newContext();
    const redirect = new URL(o.redirectUri);
    let reachedRedirect = false;
    // Intercept the client's redirect URI: nothing is ever delivered there.
    await context.route(
      (url: URL) => url.origin === redirect.origin && url.pathname === redirect.pathname,
      async (route: any) => {
        reachedRedirect = true;
        await route.fulfill({
          status: 200,
          contentType: "text/plain; charset=utf-8",
          body: "mcp-authprobe: the authorization server redirected back to the client. The consent check needs the consent page itself; you can close this window.",
        });
      },
    );

    // Redirects are not routed by Playwright: also watch every request, so a
    // 302 to the redirect URI is noticed even though it was not intercepted.
    const isRedirect = (raw: string): boolean => {
      try {
        const u = new URL(raw);
        return u.origin === redirect.origin && u.pathname === redirect.pathname;
      } catch {
        return false;
      }
    };
    context.on("request", (req: any) => {
      if (isRedirect(req.url())) reachedRedirect = true;
    });

    const page = await context.newPage();
    await page.goto(o.authorizationUrl, { timeout: o.timeoutMs ?? 60_000 });

    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      o.waitForConsentPage(page),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Timed out waiting for the consent page.")), o.timeoutMs ?? 10 * 60_000);
      }),
    ]).finally(() => clearTimeout(timer));

    // Let any navigation started by the page settle before reading it.
    let url = "";
    let html = "";
    for (let attempt = 0; attempt < 10; attempt += 1) {
      try {
        await page.waitForLoadState("load", { timeout: 5_000 });
      } catch {
        /* keep trying below */
      }
      if (reachedRedirect || isRedirect(page.url())) return { kind: "redirected" };
      try {
        html = await page.content();
        url = page.url();
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    if (reachedRedirect) return { kind: "redirected" };
    if (!html) throw new Error("The page kept navigating; could not capture the consent page.");
    const cookies = ((await context.cookies()) as PwCookie[]).map(
      (c): SnapshotCookie => ({ name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite }),
    );
    return { kind: "snapshot", snapshot: { url, html, cookies, redirectUri: o.redirectUri } };
  } finally {
    await browser.close();
  }
}
