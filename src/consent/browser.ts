import type { ConsentSnapshot, SameSite, SnapshotCookie } from "./analyze.js";

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

export interface FlowTarget {
  authorizationUrl: string;
  redirectUri: string;
}

export interface CaptureOptions {
  /**
   * Called once the browser is running, so nothing is registered on the
   * server when no browser can start. Returns where to send the user.
   */
  prepare: () => Promise<FlowTarget>;
  /** "chrome" (default), "msedge" or "chromium"; ignored with executablePath. */
  channel?: string;
  executablePath?: string;
  headless?: boolean;
  /**
   * Resolves when the consent page is displayed (the user pressing Enter in
   * the CLI, a scripted helper in tests). Must stop waiting when `signal`
   * aborts (timeout, browser closed, Ctrl-C).
   */
  waitForConsentPage: (page: unknown, signal: AbortSignal) => Promise<void>;
  /** Aborts the whole capture (the CLI wires Ctrl-C to it). */
  signal?: AbortSignal;
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

export class CaptureAbortedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CaptureAbortedError";
  }
}

interface PwCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
}

type Chromium = { launch: (o: Record<string, unknown>) => Promise<any> };

export async function loadPlaywright(): Promise<{ chromium: Chromium }> {
  try {
    const name = "playwright-core"; // kept in a variable: optional peer dependency
    return (await import(name)) as { chromium: Chromium };
  } catch {
    throw new BrowserUnavailableError(
      "The consent check needs the optional package playwright-core. Run it with: npx -p mcp-authprobe -p playwright-core mcp-authprobe consent-check <mcp-url>",
    );
  }
}

/** SameSite attribute of a raw Set-Cookie line, as the server wrote it. */
export function sameSiteOf(setCookie: string): { name: string; sameSite: SameSite } | null {
  const [pair, ...attrs] = setCookie.split(";");
  const name = pair?.split("=")[0]?.trim();
  if (!name) return null;
  let sameSite: SameSite = "Unspecified";
  for (const a of attrs) {
    const [k, v] = a.split("=").map((x) => x.trim());
    if (k?.toLowerCase() === "samesite") {
      const value = (v ?? "").toLowerCase();
      sameSite = value === "strict" ? "Strict" : value === "lax" ? "Lax" : value === "none" ? "None" : "Unspecified";
    }
  }
  return { name, sameSite };
}

export async function captureConsentSnapshot(o: CaptureOptions): Promise<CaptureResult> {
  const { chromium } = await loadPlaywright();
  const launchOptions: Record<string, unknown> = {
    headless: o.headless ?? false,
    // Our own signal handling runs the cleanup; Playwright's would exit first.
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  };
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

  const abort = new AbortController();
  const onOuterAbort = (): void => abort.abort(new CaptureAbortedError("Interrupted."));
  o.signal?.addEventListener("abort", onOuterAbort, { once: true });
  browser.on("disconnected", () => abort.abort(new CaptureAbortedError("The browser was closed before the consent page was confirmed.")));
  const timer = setTimeout(() => abort.abort(new CaptureAbortedError("Timed out waiting for the consent page.")), o.timeoutMs ?? 10 * 60_000);

  try {
    const target = await o.prepare();
    const context = await browser.newContext();
    const redirect = new URL(target.redirectUri);
    const isRedirect = (raw: string): boolean => {
      try {
        const u = new URL(raw);
        return u.origin === redirect.origin && u.pathname === redirect.pathname;
      } catch {
        return false;
      }
    };
    let reachedRedirect = false;
    // Redirects are not routed by Playwright, so watch every request.
    context.on("request", (req: any) => {
      if (isRedirect(req.url())) reachedRedirect = true;
    });
    // Raw SameSite attributes: Playwright reports a missing one as "Lax".
    const rawSameSite = new Map<string, SameSite>();
    context.on("response", async (res: any) => {
      try {
        for (const h of (await res.headersArray()) as Array<{ name: string; value: string }>) {
          if (h.name.toLowerCase() !== "set-cookie") continue;
          for (const line of h.value.split("\n")) {
            const parsed = sameSiteOf(line);
            if (parsed) rawSameSite.set(parsed.name, parsed.sameSite);
          }
        }
      } catch {
        /* response gone */
      }
    });

    const page = await context.newPage();
    page.on("close", () => abort.abort(new CaptureAbortedError("The page was closed before the consent page was confirmed.")));
    await page.goto(target.authorizationUrl, { timeout: o.timeoutMs ?? 60_000 });

    await new Promise<void>((resolve, reject) => {
      if (abort.signal.aborted) return reject(abort.signal.reason as Error);
      abort.signal.addEventListener("abort", () => reject(abort.signal.reason as Error), { once: true });
      o.waitForConsentPage(page, abort.signal).then(resolve, reject);
    });

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
      (c): SnapshotCookie => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: rawSameSite.get(c.name) ?? "Unspecified",
      }),
    );
    return { kind: "snapshot", snapshot: { url, html, cookies, redirectUri: target.redirectUri } };
  } finally {
    clearTimeout(timer);
    o.signal?.removeEventListener("abort", onOuterAbort);
    await browser.close().catch(() => undefined);
  }
}
