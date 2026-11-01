import { writeGrantFile } from "./credentials.js";
import { discover } from "./discovery.js";
import { login, LoginError, openInBrowser } from "./login.js";
import { HttpClient } from "./net/http.js";
import { verifyOwnership } from "./ownership.js";
import { hostsToVerify } from "./scan.js";

export interface LoginCommandOptions {
  mcpUrl: string;
  out: string;
  force: boolean;
  probe: boolean;
  browser: boolean;
  allowPrivate: boolean;
  secret: string | undefined;
}

const err = (t: string): void => {
  process.stderr.write(`${t}\n`);
};

/** `mcp-authprobe login`: everything goes to stderr; tokens are only written to the grant file. */
export async function runLoginCommand(o: LoginCommandOptions): Promise<number> {
  const http = new HttpClient({ allowPrivate: o.allowPrivate });
  try {
    const discovery = await discover(o.mcpUrl, http);
    let probe = false;
    if (o.probe) {
      const results = [];
      for (const host of hostsToVerify(o.mcpUrl, discovery)) results.push(await verifyOwnership(host, o.secret, { http }));
      probe = results.every((r) => r.verified);
      if (!probe) err("Ownership not proven for every host: MAP-RDR03 will not be observed.");
    }

    const result = await login({
      http,
      mcpUrl: o.mcpUrl,
      discovery,
      probeRedirectBinding: probe,
      log: err,
      openUrl: async (url) => {
        err(`\nAuthorization URL (open it if no browser appears):\n${url}\n`);
        if (o.browser) await openInBrowser(url);
      },
    });

    for (const ob of result.observations) err(`${ob.checkId}: ${ob.status} - ${ob.message}`);
    for (const n of result.notes) err(`Note: ${n}`);
    if (!result.grant) return 3;

    try {
      writeGrantFile(o.out, result.grant, result.observations, o.force);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      err(code === "EEXIST" ? `${o.out} already exists; use --force to overwrite it.` : `Could not write ${o.out}: ${(e as Error).message}`);
      return 2;
    }
    err(`Test grant written to ${o.out} (mode 600). It is consumed by the refresh token checks: scan with --credentials-file ${o.out}.`);
    return 0;
  } catch (e) {
    err(e instanceof LoginError ? `Login failed: ${e.message}` : `Login failed: ${(e as Error).message}`);
    return 3;
  } finally {
    await http.close();
  }
}
