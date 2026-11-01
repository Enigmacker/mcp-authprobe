import { isLabProfile, LAB_PROFILES } from "./lab/profiles.js";
import { startFixture, type Fixture, type FixtureOptions } from "./lab/server.js";

export interface LabCommandOptions {
  profile: string;
  /** Decimal digits only (from the command line), or a number. */
  port: string | number;
  host: string;
}

export class LabUsageError extends Error {}

/**
 * `mcp-authprobe lab`: run a local MCP server with OAuth, deliberately
 * vulnerable or compliant, to try the scanner in a minute. Loopback only.
 */
export async function startLab(o: LabCommandOptions): Promise<{ lab: Fixture; banner: string }> {
  if (!isLabProfile(o.profile)) throw new LabUsageError(`Unknown profile "${o.profile}". Use: ${Object.keys(LAB_PROFILES).join(", ")}.`);
  const host = o.host.replace(/^\[(.*)\]$/, "$1");
  if (host !== "127.0.0.1" && host !== "::1") throw new LabUsageError("The lab only listens on 127.0.0.1 or ::1: it is vulnerable on purpose.");
  const port = typeof o.port === "number" ? o.port : /^\d{1,5}$/.test(o.port) ? Number(o.port) : NaN;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new LabUsageError("--port must be a number between 0 and 65535.");
  const profile = LAB_PROFILES[o.profile];
  const options = { ...(structuredClone(profile.options) as FixtureOptions), host, port };
  const lab = await startFixture(options);
  const url = lab.mcpUrl;
  const banner = `mcp-authprobe lab (${o.profile}): ${profile.description}
MCP endpoint: ${url}
Test account: test / test

Try it, in another terminal:
  npx mcp-authprobe scan ${url} --allow-private
  npx mcp-authprobe login ${url} --allow-private --out lab-grant.json
  npx mcp-authprobe scan ${url} --allow-private --credentials-file lab-grant.json
  npx -p mcp-authprobe -p playwright-core mcp-authprobe consent-check ${url} --allow-private

Loopback targets need no ownership proof with --allow-private.
Everything is in memory and lost when the lab stops. Press Ctrl-C to stop.
`;
  return { lab, banner };
}
