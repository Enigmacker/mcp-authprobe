import type { FixtureOptions } from "./server.js";

/**
 * Lab profiles. "vulnerable" gets as many checks as possible to fail;
 * "secure" is what a compliant server looks like. Both use OAuth with a
 * consent page (account test / test), so `login` and `consent-check` work
 * against them. The two "static-bearer" profiles have no OAuth at all: the
 * MCP endpoint takes a static API key, generated when the lab starts.
 */
/** The client of the `preregistered` profile: no registration, three redirect URIs (checks, a web application, a native loopback). */
export const LAB_CLIENT = {
  clientId: "lab-preregistered-client",
  redirectUris: ["https://client.mcp-authprobe.invalid/callback", "https://app.mcp-authprobe.invalid/oauth/callback", "http://127.0.0.1:8765/callback"],
} as const;

const SECURE_OAUTH = {
  tokens: { rateLimitAfter: 5, codeReuse: "refuse" },
  consent: { csrf: "token", sameSite: "Lax" },
} as const;

export const LAB_PROFILES = {
  vulnerable: {
    description: "Deliberately misconfigured: most checks fail.",
    options: {
      tokens: { rotate: true, rejectReplay: false, bindRedirect: false, pkce: "optional", codeReuse: "allow" },
      authorization: { match: "prefix", registration: "lax" },
      consent: { csrf: "none", sameSite: "unset" },
      mcp: { checkAudience: false, validateOrigin: false, acceptQueryToken: true, sessionWithoutToken: true, cors: "reflect-credentials", metadata: "poisoned" },
    },
  },
  secure: {
    description: "Compliant: every check passes or is not applicable.",
    options: {
      ...SECURE_OAUTH,
      authorization: { match: "exact", registration: "strict" },
      mcp: { checkAudience: true, validateOrigin: true, metadata: "clean", rateLimit: 300, rateLimitHeaders: true },
    },
  },
  modern: {
    description: "Compliant, MCP 2026-07-28 only: stateless, server/discover, required headers, no session, no ping.",
    options: {
      ...SECURE_OAUTH,
      authorization: { match: "exact", registration: "strict" },
      mcp: { checkAudience: true, validateOrigin: true, metadata: "clean", protocol: "modern", sessions: false, rateLimit: 300, rateLimitHeaders: true },
    },
  },
  dual: {
    description: "Compliant, MCP 2026-07-28 and 2025-11-25 on the same endpoint.",
    options: {
      ...SECURE_OAUTH,
      authorization: { match: "exact", registration: "strict" },
      mcp: { checkAudience: true, validateOrigin: true, metadata: "clean", protocol: "dual", rateLimit: 300, rateLimitHeaders: true },
    },
  },
  preregistered: {
    description: "Compliant, without dynamic client registration: one pre-registered client (its ID is printed when the lab starts).",
    options: {
      ...SECURE_OAUTH,
      authorization: { match: "exact", registration: "disabled", clients: [{ clientId: LAB_CLIENT.clientId, redirectUris: [...LAB_CLIENT.redirectUris] }] },
      mcp: { checkAudience: true, validateOrigin: true, metadata: "clean", protocol: "dual", rateLimit: 300, rateLimitHeaders: true },
    },
  },
  "static-bearer": {
    description: "Static API key, no OAuth, deliberately misconfigured: most key checks fail.",
    options: {
      prm: false,
      asMetadata: false,
      challenge: "bearer",
      maxBodyBytes: 16 * 1024 * 1024,
      mcp: { validateOrigin: false, acceptQueryToken: true, batch: true, sessions: true, sessionWithoutToken: true, cors: "reflect-credentials", metadata: "poisoned" },
    },
  },
  "static-bearer-secure": {
    description: "Static API key, no OAuth, compliant: every key check passes or is not applicable.",
    options: {
      prm: false,
      asMetadata: false,
      challenge: "bearer",
      mcp: { validateOrigin: true, sessions: false, rateLimit: 20, metadata: "clean" },
    },
  },
} as const satisfies Record<string, { description: string; options: FixtureOptions }>;

export type LabProfile = keyof typeof LAB_PROFILES;

export function isLabProfile(name: string): name is LabProfile {
  return Object.hasOwn(LAB_PROFILES, name);
}
