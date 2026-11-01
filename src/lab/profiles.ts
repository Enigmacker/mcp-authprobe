import type { FixtureOptions } from "./server.js";

/**
 * Lab profiles. "vulnerable" gets as many checks as possible to fail;
 * "secure" is what a compliant server looks like. Both use the consent page
 * (account test / test), so `login` and `consent-check` work against them.
 */
export const LAB_PROFILES = {
  vulnerable: {
    description: "Deliberately misconfigured: most checks fail.",
    options: {
      tokens: { rotate: true, rejectReplay: false, bindRedirect: false, pkce: "optional", codeReuse: "allow" },
      authorization: { match: "prefix", registration: "lax" },
      consent: { csrf: "none", sameSite: "unset" },
      mcp: { checkAudience: false, validateOrigin: false },
    },
  },
  secure: {
    description: "Compliant: every check passes or is not applicable.",
    options: {
      tokens: { rateLimitAfter: 5, codeReuse: "refuse" },
      authorization: { match: "exact", registration: "strict" },
      consent: { csrf: "token", sameSite: "Lax" },
      mcp: { checkAudience: true, validateOrigin: true },
    },
  },
} as const satisfies Record<string, { description: string; options: FixtureOptions }>;

export type LabProfile = keyof typeof LAB_PROFILES;

export function isLabProfile(name: string): name is LabProfile {
  return Object.hasOwn(LAB_PROFILES, name);
}
