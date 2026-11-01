import { CATALOGUE } from "./checks/catalogue.js";

/** Which checks a scan runs. */
export type CheckSelector = (checkId: string) => boolean;

export class SelectionError extends Error {}

/**
 * Resolve one comma-separated list of check IDs (MAP-THR01 or THR01) and
 * families (THR) to full check IDs. Unknown names are an error, so a typo
 * never silently runs (or skips) the wrong checks.
 */
export function resolveChecks(list: string): Set<string> {
  const ids = new Set<string>();
  for (const raw of list.split(",")) {
    const name = raw.trim().toUpperCase();
    if (!name) continue;
    const full = name.startsWith("MAP-") ? name : `MAP-${name}`;
    const byId = CATALOGUE.filter((c) => c.id === full);
    const byFamily = CATALOGUE.filter((c) => c.family === name);
    const matched = byId.length > 0 ? byId : byFamily;
    if (matched.length === 0) {
      const families = [...new Set(CATALOGUE.map((c) => c.family))].join(", ");
      throw new SelectionError(`Unknown check or family "${raw.trim()}". Families: ${families}. IDs: see \`mcp-authprobe checks list\`.`);
    }
    for (const c of matched) ids.add(c.id);
  }
  return ids;
}

/** Build a selector from --only and --skip (both optional; --skip wins). */
export function parseSelection(only?: string, skip?: string): CheckSelector | undefined {
  if (only === undefined && skip === undefined) return undefined;
  const included = only !== undefined ? resolveChecks(only) : null;
  if (included && included.size === 0) throw new SelectionError("--only needs at least one check or family.");
  const excluded = skip !== undefined ? resolveChecks(skip) : new Set<string>();
  return (id) => (included === null || included.has(id)) && !excluded.has(id);
}
