import { CATALOGUE, LOGIN_CHECK_IDS } from "./checks/catalogue.js";

/**
 * Parts of the documentation generated from the catalogue, so the README and
 * the tool cannot drift apart. `npm run docs` rewrites the marked blocks of
 * README.md; a test fails when they are out of date.
 */

/** The table of the "What it checks" section. */
export function checksTable(): string {
  return [
    "| ID | Severity | Mode | Runs with | Check |",
    "| --- | --- | --- | --- | --- |",
    ...CATALOGUE.map((c) => `| \`${c.id}\` | ${c.severity} | ${c.active ? "active" : "passive"} | ${c.runsWith} | ${c.title}${c.appliesTo.length === 1 ? ` (MCP ${c.appliesTo[0]} only)` : ""} |`),
  ].join("\n");
}

/** "21 checks", wherever the README counts them. */
export function checksCount(): string {
  return `${CATALOGUE.length} checks`;
}

/** The checks `login` observes, as a sentence fragment. */
export function loginChecks(): string {
  return `${LOGIN_CHECK_IDS.length} checks are observed during login (${LOGIN_CHECK_IDS.map((id) => `\`${id}\``).join(", ")})`;
}

export const GENERATED_BLOCKS: Record<string, () => string> = {
  "checks-table": checksTable,
  "checks-count": checksCount,
  "login-checks": loginChecks,
};

/** Replace every `<!-- generated:NAME -->…<!-- /generated -->` block of a document. */
export function applyGeneratedBlocks(text: string, blocks: Record<string, () => string> = GENERATED_BLOCKS): string {
  return text.replace(/<!-- generated:([a-z-]+) -->([\s\S]*?)<!-- \/generated -->/g, (whole, name: string, inner: string) => {
    const render = blocks[name];
    if (!render) return whole;
    const block = inner.includes("\n");
    return `<!-- generated:${name} -->${block ? "\n" : ""}${render()}${block ? "\n" : ""}<!-- /generated -->`;
  });
}
