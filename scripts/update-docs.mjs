// Rewrites the generated blocks of the documentation from the built catalogue.
// Usage: npm run docs
import { readFileSync, writeFileSync } from "node:fs";
import { applyGeneratedBlocks } from "../dist/docs.js";

for (const file of ["README.md", "docs/integration.md"]) {
  let before;
  try {
    before = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
  } catch {
    continue;
  }
  const after = applyGeneratedBlocks(before);
  if (after !== before) {
    writeFileSync(new URL(`../${file}`, import.meta.url), after);
    console.log(`updated ${file}`);
  }
}
