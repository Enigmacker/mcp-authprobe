import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TOOL_VERSION } from "../src/version.js";

describe("version", () => {
  it("matches package.json and has a CHANGELOG entry", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(TOOL_VERSION).toBe(pkg.version);
    expect(readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8")).toContain(`## [${pkg.version}]`);
  });
});
