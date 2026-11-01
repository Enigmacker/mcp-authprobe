import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TOOL_VERSION } from "../src/version.js";

const read = (p: string): string => readFileSync(new URL(p, import.meta.url), "utf8");

describe("version", () => {
  const pkg = JSON.parse(read("../package.json")) as { name: string; version: string; mcpName: string };

  it("matches package.json and has a CHANGELOG entry", () => {
    expect(TOOL_VERSION).toBe(pkg.version);
    expect(read("../CHANGELOG.md")).toContain(`## [${pkg.version}]`);
  });

  it("keeps server.json (MCP Registry) in sync with package.json", () => {
    const server = JSON.parse(read("../server.json")) as {
      name: string;
      description: string;
      version: string;
      packages: Array<{ identifier: string; version: string; packageArguments?: Array<{ value?: string }> }>;
    };
    expect(server.name).toBe(pkg.mcpName);
    expect(server.version).toBe(pkg.version);
    expect(server.description.length).toBeLessThanOrEqual(100);
    expect(server.packages[0]?.identifier).toBe(pkg.name);
    expect(server.packages[0]?.version).toBe(pkg.version);
    expect(server.packages[0]?.packageArguments?.[0]?.value).toBe("mcp");
  });
});
