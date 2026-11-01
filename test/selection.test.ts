import { afterEach, describe, expect, it } from "vitest";
import { CATALOGUE } from "../src/checks/catalogue.js";
import { scan } from "../src/scan.js";
import { parseSelection, resolveChecks, SelectionError, type CheckSelector } from "../src/selection.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

describe("check selection", () => {
  it("resolves IDs, short IDs and families, case-insensitively", () => {
    expect([...resolveChecks("MAP-THR01, rdr01,RTK")]).toEqual(["MAP-THR01", "MAP-RDR01", "MAP-RTK01", "MAP-RTK02", "MAP-RTK03"]);
  });

  it("refuses unknown names and an empty --only", () => {
    expect(() => resolveChecks("RDR99")).toThrow(SelectionError);
    expect(() => parseSelection("THR,nope")).toThrow(/Unknown check or family "nope"/);
    expect(() => parseSelection(" , ")).toThrow(/at least one/);
  });

  it("lets --skip win over --only, and selects everything by default", () => {
    expect(parseSelection()).toBeUndefined();
    const sel = parseSelection("RDR", "RDR02") as (id: string) => boolean;
    expect(["MAP-RDR01", "MAP-RDR02", "MAP-RDR04", "MAP-THR01"].map(sel)).toEqual([true, false, true, false]);
  });

  it("--only RDR01 sends no request for the other checks, and lists them as not selected", async () => {
    fixture = await startFixture({});
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: parseSelection("RDR01") as CheckSelector });
    expect(report.findings.map((f) => f.checkId).sort()).toEqual(CATALOGUE.map((c) => c.id).sort());
    expect(report.findings.find((f) => f.checkId === "MAP-RDR01")?.status).toBe("pass");
    for (const f of report.findings.filter((x) => x.checkId !== "MAP-RDR01")) {
      expect([f.checkId, f.message]).toEqual([f.checkId, "Not selected (--only/--skip): not run."]);
    }
    expect(fixture.tokenRequests()).toBe(0);
    // One registration for the test client; none of RDR04's unsafe registrations.
    expect(fixture.requests.filter((r) => r.path === "/register" && r.method === "POST")).toHaveLength(1);
    expect(fixture.requests.filter((r) => r.path === "/mcp")).toHaveLength(1); // discovery only, no ORG01
  });

  it("--skip THR sends no failed token request", async () => {
    fixture = await startFixture({});
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, select: parseSelection(undefined, "THR") as CheckSelector });
    expect(report.findings.find((f) => f.checkId === "MAP-THR01")?.message).toMatch(/Not selected/);
    expect(report.findings.find((f) => f.checkId === "MAP-RDR04")?.status).toBe("pass");
    expect(fixture.tokenRequests()).toBe(0);
  });
});
