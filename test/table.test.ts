import { describe, expect, it } from "vitest";
import { colorWanted, toTable } from "../src/report/table.js";
import type { ScanReport } from "../src/types.js";

const report: ScanReport = {
  tool: { name: "mcp-authprobe", version: "0" },
  startedAt: "",
  finishedAt: "",
  target: "https://mcp.example.com/mcp",
  ownership: { verified: true, method: "well-known", detail: "" },
  findings: [
    { checkId: "MAP-RDR04", title: "t", severity: "high", status: "fail", target: "x", message: "accepted", evidence: ["a", "b", "c", "d", "e"] },
    { checkId: "MAP-RDR02", title: "t", severity: "high", status: "error", target: "x", message: "unclear", evidence: ["e1"] },
    { checkId: "MAP-DSC01", title: "t", severity: "info", status: "pass", target: "x", message: "ok", evidence: ["p1"] },
    { checkId: "MAP-CSR01", title: "t", severity: "high", status: "skipped", target: "x", message: "later", evidence: [] },
  ],
};

describe("table report", () => {
  it("shows the evidence of failing checks only, three lines each, and a summary", () => {
    const t = toTable(report);
    expect(t).not.toMatch(/\x1b/);
    expect(t).toMatch(/FAIL {9}high {5}MAP-RDR04 {2}accepted/);
    expect(t).toMatch(/ {6}c\n {6}\(2 more line\(s\): --verbose\)/);
    expect(t).not.toMatch(/e1|p1/);
    expect(t).toMatch(/1 failing, 1 passing, 1 inconclusive, 1 skipped or n\/a/);
  });

  it("groups the checks that did not run by reason", () => {
    const r = { ...report, findings: [...report.findings, { ...report.findings[3]!, checkId: "MAP-SES01" }] };
    const t = toTable(r);
    expect(t).toMatch(/skipped {6}MAP-CSR01, MAP-SES01\n {6}later/);
    expect(toTable(r, { verbose: true })).toMatch(/MAP-SES01  later/);
  });

  it("shows everything with verbose, and colours only when asked", () => {
    const t = toTable(report, { verbose: true, color: true });
    for (const e of ["e", "e1", "p1"]) expect(t).toContain(e);
    expect(t).toContain("\x1b[1;31mFAIL");
  });

  it("follows NO_COLOR, FORCE_COLOR and the terminal", () => {
    expect(colorWanted({ isTTY: true }, {})).toBe(true);
    expect(colorWanted({ isTTY: false }, {})).toBe(false);
    expect(colorWanted({ isTTY: true }, { NO_COLOR: "1" })).toBe(false);
    expect(colorWanted({ isTTY: false }, { FORCE_COLOR: "1" })).toBe(true);
  });
});
