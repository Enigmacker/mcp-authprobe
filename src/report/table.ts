import { SEVERITY_ORDER, type ScanReport } from "../types.js";

/** Plain terminal output. Strings are already neutralized by the checks. */
export function toTable(report: ScanReport): string {
  const out = [
    report.target,
    `  ownership: ${report.ownership.verified ? `verified (${report.ownership.method})` : "NOT verified"}`,
  ];
  const sorted = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity),
  );
  for (const f of sorted) {
    out.push(`  ${f.status.padEnd(8)} ${f.severity.padEnd(8)} ${f.checkId.padEnd(10)} ${f.message}`);
    for (const e of f.evidence) out.push(`           ${e}`);
  }
  return `${out.join("\n")}\n`;
}
