import { SEVERITY_ORDER, type CheckStatus, type ScanReport } from "../types.js";

export interface TableOptions {
  /** ANSI colours (the CLI enables them on a terminal, unless NO_COLOR is set). */
  color?: boolean;
  /** One line per check and every evidence line (default: failing checks show 3 evidence lines, checks that did not run are grouped by reason). */
  verbose?: boolean;
}

const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "pass",
  fail: "FAIL",
  error: "inconclusive",
  not_applicable: "n/a",
  skipped: "skipped",
};

const COLOR: Record<CheckStatus, string> = {
  pass: "\x1b[32m",
  fail: "\x1b[1;31m",
  error: "\x1b[33m",
  not_applicable: "\x1b[2m",
  skipped: "\x1b[2m",
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

const EVIDENCE_LINES = 3;

/** Colours on a terminal, unless NO_COLOR is set; FORCE_COLOR forces them. */
export function colorWanted(stream: { isTTY?: boolean } = process.stdout, env: NodeJS.ProcessEnv = process.env): boolean {
  if (env["NO_COLOR"]) return false;
  if (env["FORCE_COLOR"] && env["FORCE_COLOR"] !== "0") return true;
  return stream.isTTY === true;
}

/**
 * Terminal output. Strings are already neutralized by the checks, so the
 * only escape sequences in the output are the colours added here.
 */
export function toTable(report: ScanReport, options: TableOptions = {}): string {
  const paint = (code: string, text: string): string => (options.color ? `${code}${text}${RESET}` : text);
  const out = [
    paint(BOLD, report.target),
    `  ownership: ${report.ownership.verified ? `verified (${report.ownership.method})` : "NOT verified"}`,
  ];
  // By severity, then by ID, so a family reads in order (RTK01, RTK02, RTK03) whatever order the checks ran in.
  const sorted = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || a.checkId.localeCompare(b.checkId),
  );
  // Without --verbose, checks that did not run are grouped by reason, one line each.
  const quiet = (st: CheckStatus): boolean => !options.verbose && (st === "skipped" || st === "not_applicable");
  const groups = new Map<string, { status: CheckStatus; ids: string[] }>();
  for (const f of sorted) {
    if (!quiet(f.status)) continue;
    const key = `${f.status}\u0000${f.message}`;
    const g = groups.get(key) ?? { status: f.status, ids: [] };
    g.ids.push(f.checkId);
    groups.set(key, g);
  }
  for (const g of groups.values()) g.ids.sort();
  for (const f of sorted) {
    if (quiet(f.status)) continue;
    const status = paint(COLOR[f.status], STATUS_LABEL[f.status].padEnd(12));
    out.push(`  ${status} ${f.severity.padEnd(8)} ${f.checkId.padEnd(10)} ${f.message}`);
    const shown = options.verbose ? f.evidence : f.status === "fail" ? f.evidence.slice(0, EVIDENCE_LINES) : [];
    for (const e of shown) out.push(paint(DIM, `      ${e}`));
    const hidden = f.evidence.length - shown.length;
    if (hidden > 0 && f.status === "fail") out.push(paint(DIM, `      (${hidden} more line(s): --verbose)`));
  }
  if (groups.size > 0) out.push("");
  for (const [key, g] of groups) {
    const message = key.split("\u0000")[1] ?? "";
    out.push(`  ${paint(COLOR[g.status], STATUS_LABEL[g.status].padEnd(12))} ${g.ids.join(", ")}`);
    out.push(paint(DIM, `      ${message}`));
  }
  if (report.posture) {
    const p = report.posture;
    const bySeverity = [...SEVERITY_ORDER].reverse().map((s) => [s, p.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
    out.push("", paint(BOLD, `  ${p.tool.name} ${p.tool.version} (passive)`) + `: ${p.findings.length} finding(s)${bySeverity.length > 0 ? ` (${bySeverity.map(([s, n]) => `${n} ${s}`).join(", ")})` : ""}`);
    const KIND: Record<string, string> = { confirmed: "confirmed", "active-only": "active only", enforced: "enforced" };
    for (const c of p.correlations) {
      const colour = c.kind === "enforced" ? COLOR.pass : COLOR.fail;
      out.push(`  ${paint(colour, (KIND[c.kind] ?? c.kind).padEnd(12))} ${c.checkId.padEnd(10)} ${c.message}`);
    }
    if (options.verbose) for (const f of p.findings) out.push(paint(DIM, `      ${f.severity.padEnd(8)} ${f.checkId.padEnd(13)} ${f.message}`));
  }
  const count = (s: CheckStatus): number => report.findings.filter((f) => f.status === s).length;
  const parts = [
    paint(COLOR.fail, `${count("fail")} failing`),
    paint(COLOR.pass, `${count("pass")} passing`),
    paint(COLOR.error, `${count("error")} inconclusive`),
    paint(DIM, `${count("skipped") + count("not_applicable")} skipped or n/a`),
  ];
  out.push("", `  ${parts.join(", ")}${options.verbose ? "" : paint(DIM, "  (--verbose for all evidence)")}`);
  if (report.reachable === false) out.push(paint(COLOR.fail, "  The target is unreachable: no check was run."));
  else if (report.complete === false) out.push(paint(COLOR.error, "  The scan was interrupted: this report is partial."));
  const judged = count("pass") + count("fail");
  if (report.reachable !== false && judged * 2 < report.findings.length) {
    out.push(paint(DIM, `  Only ${judged} of ${report.findings.length} checks could be judged; the skipped lines above, and \`mcp-authprobe plan\`, say what the others need.`));
  }
  for (const l of report.leftovers ?? []) out.push(paint(COLOR.error, `  Left on the server: test client ${l.clientId} (${l.reason}); it is named "mcp-authprobe test client (safe to delete)".`));
  if (report.grant?.consumed) out.push(paint(DIM, "  The test grant was revoked by the server during the refresh token checks, as expected: log in again for a new one."));
  else if (report.grant?.rewritten) out.push(paint(DIM, "  The grant file now holds the newest refresh token."));
  return `${out.join("\n")}\n`;
}
