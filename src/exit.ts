import { severityAtLeast, type ScanReport, type Severity } from "./types.js";

/**
 * Exit codes of the CLI. They are part of the interface: a program that runs
 * the scanner can rely on them.
 */
export const EXIT = {
  /** No failing check at or above --fail-on (and, unless --fail-on-inconclusive false, no inconclusive one). */
  ok: 0,
  /** At least one failing check at or above --fail-on (or `ownership verify` failed). */
  findings: 1,
  /** Usage error: nothing was sent. */
  usage: 2,
  /** At least one inconclusive check (unless --fail-on-inconclusive false); `login` failed. */
  error: 3,
  /** The target gave no HTTP answer, or the scan could not run or was interrupted. Never silenced by --fail-on-inconclusive. */
  unreachable: 4,
  /** `login` wrote its results but no test grant. */
  noGrant: 5,
} as const;

export interface ExitOptions {
  failOn?: Severity;
  failOnInconclusive?: boolean;
}

/** The exit code the CLI gives for a report. */
export function exitCodeFor(report: ScanReport, o: ExitOptions = {}): number {
  const failOn = o.failOn ?? "high";
  if (report.reachable === false) return EXIT.unreachable;
  if (report.findings.some((f) => f.status === "fail" && severityAtLeast(f.severity, failOn))) return EXIT.findings;
  if (report.complete === false) return EXIT.unreachable;
  if ((o.failOnInconclusive ?? true) && report.findings.some((f) => f.status === "error")) return EXIT.error;
  return EXIT.ok;
}
