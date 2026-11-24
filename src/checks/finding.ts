import { safeText } from "../redact.js";
import type { CheckDefinition, CheckStatus, Finding, ReasonCode, ReportSummary, Severity } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";
import { CATALOGUE } from "./catalogue.js";

export function definition(checkId: string): CheckDefinition {
  const def = CATALOGUE.find((c) => c.id === checkId);
  if (!def) throw new Error(`Unknown check ${checkId}`);
  return def;
}

/**
 * One finding, built the same way by every check: text is neutralized and
 * redacted here, and a `skipped` or `error` status always carries a reason.
 */
export function makeFinding(checkId: string, target: string, status: CheckStatus, message: string, evidence: string[] = [], reason?: ReasonCode): Finding {
  const def = definition(checkId);
  const f: Finding = {
    checkId: def.id,
    title: def.title,
    severity: def.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
    family: def.family,
    active: def.active,
  };
  if (status === "error") f.reason = reason ?? "unexpected_answer";
  else if (status === "skipped" && reason) f.reason = reason;
  return f;
}

/** Reason for an inconclusive answer, from its HTTP status and headers. */
export function reasonForAnswer(status: number, headers: Record<string, string> = {}): ReasonCode {
  if (status === 429 || (status >= 400 && headers["retry-after"] !== undefined)) return "rate_limited";
  if (status >= 500) return "server_error";
  return "unexpected_answer";
}

export function summarize(findings: readonly Finding[]): ReportSummary {
  const counts: Record<CheckStatus, number> = { pass: 0, fail: 0, not_applicable: 0, error: 0, skipped: 0 };
  let highest: Severity | null = null;
  for (const f of findings) {
    counts[f.status] += 1;
    if (f.status === "fail" && (highest === null || SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(highest))) highest = f.severity;
  }
  const total = findings.length;
  const judged = counts.pass + counts.fail;
  return { counts, total, judged, coverage: total === 0 ? 0 : Math.round((judged / total) * 100) / 100, highestFailingSeverity: highest };
}
