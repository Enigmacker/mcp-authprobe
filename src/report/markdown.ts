import { SEVERITY_ORDER, type Finding, type ScanReport } from "../types.js";

/**
 * Text for a Markdown table cell, or any inline position. Report text mixes
 * the tool's words with server-controlled values, and the report is pasted
 * into pull request comments and job summaries: nothing in it may become a
 * link, an image, a mention, HTML or formatting.
 */
export function escapeMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/@/g, "&#64;")
    .replace(/[\\`*_[\]{}()#!|~]/g, "\\$&")
    .replace(/\r?\n/g, "<br>");
}

const escapeCell = escapeMarkdown;

const STATUS_LABEL: Record<Finding["status"], string> = {
  fail: "FAIL",
  pass: "pass",
  not_applicable: "n/a",
  error: "error",
  skipped: "skipped",
};

export function toMarkdown(report: ScanReport): string {
  const sorted = [...report.findings].sort(
    (a, b) =>
      Number(b.status === "fail") - Number(a.status === "fail") ||
      SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) ||
      a.checkId.localeCompare(b.checkId),
  );
  const failures = report.findings.filter((f) => f.status === "fail").length;

  const lines = [
    `# mcp-authprobe report`,
    ``,
    `- **Target:** \`${report.target.replace(/`/g, "%60")}\``,
    `- **Ownership:** ${report.ownership.verified ? `verified (${escapeMarkdown(report.ownership.method ?? "")})` : "not verified"}: ${escapeMarkdown(report.ownership.detail)}`,
    `- **Started:** ${report.startedAt}`,
    `- **Tool:** ${report.tool.name} ${report.tool.version}`,
    `- **Failing checks:** ${failures}`,
    ``,
    `| Status | Severity | Check | Message |`,
    `| --- | --- | --- | --- |`,
    ...sorted.map(
      (f) => `| ${STATUS_LABEL[f.status]} | ${f.severity} | ${f.checkId} | ${escapeCell(f.message)} |`,
    ),
    ``,
  ];
  if (report.posture) {
    const p = report.posture;
    lines.push(
      `## Passive results from ${escapeMarkdown(p.tool.name)} ${escapeMarkdown(p.tool.version)}`,
      ``,
      `What the server announces (${escapeMarkdown(p.tool.name)}${p.generatedAt ? `, ${escapeMarkdown(p.generatedAt)}` : ""}) next to what it enforces (mcp-authprobe).`,
      ``,
    );
    if (p.correlations.length > 0) {
      lines.push(`| Check | Relation | mcp-posture | Note |`, `| --- | --- | --- | --- |`);
      for (const c of p.correlations) lines.push(`| ${c.checkId} | ${c.kind} | ${escapeCell(c.postureIds.join(", ")) || "-"} | ${escapeCell(c.message)} |`);
      lines.push(``);
    }
    if (p.findings.length > 0) {
      lines.push(`| Severity | mcp-posture check | Message |`, `| --- | --- | --- |`);
      for (const f of [...p.findings].sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity))) {
        lines.push(`| ${f.severity} | ${escapeCell(f.checkId)} | ${escapeCell(f.message)} |`);
      }
      lines.push(``);
    }
  }
  return lines.join("\n");
}
