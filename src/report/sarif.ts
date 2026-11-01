import { CATALOGUE } from "../checks/catalogue.js";
import type { ScanReport, Severity } from "../types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

/**
 * SARIF 2.1.0 output. Only failing checks become results; passes are
 * recorded as rule metadata only. Each result points at the scanned URL,
 * since there is no source file for a remote server.
 */
export function toSarif(report: ScanReport): string {
  const rules = CATALOGUE.map((c) => ({
    id: c.id,
    name: c.id.replace(/-/g, ""),
    shortDescription: { text: c.title },
    fullDescription: { text: c.rationale },
    help: { text: c.remediation, markdown: `${c.remediation}\n\n${c.references.map((r) => `- [${r.title}](${r.url})`).join("\n")}` },
    helpUri: c.references[0]?.url,
    properties: {
      "security-severity": SECURITY_SEVERITY[c.severity],
      tags: ["security", "mcp", "oauth", c.active ? "active" : "passive"],
    },
  }));

  const results = report.findings
    .filter((f) => f.status === "fail")
    .map((f) => ({
      ruleId: f.checkId,
      level: LEVEL[f.severity],
      message: { text: [f.message, ...f.evidence].join("\n") },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri: f.target } },
        },
      ],
    }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            version: report.tool.version,
            informationUri: "https://github.com/Enigmacker/mcp-authprobe",
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: !report.findings.some((f) => f.status === "error"),
            startTimeUtc: report.startedAt,
            endTimeUtc: report.finishedAt,
          },
        ],
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}
