import type { ScanReport } from "../types.js";

/** Identifier of the report format. Fields are only ever added within v1; see schema/report.schema.json. */
export const REPORT_SCHEMA = "mcp-authprobe/report/v1";

export function toJson(report: ScanReport): string {
  return `${JSON.stringify({ schema: REPORT_SCHEMA, ...report }, null, 2)}\n`;
}
