import type { ScanReport } from "../types.js";

export function toJson(report: ScanReport): string {
  return `${JSON.stringify({ schema: "mcp-authprobe/report/v1", ...report }, null, 2)}\n`;
}
