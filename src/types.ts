export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export function severityAtLeast(value: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(value) >= SEVERITY_ORDER.indexOf(threshold);
}

/** Outcome of a single check against a single target. */
export type CheckStatus = "pass" | "fail" | "not_applicable" | "error" | "skipped";

export interface Reference {
  title: string;
  url: string;
}

/** Static description of a check, independent of any target. */
export interface CheckDefinition {
  /** Stable identifier, never reused, e.g. "MAP-RTK01". */
  id: string;
  title: string;
  severity: Severity;
  /** Whether the check sends state-changing requests to the target. */
  active: boolean;
  /** Family the check belongs to, e.g. "RTK" for refresh tokens. */
  family: string;
  /** "available" checks run today; "planned" ones are documented ahead of time. */
  availability: "available" | "planned";
  /** MCP revisions whose requirements the check tests. A check does not apply to a server that speaks none of them. */
  appliesTo: readonly string[];
  /** What a run needs for this check to execute, in a few words (Markdown), for the documentation. */
  runsWith: string;
  rationale: string;
  remediation: string;
  references: readonly Reference[];
}

/**
 * Why a check is `skipped` or `error` (inconclusive), as a stable code: the
 * message says the same in English, this is for programs. New codes may be
 * added in minor versions; existing ones are never renamed.
 */
export type ReasonCode =
  // skipped
  | "not_selected"
  | "ownership_unproven"
  | "needs_grant"
  | "needs_login"
  | "needs_browser"
  | "needs_static_key"
  | "needs_credential"
  | "no_client"
  | "no_endpoint"
  | "not_observed"
  | "stale_observation"
  // error (inconclusive)
  | "unreachable"
  | "rate_limited"
  | "server_error"
  | "credential_rejected"
  | "credential_expired"
  | "deferred_validation"
  | "incomplete"
  | "ambiguous"
  | "protocol_unsupported"
  | "interrupted"
  | "unexpected_answer";

export const REASON_CODES: readonly ReasonCode[] = [
  "not_selected", "ownership_unproven", "needs_grant", "needs_login", "needs_browser", "needs_static_key", "needs_credential", "no_client", "no_endpoint",
  "not_observed", "stale_observation", "unreachable", "rate_limited", "server_error", "credential_rejected", "credential_expired", "deferred_validation",
  "incomplete", "ambiguous", "protocol_unsupported", "interrupted", "unexpected_answer",
];

/** Result of running one check against one target. */
export interface Finding {
  checkId: string;
  title: string;
  severity: Severity;
  status: CheckStatus;
  target: string;
  message: string;
  /** Short, already-redacted evidence lines. Never contains tokens. */
  evidence: string[];
  /** Family of the check, e.g. "RTK". */
  family?: string;
  /** Whether the check sends state-changing requests. */
  active?: boolean;
  /** Present when the status is `skipped` or `error`: why, as a stable code. */
  reason?: ReasonCode;
  /** Where the result comes from: this scan, or an earlier `login` or `consent-check` stored in the grant file. */
  source?: "scan" | "login" | "consent-check";
  /** When the result was observed (ISO 8601). For `source: "login"`, the time of that login. */
  observedAt?: string;
  /** Time spent on the check, or on the group of checks that share requests with it, in milliseconds. */
  durationMs?: number;
}

/** Proof of ownership for one host. */
export interface HostOwnership {
  host: string;
  verified: boolean;
  method: "well-known" | "dns-txt" | "loopback" | null;
  detail: string;
}

/** What discovery found, without any secret. */
export interface DiscoverySummary {
  challengeStatus: number | null;
  resourceMetadataUrl: string | null;
  authorizationServerMetadataUrl: string | null;
  /** `resource` announced by the Protected Resource Metadata. */
  resource: string | null;
  issuer: string | null;
  /** Every authorization server the resource lists; only `issuer` was examined. */
  authorizationServers: string[];
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  registrationEndpoint: string | null;
  /** How a client can be obtained: dynamic registration ("dcr"), a client ID metadata document ("cimd"); empty when neither is offered. */
  registration: Array<"dcr" | "cimd">;
  pkceMethods: string[] | null;
  /** MCP protocol era and version the endpoint was spoken to with. */
  protocol: { era: "legacy" | "modern" | "unknown"; version: string | null; supportedVersions: string[]; transport?: "streamable-http" | "http+sse" };
  notes: string[];
}

export interface ReportSummary {
  counts: Record<CheckStatus, number>;
  total: number;
  /** Checks with a verdict (pass or fail). */
  judged: number;
  /** judged / total, between 0 and 1: a scan that exits 0 with most checks skipped has a low coverage. */
  coverage: number;
  highestFailingSeverity: Severity | null;
  /** Exit code of the CLI for this report (absent when the report was built by the library without exit options). */
  exitCode?: number;
}

/** A temporary object the scanner created on the server and could not remove. */
export interface Leftover {
  kind: "client";
  clientId: string;
  /** Where it was registered. */
  endpoint: string;
  reason: string;
}

/** What became of the test grant during the scan (never its values). */
export interface GrantReport {
  /** Token requests were sent with the grant. */
  used: boolean;
  /** The server returned a new refresh token. */
  rotated: boolean;
  /** The grant is spent: the server revoked it (expected after MAP-RTK03 on a compliant server). */
  consumed: boolean;
  state: "valid" | "revoked" | "unknown" | "unused";
  /** The grant file was rewritten with the newest refresh token. */
  rewritten: boolean;
}

export interface ScanReport {
  tool: { name: string; version: string };
  startedAt: string;
  finishedAt: string;
  target: string;
  /** False when the target gave no HTTP answer at all: no check ran, and the CLI exits with an error whatever --fail-on-inconclusive says. */
  reachable?: boolean;
  /** False when the scan was interrupted (signal, deadline, request budget): the findings are partial. */
  complete?: boolean;
  ownership: { verified: boolean; method: string | null; detail: string; hosts?: HostOwnership[] };
  findings: Finding[];
  summary?: ReportSummary;
  discovery?: DiscoverySummary;
  /** The credential used for the MCP endpoint checks: its kind and header, never its value. */
  credential?: { kind: "static" | "oauth"; header: string };
  grant?: GrantReport;
  /** How the checks that need an OAuth client obtain one. */
  client?: { source: "pre-registered" | "metadata-document" | "dynamic-registration" | "none" };
  leftovers?: Leftover[];
  /** The preset the selection came from (--preset), when one was used. */
  preset?: string;
  /** Imported mcp-posture results and how they relate to these findings (--posture-report). */
  posture?: import("./posture.js").PostureSection;
}
