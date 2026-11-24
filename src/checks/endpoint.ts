import type { HttpClient } from "../net/http.js";
import { classifyAnswer, endSession, FOREIGN_ORIGIN, isJsonRpcError, isJsonRpcResult, jsonRpcMessages, mcpPost, type Credential } from "../oauth/mcp-call.js";
import { safeText } from "../redact.js";
import type { CheckStatus, Finding } from "../types.js";
import { CATALOGUE } from "./catalogue.js";
import { inspectMetadata, isPoisoned } from "./metadata.js";

/**
 * Checks of the MCP endpoint itself, with a working credential: an OAuth
 * access token during `login`, or a static API key (`--bearer-file`) during
 * `scan`. Only side-effect-free methods are sent (initialize, ping and the
 * list methods): never
 * tools/call, so no real tool runs. Every check has a hard request cap, and
 * a failed request makes that check inconclusive without stopping the others.
 *
 * Order matters: the per-key rate limit runs last, since once limited the
 * credential may be refused for a while.
 */

export type EndpointCheckId = "MAP-ORG01" | "MAP-TOK01" | "MAP-SES01" | "MAP-BAT01" | "MAP-BOD01" | "MAP-INJ01" | "MAP-THR02";

export interface EndpointOptions {
  /** Checks to run (default: all but MAP-THR02). */
  checks?: readonly EndpointCheckId[];
  /** Requests sent by MAP-THR02 (10-100, default 30). */
  rateAttempts?: number;
}

export interface EndpointResult {
  findings: Finding[];
  /** Status of initialize with the credential (null if the request failed). */
  control: number | null;
}

/** Size of the oversized bodies sent by MAP-BOD01 (above common 1-4 MB limits). */
export const OVERSIZED_BODY_BYTES = 6 * 1024 * 1024;
const BATCH_SIZE = 5;
/** Large uploads get their own, longer timeout: 6 MiB on a slow link needs more than the default 10 s. */
const UPLOAD_TIMEOUT_MS = 60_000;
/** Names under which MAP-TOK01 tries the secret in the query string. */
export const QUERY_NAMES = ["access_token", "api_key", "key", "token"] as const;
const ORIGIN_VARIANTS = [
  { label: "a foreign Origin", value: FOREIGN_ORIGIN },
  { label: 'Origin "null" (sandboxed frames, file: pages)', value: "null" },
  { label: "a malformed Origin", value: "https://[mcp-authprobe" },
] as const;

const is2xx = (s: number | null | undefined): s is number => typeof s === "number" && s >= 200 && s < 300;

function result(checkId: string, target: string, status: CheckStatus, message: string, evidence: string[]): Finding {
  const def = CATALOGUE.find((c) => c.id === checkId);
  if (!def) throw new Error(`Unknown check ${checkId}`);
  return { checkId, title: def.title, severity: def.severity, status, target, message: safeText(message), evidence: evidence.map((e) => safeText(e)) };
}

export function clampRateAttempts(n: number | undefined): number {
  if (n === undefined || !Number.isFinite(n)) return 30;
  return Math.min(100, Math.max(10, Math.round(n)));
}

/** A JSON-RPC ping padded to `size` bytes, still valid JSON. */
function paddedPing(size: number): string {
  const head = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"pad":"';
  const tail = '"}}}';
  return head + "x".repeat(Math.max(0, size - head.length - tail.length)) + tail;
}

async function* chunked(text: string): AsyncIterable<Uint8Array> {
  const buf = Buffer.from(text);
  for (let i = 0; i < buf.length; i += 256 * 1024) yield buf.subarray(i, i + 256 * 1024);
}

export async function runEndpointChecks(http: HttpClient, target: string, cred: Credential, options: EndpointOptions = {}): Promise<EndpointResult> {
  const wanted = new Set<EndpointCheckId>(options.checks ?? ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"]);
  const findings: Finding[] = [];
  const what = cred.kind === "static" ? "key" : "token";
  const guard = async (checkId: EndpointCheckId, run: () => Promise<void>): Promise<void> => {
    if (!wanted.has(checkId)) return;
    try {
      await run();
    } catch (e) {
      findings.push(result(checkId, target, "error", `Inconclusive: a request failed (${(e as Error).message}).`, []));
    }
  };

  // Control: the credential must work, or nothing below can be judged.
  let control: number | null = null;
  let controlSession: string | null = null;
  try {
    const c = await mcpPost(http, target, { auth: cred });
    control = c.status;
    controlSession = c.sessionId;
  } catch {
    control = null;
  }
  if (controlSession) await endSession(http, target, cred, controlSession);
  const controlLine = `initialize with the ${what}: ${control === null ? "request failed" : `HTTP ${control}`}`;
  if (!is2xx(control)) {
    for (const id of wanted) {
      findings.push(result(id, target, "error", `Inconclusive: the MCP endpoint did not accept the ${what}, so this check cannot be judged.`, [controlLine]));
    }
    return { findings, control };
  }

  // Checks below mean nothing on an endpoint that also serves anonymous requests.
  let anonymous: number | null = null;
  try {
    anonymous = (await mcpPost(http, target, {})).status;
  } catch {
    anonymous = null;
  }
  const anonymousLine = `initialize without any credential: ${anonymous === null ? "request failed" : `HTTP ${anonymous}`}`;
  const servesAnonymous = is2xx(anonymous);

  /** Opens a session if the server uses them; returns its ID (or null). */
  const openSession = async (): Promise<string | null> => (await mcpPost(http, target, { auth: cred })).sessionId;

  // --- MAP-ORG01: foreign, "null" and malformed Origins, with the credential.
  await guard("MAP-ORG01", async () => {
    const lines = [controlLine];
    const accepted: string[] = [];
    const not403: string[] = [];
    let unexpected = false;
    let limited = false;
    for (const v of ORIGIN_VARIANTS) {
      const r = await mcpPost(http, target, { auth: cred, origin: v.value });
      if (r.sessionId) await endSession(http, target, cred, r.sessionId);
      lines.push(`initialize with ${v.label}: HTTP ${r.status}`);
      const cls = classifyAnswer(r.status, r.headers);
      if (cls === "accepted") accepted.push(v.label);
      else if (r.status === 403) continue;
      else if (cls === "refused") not403.push(v.label);
      else {
        unexpected = true;
        if (cls === "rate_limited") limited = true;
      }
    }
    // The credential must still work, or a refusal could come from a dead credential.
    const again = await mcpPost(http, target, { auth: cred });
    if (again.sessionId) await endSession(http, target, cred, again.sessionId);
    lines.push(`control again without Origin: HTTP ${again.status}`);
    if (accepted.length > 0) {
      findings.push(result("MAP-ORG01", target, "fail", `The endpoint processes requests with ${accepted.join(", ")}: the Origin header is not validated (DNS rebinding, cross-site calls).`, lines));
    } else if (!is2xx(again.status)) {
      findings.push(result("MAP-ORG01", target, "error", `Inconclusive: the ${what} stopped working during the check.`, lines));
    } else if (unexpected) {
      findings.push(result("MAP-ORG01", target, "error", limited ? `Inconclusive: the endpoint rate-limited the ${what} during the check (429 or Retry-After), which says nothing about Origin validation.` : "Unexpected answers to requests with an invalid Origin; inconclusive.", lines));
    } else if (not403.length > 0) {
      findings.push(result("MAP-ORG01", target, "pass", `Requests with an invalid Origin are refused; the MCP specification expects 403 (got another 4xx for ${not403.join(", ")}).`, lines));
    } else {
      findings.push(result("MAP-ORG01", target, "pass", `Requests with a foreign, "null" or malformed Origin are refused with 403, even with a valid ${what}.`, lines));
    }
  });

  // --- MAP-TOK01: the secret in the URL instead of the header.
  await guard("MAP-TOK01", async () => {
    const lines = [anonymousLine, controlLine];
    if (servesAnonymous) {
      findings.push(result("MAP-TOK01", target, "error", "Inconclusive: the endpoint also answers requests without any credential, so a refused query credential cannot be observed.", lines));
      return;
    }
    const accepted: string[] = [];
    let unexpected = false;
    for (const name of QUERY_NAMES) {
      const q = await mcpPost(http, target, { auth: cred, secretInQuery: name });
      if (q.sessionId) await endSession(http, target, cred, q.sessionId);
      lines.push(`initialize with the ${what} as ?${name}= and no header: HTTP ${q.status}`);
      const cls = classifyAnswer(q.status, q.headers);
      if (cls === "accepted") accepted.push(name);
      else if (cls !== "refused") unexpected = true;
    }
    const again = await mcpPost(http, target, { auth: cred });
    if (again.sessionId) await endSession(http, target, cred, again.sessionId);
    lines.push(`control again with the header: HTTP ${again.status}`);
    if (accepted.length > 0) {
      findings.push(
        result("MAP-TOK01", target, "fail", `The endpoint accepts the ${what} in the URL query string (${accepted.map((n) => `?${n}=`).join(", ")}), where it ends up in logs, history and Referer headers.`, lines),
      );
    } else if (!is2xx(again.status)) {
      findings.push(result("MAP-TOK01", target, "error", `Inconclusive: the ${what} stopped working during the check.`, lines));
    } else if (unexpected) {
      findings.push(result("MAP-TOK01", target, "error", `Unexpected answer to a request with the ${what} in the URL; inconclusive.`, lines));
    } else {
      findings.push(result("MAP-TOK01", target, "pass", `A ${what} in the URL query string is refused (${QUERY_NAMES.join(", ")}).`, lines));
    }
  });

  // --- MAP-SES01: a session ID alone must not authenticate.
  await guard("MAP-SES01", async () => {
    if (servesAnonymous) {
      findings.push(result("MAP-SES01", target, "error", "Inconclusive: the endpoint also answers requests without any credential.", [anonymousLine]));
      return;
    }
    const init = await mcpPost(http, target, { auth: cred });
    const lines = [`initialize with the ${what}: HTTP ${init.status}, ${init.sessionId ? "session ID assigned" : "no session ID"}`];
    if (!init.sessionId) {
      findings.push(result("MAP-SES01", target, "not_applicable", "The server assigned no session ID (stateless): nothing to misuse.", lines));
      return;
    }
    try {
      const withCred = await mcpPost(http, target, { auth: cred, sessionId: init.sessionId, method: "ping" });
      lines.push(`ping with the session ID and the ${what}: HTTP ${withCred.status}`);
      const without = await mcpPost(http, target, { sessionId: init.sessionId, method: "ping" });
      lines.push(`ping with the session ID and no ${what}: HTTP ${without.status}`);
      if (!is2xx(withCred.status)) {
        findings.push(result("MAP-SES01", target, "error", `Inconclusive: the session could not be used even with the ${what}.`, lines));
      } else if (is2xx(without.status)) {
        findings.push(result("MAP-SES01", target, "fail", `A request carrying only the Mcp-Session-Id, without any ${what}, is processed: whoever sees a session ID can act as the user.`, lines));
      } else if (without.status === 401) {
        findings.push(result("MAP-SES01", target, "pass", `A request carrying only the session ID is refused with 401: every request needs its ${what}.`, lines));
      } else if (without.status === 403 || without.status === 400 || without.status === 404) {
        findings.push(result("MAP-SES01", target, "pass", `A request carrying only the session ID is refused (HTTP ${without.status}); the MCP specification expects 401 with a WWW-Authenticate challenge.`, lines));
      } else {
        findings.push(result("MAP-SES01", target, "error", `Unexpected answer to a request without a ${what}; inconclusive.`, lines));
      }
    } finally {
      await endSession(http, target, cred, init.sessionId);
    }
  });

  // --- MAP-BAT01: a JSON-RPC batch of pings in one HTTP request.
  await guard("MAP-BAT01", async () => {
    const session = await openSession();
    try {
      // Control: one ping, same configuration, must work; otherwise a refused batch proves nothing.
      const single = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), method: "ping" });
      if (!is2xx(single.status)) {
        findings.push(result("MAP-BAT01", target, "error", "Inconclusive: a single ping is not accepted either, so a refused batch proves nothing.", [`control, one ping request: HTTP ${single.status}`]));
        return;
      }
      const batch = JSON.stringify(Array.from({ length: BATCH_SIZE }, (_, i) => ({ jsonrpc: "2.0", id: i + 1, method: "ping" })));
      const r = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), body: batch });
      const messages = jsonRpcMessages(r);
      // Only real JSON-RPC 2.0 messages count: any JSON object with an "error" key is not a JSON-RPC refusal.
      const results = messages.filter(isJsonRpcResult).length;
      const errors = messages.filter(isJsonRpcError).length;
      const cls = classifyAnswer(r.status, r.headers);
      const lines = [`control, one ping request: HTTP ${single.status}`, `one POST carrying a JSON-RPC batch of ${BATCH_SIZE} ping requests: HTTP ${r.status}, ${results} result(s), ${errors} error(s)`];
      if (results >= 2) {
        findings.push(
          result(
            "MAP-BAT01",
            target,
            "fail",
            `A JSON-RPC batch is executed: ${results} requests ran from one HTTP request. Limits counted per HTTP request see one call (amplification), and MCP has not allowed batches since the 2025-06-18 revision.`,
            lines,
          ),
        );
      } else if (cls === "rate_limited" || cls === "server_error") {
        findings.push(
          result("MAP-BAT01", target, "error", cls === "rate_limited" ? "Inconclusive: the batch was answered with a rate limit (429 or Retry-After), which says nothing about batches. Scan again once the limit has passed." : "Inconclusive: the batch was answered with a server error (5xx), which is not a refusal of batches.", lines),
        );
      } else if (cls === "refused" || (cls === "accepted" && results === 0 && errors >= 1)) {
        // The same single ping must still work: otherwise the refusal may be about something else (a limit, a dead credential).
        const again = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), method: "ping" });
        lines.push(`control again, one ping request: HTTP ${again.status}`);
        if (!is2xx(again.status)) {
          findings.push(result("MAP-BAT01", target, "error", `Inconclusive: a single ping stopped working after the batch (HTTP ${again.status}), so the refusal cannot be attributed to the batch.`, lines));
        } else {
          findings.push(result("MAP-BAT01", target, "pass", "A JSON-RPC batch is refused: one HTTP request carries one message, as MCP requires.", lines));
        }
      } else {
        findings.push(result("MAP-BAT01", target, "error", "Unexpected answer to a JSON-RPC batch; inconclusive.", lines));
      }
    } finally {
      if (session) await endSession(http, target, cred, session);
    }
  });

  // --- MAP-BOD01: an oversized body, with Content-Length and chunked.
  await guard("MAP-BOD01", async () => {
    const session = await openSession();
    const mib = OVERSIZED_BODY_BYTES / 1024 / 1024;
    const lines: string[] = [];
    const verdicts: Array<"accepted" | "refused" | "limited" | "unclear"> = [];
    let controlAgain: number | null = null;
    try {
      // Control: the same request at 1 KiB must work, so a refusal is about the size.
      const small = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), body: paddedPing(1024) });
      lines.push(`control, the same ping padded to 1 KiB: HTTP ${small.status}`);
      if (!is2xx(small.status)) {
        findings.push(result("MAP-BOD01", target, "error", "Inconclusive: the padded ping is refused even at 1 KiB, so a refusal of the large one proves nothing.", lines));
        return;
      }
      const text = paddedPing(OVERSIZED_BODY_BYTES);
      for (const variant of [
        { label: `${mib} MiB body with Content-Length`, body: text as string | AsyncIterable<Uint8Array> },
        { label: `${mib} MiB body, chunked (no Content-Length)`, body: chunked(text) },
      ]) {
        try {
          const r = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), body: variant.body, timeoutMs: UPLOAD_TIMEOUT_MS });
          lines.push(`${variant.label}: HTTP ${r.status}`);
          // A 4xx is about the size (413 is the expected one) only if it is not a rate limit, and if the control still works afterwards.
          const cls = classifyAnswer(r.status, r.headers);
          verdicts.push(cls === "accepted" ? "accepted" : cls === "refused" ? "refused" : cls === "rate_limited" ? "limited" : "unclear");
        } catch (e) {
          lines.push(`${variant.label}: connection closed before an answer (${(e as Error).message})`);
          verdicts.push("unclear");
        }
      }
      if (!verdicts.includes("accepted") && verdicts.every((v) => v === "refused")) {
        try {
          controlAgain = (await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), body: paddedPing(1024) })).status;
          lines.push(`control again, the ping padded to 1 KiB: HTTP ${controlAgain}`);
        } catch (e) {
          lines.push(`control again, the ping padded to 1 KiB: request failed (${(e as Error).message})`);
        }
      }
    } finally {
      if (session) await endSession(http, target, cred, session);
    }
    if (verdicts.includes("accepted")) {
      findings.push(result("MAP-BOD01", target, "fail", `The endpoint accepts a ${mib} MiB request: without a body size limit, a few requests can exhaust memory.`, lines));
    } else if (verdicts.includes("limited")) {
      findings.push(result("MAP-BOD01", target, "error", "Inconclusive: a large request was answered with a rate limit (429 or Retry-After), which says nothing about the body size limit. Scan again once the limit has passed.", lines));
    } else if (verdicts.every((v) => v === "refused")) {
      if (!is2xx(controlAgain)) {
        findings.push(result("MAP-BOD01", target, "error", "Inconclusive: the 1 KiB control stopped working after the large requests, so their refusal cannot be attributed to the size.", lines));
      } else {
        findings.push(result("MAP-BOD01", target, "pass", `${mib} MiB requests are refused, with and without Content-Length.`, lines));
      }
    } else {
      findings.push(result("MAP-BOD01", target, "error", "Inconclusive: the server closed the connection or answered unexpectedly; many servers do this when a limit is hit, but it cannot be told apart from a network error.", lines));
    }
  });

  // --- MAP-THR02: a rate limit per credential (last: it may lock the credential for a while).
  await guard("MAP-INJ01", async () => {
    findings.push(await runMetadataCheck(http, target, cred));
  });

  await guard("MAP-THR02", async () => {
    const attempts = clampRateAttempts(options.rateAttempts);
    const session = await openSession();
    const counts = new Map<number, number>();
    const started = Date.now();
    let accepted = 0;
    try {
      for (let i = 1; i <= attempts; i += 1) {
        const r = await mcpPost(http, target, { auth: cred, ...(session ? { sessionId: session } : {}), method: "ping" });
        counts.set(r.status, (counts.get(r.status) ?? 0) + 1);
        const evidence = [`ping requests with the ${what}: ${[...counts].map(([s, n]) => `HTTP ${s} x${n}`).join(", ")}`];
        if (is2xx(r.status)) {
          accepted += 1;
          continue;
        }
        if (r.status === 429 || (r.headers["retry-after"] !== undefined && r.status >= 400 && r.status < 500)) {
          findings.push(result("MAP-THR02", target, "pass", `The ${what} is rate limited: refused after ${accepted} accepted requests in ${Date.now() - started} ms.`, evidence));
        } else if (accepted > 0 && (r.status === 401 || r.status === 403)) {
          findings.push(result("MAP-THR02", target, "pass", `The ${what} was refused (HTTP ${r.status}) after ${accepted} accepted requests: probably a limit or a block; 429 with Retry-After is the standard answer.`, evidence));
        } else {
          findings.push(result("MAP-THR02", target, "error", `Unexpected answer (HTTP ${r.status}) to a ping with the ${what}; inconclusive.`, evidence));
        }
        return;
      }
    } finally {
      if (session) await endSession(http, target, cred, session);
    }
    const tally = [...counts].map(([s, n]) => `HTTP ${s} x${n}`).join(", ");
    findings.push(
      result(
        "MAP-THR02",
        target,
        "fail",
        `No rate limit observed for the ${what} after ${attempts} requests in ${Date.now() - started} ms. If your limit is higher on purpose, raise --rate-attempts (up to 100) or skip THR02.`,
        [`ping requests with the ${what}: ${tally}`],
      ),
    );
  });

  return { findings, control };
}

/**
 * MAP-INJ01 on its own: with a credential, or anonymously for a server that
 * serves anonymous requests (`cred` undefined).
 */
export async function runMetadataCheck(http: HttpClient, target: string, cred?: Credential): Promise<Finding> {
  const what = !cred ? "no credential" : cred.kind === "static" ? "the key" : "the token";
  const r = await inspectMetadata(http, target, cred);
  if (r.initializeStatus === null || r.initializeStatus < 200 || r.initializeStatus >= 300) {
    return result("MAP-INJ01", target, "error", `Inconclusive: initialize with ${what} did not work, so the metadata cannot be read.`, [
      `initialize with ${what}: ${r.initializeStatus === null ? "no usable answer" : `HTTP ${r.initializeStatus}`}`,
      ...r.notes,
    ]);
  }
  const c = r.counts;
  const read = `read: ${c.tools} tool(s), ${c.prompts} prompt(s), ${c.resources} resource(s), ${c.templates} resource template(s) and the initialize result`;
  // Locations and pattern names only: the suspicious text itself is never copied into the report.
  const lines = [read, ...r.issues.slice(0, 30).map((i) => `${i.where}: ${i.detail}`), ...(r.issues.length > 30 ? [`… and ${r.issues.length - 30} more`] : []), ...r.notes];
  if (isPoisoned(r.issues)) {
    const n = new Set(r.issues.filter((i) => i.kind !== "name").map((i) => i.item)).size;
    return result("MAP-INJ01", target, "fail", `Metadata the client's model reads contains hidden characters or instruction-like text (${n} place(s)): review it as a possible prompt injection.`, lines);
  }
  if (r.incomplete.length > 0) {
    // What was read is clean, but not everything was read: never a pass.
    return result("MAP-INJ01", target, "error", `Inconclusive: the metadata could not be read in full (${r.incomplete.slice(0, 3).join("; ")}${r.incomplete.length > 3 ? "; …" : ""}), so hidden instructions cannot be ruled out.`, lines);
  }
  const names = r.issues.filter((i) => i.kind === "name").length;
  return result("MAP-INJ01", target, "pass", `No hidden characters or instruction-like text in the metadata${names ? ` (${names} tool name(s) outside the recommended format)` : ""}.`, lines);
}
