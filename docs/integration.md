# Integrating mcp-authprobe

This page is for a program that runs mcp-authprobe: a CI job, a scheduler, a web application that scans its users' servers. It describes what is stable, what a run consumes, and how to read the result without parsing English.

## Three ways to run it

| Way | Use it when | Stable surface |
| --- | --- | --- |
| Subprocess (`mcp-authprobe scan … --json`) | You want isolation, a pinned version, or another language | Options, exit codes, the JSON report |
| Library (`import { runScan } from "mcp-authprobe"`) | You are in Node.js and want events and the grant state in memory | Everything exported by the package entry point |
| MCP server (`mcp-authprobe mcp`) | An MCP client runs the audit | The five tools; `scan` returns the same report as `structuredContent.report` |

`mcp-authprobe capabilities --json` prints what the installed version supports: report schema, MCP protocol eras, check IDs, reason codes, exit codes, lab profiles. Read it instead of comparing version numbers.

## Subprocess

```sh
mcp-authprobe scan https://mcp.example.com/mcp \
  --secret-file /run/secrets/ownership \
  --access-token-file /run/scan/access-token \
  --credentials-file /run/scan/grant.json \
  --json /run/scan/report.json --quiet \
  --events /run/scan/events.ndjson \
  --deadline 300 --fail-on-inconclusive false
```

- **Secrets only come from files or the environment**, never from the command line: `--secret-file` (or `MCP_AUTHPROBE_SECRET`), `--bearer-file`, `--access-token-file`, `--credentials-file`, `--client-secret-file`, `--session-cookie-file`. Each is read once, must be a regular file of bounded size, and gets a warning when other users can read it. Key and token files are refused when they are symbolic links; the ownership secret and the grant file may be links (container secret volumes are).
- **`--json -`** writes the report to standard output instead of the table; `--quiet` drops the table. Warnings and progress go to standard error.
- **`--events <file>`** appends one JSON line per event: `scan_started`, `discovery_finished`, `check_started`, `check_finished` (with `status`, `reason`, `durationMs`), `scan_finished`. Checks that share requests (the three refresh token checks, the redirect URI checks, the MCP endpoint checks) start and finish together.
- **`--deadline <seconds>`** and **`--max-requests <n>`** stop the scan with a partial report (`"complete": false`, exit 4). `SIGTERM` and `SIGINT` do the same: temporary clients are deleted first, then the reports are written. Prefer them to `SIGKILL`, which leaves registered test clients on the server and loses the report.
- Report paths, option values and the target URL are checked before the first request: a mistake is exit 2 and consumes nothing.
- **`mcp-authprobe plan <url> [the options of scan] --json -`** says what a scan with these options would run and why not the rest, with the reason codes of the report. It sends discovery and the ownership lookups only.
- **`--preset passive|standard|intrusive`** chooses how much a scan does; `intrusive` is the default. `standard` leaves out the 12 MiB uploads and the request burst.
- **`--journal <file>`** records the temporary clients as they are registered; after a scan that was killed, `mcp-authprobe cleanup --journal <file>` deletes what is left.
- **`--allow-private`** accepts a private address for the scanned host only; `--allow-host <host>` names another one (an authorization server on its own private address).
- **`--header-file <file>`** adds headers (`Name: value` lines) to requests to the scanned origin, and to no other: a gateway token in front of the server.

### Exit codes

| Code | Meaning | Silenced by `--fail-on-inconclusive false` |
| --- | --- | --- |
| 0 | No failing check at or above `--fail-on`. For `login`: a test grant was written | |
| 1 | A failing check at or above `--fail-on` | no |
| 2 | Usage error, nothing was sent | no |
| 3 | An inconclusive check. For `login`: it failed | yes |
| 4 | The target gave no HTTP answer, or the scan could not run or was interrupted | **no** |
| 5 | `login` wrote its results but no test grant | no |

Exit 0 does not mean that everything was tested: read `summary.coverage`.

## The report

The schema identifier is `mcp-authprobe/report/v1`, and the JSON Schema ships in the package as `mcp-authprobe/schema/report.schema.json`. Within v1, fields are only added: ignore the ones you do not know. A report with a new, incompatible shape would carry another identifier and be announced one minor version ahead.

| Field | Content |
| --- | --- |
| `reachable` | `false` when the target gave no HTTP answer. One finding (`MAP-DSC01`) carries the cause; nothing else ran |
| `complete` | `false` when the scan was interrupted; findings that did not run have `reason: "interrupted"` |
| `summary` | `counts` per status, `total`, `judged` (pass + fail), `coverage` (judged / total), `highestFailingSeverity`, `exitCode` |
| `discovery` | Metadata URLs, `issuer`, endpoints, `resource`, every announced authorization server, how a client can be obtained (`registration`: `dcr`, `cimd`), PKCE methods, the MCP `protocol` era and version, notes |
| `ownership.hosts[]` | One entry per host an active check would contact: `host`, `verified`, `method`, `detail`. A check runs when the hosts it sends requests to are proven: with a hosted authorization server whose host you cannot prove, the MCP endpoint checks still run. `ownership.verified` is true only when every host is |
| `client` | `source`: how the checks that need an OAuth client obtain one (`pre-registered`, `metadata-document`, `dynamic-registration`, `none`) |
| `preset` | The preset used, when one was |
| `credential` | `kind` (`static` or `oauth`) and `header` of the credential used. Never its value |
| `grant` | `used`, `rotated`, `consumed`, `state` (`valid`, `revoked`, `unknown`, `unused`), `rewritten` |
| `leftovers[]` | Temporary clients the scanner could not delete (`clientId`, `endpoint`, `reason`) |
| `findings[]` | One entry per check, always all of them |

Each finding has `checkId`, `family`, `active`, `severity`, `status`, `message`, `evidence`, and:

- `reason`, whenever `status` is `skipped` or `error`: a stable code. Branch on it, not on the message.
- `source` (`scan`, `login`, `consent-check`) and `observedAt`: a result with `source: "login"` was observed during an earlier `login` and read from the grant file. Results older than `--max-observation-age` (24 hours by default) are not reported: they are `skipped` with `reason: "stale_observation"`.
- `durationMs`: time spent on the check, or on the group it shares requests with.

| `reason` | Status | What to do |
| --- | --- | --- |
| `not_selected` | skipped | Nothing: `--only`, `--skip`, `--rtk` or `--preset` excluded it |
| `ownership_unproven` | skipped | Publish the proof for the host named in `ownership.hosts[]` |
| `needs_grant` | skipped | Pass a test grant with `--credentials-file` |
| `needs_login` | skipped | Run `login` (or `login begin` / `login complete`) and pass the file it writes |
| `needs_browser` | skipped | Run `consent-check` |
| `needs_static_key`, `needs_credential` | skipped, error | Pass `--bearer-file` or `--access-token-file` |
| `no_client` | skipped | The server offers no dynamic registration: pass `--client-id` |
| `no_endpoint` | skipped | Discovery found no such endpoint; see `MAP-DSC01` |
| `not_observed` | skipped | An earlier login probe spent the authorization code; log in again |
| `stale_observation` | skipped | Run `login` again, or raise `--max-observation-age` |
| `unreachable` | skipped, error | Network: the message has the cause code (`ECONNREFUSED`, `ENOTFOUND`, a TLS code, `ETIMEDOUT`) |
| `rate_limited` | error | Wait (the message gives `Retry-After` when the server sent one), or use `--wait-on-rate-limit`, `--delay-ms` |
| `server_error` | error | The server answered 5xx: look at its logs |
| `credential_rejected` | error | The key, token, grant or session cookie was refused: supply a fresh one |
| `credential_expired` | error | The access token stopped working during the scan: supply a fresh one |
| `deferred_validation` | error | The server validates `redirect_uri` after login, which cannot be seen from outside: pass `--session-cookie-file` (and, to settle a consent page, `--approve-consent`) |
| `incomplete` | error | Metadata could not be read in full (`MAP-INJ01`) |
| `ambiguous` | error | The answers cannot be attributed (anonymous endpoint, opaque token, control that fails) |
| `protocol_unsupported` | error | The server speaks no MCP revision this version knows |
| `interrupted` | error | The scan was stopped before this check |
| `unexpected_answer` | error | None of the above; read the evidence. Unknown codes should be treated like this one |

## What a scan consumes

| You supply | Checks that run | Effect on the server |
| --- | --- | --- |
| Nothing | `MAP-DSC01`, `MAP-ORG01`, `MAP-COR01` | A handful of ordinary requests |
| The ownership proof | + `MAP-RDR01`, `RDR02`, `RDR04`, `THR01` (and `MAP-INJ01` on an anonymous server) | Temporary clients, registered and deleted; 10 failed token requests |
| + a static key (`--bearer-file`) | + `MAP-ORG01` with the key, `TOK01`, `SES01`, `BAT01`, `BOD01`, `INJ01`, `THR02` | 12 MiB of uploads; up to 30 requests in a row, which may get the key limited for a while |
| + an access token (`--access-token-file`) | The same without `THR02` (add `--only THR02` to run it) | 12 MiB of uploads |
| + a test grant (`--credentials-file`) | + `MAP-RTK01`, `RTK02`, `RTK03`; `MAP-AUD01` when an access token comes with it | See below |
| + a session cookie (`--session-cookie-file`) | `MAP-RDR01`, `RDR02` replayed in the test account's session | None; with `--approve-consent`, one consent granted to the test client per variant whose consent page was shown |
| `login` | `MAP-PKC01`, `RDR03`, `COD01`, `AUD01` and the endpoint checks, stored in the grant file | One authorization; the code is spent |
| `consent-check` | `MAP-CSR01` | One browser session |

### The life of a test grant

The full refresh token sequence proves that replaying a refresh token revokes the whole family (`MAP-RTK03`). On a compliant server it therefore **ends the grant**: that is the result, not a side effect. Plan for it:

- `--rtk rotate-only` runs `MAP-RTK01` alone: one refresh. The file is rewritten with the new refresh token, atomically (a new file, then a rename, mode 600), and can be used again. Use it for frequent monitoring.
- `--rtk destructive` (the default) runs the three checks. Afterwards `grant.consumed` tells you whether the server revoked the grant. When it did not (replay accepted, or family not revoked: both are failing checks), the file is rewritten with the newest token, which is still valid.
- `--rtk off` leaves the grant untouched.
- `--credentials-out <file>` writes the newest grant somewhere else and leaves the input as it was.
- `MAP-AUD01` during a scan and the login probes each use one refresh; the grant keeps the newest token.

A workable scheme: keep **two grants** for the same test account. One is used with `--rtk rotate-only` on every run and never dies. The other is used with the default mode on a slower schedule, and is renewed by a login after each run that reports `grant.consumed: true`.

## Library

```ts
import { runScan, loadGrant, loadAccessTokenFile, parseSelection, exitCodeFor, toJson } from "mcp-authprobe";

const { grant, observations } = loadGrant("/run/scan/grant.json");
const { credential } = loadAccessTokenFile("/run/scan/access-token");
const controller = new AbortController();
const { report, grant: after } = await runScan("https://mcp.example.com/mcp", {
  secret: process.env.MCP_AUTHPROBE_SECRET,
  credential,
  ...(grant ? { grant } : {}),
  observations,
  select: parseSelection(undefined, "THR"),
  signal: controller.signal,
  deadlineMs: 300_000,
  onEvent: (e) => console.error(JSON.stringify(e)),
});
// after.latest holds the newest refresh token (never in the report); after.state says whether it is still valid.
process.exitCode = exitCodeFor(report, { failOn: "high", failOnInconclusive: false });
```

- `scan()` returns the report alone; `runScan()` also returns the grant as the scan left it. Nothing is written to disk by the library: `writeGrantFile()` does it when you ask.
- Secrets are masked in every string the library returns once it has seen them. In a process that scans for several customers, call `forgetSecrets()` between unrelated scans.
- The checks can be run one family at a time: `runEndpointChecks`, `runRedirectUriChecks`, `runRefreshTokenSequence`, `runThrottlingCheck`, `runAudienceCheck`, on top of `discover()` and an `HttpClient`. The ownership gate is in `runScan`: if you call a check directly, **you** are responsible for only pointing it at hosts whose operator agreed.
- Imports from `mcp-authprobe/dist/...` still resolve, but only the package entry point, `mcp-authprobe/lab` (the lab server, for your own tests) and the schema follow semantic versioning.

## A lab for your tests

`mcp-authprobe lab --profile <name> --port <n>` starts a server on `127.0.0.1`; `import { startFixture } from "mcp-authprobe/lab"` starts the same server in-process with any combination of behaviours. Both are loopback only and vulnerable on purpose.
