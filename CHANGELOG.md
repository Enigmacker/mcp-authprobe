# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- With `--access-token-file` and no test grant, `MAP-AUD01` stays skipped, but when the token is a JWT its evidence now says which audience it was issued for (read locally, never verified, never sent anywhere): a hint, not a result.
- MCP mode: the `scan` tool declares its structured result (`outputSchema`): the report, with `schema`, `target` and `findings`, kept open for the fields later versions add.

## [0.13.0] - 2026-11-24

### Changed (read this before upgrading)

- **`--allow-private` is for the scanned host.** It used to lift the address filter for every host, so the metadata of a server could send the scanner to other internal addresses. Private addresses are now only accepted for the scanned host and the other names of the loopback; an authorization server on another private address needs `--allow-host <host>` (repeatable; `MCP_AUTHPROBE_ALLOW_HOSTS` in MCP mode). Library callers of `HttpClient` keep the old behaviour unless they pass `privateHosts`; `scan()` applies the new rule.
- **The ownership proof is judged host by host.** With the MCP host proven and the authorization server's not, the checks of the MCP endpoint (with a key or a token), and the endpoint checks of `login`, now run; they were all skipped. The checks that send requests to the authorization server stay skipped, with the reason `ownership_unproven` and the host named. No active request goes to a host without a proof. `ownership.verified` keeps its meaning (every host proven).
- In MCP mode, a lab listed in `MCP_AUTHPROBE_LAB_ORIGINS` is exempt from the proof by its exact origin; the exemption used to cover every port of the loopback once the target was listed.
- `ownership init` and `ownership proof` print the version 2 proof (below). Version 1 proofs already published keep working; versions before 0.13 only verify version 1, which both commands still show.
- The Docker image's entry point is the CLI (`docker run … mcp-authprobe scan …`); without arguments it still runs the MCP server, so existing `docker run -i` configurations are unchanged. An explicit `--entrypoint node … dist/cli.js` is no longer needed.

### Added

- `mcp-authprobe plan <url>`: what a scan with these options would run, why not the rest, how many requests and what effect, after discovery only. A test keeps it in agreement with `scan`.
- `--preset passive|standard|intrusive`. `intrusive` is the default and equals the previous behaviour; `standard` leaves out `MAP-BOD01` and `MAP-THR02`; `passive` uses no credential and sends nothing active.
- Ownership proof version 2: HMAC-SHA256 keyed by the secret, with an optional expiry (`ownership proof <host> --expires YYYY-MM-DD`). A warning for a secret that does not look random.
- `--journal <file>` and `mcp-authprobe cleanup --journal <file>`: delete the test clients a killed scan left on the server.
- `--header-file <file>`: extra headers for the scanned origin only.
- `MCP_AUTHPROBE_ALLOWED_HOSTS` in MCP mode: the only hosts the `scan` tool accepts.
- SARIF results carry `partialFingerprints`, stable for a check and a target.
- GitHub Action: inputs `access-token`, `client-id`, `redirect-uri`, `preset`, `protocol`; output `coverage`.
- A `Docker image` workflow: amd64 and arm64, build provenance and SBOM, on each release and weekly on a fresh base image.
- `MAP-ORG01`: when it fails on a server reached over https with header authentication and no credentialed CORS access, the evidence gives that context. The severity is unchanged.

## [0.12.0] - 2026-11-24

MCP 2026-07-28. Until now the scanner only spoke the `initialize` handshake of 2025-11-25: against a server that only speaks the stateless revision, every check of the MCP endpoint was inconclusive, with a message that blamed the credential.

### Added

- **Both MCP eras.** The scanner sends a 2026-07-28 request first (`server/discover`, with the `MCP-Protocol-Version` and `Mcp-Method` headers and the per-request `_meta`), recognises a modern server by its answer or by the errors only that revision defines (`-32020`, `-32021`, `-32022`), and otherwise falls back to `initialize`, as the specification describes for a dual-era client. `--protocol auto|modern|legacy`. The era, the version and the versions the server announces are in the report (`discovery.protocol`).
- In the modern era `server/discover` replaces `initialize` and `ping` as the harmless request of `MAP-ORG01`, `MAP-TOK01`, `MAP-BAT01`, `MAP-BOD01`, `MAP-THR02`, `MAP-COR01` and the controls; `MAP-INJ01` reads the instructions from `server/discover` and the lists with `_meta`; `MAP-SES01` is not applicable (the revision has no session) and no DELETE is sent.
- A server that speaks neither revision is reported as such (`protocol_unsupported`); the deprecated HTTP+SSE transport of 2024-11-05 is recognised and named.
- **Clients without dynamic registration** (deprecated by 2026-07-28): `--client-id`, `--client-secret-file` and `--redirect-uri` for `login`, `scan` (`MAP-RDR01`, `MAP-RDR02`, `MAP-THR01`) and `consent-check`. A client ID that is an https URL is passed through as a client ID metadata document. The order is the specification's: supplied client, then dynamic registration. The report says which was used (`client.source`).
- **`login begin` and `login complete`**: the login in two steps, without a loopback listener, for an application that receives the redirect itself. `beginLogin` and `completeLogin` in the library.
- `login --rounds 2`: a second authorization gives `MAP-RDR03` a code of its own when a probe spent the first one (a server that does not enforce PKCE otherwise hid it).
- `--issuer <url>` when a resource announces several authorization servers; all of them are listed in the report.
- Lab profiles `modern`, `dual` and `preregistered`, and `lab --auto-approve`. The limit on failed token requests of the lab is per client and lifts after 60 seconds, so the documented order (scan, login, scan) works; the `secure` profile announces a per-token rate limit in `RateLimit` headers.
- The catalogue says which revisions each check applies to (`appliesTo`), and references both.

### Changed

- **Metadata is validated, as a client must.** Authorization server metadata whose `issuer` is not identical to the issuer it was fetched for is not used (RFC 8414 section 3.3; a MUST of the MCP specification): on such a server `MAP-DSC01` now fails instead of passing. A Protected Resource Metadata document whose `resource` is neither the scanned URL nor a prefix of it is remarked in `MAP-DSC01` (which still passes, with the inconsistency in its message) and its value is not sent as the `resource` parameter.
- Dynamic registration requests carry `application_type` (`native` for a loopback redirect URI, `web` otherwise), as 2026-07-28 requires; `login` retries once without it when a server rejects the field.
- The refresh token checks send the `resource` parameter with every refresh (RFC 8707: in every token request).
- `login` checks `iss` before it reads `error` from the authorization response: an error from another issuer is no longer displayed.
- The redirect URI checks request the same scopes as `login` (the challenge first, then `scopes_supported`).
- The CORS preflight of `MAP-COR01` asks for the 2026-07-28 headers too (`mcp-protocol-version`, `mcp-method`, `mcp-name`).
- Missing `code_challenge_methods_supported` is noted in `MAP-DSC01` and by `login`, which goes on (the specification tells clients to stop; the tool tests what the server enforces).

## [0.11.0] - 2026-11-24

The integration contract: what a program that runs the scanner needs. Options and report fields of 0.10 are all still accepted; the report keeps its `mcp-authprobe/report/v1` identifier and only gains fields.

### Changed (read this before upgrading)

- **Exit code 4** for a target that gives no HTTP answer, a scan that could not run, or one that was interrupted. It was 3, shared with inconclusive checks. `--fail-on-inconclusive false` never silences it. Exit code 3 now only means inconclusive checks.
- **`login` exits 5** when it wrote its results but no test grant (it exited 0), and 4 when the server is unreachable. 0 means a grant was written.
- **Login results older than 24 hours are no longer reported** by a scan: they are listed as skipped with the reason `stale_observation`. `--max-observation-age <hours>` changes the limit (0 for none).
- **The grant file is rewritten** after a scan that left the grant valid, with the newest refresh token (atomically, mode 600). It used to keep a token the scan had already spent. `--credentials-out <file>` writes elsewhere.
- The GitHub Action fails on an unreachable target, as its documentation said; it used to give a warning.

### Added

- Report, all additive: `summary` (counts, `judged`, `coverage`, highest failing severity, exit code), `discovery` (metadata URLs, issuer, endpoints, announced authorization servers, registration modes, PKCE methods, protocol), `ownership.hosts[]`, `credential` (kind and header, never the value), `grant` (`used`, `rotated`, `consumed`, `state`, `rewritten`), `leftovers[]` (temporary clients that could not be deleted), `complete`; per finding `family`, `active`, `reason`, `source`, `observedAt`, `durationMs`. `reason` is a stable code for every skipped or inconclusive check (`not_selected`, `ownership_unproven`, `needs_grant`, `needs_login`, `rate_limited`, `credential_rejected`, `unreachable`…).
- The JSON Schema of the report ships in the package (`schema/report.schema.json`); the tests validate every report against it. In MCP mode, `structuredContent.report` carries the `schema` key too.
- `--access-token-file <file>`: an OAuth access token for the MCP endpoint checks, reported as a token and not as a key. `MAP-THR02` then only runs when named with `--only`; an expiry during the scan gives the reason `credential_expired`; with `--credentials-file`, `MAP-AUD01` is judged during the scan. `MCP_AUTHPROBE_ACCESS_TOKEN_FILE` in MCP mode.
- `--rtk destructive|rotate-only|off` for the refresh token sequence, and `--credentials-out`.
- A credential that is rate limited at the control request is reported as such (`rate_limited`, with the `Retry-After`), not as a rejected key. `--wait-on-rate-limit <seconds>` waits once; `--delay-ms` spaces requests; `--max-requests` caps them.
- `MAP-THR02` reads announced limits (`RateLimit`, `RateLimit-Policy`, `X-RateLimit-*`): a decreasing counter passes even when the limit is above the number of requests sent. Its message counts every request the scan sent with the credential, and says for how long the credential stays limited.
- `--events <file>` (one JSON line per event), `--deadline <seconds>`, `--quiet`, `--json -`. `SIGTERM` and `SIGINT` stop a scan cleanly: temporary clients are deleted, then a partial report is written.
- `login --json <file>`: the login results as a report, without any token.
- `checks list --json` and `capabilities --json`.
- Library: the package entry point now exports what is needed to build scan options and run checks (`runScan`, `login`, `bearerCredential`, `loadBearerFile`, `loadAccessTokenFile`, `parseSelection`, the check runners, `exitCodeFor`, `writeGrantFile`, the types `Credential`, `Observation`, `ScanEvent`…). `ScanOptions` takes an `AbortSignal`, a deadline and `onEvent`. `package.json` has an `exports` map; deep imports under `dist/` still resolve but are not covered by semantic versioning.
- `docs/integration.md`: subprocess, library, report, reason codes, exit codes, what a scan consumes, the life of a test grant.

### Security

- One reader for every secret file (ownership secret, static key, access token, test grant): a regular file of bounded size, opened once, with a warning when other users can read it. The ownership secret file had no check at all. Key and token files are refused when they are symbolic links; the ownership secret and the grant may be links, since container secret volumes are.
- Grant files are written to a new file and renamed: an interruption no longer destroys the grant.
- `MAP-AUD01` compares the token audience with the `resource` the server announces as well as with the scanned URL.

## [0.10.2] - 2026-11-24

Corrections only: wrong results, and gaps between the documentation and the tool. No option or report field is removed.

### Fixed

- **False passes on a rate limit.** `MAP-BAT01` and `MAP-BOD01` passed on any 4xx, so a 429 arriving at the right moment turned a server that runs batches and accepts 6 MiB bodies green. Every endpoint check now classifies answers the same way: 429, a `Retry-After` on an error and 5xx are inconclusive, never a refusal. Both checks send their control request again after the attempt, and only a JSON-RPC 2.0 error (`"jsonrpc": "2.0"`, numeric `error.code`) counts as a refused batch: any JSON object with an `error` key no longer does. `MAP-ORG01` and `MAP-TOK01` no longer take a 429 for a refusal either.
- **False passes of `MAP-INJ01` on metadata it had not read.** A list answer larger than the 1 MiB response cap was cut, could not be parsed, and the check concluded "pass" with "read: 0 tool(s)"; an item with more than 200 strings was no longer inspected past the 200th, so a large schema could hide a poisoned description. List answers are now read up to 8 MiB, the name, title and description of every item are inspected first, up to 2,000 strings per item are read, and whenever a list the server announces was not read in full (larger answer, JSON-RPC error, page, item or string bound reached) the result is inconclusive with the reason.
- **`--only RTK01` sent the replay and consumed the test grant.** Selecting one refresh token check ran the three steps. Only the steps the selected checks need are sent now: `RTK01` alone is one refresh, `RTK02` adds the replay, `RTK03` adds the use of the newest token. A check that is not selected but whose request a selected one needs says which request was sent.
- **An unreachable target could exit 0** with `--fail-on-inconclusive false`, although the documentation said otherwise. The report now says `"reachable": false`, one finding gives the cause (`connection refused (ECONNREFUSED)`, `host not found (ENOTFOUND)`, a TLS error code, a timeout) instead of four "fetch failed", the other checks are listed as not run, and the exit code is 3 whatever the flag.
- **Configuration mistakes reported as test results.** Plain `http` without `--allow-private`, a private address without it, a URL with credentials, an unwritable `--json`, `--sarif` or `--markdown` path: all are usage errors (exit 2) found before any request, and no longer after a scan that consumed the test grant.
- **Opaque tokens in reports.** Only JWTs, `Bearer` values and a few parameter names were masked, so a server echoing the refresh token it was sent in its `error` member got it into the report. Every secret the tool loads or receives (ownership secret, test grant, client secret, access and refresh tokens, authorization code, registration access token) is now masked by exact value, and the `error` member of an OAuth answer is only copied when it looks like an error code. The `code` pattern no longer eats ordinary words ("unicode: …", "status code: 4001", JSON-RPC error codes).
- **Markdown reports did not escape Markdown.** A server-controlled value could put a link, a mention, an image or HTML into a pull request comment or a job summary. Every inline value is escaped.
- `--timeout` was documented for `login` and `consent-check` but ignored; it is applied and validated there and for `ownership verify`.
- `checks show rtk02` is accepted, like `--only RTK02` and the MCP tool `explain_check`.
- `MAP-THR01` counts a `Retry-After` on a 4xx as throttling, as documented, and says when the endpoint was already limiting at the very first request.
- Checks that are observed during `login` no longer advise running `login` on a server without dynamic client registration, where it cannot work.
- `MAP-BOD01` gives its two 6 MiB uploads a 60 s timeout instead of the per-request default.

### Changed

- The README's check table, check count and list of login checks are generated from the catalogue (`npm run docs`), and a test fails when they drift. The README said 19 checks (there are 21) and seven login checks (there are ten); the help listed two of the four lab profiles.
- The published package no longer ships source maps that pointed at sources it does not contain.
- `SECURITY.md` names the supported version correctly (the latest release).

## [0.10.1] - 2026-11-13

### Changed

- MCP mode: every tool description now says when to use the tool, what it returns and what it never does, every parameter is documented, and the server instructions describe the whole flow (checks, ownership proof, scan) and all check families.
- `explain_check` also accepts IDs without the `MAP-` prefix, case-insensitive (`rtk02`).

## [0.10.0] - 2026-11-13

### Added

- `MAP-INJ01` (tool poisoning, high): tool, prompt and resource metadata and the initialize `instructions` are read with the list methods only (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`; nothing is called or read) and must carry no invisible characters (Unicode tags, decoded before matching; zero-width and bidi controls; ANSI escapes) and no instruction-like text ("ignore previous instructions", `<IMPORTANT>`, "do not tell the user", `~/.ssh`…). Tool names with non-ASCII characters fail too. Runs with a static key, during `login`, or anonymously on a server that answers anonymous requests. The report locates matches and never copies the suspicious text.
- The `vulnerable` and `static-bearer` lab profiles announce a poisoned tool, prompt and resource; the secure profiles, clean ones.

### Changed

- The lab answers JSON-RPC notifications with 202 and echoes request IDs.

## [0.9.0] - 2026-11-13

Servers authenticated by a static API key (no OAuth) are now tested, following a field trial against one: 0.8.0 skipped 14 of 19 checks there.

### Added

- `--bearer-file <file>` and `--bearer-header <name>`: a static API key, read from a file (warning if other users can read it), never accepted on the command line, masked in every report, and only sent to the target once its ownership is proven. With it, the MCP endpoint checks run with the key. In MCP mode, `MCP_AUTHPROBE_BEARER_FILE` must come with `MCP_AUTHPROBE_BEARER_TARGET`, the only URL the key may be used for. Also `bearer` and `bearer-header` inputs of the GitHub Action.
- `MAP-BAT01` (JSON-RPC batches): one POST carrying a batch of 5 `ping` requests must be refused; MCP has required one message per request since 2025-06-18, and a server that runs batches counts many calls as one. The TypeScript SDK 1.x accepts batches of up to 100 messages by default.
- `MAP-BOD01` (body size): two 6 MiB `ping` requests, with `Content-Length` and chunked, must be refused.
- `MAP-THR02` (rate limit per credential): up to 30 `ping` requests with the static key (`--rate-attempts`, 10 to 100) must meet a 429 or a `Retry-After`.
- `--fail-on-inconclusive <true|false>` for the CLI (exit code 3 for inconclusive checks stays the default); exit codes documented in the help and the README.
- Lab profiles `static-bearer` and `static-bearer-secure`, with a key generated at each start.

### Changed

- `MAP-ORG01` with a credential now tries a foreign Origin, `Origin: null` and a malformed Origin.
- `MAP-TOK01` tries the credential as `?access_token=`, `?api_key=`, `?key=` and `?token=`.
- The MCP endpoint checks (ORG01, TOK01, SES01, BAT01, BOD01) share one implementation, used by `login` with the OAuth access token and by `scan` with a static key. Only side-effect-free methods are sent: `initialize` and `ping`, never `tools/call`.
- `MAP-DSC01` and the authorization server checks are *not applicable* when a static key is declared and no OAuth metadata is published.

## [0.8.0] - 2026-11-04

### Added

- `--posture-report <file>`: merges an mcp-posture JSON report (schema 1.x) for the same URL into the scan. The table, JSON (`posture` block) and Markdown reports show mcp-posture's findings with their fingerprints, and relate each active result to the passive findings on the same subject: confirmed, only visible actively, or enforced despite what the metadata suggests. The file is size-capped, type-checked and neutralized; suppressed findings are left out; the exit code is unchanged. Also an input of the GitHub Action.

- `Dockerfile` for the stdio MCP server, tested in CI (the image must answer `initialize` and `tools/list`), and `glama.json` for the Glama directory.

## [0.7.0] - 2026-11-01

### Changed

- Easier-to-read terminal output: colours on a terminal (`NO_COLOR` and `FORCE_COLOR` are honoured), at most three evidence lines per failing check, checks that did not run grouped by reason, and a summary line. `--verbose` shows everything, as before. JSON, SARIF and Markdown reports are unchanged.

### Added

- An animated demo in the README, recorded from real output against the lab (`npm run demo` re-records it).

## [0.6.0] - 2026-11-01

### Added

- `MAP-TOK01` (token in the URL): during `login`, an `initialize` request carries the access token as `?access_token=` without an `Authorization` header and must be refused, as the MCP specification requires. The token never appears in evidence or error messages.
- `MAP-SES01` (session ID instead of a token): during `login`, a session is opened with the token, then a `ping` carrying only the `Mcp-Session-Id` must be refused (401 expected). Not applicable to stateless servers; the sessions opened are ended.
- `MAP-COR01` (CORS): in every scan, a preflight and an ordinary request with a foreign `Origin`; fails when the origin is reflected with `Access-Control-Allow-Credentials: true`.
- Both login checks are inconclusive on an endpoint that also serves anonymous requests. The `vulnerable` lab profile plants the three flaws.

## [0.5.0] - 2026-11-01

Fixes from a trial against node-oidc-provider (with an MCP server built on the official SDK) and the MCP SDK's OAuth example server.

### Changed

- `MAP-CSR01` recognises per-flow identifiers issued by the authorization server (hidden fields such as `consent_challenge`, or a random part of the form URL as in node-oidc-provider's `/interaction/<id>`). Without an anti-CSRF field, it first submits the form with the identifier altered and without any cookie: either one accepted is a failure; both refused makes the result inconclusive with an explanation, instead of a failure.
- `login` still observes `MAP-ORG01` and `MAP-COD01` when the server issues no refresh token (COD01 then looks at the access token), and keeps the probe results when the real code exchange fails after the probes.
- `MAP-THR01` switches once to random authorization codes when the refresh grant answers a server error or `unsupported_grant_type`.
- Clearer messages for a token endpoint that crashes on a reused code, and for a rate-limited registration endpoint.

## [0.4.0] - 2026-11-01

### Added

- Official GitHub Action (`uses: Enigmacker/mcp-authprobe@v0.4.0`): runs the scan with the ownership secret from the environment, adds the results table to the job summary, can upload SARIF to code scanning, fails on findings at or above `fail-on`, warns on inconclusive checks (or fails with `fail-on-inconclusive`), and exposes the exit code, the number of failing checks and the report paths. CI tests it against both lab profiles.
- `--only` and `--skip` (and `only` / `skip` in the MCP `scan` tool): choose checks by ID or family. Unselected checks send no request and are reported as skipped; unknown names are refused.

## [0.3.0] - 2026-11-01

### Added

- `MAP-PKC01` (PKCE enforcement): during `login`, the code is first presented without `code_verifier`, then with a wrong one; the token endpoint must refuse both.
- `MAP-COD01` (single-use codes): after the exchange, `login` presents the used code again, then checks whether the tokens issued from it were revoked (recommended, reported in the result).
- `MAP-AUD01` (token audience, RFC 8707): `login` requests a token for an unrelated resource with the refresh token and presents it to the MCP endpoint, after a successful control with its own token. Passes on `invalid_target` from the authorization server or 401/403 from the MCP endpoint. Fails only when the MCP endpoint accepts a token whose JWT audience is the other resource; an opaque token, or an authorization server that ignores `resource`, is reported as inconclusive with the reason.
- `lab` command: a local MCP server with its own OAuth authorization server, in a `vulnerable` profile (most checks fail) or a `secure` one, to try every check in a minute. Loopback only, test account `test` / `test`, in memory.
- `MAP-ORG01` (Origin validation): an `initialize` request with a foreign `Origin` must get 403. Observed during `login` with a valid token, and in every scan without credentials (inconclusive when the server asks for a token first).

### Changed

- `login` runs its probes in a fixed order and handles servers that invalidate a code after the first refused attempt: only that first refusal is trusted. If a probe obtains tokens, the remaining probes are reported as not run and those tokens become the grant. The grant always keeps the newest refresh token.
- Scans report every login observation; no check is listed as "not implemented" any more.
- `login` writes its results even when it keeps no grant (strict servers), and a later `login --no-probe --force` to the same file keeps them. A grant file may therefore hold results only; scans then skip the refresh token checks with a warning.
- The lab server doubles as the test fixture: its consent mode validates authorization requests before asking for a login, and returns the RFC 9207 `iss` parameter.

## [0.2.0] - 2026-11-01

### Added

- `MAP-CSR01` (consent CSRF) with the new `consent-check` command: it opens the installed Chrome or Edge through the optional `playwright-core` peer dependency, lets the user log in with a test account and stop on the consent page, reads the consent form and cookie attributes, then replays at most four submissions with the session cookies (from a foreign Origin: without the anti-CSRF field, with it altered, untouched; plus a control from the page's own Origin). A pass requires a control submission (the untouched form from the page's own Origin) to be accepted, so a badly rebuilt request is reported as inconclusive, never as a pass. It recognises approve controls in several languages and "Don't allow" style labels, honours `formaction`, `<base>`, required checkboxes, selects and textareas, follows one redirect on a proven host to detect resumed grants, alters tokens within their alphabet, reads the raw SameSite attribute, matches cookies like a browser, and stops cleanly on Ctrl-C, browser close or timeout. Requires ownership proof, launches the browser before registering anything, only posts to proven hosts, owns its loopback redirect URI, never reports cookie or token values, and deletes its temporary client.

## [0.1.1] - 2026-11-01

### Added

- Listed in the official MCP Registry as `io.github.Enigmacker/mcp-authprobe` (`server.json`, `mcpName` in `package.json`); releases publish the registry entry from GitHub Actions with OIDC.

### Changed

- Requires Node.js 22.19 or later (Node.js 20 is end-of-life); `undici` 8.
- GitHub Actions updated (`actions/checkout` and `actions/setup-node` v7); the release workflow skips the npm publish when the version already exists.

## [0.1.0] - 2026-11-01

First release.

### Added

- Hardened HTTP client: connect-time refusal of loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses (after DNS resolution), timeouts, 1 MiB body cap, no automatic redirects, no compression.
- Ownership proof: host-bound SHA-256 proof of a local secret, published as `/.well-known/mcp-authprobe.txt` or a `_mcp-authprobe` DNS TXT record. Required for every host an active check would contact; loopback labs are exempt with `--allow-private`.
- OAuth discovery following the MCP Authorization specification: 401 challenge, Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414 and OpenID Connect Discovery).
- Check catalogue with stable `MAP-` identifiers: `MAP-DSC01` available; refresh token, redirect URI, throttling and consent CSRF families documented as planned.
- Reports: terminal table, JSON (`mcp-authprobe/report/v1`), SARIF 2.1.0 and Markdown, with redaction of token-shaped values and neutralization of control, bidi and invisible characters.
- CLI: `scan`, `ownership init|proof|verify`, `checks list|show`, `--fail-on`, exit codes 0/1/2/3.
- Refresh token checks `MAP-RTK01` (rotation), `MAP-RTK02` (replay rejected) and `MAP-RTK03` (family revocation on reuse), in at most three token requests, from a test grant passed with `--credentials-file` (public clients, `client_secret_post`, `client_secret_basic`). Inconclusive outcomes, such as throttling, are reported as errors, never as passes.
- Redirect URI checks `MAP-RDR01` (unregistered URI refused), `MAP-RDR02` (exact matching, 7 near-miss variants) and `MAP-RDR04` (registration refuses unsafe redirect URIs). They register a temporary client, compare each answer with a baseline request, report deferred validation as inconclusive, use only the reserved `.invalid` domain, and delete every client they created (RFC 7592).
- MCP server mode: `mcp-authprobe mcp` serves `list_checks`, `explain_check`, `ownership_proof`, `verify_ownership` and `scan` over stdio. The secret, the test grant and private-address access come only from the environment, never from tool arguments; `scan` is annotated destructive, accepts only `https` targets (unless private labs are enabled), refuses URLs with credentials, runs one scan at a time, and marks server-controlled text as data.
- CLI: `mcp` command.
- Interactive `login`: dynamic registration with a loopback redirect URI, PKCE S256, random state, RFC 8707 resource and RFC 9207 iss check; the browser only opens the discovered authorization endpoint; the grant file is written with mode 600, without following symbolic links or overwriting without `--force`; clients from failed logins are deleted.
- `MAP-RDR03` (token endpoint binds the code to its redirect_uri), observed during `login` when ownership is proven, stored in the grant file and reported by the next scan of the same target.
- `MAP-THR01` (repeated failed token requests are throttled): 5 to 20 sequential requests (default 10, hard-capped, `--throttle-attempts`) carrying random refresh tokens for the operator's test client or a temporary deleted-afterwards client; stops at the first 429, Retry-After, `slow_down` or `temporarily_unavailable`; runs last in a scan.
- Hardening from an independent review before release: HTTPS is required for every request outside loopback/private labs; rate limits and server errors make redirect URI, registration and throttling checks inconclusive instead of passing; test grants record their target and token endpoint and are never used elsewhere (and must name their target in MCP mode); loopback targets need a proof in MCP mode unless listed in `MCP_AUTHPROBE_LAB_ORIGINS`; `login` output is neutralized; more IPv6 transition ranges are refused; a malformed issuer no longer aborts discovery.
- Local fixture server with a stateful token endpoint, dynamic registration and an authorization endpoint and test suite; GitHub Actions CI.

[Unreleased]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Enigmacker/mcp-authprobe/releases/tag/v0.1.0
