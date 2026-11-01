# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-01

### Added

- `MAP-CSR01` (consent CSRF) with the new `consent-check` command: it opens the installed Chrome or Edge through the optional `playwright-core` peer dependency, lets the user log in with a test account and stop on the consent page, reads the consent form and cookie attributes, then replays at most three submissions with the session cookies and a foreign Origin (without the anti-CSRF field, with it altered, untouched). A pass requires a control submission (the untouched form from the page's own Origin) to be accepted, so a badly rebuilt request is reported as inconclusive, never as a pass. It recognises approve controls in several languages and "Don't allow" style labels, honours `formaction`, `<base>`, required checkboxes, selects and textareas, follows one redirect on a proven host to detect resumed grants, alters tokens within their alphabet, reads the raw SameSite attribute, matches cookies like a browser, and stops cleanly on Ctrl-C, browser close or timeout. Requires ownership proof, launches the browser before registering anything, only posts to proven hosts, owns its loopback redirect URI, never reports cookie or token values, and deletes its temporary client.

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

[Unreleased]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Enigmacker/mcp-authprobe/releases/tag/v0.1.0
