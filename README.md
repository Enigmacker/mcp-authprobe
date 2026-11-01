# mcp-authprobe

[![CI](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Active authorization testing for remote MCP servers you own.**

Passive scanners read what a remote [Model Context Protocol](https://modelcontextprotocol.io) server *announces*: its OAuth metadata, its TLS setup, its tool descriptions. Some properties can only be confirmed by actually exercising the authorization server: does it really rotate refresh tokens, does it really refuse a redirect URI it never registered, does it slow down repeated failures?

`mcp-authprobe` runs those active checks, against servers whose ownership you have proven, and reports the results as JSON, SARIF and Markdown.

> **Status: early development (0.1.0-dev).** Available today: ownership proof, OAuth discovery, and the refresh token checks (rotation, replay, family revocation). The other active families are documented and being implemented; see [Roadmap](#roadmap).

> **Only test servers you own or are explicitly authorized to test.** Active checks change state on the target. The tool enforces an ownership proof before running them, but responsibility stays with the operator.

## Contents

- [Why another scanner?](#why-another-scanner)
- [Install](#install)
- [Quick start](#quick-start)
- [Ownership proof](#ownership-proof)
- [Refresh token checks](#refresh-token-checks)
- [What it checks](#what-it-checks)
- [Reports and exit codes](#reports-and-exit-codes)
- [CI usage](#ci-usage)
- [Safety of the scanner](#safety-of-the-scanner)
- [Roadmap](#roadmap)
- [Development](#development)
- [Contributing and security](#contributing-and-security)

## Why another scanner?

Good tools already exist, and this one is meant to sit next to them, not replace them:

| Tool | Focus | Overlap with mcp-authprobe |
| --- | --- | --- |
| [mcp-posture](https://github.com/batou9150/mcp-posture) | Passive posture of remote servers: OAuth metadata per RFC, transport, tool poisoning, rug pulls | None by design: it never sends state-changing requests. Run it first. |
| [MCPJam OAuth conformance](https://docs.mcpjam.com/cli/oauth-conformance) | Runs real OAuth flows and checks conformance, with a few negative checks | Basic redirect URI rejection. No refresh token replay, throttling or consent CSRF. |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner), [Snyk agent-scan](https://github.com/snyk/agent-scan) | Malicious tools, configs, local servers | None. |

`mcp-authprobe` focuses on what only an **active, authorized** test can confirm, and uses check IDs (`MAP-…`) that do not clash with mcp-posture's (`MCPP-…`), so both reports can be read side by side.

## Install

Requires Node.js 20.18.1 or later.

```sh
# from source, until the first npm release
git clone https://github.com/Enigmacker/mcp-authprobe.git
cd mcp-authprobe
npm ci
npm run build
node dist/cli.js --help
```

## Quick start

```sh
# 1. Create a secret and the proof to publish for your MCP host
mcp-authprobe ownership init mcp.example.com

# 2. Publish the proof (well-known file or DNS TXT), then keep the secret in your environment
export MCP_AUTHPROBE_SECRET='…'

# 3. Check the proof is visible
mcp-authprobe ownership verify mcp.example.com

# 4. Scan
mcp-authprobe scan https://mcp.example.com/mcp --sarif results.sarif --markdown summary.md

# 5. Add a test grant to run the refresh token checks (see below)
mcp-authprobe scan https://mcp.example.com/mcp --credentials-file ./test-grant.json
```

Without a valid proof the scan still runs discovery (the same read-only requests any MCP client sends before logging in), and every active check is reported as `skipped`.

For a local lab on your own machine:

```sh
mcp-authprobe scan http://127.0.0.1:8080/mcp --allow-private
```

Loopback targets with `--allow-private` do not need a proof.

## Ownership proof

Active checks register clients, rotate tokens and send failing requests. To make sure they only ever hit servers whose operator agreed to it, the scanner requires a proof for **every host it would contact**: the MCP server host and, when it differs, the authorization server host.

The proof is a hash, bound to the host, of a secret that only you hold:

```
mcp-authprobe-verification=sha256:<hex(sha256("<host>:<secret>"))>
```

Publish it in **one** of two places:

| Method | Where | Value |
| --- | --- | --- |
| Well-known file | `https://<host>/.well-known/mcp-authprobe.txt` | one line per proof; other lines are ignored |
| DNS TXT | `_mcp-authprobe.<host>` | the proof string |

Design choices:

- **The secret never leaves your machine.** Only its hash is published, so a proof found in the wild cannot be reused by someone else to scan your server.
- **Proofs are host-bound.** A proof for `mcp.example.com` is useless for any other host.
- **The secret is read from `MCP_AUTHPROBE_SECRET` or `--secret-file`, never from the command line**, so it does not land in shell history or process listings.
- **Hosted authorization servers.** If your authorization server is a third-party service on its own domain, you can only publish a proof if you control that domain (for example a custom domain). Check the provider's penetration testing policy before running active checks against it.

You can remove the proof as soon as you are done testing.

## Refresh token checks

MCP clients are usually public clients, so OAuth 2.1 requires their refresh tokens to be rotated, and RFC 9700 recommends revoking the whole token family when an old one is reused. These properties cannot be read from metadata; they have to be exercised.

The checks need a **test grant**: a client and a refresh token obtained by logging in to your own server with a **dedicated test account**. Save it to a file readable only by you (`chmod 600`):

```json
{
  "client_id": "your-test-client-id",
  "refresh_token": "the-refresh-token",
  "client_secret": "only-for-confidential-clients",
  "token_endpoint_auth_method": "none"
}
```

`token_endpoint_auth_method` is `none` (default for public clients), `client_secret_post` (default when a secret is present) or `client_secret_basic`.

The scan sends **at most three** `refresh_token` requests to the token endpoint found by discovery:

| Step | Request | Expected on a compliant server | Check |
| --- | --- | --- | --- |
| 1 | Refresh with the supplied token | New access token **and a new refresh token** | `MAP-RTK01` |
| 2 | Refresh again with the token from step 1's input (already used) | Rejected, typically `invalid_grant` | `MAP-RTK02` |
| 3 | Refresh with the newest token (from step 1's output) | Rejected: reuse revoked the whole family | `MAP-RTK03` |

Important:

- **The grant is consumed.** On a compliant server, step 3 revokes it. Never use a grant you still need.
- If tokens are not rotated, `MAP-RTK01` fails and the two replay checks are reported as not applicable.
- A throttled or unexpected response is reported as `error` (inconclusive), never as a pass.
- Token values never appear in output or reports; evidence only shows status codes and OAuth error codes.

## What it checks

`mcp-authprobe checks list` prints the catalogue, and `mcp-authprobe checks show <ID>` explains a check: why it matters, how to fix it, and references. IDs are stable and never reused.

| ID | Mode | Status | Check |
| --- | --- | --- | --- |
| `MAP-DSC01` | passive | available | Authorization endpoints are discoverable (401 challenge, RFC 9728, RFC 8414) |
| `MAP-RTK01` | active | available | Refresh tokens for public clients are rotated |
| `MAP-RTK02` | active | available | A rotated refresh token cannot be replayed |
| `MAP-RTK03` | active | available | Refresh token replay revokes the token family |
| `MAP-RDR01` | active | planned | Unregistered `redirect_uri` is refused at the authorization endpoint |
| `MAP-RDR02` | active | planned | `redirect_uri` matching is exact, not prefix or pattern based |
| `MAP-RDR03` | active | planned | Token endpoint enforces the `redirect_uri` used at authorization |
| `MAP-RDR04` | active | planned | Dynamic client registration refuses unsafe redirect URIs |
| `MAP-THR01` | active | planned | Repeated failed client authentication is throttled (small, capped number of attempts) |
| `MAP-CSR01` | active | planned | Consent decision is protected against CSRF |

Families: **DSC** discovery, **RTK** refresh tokens, **RDR** redirect URIs, **THR** throttling, **CSR** consent CSRF.

## Reports and exit codes

| Option | Output |
| --- | --- |
| *(always)* | Human-readable table on stdout |
| `--json <file>` | Full report, schema `mcp-authprobe/report/v1` |
| `--sarif <file>` | SARIF 2.1.0, for GitHub code scanning; only failing checks become results |
| `--markdown <file>` | Table for a pull request comment or a CI job summary |
| `--credentials-file <file>` | Test grant for the refresh token checks (input) |

| Exit code | Meaning |
| --- | --- |
| `0` | No failing check at or above `--fail-on` (default `high`) |
| `1` | At least one failing check at or above `--fail-on` (or `ownership verify` failed) |
| `2` | Usage error |
| `3` | A check errored or the target was unreachable |

All server-controlled text is neutralized before it reaches a report: terminal escape sequences, bidi overrides and invisible characters are escaped, and token-shaped values are redacted.

## CI usage

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: 22
- run: npx mcp-authprobe scan "$MCP_URL" --sarif results.sarif --markdown summary.md
  env:
    MCP_URL: https://mcp.example.com/mcp
    MCP_AUTHPROBE_SECRET: ${{ secrets.MCP_AUTHPROBE_SECRET }}
- run: cat summary.md >> "$GITHUB_STEP_SUMMARY"
  if: always()
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

Run active scans against a staging environment rather than production whenever you can.

## Safety of the scanner

The scanner talks to servers that may be hostile, and it may be driven by an AI agent. It protects both you and third parties:

- **Ownership gate:** no active request without a valid proof for every contacted host.
- **SSRF protection:** loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses are refused at connect time, after DNS resolution, unless `--allow-private` is passed.
- **No automatic redirects:** every redirect is inspected, never followed blindly.
- **Bounded resources:** per-request timeouts, response bodies capped at 1 MiB, no compression requested.
- **Secrets stay secret:** tokens and the ownership secret are never printed, and are redacted from every report.
- **No telemetry.**

## Roadmap

**0.1.0**
- ~~Refresh token checks (RTK01-03)~~ done, from a test grant file.
- Optional one-time interactive login to your own server to create the test grant.
- Redirect URI checks (RDR01-04).
- Throttling check (THR01), capped at a small number of attempts against a dedicated test client.
- MCP server mode (stdio), so the same engine can be used from an MCP client.
- npm release.

**0.2.0**
- Consent CSRF check (CSR01), driven through a browser session.
- Optional integration with mcp-posture: run it alongside, or import its JSON report, and merge both into one report where active results confirm or refute what the metadata announces.

## Development

```sh
npm ci
npm run typecheck
npm test          # unit and integration tests against a local fixture server
npm run build
npm run check     # all of the above
```

Tests never leave the machine: integration tests run against a fixture server bound to `127.0.0.1`.

## Contributing and security

- How to add a check: [CONTRIBUTING.md](CONTRIBUTING.md)
- Reporting a vulnerability in mcp-authprobe itself: [SECURITY.md](SECURITY.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Enigmacker
