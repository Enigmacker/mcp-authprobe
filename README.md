# mcp-authprobe

[![CI](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Active authorization testing for remote MCP servers you own.**

Passive scanners read what a remote [Model Context Protocol](https://modelcontextprotocol.io) server *announces*: its OAuth metadata, its TLS setup, its tool descriptions. Some properties can only be confirmed by actually exercising the authorization server: does it really rotate refresh tokens, does it really refuse a redirect URI it never registered, does it slow down repeated failures?

`mcp-authprobe` runs those active checks, against servers whose ownership you have proven, and reports the results as JSON, SARIF and Markdown.

> **Status: 0.1.0, first release.** Nine of the ten checks are available: OAuth discovery, refresh token rotation and replay, redirect URI strictness, and token endpoint throttling, behind an ownership proof. It works as a CLI, with an interactive `login` that creates the test grant, and as an MCP server so an AI assistant can run the audit. Consent CSRF (`MAP-CSR01`) is planned; see [Roadmap](#roadmap).

> **Only test servers you own or are explicitly authorized to test.** Active checks change state on the target. The tool enforces an ownership proof before running them, but responsibility stays with the operator.

## Contents

- [Why another scanner?](#why-another-scanner)
- [Install](#install)
- [Quick start](#quick-start)
- [Ownership proof](#ownership-proof)
- [Refresh token checks](#refresh-token-checks)
- [Interactive login](#interactive-login)
- [Redirect URI checks](#redirect-uri-checks)
- [Throttling check](#throttling-check)
- [Use it from an MCP client](#use-it-from-an-mcp-client)
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
# run without installing
npx mcp-authprobe --help

# or install globally
npm install -g mcp-authprobe
```

Releases are published from GitHub Actions with npm trusted publishing; check the provenance on the package page before installing a security tool.

From source:

```sh
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

# 5. Log in once with a dedicated test account to create a test grant
mcp-authprobe login https://mcp.example.com/mcp --out ./test-grant.json

# 6. Full scan, including the refresh token checks
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

The checks need a **test grant**: a client and a refresh token obtained by logging in to your own server with a **dedicated test account**.

The easy way is `mcp-authprobe login` (see [Interactive login](#interactive-login)), which writes the file for you. You can also write it by hand, readable only by you (`chmod 600`):

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

## Interactive login

```sh
mcp-authprobe login https://mcp.example.com/mcp --out ./test-grant.json
```

`login` behaves like a careful native MCP client ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)):

- It registers a client through dynamic client registration, with a loopback redirect URI on `127.0.0.1` and a random port.
- It opens your browser on the **discovered authorization endpoint only** (or prints the URL with `--no-browser`). Log in with your **test account**.
- The loopback listener accepts a single `GET /callback` carrying the expected `state`, and echoes nothing back.
- It uses PKCE S256, a random `state`, the RFC 8707 `resource`, and checks the RFC 9207 `iss` parameter against the discovered issuer.
- It writes the grant with mode 600, never through a symbolic link, and never over an existing file unless you pass `--force`. Tokens are never printed.
- If login fails, the client it registered is deleted when the server allows it.

**`MAP-RDR03` is observed during login**, because it needs a fresh authorization code. When ownership of every contacted host is proven, `login` first presents the code with a *different* `redirect_uri`, which a compliant token endpoint must refuse, then exchanges it normally. The result is stored in the grant file and reported by the next scan of the same target. Use `--no-probe` to skip it.

Some strict servers invalidate a code after any failed attempt. That is acceptable behaviour: `MAP-RDR03` passes, and `login` asks you to run it again with `--no-probe` to obtain the grant.

## Redirect URI checks

If an authorization server redirects to a URI the client never registered, authorization codes can end up with an attacker. OAuth 2.1 requires exact string matching. These checks need **dynamic client registration** on your server; no test grant and no login are required.

How they work:

1. The scanner registers a temporary client whose only redirect URI is `https://client.mcp-authprobe.invalid/callback`.
2. It sends a **baseline** authorization request with that registered URI (PKCE S256, random `state`, RFC 8707 `resource`), then one request per variant, and compares the answers. Redirects are never followed.
3. It deletes every client it created (RFC 7592). Clients it could not delete are listed in the report, named `mcp-authprobe test client (safe to delete)`.

| Check | What is sent | Fails when |
| --- | --- | --- |
| `MAP-RDR01` | A completely different host | The server redirects to it |
| `MAP-RDR02` | 7 near misses: extra path segment, trailing slash, added query, different port, subdomain, userinfo trick, `http` downgrade | The server redirects to any of them |
| `MAP-RDR04` | Registrations with plain HTTP on a non-loopback host, `javascript:`, `data:`, and a fragment | The registration endpoint accepts any of them |

Safety by design: every host used lives under the reserved `.invalid` top-level domain ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)), which can never resolve. Even a vulnerable server could not deliver a code anywhere.

Reading the results: a variant answered exactly like the baseline (for example both redirected to the login page) is reported as **inconclusive** (`error`), never as a pass, because some servers only check `redirect_uri` after the user logs in. `MAP-RDR03` (token endpoint enforcement) is observed during [interactive login](#interactive-login).

## Throttling check

Without rate limiting, refresh tokens, authorization codes and client secrets can be guessed at line speed. `MAP-THR01` checks that the token endpoint slows down repeated failures, with strict bounds:

- It sends **10** token requests by default (`--throttle-attempts`, between **5 and 20**, hard-capped), **one at a time**.
- Each request carries a **freshly generated random refresh token** that cannot be valid. Nothing is guessed, and **user passwords and login forms are never involved**.
- It uses your test client when a grant is supplied (your real refresh token is not sent), otherwise a temporary client that is deleted afterwards.
- It stops at the first sign of throttling: HTTP 429, a `Retry-After` header, or an OAuth `slow_down` / `temporarily_unavailable` error.
- It runs **last** in a scan, so a throttled token endpoint cannot disturb the other checks.

A failure means no throttling was seen within the cap. Your limit may simply be higher than 20; the finding asks you to confirm that one exists.

## Use it from an MCP client

`mcp-authprobe mcp` runs the same engine as an MCP server over stdio, so an AI assistant in any MCP client can audit your servers for you.

Add it to your client's MCP configuration (most clients use this `mcpServers` format):

```json
{
  "mcpServers": {
    "mcp-authprobe": {
      "command": "npx",
      "args": ["-y", "mcp-authprobe", "mcp"],
      "env": {
        "MCP_AUTHPROBE_SECRET_FILE": "/home/you/.config/mcp-authprobe/secret",
        "MCP_AUTHPROBE_CREDENTIALS_FILE": "/home/you/.config/mcp-authprobe/test-grant.json"
      }
    }
  }
}
```

From a source checkout, use `"command": "node"` with `"args": ["/path/to/mcp-authprobe/dist/cli.js", "mcp"]`.

| Tool | What it does | Annotations |
| --- | --- | --- |
| `list_checks` | Lists the catalogue | read-only |
| `explain_check` | Explains one check | read-only |
| `ownership_proof` | Returns the proof to publish for a host (never the secret) | read-only |
| `verify_ownership` | Checks that the proof is published | read-only, open world |
| `scan` | Runs discovery and the active checks; returns a Markdown summary and the full report as structured content | **destructive**, open world |

The server is built so that the assistant, or a prompt injection reaching it, cannot widen what the scanner may do:

- **Everything sensitive is set by you in the configuration, never by tool arguments:** the ownership secret, the test grant, and private-address access. The `scan` tool takes a URL and nothing else.
- **`scan` is annotated as destructive**, so well-behaved clients ask for your confirmation before each call. It consumes the test grant and registers temporary clients.
- **Only `https` targets** are accepted, unless you set `MCP_AUTHPROBE_ALLOW_PRIVATE=1` for a local lab. URLs with embedded credentials are refused, and only one scan runs at a time.
- **Reports are marked as data:** every scan result ends with a notice that server-controlled text in it must not be treated as instructions.

| Environment variable | Purpose |
| --- | --- |
| `MCP_AUTHPROBE_SECRET` or `MCP_AUTHPROBE_SECRET_FILE` | Ownership secret (prefer the file) |
| `MCP_AUTHPROBE_CREDENTIALS_FILE` | Test grant for the refresh token checks |
| `MCP_AUTHPROBE_ALLOW_PRIVATE=1` | Allow loopback and private targets (local labs only) |
| `MCP_AUTHPROBE_TIMEOUT_MS` | Per-request timeout |

## What it checks

`mcp-authprobe checks list` prints the catalogue, and `mcp-authprobe checks show <ID>` explains a check: why it matters, how to fix it, and references. IDs are stable and never reused.

| ID | Mode | Status | Check |
| --- | --- | --- | --- |
| `MAP-DSC01` | passive | available | Authorization endpoints are discoverable (401 challenge, RFC 9728, RFC 8414) |
| `MAP-RTK01` | active | available | Refresh tokens for public clients are rotated |
| `MAP-RTK02` | active | available | A rotated refresh token cannot be replayed |
| `MAP-RTK03` | active | available | Refresh token replay revokes the token family |
| `MAP-RDR01` | active | available | Unregistered `redirect_uri` is refused at the authorization endpoint |
| `MAP-RDR02` | active | available | `redirect_uri` matching is exact, not prefix or pattern based |
| `MAP-RDR03` | active | available (via `login`) | Token endpoint enforces the `redirect_uri` used at authorization |
| `MAP-RDR04` | active | available | Dynamic client registration refuses unsafe redirect URIs |
| `MAP-THR01` | active | available | Repeated failed token requests are throttled (5 to 20 sequential requests with random values) |
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
- ~~Interactive login creating the test grant~~ done.
- ~~Redirect URI checks (RDR01, RDR02, RDR04)~~ done.
- ~~`MAP-RDR03`~~ done, observed during login.
- ~~Throttling check (THR01)~~ done.
- ~~MCP server mode (stdio)~~ done.
- ~~npm release~~ done.

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
