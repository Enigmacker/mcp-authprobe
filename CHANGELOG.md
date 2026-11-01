# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Hardened HTTP client: connect-time refusal of loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses (after DNS resolution), timeouts, 1 MiB body cap, no automatic redirects, no compression.
- Ownership proof: host-bound SHA-256 proof of a local secret, published as `/.well-known/mcp-authprobe.txt` or a `_mcp-authprobe` DNS TXT record. Required for every host an active check would contact; loopback labs are exempt with `--allow-private`.
- OAuth discovery following the MCP Authorization specification: 401 challenge, Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414 and OpenID Connect Discovery).
- Check catalogue with stable `MAP-` identifiers: `MAP-DSC01` available; refresh token, redirect URI, throttling and consent CSRF families documented as planned.
- Reports: terminal table, JSON (`mcp-authprobe/report/v1`), SARIF 2.1.0 and Markdown, with redaction of token-shaped values and neutralization of control, bidi and invisible characters.
- CLI: `scan`, `ownership init|proof|verify`, `checks list|show`, `--fail-on`, exit codes 0/1/2/3.
- Local fixture server and test suite; GitHub Actions CI.
