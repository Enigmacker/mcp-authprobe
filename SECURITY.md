# Security policy

## Supported versions

Until 1.0, only the latest release (and `main`) receives security fixes.

| Version | Supported |
| --- | --- |
| 0.1.x (development) | yes |

## Reporting a vulnerability in mcp-authprobe

Please **do not open a public issue** for a vulnerability in the scanner itself.

Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. Include:

- the affected version or commit,
- a description of the issue and its impact,
- steps to reproduce, ideally against the local fixture server or a lab you control.

You can expect an acknowledgement within 7 days and a status update within 30 days. Fixes are released as soon as they are ready, with credit to the reporter unless you prefer otherwise.

Examples of issues we want to hear about:

- a way to run active checks without a valid ownership proof,
- a way to make the scanner contact a private, loopback or metadata address without `--allow-private`,
- secrets (tokens, the ownership secret) appearing in output, reports or logs,
- server-controlled text reaching the terminal or a report without neutralization,
- denial of service of the scanner by a hostile server (unbounded memory or time).

## Vulnerabilities found *with* mcp-authprobe

Findings about a server you scanned belong to that server's operator. If you scanned your own server, fix it. If you were authorized to test someone else's server, follow the disclosure terms agreed with them. This project does not collect or handle third-party findings.

## Responsible use

`mcp-authprobe` performs active tests. Use it only against servers you own or are explicitly authorized to test. The ownership proof mechanism is a safeguard, not a permission: running the tool remains the operator's responsibility, and unauthorized testing may breach terms of service or the law.
