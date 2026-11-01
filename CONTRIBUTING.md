# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Safety first.** Every active check must run only after the ownership gate, send a small and bounded number of requests, clean up what it creates (for example registered clients) and never print secrets.
- **Tests never leave the machine.** New checks come with fixture behaviours (compliant and misconfigured) in `test/fixtures/server.ts` and tests against them.
- **IDs are stable.** A check ID (`MAP-XXX00`) is never renamed or reused, even if the check is removed.
- **English everywhere:** code, comments, messages and documentation.

## Adding a check

1. Add its definition to `src/checks/catalogue.ts`: ID, family, title, severity, whether it is active, rationale, remediation and references (prefer RFCs and the MCP specification).
2. Implement it under `src/checks/`, returning `Finding` objects. Pass every server-controlled string through `safeText`.
3. Add fixture behaviours that make it pass and fail, and tests for both.
4. Update the table in `README.md` and the `Unreleased` section of `CHANGELOG.md`.

## Development

```sh
npm ci
npm run check   # typecheck, tests, build
```

## Commit messages

Short imperative subject line (`Add refresh token replay check`), optional body explaining why.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## Releasing (maintainers)

1. Move the `Unreleased` entries of `CHANGELOG.md` under a new `## [x.y.z] - YYYY-MM-DD` heading and update the links at the bottom.
2. Set the same version in `package.json` and `src/version.ts` (a test checks they match and that the changelog has the entry).
3. Commit, then tag and push: `git tag vx.y.z && git push origin vx.y.z`.
4. The `Release` workflow checks that the tag matches `package.json`, runs the full check and the audit, publishes to npm with trusted publishing (no token stored), and creates the GitHub release from the changelog section.
