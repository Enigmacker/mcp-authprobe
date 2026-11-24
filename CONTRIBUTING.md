# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Safety first.** Every active check must run only after the ownership gate (a proof for each host it sends requests to), send a small and bounded number of requests, clean up what it creates (for example registered clients) and never print secrets.
- **Inconclusive is never a pass.** A rate limit, a server error, an answer that was not read in full or a control that stops working makes a check `error`, with a reason code. A check that passes on a refusal repeats its control afterwards.
- **Both MCP eras.** A check of the MCP endpoint must behave on 2026-07-28 (stateless, `server/discover`) and on 2025-11-25 (`initialize`); the lab has `modern`, `dual` and legacy behaviours to test it.
- **Tests never leave the machine.** New checks come with fixture behaviours (compliant and misconfigured) in `test/fixtures/server.ts` and tests against them.
- **IDs are stable.** A check ID (`MAP-XXX00`) is never renamed or reused, even if the check is removed.
- **English everywhere:** code, comments, messages and documentation.

## Adding a check

1. Add its definition to `src/checks/catalogue.ts`: ID, family, title, severity, whether it is active, the MCP revisions it applies to (`appliesTo`), what a run needs for it (`runsWith`), rationale, remediation and references (prefer RFCs and the MCP specification).
2. Implement it under `src/checks/`, building findings with `makeFinding` (it neutralizes and redacts text, and requires a reason code for `skipped` and `error`).
3. Add fixture behaviours that make it pass and fail, and tests for both. Say in `src/plan.ts` when it runs and what it costs: a test compares `plan` with `scan`.
4. Run `npm run docs` (the README tables are generated from the catalogue; a test fails when they are out of date) and update the `Unreleased` section of `CHANGELOG.md`.

A new field in the JSON report goes into `schema/report.schema.json` and `docs/integration.md`; fields are only ever added within `mcp-authprobe/report/v1`. A new reason code goes into `REASON_CODES`, the schema and that page.

## Development

```sh
npm ci
npm run check   # typecheck, tests, build
npm run docs    # regenerate the generated blocks of README.md
```

## Commit messages

Short imperative subject line (`Add refresh token replay check`), optional body explaining why.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## Releasing (maintainers)

1. Move the `Unreleased` entries of `CHANGELOG.md` under a new `## [x.y.z] - YYYY-MM-DD` heading and update the links at the bottom.
2. Set the same version in `package.json`, `package-lock.json`, `server.json` and `src/version.ts` (a test checks they match and that the changelog has the entry), and in the examples of `README.md`.
3. Commit, then tag and push: `git tag vx.y.z && git push origin vx.y.z`.
4. The `Release` workflow checks that the tag matches `package.json`, runs the full check and the audit, publishes to npm with trusted publishing (no token stored), and creates the GitHub release from the changelog section. The `Docker image` workflow builds and pushes the image for the same tag.
