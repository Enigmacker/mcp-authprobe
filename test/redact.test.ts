import { describe, expect, it } from "vitest";
import { neutralize, redactSecrets, safeText } from "../src/redact.js";

describe("redaction", () => {
  it("redacts JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(redactSecrets(`token ${jwt} end`)).toBe("token [REDACTED] end");
  });

  it("redacts bearer values and OAuth secrets but keeps the parameter name", () => {
    expect(redactSecrets("Authorization: Bearer abcdefgh12345678")).toBe("Authorization: Bearer [REDACTED]");
    expect(redactSecrets("refresh_token=r3fr3shT0ken&x=1")).toBe("refresh_token=[REDACTED]&x=1");
    expect(redactSecrets('{"access_token":"s3cr3tvalue"}')).toBe('{"access_token":"[REDACTED]"}');
  });
});

describe("neutralization", () => {
  it("escapes terminal escapes, bidi overrides and zero-width characters", () => {
    expect(neutralize("a\u001b[31mb")).toBe("a\\u{1b}[31mb");
    expect(neutralize("x‮y")).toBe("x\\u{202e}y");
    expect(neutralize("p​q")).toBe("p\\u{200b}q");
    expect(neutralize("t\u{E0041}")).toBe("t\\u{e0041}");
  });

  it("keeps newlines and tabs", () => {
    expect(neutralize("a\tb\nc")).toBe("a\tb\nc");
  });

  it("truncates long text", () => {
    expect(safeText("x".repeat(600), 10)).toBe(`${"x".repeat(10)}…`);
  });
});
