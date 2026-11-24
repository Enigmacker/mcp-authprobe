import { describe, expect, it } from "vitest";
import { audienceHint } from "../src/scan.js";

const jwt = (payload: object): string =>
  `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;

describe("audience hint from a supplied access token", () => {
  const target = "https://mcp.example.com/mcp";
  it("says nothing for an opaque token", () => {
    expect(audienceHint("opaque-token-value", target, undefined)).toBeNull();
    expect(audienceHint(jwt({ sub: "x" }), target, undefined)).toBeNull();
  });
  it("recognises a token issued for this server, by URL or announced resource", () => {
    expect(audienceHint(jwt({ aud: "https://mcp.example.com/mcp/" }), target, undefined)).toMatch(/issued for this server/);
    expect(audienceHint(jwt({ aud: ["https://api.example.com", "https://mcp.example.com"] }), target, "https://mcp.example.com")).toMatch(/issued for this server/);
  });
  it("flags a token for another audience, without judging the check", () => {
    const hint = audienceHint(jwt({ aud: ["https://other.example.org/mcp"] }), target, "https://mcp.example.com/mcp");
    expect(hint).toMatch(/does not name this server/);
    expect(hint).toMatch(/supply a test grant/);
  });
  it("keeps what it repeats from the token short", () => {
    const hint = audienceHint(jwt({ aud: Array.from({ length: 20 }, (_, i) => `https://a${i}.example/${"x".repeat(300)}`) }), target, undefined) ?? "";
    expect(hint.length).toBeLessThan(900);
  });
});
