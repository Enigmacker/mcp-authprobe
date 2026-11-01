import { afterEach, describe, expect, it } from "vitest";
import { asMetadataCandidates, discover, parseResourceMetadata, prmCandidates } from "../src/discovery.js";
import { HttpClient } from "../src/net/http.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

describe("discovery helpers", () => {
  it("parses resource_metadata, quoted or not", () => {
    expect(parseResourceMetadata('Bearer resource_metadata="https://a.example/.well-known/x", scope="mcp"')).toBe("https://a.example/.well-known/x");
    expect(parseResourceMetadata("Bearer resource_metadata=https://a.example/x")).toBe("https://a.example/x");
    expect(parseResourceMetadata('Bearer realm="x"')).toBeNull();
    expect(parseResourceMetadata(null)).toBeNull();
  });

  it("builds RFC 9728 candidates, path-inserted first", () => {
    expect(prmCandidates("https://a.example/v1/mcp")).toEqual([
      "https://a.example/.well-known/oauth-protected-resource/v1/mcp",
      "https://a.example/.well-known/oauth-protected-resource",
    ]);
    expect(prmCandidates("https://a.example/")).toEqual(["https://a.example/.well-known/oauth-protected-resource"]);
  });

  it("builds RFC 8414 and OIDC candidates", () => {
    expect(asMetadataCandidates("https://auth.example")).toEqual([
      "https://auth.example/.well-known/oauth-authorization-server",
      "https://auth.example/.well-known/openid-configuration",
    ]);
    expect(asMetadataCandidates("https://auth.example/tenant")[0]).toBe("https://auth.example/.well-known/oauth-authorization-server/tenant");
  });
});

describe("discover", () => {
  it("follows challenge -> PRM -> AS metadata on a compliant server", async () => {
    fixture = await startFixture();
    http = new HttpClient({ allowPrivate: true });
    const result = await discover(fixture.mcpUrl, http);
    expect(result.challenge.status).toBe(401);
    expect(result.challenge.resourceMetadataUrl).toBe(`${fixture.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(result.prm?.metadata.authorization_servers).toEqual([fixture.baseUrl]);
    expect(result.as?.metadata.token_endpoint).toBe(`${fixture.baseUrl}/token`);
    expect(result.notes).toEqual([]);
  });

  it("falls back to well-known PRM without a challenge", async () => {
    fixture = await startFixture({ challenge: false });
    http = new HttpClient({ allowPrivate: true });
    const result = await discover(fixture.mcpUrl, http);
    expect(result.challenge.resourceMetadataUrl).toBeNull();
    expect(result.prm).not.toBeNull();
  });

  it("notes an endpoint answering without credentials", async () => {
    fixture = await startFixture({ anonymous: true });
    http = new HttpClient({ allowPrivate: true });
    const result = await discover(fixture.mcpUrl, http);
    expect(result.notes.some((n) => n.includes("without credentials"))).toBe(true);
  });

  it("sends only read-only requests besides the MCP initialize", async () => {
    fixture = await startFixture();
    http = new HttpClient({ allowPrivate: true });
    await discover(fixture.mcpUrl, http);
    const writes = fixture.requests.filter((r) => r.method !== "GET");
    expect(writes).toEqual([{ method: "POST", path: "/mcp" }]);
  });
});
