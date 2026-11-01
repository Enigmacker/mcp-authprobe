import { afterEach, describe, expect, it } from "vitest";
import { HttpClient } from "../src/net/http.js";
import { generateSecret, PROOF_PREFIX, proofFor, proofsInText, verifyOwnership } from "../src/ownership.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

const noTxt = async (): Promise<string[][]> => {
  throw new Error("ENOTFOUND");
};

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

describe("proof derivation", () => {
  it("is deterministic, host-bound and case-insensitive on the host", () => {
    const secret = generateSecret();
    expect(proofFor("Example.com.", secret)).toBe(proofFor("example.com", secret));
    expect(proofFor("example.com", secret)).not.toBe(proofFor("example.org", secret));
    expect(proofFor("example.com", secret).startsWith(PROOF_PREFIX)).toBe(true);
  });

  it("never contains the secret", () => {
    const secret = generateSecret();
    expect(proofFor("example.com", secret)).not.toContain(secret);
  });

  it("extracts proof lines from a file with comments", () => {
    const text = `# owner: me\n${PROOF_PREFIX}abc\n  ${PROOF_PREFIX}def  \nother`;
    expect(proofsInText(text)).toEqual([`${PROOF_PREFIX}abc`, `${PROOF_PREFIX}def`]);
  });
});

describe("verifyOwnership", () => {
  // "lab.test" is not a loopback name, so the proof is really required;
  // wellKnownBaseUrl points the request at the local fixture.
  const host = "lab.test";

  it("verifies a proof published in the well-known file", async () => {
    const secret = generateSecret();
    fixture = await startFixture({ ownershipFile: `# test\n${proofFor(host, secret)}\n` });
    http = new HttpClient({ allowPrivate: true });
    const result = await verifyOwnership(host, secret, { http, wellKnownBaseUrl: fixture.baseUrl, resolveTxtRecords: noTxt });
    expect(result).toMatchObject({ verified: true, method: "well-known" });
  });

  it("verifies a proof published in DNS", async () => {
    const secret = generateSecret();
    fixture = await startFixture({ ownershipFile: null });
    http = new HttpClient({ allowPrivate: true });
    const resolver = async (name: string): Promise<string[][]> => {
      expect(name).toBe(`_mcp-authprobe.${host}`);
      const proof = proofFor(host, secret);
      return [[proof.slice(0, 40), proof.slice(40)]]; // TXT values may be split in chunks
    };
    const result = await verifyOwnership(host, secret, { http, wellKnownBaseUrl: fixture.baseUrl, resolveTxtRecords: resolver });
    expect(result).toMatchObject({ verified: true, method: "dns-txt" });
  });

  it("rejects a proof made with another secret", async () => {
    fixture = await startFixture({ ownershipFile: proofFor(host, generateSecret()) });
    http = new HttpClient({ allowPrivate: true });
    const result = await verifyOwnership(host, generateSecret(), { http, wellKnownBaseUrl: fixture.baseUrl, resolveTxtRecords: noTxt });
    expect(result.verified).toBe(false);
    expect(result.detail).toMatch(/no matching proof/);
  });

  it("rejects a proof made for another host", async () => {
    const secret = generateSecret();
    fixture = await startFixture({ ownershipFile: proofFor("other.test", secret) });
    http = new HttpClient({ allowPrivate: true });
    const result = await verifyOwnership(host, secret, { http, wellKnownBaseUrl: fixture.baseUrl, resolveTxtRecords: noTxt });
    expect(result.verified).toBe(false);
  });

  it("requires a secret, and a long enough one", async () => {
    http = new HttpClient({ allowPrivate: true });
    expect((await verifyOwnership(host, undefined, { http })).verified).toBe(false);
    expect((await verifyOwnership(host, "short", { http })).detail).toMatch(/too short/);
  });

  it("accepts loopback labs only when private addresses are explicitly allowed", async () => {
    http = new HttpClient({ allowPrivate: true });
    expect(await verifyOwnership("127.0.0.1", undefined, { http })).toMatchObject({ verified: true, method: "loopback" });
    await http.close();
    http = new HttpClient();
    expect((await verifyOwnership("127.0.0.1", undefined, { http })).verified).toBe(false);
  });
});
