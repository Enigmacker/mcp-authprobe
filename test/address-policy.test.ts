import { describe, expect, it } from "vitest";
import { isBlockedAddress, isLoopbackHost } from "../src/net/address-policy.js";
import { BlockedAddressError, HttpClient } from "../src/net/http.js";

describe("address policy", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:7f00:1"])(
    "blocks %s",
    (addr) => {
      expect(isBlockedAddress(addr)).toBe(true);
    },
  );

  it.each(["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])("allows public %s", (addr) => {
    expect(isBlockedAddress(addr)).toBe(false);
  });

  it("refuses non-IP input rather than guessing", () => {
    expect(isBlockedAddress("example.com")).toBe(true);
  });

  it("recognizes loopback hosts", () => {
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("app.localhost")).toBe(true);
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("[::1]")).toBe(true);
    expect(isLoopbackHost("example.com")).toBe(false);
  });
});

describe("HttpClient", () => {
  it("refuses IP-literal private targets by default", async () => {
    const http = new HttpClient();
    await expect(http.request({ url: "http://127.0.0.1:8080/" })).rejects.toBeInstanceOf(BlockedAddressError);
    await http.close();
  });

  it("refuses hostnames that resolve to loopback", async () => {
    const http = new HttpClient();
    await expect(http.request({ url: "http://localhost:8080/" })).rejects.toThrow(/private or reserved/);
    await http.close();
  });

  it("rejects unsupported schemes", async () => {
    const http = new HttpClient({ allowPrivate: true });
    await expect(http.request({ url: "file:///etc/passwd" })).rejects.toThrow(/Unsupported URL scheme/);
    await http.close();
  });
});
