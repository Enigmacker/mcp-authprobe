import { describe, expect, it } from "vitest";
import { isBlockedAddress, isLoopbackHost } from "../src/net/address-policy.js";
import { BlockedAddressError, HttpClient, InsecureTransportError, plainHttpAllowed } from "../src/net/http.js";

describe("address policy", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::a9fe:a9fe", "::7f00:1", "2002:a9fe:a9fe::1", "64:ff9b:1::a9fe:a9fe", "fec0::1"])(
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
    await expect(http.request({ url: "https://127.0.0.1:8443/" })).rejects.toBeInstanceOf(BlockedAddressError);
    await http.close();
  });

  it("refuses hostnames that resolve to loopback", async () => {
    const http = new HttpClient();
    await expect(http.request({ url: "https://localhost:8443/" })).rejects.toThrow(/private or reserved/);
    await http.close();
  });

  it("refuses plain HTTP to public hosts, even with --allow-private", async () => {
    for (const allowPrivate of [false, true]) {
      const http = new HttpClient({ allowPrivate });
      await expect(http.request({ url: "http://auth.example.com/token" })).rejects.toBeInstanceOf(InsecureTransportError);
      await http.close();
    }
  });

  it("allows plain HTTP only for loopback or private labs with --allow-private", () => {
    expect(plainHttpAllowed(new URL("http://127.0.0.1:8080/"), true)).toBe(true);
    expect(plainHttpAllowed(new URL("http://[::1]:8080/"), true)).toBe(true);
    expect(plainHttpAllowed(new URL("http://10.0.0.5/"), true)).toBe(true);
    expect(plainHttpAllowed(new URL("http://localhost/"), true)).toBe(true);
    expect(plainHttpAllowed(new URL("http://127.0.0.1:8080/"), false)).toBe(false);
    expect(plainHttpAllowed(new URL("http://lab.example.com/"), true)).toBe(false);
  });

  it("rejects unsupported schemes", async () => {
    const http = new HttpClient({ allowPrivate: true });
    await expect(http.request({ url: "file:///etc/passwd" })).rejects.toThrow(/Unsupported URL scheme/);
    await http.close();
  });
});
