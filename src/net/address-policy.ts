import { BlockList, isIP } from "node:net";

/**
 * Addresses the scanner refuses to connect to unless `allowPrivate` is set:
 * loopback, private, link-local, CGNAT, multicast, reserved, unspecified and
 * cloud metadata ranges. The check runs at connect time, after DNS
 * resolution, so a hostname that resolves to an internal address is refused
 * too (no DNS-rebinding window between check and use).
 */
// Separate lists: Node's BlockList makes an IPv4-mapped IPv6 subnet match
// every plain IPv4 address, so the two families must not share one list.
const blockedV4 = new BlockList();
const blockedV6 = new BlockList();

const V4_RANGES: ReadonlyArray<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const V6_RANGES: ReadonlyArray<[string, number]> = [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
];

for (const [net, prefix] of V4_RANGES) blockedV4.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of V6_RANGES) blockedV6.addSubnet(net, prefix, "ipv6");

export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blockedV4.check(address, "ipv4");
  if (family === 6) {
    // IPv4-mapped IPv6: judge by the embedded IPv4 address.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped?.[1]) return blockedV4.check(mapped[1], "ipv4");
    // Other mapped spellings (hex form) fall in ::ffff:0:0/96 and are refused.
    return blockedV6.check(address, "ipv6");
  }
  return true; // not an IP literal: refuse rather than guess
}

/** Loopback-only targets are the one case where ownership proof may be skipped. */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (isIP(host) === 4) return host.startsWith("127.");
  if (isIP(host) === 6) return host === "::1";
  return false;
}
