// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { TrustedProxies, clientAddressOf, normalizeAddress, parseTrustedProxies } from "../src/http/client-address.js";

/** The client address behind trusted proxies (VARLATCH_TRUSTED_PROXIES). */

const NGINX = "10.0.0.2";
const INGRESS = "10.0.0.3";
const trusted = (...addresses: string[]) => (a: string) => addresses.includes(a);

describe("clientAddressOf", () => {
  it("uses the socket peer, ignoring X-Forwarded-For, when the peer is not a trusted proxy", () => {
    expect(clientAddressOf("198.51.100.9", "192.0.2.1", trusted(NGINX))).toBe("198.51.100.9");
    expect(clientAddressOf("::ffff:198.51.100.9", "192.0.2.1, 10.0.0.2", trusted(NGINX))).toBe("198.51.100.9");
  });

  it("reads the header from the right through trusted proxies: the first untrusted address is the client", () => {
    expect(clientAddressOf(NGINX, "192.0.2.10", trusted(NGINX))).toBe("192.0.2.10");
    expect(clientAddressOf(NGINX, `192.0.2.10, ${INGRESS}`, trusted(NGINX, INGRESS))).toBe("192.0.2.10");
  });

  it("never reaches what a caller wrote: it sits left of the address its first trusted proxy appended", () => {
    for (const forged of ["1.1.1.1", "1.1.1.1, 2.2.2.2", "garbage", `${INGRESS}`, "::1"]) {
      expect(clientAddressOf(NGINX, `${forged}, 192.0.2.10, ${INGRESS}`, trusted(NGINX, INGRESS))).toBe("192.0.2.10");
      // Directly to nginx, bypassing the ingress: nginx appends the caller's own address.
      expect(clientAddressOf(NGINX, `${forged}, 198.51.100.7`, trusted(NGINX, INGRESS))).toBe("198.51.100.7");
    }
  });

  it("an untrusted ingress makes the ingress the client (the control: trust is what makes the header count)", () => {
    expect(clientAddressOf(NGINX, `192.0.2.10, ${INGRESS}`, trusted(NGINX))).toBe(INGRESS);
  });

  it("falls back to the last good address on a malformed entry, or when every hop is trusted", () => {
    expect(clientAddressOf(NGINX, "not-an-ip", trusted(NGINX))).toBe(NGINX);
    expect(clientAddressOf(NGINX, `${INGRESS}`, trusted(NGINX, INGRESS))).toBe(INGRESS);
    expect(clientAddressOf(NGINX, "", trusted(NGINX))).toBe(NGINX);
  });

  it("reads at most 20 hops", () => {
    const chain = [...Array.from({ length: 30 }, () => INGRESS)].join(", ");
    expect(clientAddressOf(NGINX, `192.0.2.10, ${chain}`, trusted(NGINX, INGRESS))).toBe(INGRESS);
  });

  it("normalizes brackets, ports, zones, case, and IPv4-mapped addresses", () => {
    expect(normalizeAddress("[2001:DB8::1]:443")).toBe("2001:db8::1");
    expect(normalizeAddress("192.0.2.1:8080")).toBe("192.0.2.1");
    expect(normalizeAddress("fe80::1%eth0")).toBe("fe80::1");
    expect(normalizeAddress("::ffff:192.0.2.1")).toBe("192.0.2.1");
    expect(normalizeAddress("unknown")).toBeNull();
  });
});

describe("VARLATCH_TRUSTED_PROXIES", () => {
  it("parses addresses, CIDR ranges, and host names, and refuses anything else", () => {
    expect(parseTrustedProxies("varlatch-web, caddy,10.0.0.2, 172.18.0.0/16, 2001:db8::/32")).toEqual([
      { kind: "name", name: "varlatch-web" },
      { kind: "name", name: "caddy" },
      { kind: "address", address: "10.0.0.2" },
      { kind: "range", address: "172.18.0.0", prefix: 16 },
      { kind: "range", address: "2001:db8::", prefix: 32 },
    ]);
    for (const bad of ["10.0.0.0/33", "under_score", "http://proxy", "*"]) expect(() => parseTrustedProxies(bad)).toThrow();
  });

  it("trusts resolved names and literal ranges, follows a changed address, and trusts nothing for a name that does not resolve", async () => {
    let web = ["172.18.0.4"];
    const logs: string[] = [];
    const proxies = await new TrustedProxies("varlatch-web, coolify-proxy, 10.9.0.0/24", async (name) => {
      if (name === "varlatch-web") return web;
      throw Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
    }, (m) => logs.push(m)).start(60_000);
    try {
      expect(proxies.trusts("172.18.0.4")).toBe(true);
      expect(proxies.trusts("::ffff:172.18.0.4")).toBe(true);
      expect(proxies.trusts("10.9.0.77")).toBe(true);
      expect(proxies.trusts("172.18.0.1")).toBe(false); // the network's gateway: host callers are not proxies
      expect(logs.some((l) => /coolify-proxy does not resolve \(ENOTFOUND\)/.test(l))).toBe(true);
      web = ["172.18.0.9"]; // recreated container
      await proxies.refresh();
      expect(proxies.trusts("172.18.0.9")).toBe(true);
      expect(proxies.trusts("172.18.0.4")).toBe(false);
    } finally {
      proxies.stop();
    }
  });

  it("drops a name's addresses when a refresh fails: forwarding from the old address is ignored, until it resolves again", async () => {
    let answer: string[] | "ENOTFOUND" = ["172.18.0.4"];
    const logs: string[] = [];
    const proxies = await new TrustedProxies("varlatch-web, 10.9.0.0/24", async () => {
      if (answer === "ENOTFOUND") throw Object.assign(new Error("getaddrinfo ENOTFOUND varlatch-web"), { code: "ENOTFOUND" });
      return answer;
    }, (m) => logs.push(m)).start(60_000);
    try {
      expect(clientAddressOf("172.18.0.4", "198.51.100.99", proxies.trusts)).toBe("198.51.100.99");
      answer = "ENOTFOUND"; // the container is gone; its address may be reused by another
      await proxies.refresh();
      expect(proxies.trusts("172.18.0.4")).toBe(false);
      expect(clientAddressOf("172.18.0.4", "198.51.100.99", proxies.trusts)).toBe("172.18.0.4");
      expect(logs.some((l) => /varlatch-web no longer resolves \(ENOTFOUND\); 172\.18\.0\.4 are no longer trusted/.test(l))).toBe(true);
      expect(proxies.trusts("10.9.0.5")).toBe(true); // literal ranges are not affected
      await proxies.refresh(); // still failing: logged once
      expect(logs.filter((l) => /no longer resolves|does not resolve/.test(l))).toHaveLength(1);
      answer = ["172.18.0.11"]; // back, at a new address
      await proxies.refresh();
      expect(clientAddressOf("172.18.0.11", "198.51.100.99", proxies.trusts)).toBe("198.51.100.99");
      expect(proxies.trusts("172.18.0.4")).toBe(false);
      expect(logs.at(-1)).toMatch(/varlatch-web is 172\.18\.0\.11/);
    } finally {
      proxies.stop();
    }
  });

  it("stops trusting a resolution older than three refresh periods, even if refreshing stalls", async () => {
    let clock = 1_000_000;
    let stall = false;
    const proxies = await new TrustedProxies("varlatch-web", async () => {
      if (stall) return new Promise<string[]>(() => {}); // a lookup that never returns
      return ["172.18.0.4"];
    }, () => {}, () => clock).start(10_000);
    try {
      expect(proxies.trusts("172.18.0.4")).toBe(true);
      stall = true;
      void proxies.refresh();
      clock += 29_000;
      expect(proxies.trusts("172.18.0.4")).toBe(true);
      clock += 2_000; // past 3 x 10 s
      expect(proxies.trusts("172.18.0.4")).toBe(false);
    } finally {
      proxies.stop();
    }
  });
});
