// SPDX-License-Identifier: AGPL-3.0-or-later
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import {
  CLASS_TABLE,
  classifyAddress,
  decide,
  destinationOf,
  OUTBOUND_RESOLVE,
  OutboundPolicy,
  OutboundRefusedError,
  parseOutboundAllow,
  RefusalAuditLimiter,
  allowListWarnings,
  type Resolver,
} from "../src/net/outbound.js";

/** The shared outbound policy (ADR-0057): classes, the allow list, decisions, and the connection-time check. */

const resolverOf =
  (answers: Record<string, string[]>): Resolver =>
  async (name) => {
    const list = answers[name];
    if (!list) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
    return list.map((address) => ({ address, family: address.includes(":") ? (6 as const) : (4 as const) }));
  };

const at = (url: string) => destinationOf(new URL(url))!;

describe("address classes (Decision 2)", () => {
  /** First and last address of each range, and one just outside. */
  function v4Bounds(cidr: string): { first: string; last: string; outside: string | null } {
    const [base, prefixText] = cidr.split("/") as [string, string];
    const prefix = Number(prefixText);
    const n = base.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
    const size = 2 ** (32 - prefix);
    const toIp = (v: number) => [24, 16, 8, 0].map((s) => Math.floor(v / 2 ** s) % 256).join(".");
    const after = n + size;
    return { first: toIp(n), last: toIp(n + size - 1), outside: after < 2 ** 32 ? toIp(after) : n > 0 ? toIp(n - 1) : null };
  }

  it.each(CLASS_TABLE.filter((row) => !row.cidr.includes(":")).map((row) => [row.cidr, row.class] as const))(
    "%s is %s at its first and last address",
    (cidr, cls) => {
      const { first, last } = v4Bounds(cidr);
      expect(classifyAddress(first)).toBe(cls);
      expect(classifyAddress(last)).toBe(cls);
    },
  );

  it("classifies just outside each IPv4 range by its neighbour, never by the range", () => {
    expect(classifyAddress("11.0.0.0")).toBe("public");
    expect(classifyAddress("9.255.255.255")).toBe("public");
    expect(classifyAddress("172.32.0.0")).toBe("public");
    expect(classifyAddress("172.15.255.255")).toBe("public");
    expect(classifyAddress("192.169.0.0")).toBe("public");
    expect(classifyAddress("100.128.0.0")).toBe("public");
    expect(classifyAddress("100.63.255.255")).toBe("public");
    expect(classifyAddress("128.0.0.0")).toBe("public");
    expect(classifyAddress("126.255.255.255")).toBe("public");
    expect(classifyAddress("169.255.0.0")).toBe("public");
    expect(classifyAddress("1.0.0.0")).toBe("public");
    expect(classifyAddress("223.255.255.255")).toBe("public");
    expect(classifyAddress("192.0.1.0")).toBe("public");
    expect(classifyAddress("198.20.0.0")).toBe("public");
    expect(classifyAddress("198.17.255.255")).toBe("public");
    expect(classifyAddress("192.88.100.0")).toBe("public");
    expect(classifyAddress("203.0.114.0")).toBe("public");
    expect(classifyAddress("198.51.101.0")).toBe("public");
    // The metadata exceptions are single addresses: their neighbours keep the outer class.
    expect(classifyAddress("100.100.100.200")).toBe("host-only");
    expect(classifyAddress("100.100.100.201")).toBe("private");
    expect(classifyAddress("168.63.129.16")).toBe("host-only");
    expect(classifyAddress("168.63.129.17")).toBe("public");
    expect(classifyAddress("255.255.255.255")).toBe("never");
  });

  it.each([
    ["::", "never"],
    ["::1", "host-only"],
    ["::2", "never"], // IPv4-compatible 0.0.0.2
    ["ff00::", "never"],
    ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "never"],
    ["fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "public"],
    ["100::", "never"],
    ["100::ffff:ffff:ffff:ffff", "never"],
    ["100:0:0:1::", "public"],
    ["fe80::", "host-only"],
    ["febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["fec0::", "host-only"],
    ["feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["fd00:ec2::254", "host-only"],
    ["fd00:ec2::255", "private"],
    ["2001::", "host-only"],
    ["2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["2001:200::", "public"],
    ["2002::", "host-only"],
    ["2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["2003::", "public"],
    ["64:ff9b:1::", "host-only"],
    ["64:ff9b:1:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["2001:db8::", "host-only"],
    ["2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["2001:db9::", "public"],
    ["3fff::", "host-only"],
    ["3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["3fff:1000::", "public"],
    ["5f00::", "host-only"],
    ["5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "host-only"],
    ["5f01::", "public"],
    ["fc00::", "private"],
    ["fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "private"],
    ["fd7a:115c:a1e0::1", "private"],
    ["fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "public"],
    ["fe00::", "public"],
    ["2606:4700::1111", "public"],
  ])("%s is %s", (address, cls) => {
    expect(classifyAddress(address)).toBe(cls);
  });

  it("classifies IPv4-mapped, IPv4-compatible and NAT64 addresses by the IPv4 address they carry", () => {
    expect(classifyAddress("::ffff:127.0.0.1")).toBe("host-only");
    expect(classifyAddress("::ffff:7f00:1")).toBe("host-only");
    expect(classifyAddress("0:0:0:0:0:ffff:7f00:0001")).toBe("host-only");
    expect(classifyAddress("::ffff:a9fe:a9fe")).toBe("host-only"); // 169.254.169.254
    expect(classifyAddress("::ffff:10.0.0.1")).toBe("private");
    expect(classifyAddress("::ffff:8.8.8.8")).toBe("public");
    expect(classifyAddress("::127.0.0.1")).toBe("host-only"); // compatible
    expect(classifyAddress("::a00:1")).toBe("private"); // compatible 10.0.0.1
    expect(classifyAddress("64:ff9b::a00:1")).toBe("private"); // NAT64 to 10.0.0.1
    expect(classifyAddress("64:ff9b::7f00:1")).toBe("host-only");
    expect(classifyAddress("64:ff9b::808:808")).toBe("public"); // NAT64 to 8.8.8.8
    expect(classifyAddress("64:ff9b::0:0")).toBe("never");
  });

  it("reads the forms the URL parser normalizes, never the raw string", () => {
    for (const url of ["http://2130706433/", "http://0x7f.1/", "http://0177.0.0.1/", "http://127.1/", "http://0x7f000001/", "http://[0:0:0:0:0:0:0:1]/", "http://[::ffff:127.0.0.1]/"]) {
      const host = at(url).host;
      expect(classifyAddress(host), url).toBe("host-only");
    }
    expect(at("https://Coolify.Example.COM./x").host).toBe("coolify.example.com");
    expect(at("https://bücher.example/").host).toBe("xn--bcher-kva.example");
  });
});

describe("name resolution", () => {
  it("is bounded: a lookup that never answers is unresolved after OUTBOUND_RESOLVE.timeoutMs, and nothing waits longer", async () => {
    const saved = OUTBOUND_RESOLVE.timeoutMs;
    OUTBOUND_RESOLVE.timeoutMs = 100;
    try {
      const policy = new OutboundPolicy([], { resolve: () => new Promise(() => undefined), log: () => {} });
      const began = Date.now();
      const checked = await policy.check("https://stalled.example/");
      expect(checked).toMatchObject({ outcome: "unresolved", error: "ETIMEOUT" });
      expect(Date.now() - began).toBeLessThan(2_000);
      expect(await policy.refusalFor("https://stalled.example/", "webhook")).toBeNull();
    } finally {
      OUTBOUND_RESOLVE.timeoutMs = saved;
    }
  });
});

describe("VARLATCH_OUTBOUND_ALLOW (Decision 5)", () => {
  it("parses names, wildcards, addresses, ranges and ports", () => {
    const entries = parseOutboundAllow(" coolify.lan, *.private.example.com:8443 ,10.0.0.0/8:8000,10.1.2.3,10.1.2.4:443,[fd00::/8]:3210,fd7a:115c:a1e0::/48,::1/128:*,127.0.0.1/32:*,[::1]:*,convex.example.com:3210");
    expect(entries.map((e) => e.text)).toEqual([
      "coolify.lan", "*.private.example.com:8443", "10.0.0.0/8:8000", "10.1.2.3", "10.1.2.4:443", "[fd00::/8]:3210",
      "fd7a:115c:a1e0::/48", "::1/128:*", "127.0.0.1/32:*", "[::1]:*", "convex.example.com:3210",
    ]);
    expect(entries[0]).toMatchObject({ kind: "name", name: "coolify.lan", wildcard: false, port: null });
    expect(entries[1]).toMatchObject({ kind: "name", name: "private.example.com", wildcard: true, port: 8443 });
    expect(entries[2]).toMatchObject({ kind: "cidr", port: 8000, hostOnly: false });
    expect(entries[3]).toMatchObject({ kind: "cidr", port: null, range: { prefix: 32 } });
    expect(entries[5]).toMatchObject({ kind: "cidr", port: 3210, range: { family: 6, prefix: 8 } });
    expect(entries[6]).toMatchObject({ kind: "cidr", port: null, range: { family: 6, prefix: 48 } });
    expect(entries[7]).toMatchObject({ kind: "cidr", port: "*", hostOnly: true });
    expect(entries[9]).toMatchObject({ kind: "cidr", port: "*", hostOnly: true, range: { prefix: 128 } });
    expect(parseOutboundAllow("")).toEqual([]);
    expect(parseOutboundAllow(undefined)).toEqual([]);
  });

  it.each(["10.0.0.0/33", "under_score.lan", "http://coolify.lan", "*", "*.", "coolify.lan:0", "coolify.lan:65536", "coolify.lan:x", "fd00::1:443:", "[fd00::/129]", "1.2.3.4/8/8", "a..b", "*.*.lan"])(
    "refuses %s",
    (entry) => {
      expect(() => parseOutboundAllow(`coolify.lan,${entry}`)).toThrow(entry);
    },
  );

  it("stops varlatchd at startup on an invalid entry, naming it", () => {
    const base = { VARLATCH_DATABASE_URL: "postgres://x@y/z", VARLATCH_KEK: "a".repeat(64) };
    expect(() => loadConfig({ ...base, VARLATCH_OUTBOUND_ALLOW: "coolify.lan,10.0.0.0/40" })).toThrow(/VARLATCH_OUTBOUND_ALLOW: 10\.0\.0\.0\/40/);
    expect(loadConfig({ ...base, VARLATCH_OUTBOUND_ALLOW: "coolify.lan" }).outboundAllow).toHaveLength(1);
    expect(loadConfig(base).outboundAllow).toEqual([]);
  });

  it("warns about entries that open host-only ranges or add nothing", () => {
    const warnings = allowListWarnings(parseOutboundAllow("0.0.0.0/0,127.0.0.1/32:*,localhost,224.0.0.0/4,coolify.lan"));
    expect(warnings).toHaveLength(4);
    expect(warnings.join("\n")).toMatch(/0\.0\.0\.0\/0 adds only the private ranges/);
    expect(warnings.join("\n")).toMatch(/127\.0\.0\.1\/32:\* opens a host-only range/);
  });
});

describe("decisions (Decisions 3 and 5)", () => {
  const allow = (spec: string) => parseOutboundAllow(spec);

  it("allows public https on any port, and refuses http without an entry", () => {
    expect(decide([], at("https://example.com/"), ["93.184.215.14"])).toMatchObject({ allowed: true, via: "public" });
    expect(decide([], at("https://example.com:8443/"), ["93.184.215.14"])).toMatchObject({ allowed: true });
    expect(decide([], at("http://example.com/"), ["93.184.215.14"])).toEqual({ allowed: false, reason: "scheme" });
    expect(decide(allow("example.com"), at("http://example.com/"), ["93.184.215.14"])).toMatchObject({ allowed: true, entries: ["example.com"] });
    expect(decide(allow("93.184.215.14/32"), at("http://example.com/"), ["93.184.215.14"])).toMatchObject({ allowed: true });
  });

  it("opens private addresses by a hostname entry, never host-only ones", () => {
    expect(decide([], at("https://coolify.lan/"), ["10.0.0.5"])).toEqual({ allowed: false, reason: "private_address" });
    expect(decide(allow("coolify.lan"), at("https://coolify.lan/"), ["10.0.0.5"])).toMatchObject({ allowed: true, entries: ["coolify.lan"] });
    expect(decide(allow("coolify.lan"), at("https://coolify.lan/"), ["127.0.0.1"])).toEqual({ allowed: false, reason: "host_only_address" });
    expect(decide(allow("coolify.lan"), at("https://coolify.lan/"), ["169.254.169.254"])).toEqual({ allowed: false, reason: "host_only_address" });
    // Wildcards match subdomains, never the apex.
    expect(decide(allow("*.lan.example"), at("https://a.b.lan.example/"), ["10.0.0.5"])).toMatchObject({ allowed: true });
    expect(decide(allow("*.lan.example"), at("https://lan.example/"), ["10.0.0.5"])).toEqual({ allowed: false, reason: "private_address" });
  });

  it("opens host-only ranges only by a CIDR entry inside them", () => {
    expect(decide(allow("127.0.0.1/32:*"), at("http://127.0.0.1:8080/"), ["127.0.0.1"])).toMatchObject({ allowed: true });
    expect(decide(allow("127.0.0.0/8:*"), at("http://localhost:8080/"), ["127.0.0.1"])).toMatchObject({ allowed: true });
    expect(decide(allow("0.0.0.0/0:*"), at("http://127.0.0.1:8080/"), ["127.0.0.1"])).toEqual({ allowed: false, reason: "host_only_address" });
    expect(decide(allow("0.0.0.0/0:*"), at("https://x.lan/"), ["10.1.1.1"])).toMatchObject({ allowed: true });
    expect(decide(allow("100.64.0.0/10"), at("https://meta.lan/"), ["100.100.100.200"])).toEqual({ allowed: false, reason: "host_only_address" });
    expect(decide(allow("100.64.0.0/10"), at("https://ts.lan/"), ["100.101.102.103"])).toMatchObject({ allowed: true });
    expect(decide(allow("fc00::/7"), at("https://meta.lan/"), ["fd00:ec2::254"])).toEqual({ allowed: false, reason: "host_only_address" });
    expect(decide(allow("fd00:ec2::254/128"), at("https://meta.lan/"), ["fd00:ec2::254"])).toMatchObject({ allowed: true });
    expect(decide(allow("::1/128:*"), at("http://[::1]:3000/"), ["::1"])).toMatchObject({ allowed: true });
    // A mapped loopback is loopback; an IPv4 entry inside loopback opens it.
    expect(decide(allow("127.0.0.1/32:*"), at("http://[::ffff:127.0.0.1]:80/"), ["::ffff:7f00:1"])).toMatchObject({ allowed: true });
    expect(decide(allow("10.0.0.0/8"), at("http://[::ffff:127.0.0.1]/"), ["::ffff:7f00:1"])).toEqual({ allowed: false, reason: "host_only_address" });
  });

  it("never opens never-class addresses", () => {
    for (const spec of ["0.0.0.0/0:*", "224.0.0.0/4:*", "0.0.0.0/8:*", "::/0:*"]) {
      expect(decide(allow(spec), at("https://x.lan/"), ["0.0.0.0"])).toEqual({ allowed: false, reason: "never_address" });
      expect(decide(allow(spec), at("https://x.lan/"), ["239.1.1.1"])).toEqual({ allowed: false, reason: "never_address" });
    }
  });

  it("applies the entry's port: portless is the scheme's default only, :* any", () => {
    expect(decide(allow("convex.lan"), at("https://convex.lan:3210/"), ["10.0.0.6"])).toEqual({ allowed: false, reason: "port" });
    expect(decide(allow("convex.lan:3210"), at("https://convex.lan:3210/"), ["10.0.0.6"])).toMatchObject({ allowed: true });
    expect(decide(allow("convex.lan:3210"), at("https://convex.lan/"), ["10.0.0.6"])).toEqual({ allowed: false, reason: "port" });
    expect(decide(allow("convex.lan:*"), at("https://convex.lan:9/"), ["10.0.0.6"])).toMatchObject({ allowed: true });
    expect(decide(allow("hooks.lan"), at("http://hooks.lan/"), ["192.168.1.9"])).toMatchObject({ allowed: true });
    expect(decide(allow("hooks.lan"), at("http://hooks.lan:443/"), ["192.168.1.9"])).toEqual({ allowed: false, reason: "port" });
    expect(decide(allow("10.0.0.0/8:8000"), at("https://x.lan:8000/"), ["10.2.2.2"])).toMatchObject({ allowed: true });
    expect(decide(allow("10.0.0.0/8:8000"), at("https://x.lan/"), ["10.2.2.2"])).toEqual({ allowed: false, reason: "port" });
  });

  it("never matches a hostname entry to a literal address", () => {
    expect(decide(allow("10.0.0.5.nip.example"), at("https://10.0.0.5/"), ["10.0.0.5"])).toEqual({ allowed: false, reason: "private_address" });
    expect(decide(allow("10.0.0.5/32"), at("https://10.0.0.5/"), ["10.0.0.5"])).toMatchObject({ allowed: true });
    expect(decide([], at("https://8.8.8.8/"), ["8.8.8.8"])).toMatchObject({ allowed: true, via: "public" });
  });

  it("refuses a name when any answer is refused, even with a public one", () => {
    expect(decide([], at("https://mixed.example/"), ["93.184.215.14", "10.0.0.1"])).toEqual({ allowed: false, reason: "mixed_answers" });
    expect(decide([], at("https://mixed.example/"), ["10.0.0.1", "93.184.215.14"])).toEqual({ allowed: false, reason: "mixed_answers" });
    expect(decide(allow("mixed.example"), at("https://mixed.example/"), ["93.184.215.14", "10.0.0.1"])).toMatchObject({ allowed: true });
    expect(decide(allow("mixed.example"), at("https://mixed.example/"), ["93.184.215.14", "127.0.0.1"])).toEqual({ allowed: false, reason: "mixed_answers" });
    // Dual-stack and IPv6-only.
    expect(decide([], at("https://dual.example/"), ["93.184.215.14", "2606:4700::1111"])).toMatchObject({ allowed: true });
    expect(decide([], at("https://v6.example/"), ["2606:4700::1111"])).toMatchObject({ allowed: true });
    expect(decide([], at("https://v6.example/"), ["fd7a:115c:a1e0::5"])).toEqual({ allowed: false, reason: "private_address" });
  });
});

describe("the configuration-time check (Decision 6)", () => {
  it("resolves, classifies, and treats a DNS failure as no refusal", async () => {
    const policy = new OutboundPolicy("coolify.lan", { resolve: resolverOf({ "coolify.lan": ["10.0.0.5"], "evil.example": ["127.0.0.1"], "pub.example": ["93.184.215.14"] }) });
    expect(await policy.check("https://coolify.lan")).toMatchObject({ outcome: "allowed", addresses: ["10.0.0.5"] });
    expect(await policy.check("https://evil.example")).toMatchObject({ outcome: "refused", verdict: { reason: "host_only_address" } });
    expect(await policy.check("https://pub.example")).toMatchObject({ outcome: "allowed" });
    expect(await policy.check("https://nowhere.example")).toMatchObject({ outcome: "unresolved", error: "ENOTFOUND" });
    const refusal = await policy.refusalFor("https://evil.example/hook?token=abc", "webhook");
    expect(refusal).toBeInstanceOf(OutboundRefusedError);
    expect(refusal?.message).toMatch(/loopback or link-local address/);
    expect(refusal?.message).not.toContain("127.0.0.1");
    expect(refusal?.message).not.toContain("evil");
    expect(await policy.refusalFor("https://nowhere.example", "webhook")).toBeNull();
  });
});

describe("the connection-time check (Decision 4)", () => {
  const servers: { close: () => void }[] = [];
  const policies: OutboundPolicy[] = [];
  afterEach(async () => {
    for (const s of servers.splice(0)) s.close();
    for (const p of policies.splice(0)) await p.close();
    vi.unstubAllEnvs();
  });

  function policyOf(spec: string, resolve: Resolver, extra: Record<string, unknown> = {}): OutboundPolicy {
    const policy = new OutboundPolicy(spec, { resolve, log: () => {}, ...extra });
    policies.push(policy);
    return policy;
  }

  async function httpServer(handler: http.RequestListener, host = "127.0.0.1"): Promise<number> {
    const server = http.createServer(handler);
    await new Promise<void>((r) => server.listen(0, host, r));
    servers.push({ close: () => server.close() });
    return (server.address() as AddressInfo).port;
  }

  it("refuses at connection time a name that answered public when it was saved (rebinding)", async () => {
    let calls = 0;
    const policy = policyOf("", async () => [{ address: calls++ === 0 ? "93.184.215.14" : "127.0.0.1", family: 4 }]);
    expect(await policy.check("https://rebind.example")).toMatchObject({ outcome: "allowed" });
    const err = await policy.fetch("webhook")("https://rebind.example/hook", { method: "POST" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboundRefusedError);
    expect((err as OutboundRefusedError).reason).toBe("host_only_address");
  });

  it("keeps the socket on the checked address when the answer changes after the check, and checks each new connection", async () => {
    const seen: string[] = [];
    const port = await httpServer((req, res) => {
      seen.push(`${req.socket.remoteAddress}->${req.socket.localAddress} ${req.headers.host}`);
      res.setHeader("Connection", "close");
      res.end("ok");
    });
    const answers = ["127.0.0.1", "127.0.0.2"];
    let calls = 0;
    const policy = policyOf("127.0.0.1/32:*", async () => [{ address: answers[Math.min(calls++, 1)] as string, family: 4 }]);
    const res = await policy.fetch("webhook")(`http://moving.test:${port}/`);
    expect(await res.text()).toBe("ok");
    expect(calls).toBe(1);
    expect(seen[0]).toMatch(new RegExp(`->127\\.0\\.0\\.1 moving\\.test:${port}$`));
    // A new connection resolves again, and the new answer is refused.
    const err = await policy.fetch("webhook")(`http://moving.test:${port}/`).catch((e: unknown) => e);
    expect(calls).toBe(2);
    expect(err).toBeInstanceOf(OutboundRefusedError);
    expect(seen).toHaveLength(1);
  });

  it("refuses literal addresses in the connector, without DNS", async () => {
    const resolve = vi.fn<Resolver>(async () => []);
    const policy = policyOf("", resolve);
    for (const url of ["http://127.0.0.1:9999/", "https://[::1]:9999/", "https://169.254.169.254/latest/meta-data", "https://10.0.0.1/", "https://[::ffff:127.0.0.1]/", "https://2130706433/", "https://0.0.0.0/"]) {
      const err = await policy.fetch("webhook")(url).catch((e: unknown) => e);
      expect(err, url).toBeInstanceOf(OutboundRefusedError);
    }
    expect(resolve).not.toHaveBeenCalled();
  });

  it("refuses mixed answers at connection time", async () => {
    const policy = policyOf("", resolverOf({ "mixed.example": ["93.184.215.14", "10.0.0.1"] }));
    const err = await policy.fetch("sync_delivery")("https://mixed.example/").catch((e: unknown) => e);
    expect((err as OutboundRefusedError).reason).toBe("mixed_answers");
  });

  it("never follows a redirect, and throws when a caller asks it to", async () => {
    for (const status of [301, 302, 307, 308]) {
      const port = await httpServer((_req, res) => {
        res.writeHead(status, { Location: "http://169.254.169.254/" });
        res.end();
      });
      const policy = policyOf("127.0.0.1/32:*", resolverOf({ "redir.test": ["127.0.0.1"] }));
      const err = await policy.fetch("oidc")(`http://redir.test:${port}/`).catch((e: unknown) => e);
      expect(err, String(status)).toBeInstanceOf(TypeError);
      expect(String((err as Error & { cause?: Error }).cause?.message ?? (err as Error).message)).toMatch(/redirect/i);
    }
    const policy = policyOf("", resolverOf({}));
    await expect(policy.fetch("webhook")("https://example.com/", { redirect: "follow" })).rejects.toThrow(/never follow redirects/);
    await expect(policy.fetch("webhook")("https://example.com/", { redirect: "manual" })).rejects.toThrow(/never follow redirects/);
  });

  it("ignores HTTPS_PROXY and HTTP_PROXY", async () => {
    let proxied = 0;
    const proxyPort = await httpServer((_req, res) => {
      proxied++;
      res.end("proxy");
    });
    const port = await httpServer((_req, res) => res.end("direct"));
    vi.stubEnv("HTTP_PROXY", `http://127.0.0.1:${proxyPort}`);
    vi.stubEnv("HTTPS_PROXY", `http://127.0.0.1:${proxyPort}`);
    vi.stubEnv("http_proxy", `http://127.0.0.1:${proxyPort}`);
    vi.stubEnv("NODE_USE_ENV_PROXY", "1");
    const policy = policyOf("127.0.0.1/32:*", resolverOf({ "direct.test": ["127.0.0.1"] }));
    expect(await (await policy.fetch("webhook")(`http://direct.test:${port}/`)).text()).toBe("direct");
    expect(proxied).toBe(0);
    // A refused name never reaches a proxy either.
    await expect(policy.fetch("webhook")("https://10.9.9.9/")).rejects.toBeInstanceOf(OutboundRefusedError);
    expect(proxied).toBe(0);
  });

  describe("TLS stays the name's", () => {
    let pair: { key: string; cert: string };
    function makePair(name: string): { key: string; cert: string } {
      const dir = mkdtempSync(join(tmpdir(), "outbound-cert-"));
      execFileSync("openssl", [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "2",
        "-subj", `/CN=${name}`, "-addext", `subjectAltName=DNS:${name}`,
      ], { stdio: "ignore" });
      return { key: readFileSync(join(dir, "key.pem"), "utf8"), cert: readFileSync(join(dir, "cert.pem"), "utf8") };
    }

    async function tlsServer(): Promise<{ port: number; seen: { servername: string | undefined; host: string | undefined }[] }> {
      pair ??= makePair("pinned.test");
      const seen: { servername: string | undefined; host: string | undefined }[] = [];
      const server = https.createServer({ key: pair.key, cert: pair.cert }, (req, res) => {
        seen.push({ servername: (req.socket as import("node:tls").TLSSocket).servername || undefined, host: req.headers.host });
        res.end("tls");
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      servers.push({ close: () => server.close() });
      return { port: (server.address() as AddressInfo).port, seen };
    }

    it("connects to the checked address with SNI, certificate and Host for the name", async () => {
      const { port, seen } = await tlsServer();
      const policy = policyOf("127.0.0.1/32:*", resolverOf({ "pinned.test": ["127.0.0.1"], "other.test": ["127.0.0.1"] }), { tls: { ca: pair.cert } });
      const res = await policy.fetch("sync_check")(`https://pinned.test:${port}/`);
      expect(await res.text()).toBe("tls");
      expect(seen[0]).toEqual({ servername: "pinned.test", host: `pinned.test:${port}` });
      // The same server under another name: the certificate is not for it.
      const err = await policy.fetch("sync_check")(`https://other.test:${port}/`).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TypeError);
      expect(String((err as { cause?: { code?: string } }).cause?.code)).toMatch(/ERR_TLS_CERT_ALTNAME_INVALID/);
    });

    it("gives the https.Agent form the same check", async () => {
      const { port } = await tlsServer();
      const policy = policyOf("127.0.0.1/32:*", resolverOf({ "pinned.test": ["127.0.0.1"], "far.test": ["10.0.0.9"] }), { tls: { ca: pair.cert } });
      const agent = policy.httpsAgent("audit_export");
      const get = (url: string) =>
        new Promise<string>((resolve, reject) => {
          https.get(url, { agent }, (res) => {
            let body = "";
            res.on("data", (c) => (body += String(c)));
            res.on("end", () => resolve(body));
          }).on("error", reject);
        });
      expect(await get(`https://pinned.test:${port}/`)).toBe("tls");
      await expect(get("https://far.test/")).rejects.toBeInstanceOf(OutboundRefusedError);
      await expect(get("https://169.254.169.254/")).rejects.toBeInstanceOf(OutboundRefusedError);
      agent.destroy();
    });
  });
});

describe("the audit bound (Decision 8)", () => {
  it("records one event per key per hour, and expires the key after its hour", () => {
    let now = 0;
    const limiter = new RefusalAuditLimiter(() => now);
    expect(limiter.admit("org|webhook|wh1|private_address")).toEqual({ record: true, suppressed: 0 });
    expect(limiter.admit("org|webhook|wh1|private_address").record).toBe(false);
    expect(limiter.admit("org|webhook|wh2|private_address")).toEqual({ record: true, suppressed: 1 });
    now = 3_600_000;
    expect(limiter.size).toBe(2);
    expect(limiter.admit("org|webhook|wh1|private_address")).toEqual({ record: true, suppressed: 0 });
    expect(limiter.size).toBe(1);
  });

  it("caps the process at 100 an hour and carries the count", () => {
    let now = 0;
    const limiter = new RefusalAuditLimiter(() => now);
    for (let i = 0; i < 100; i++) expect(limiter.admit(`k${i}`).record).toBe(true);
    for (let i = 100; i < 150; i++) expect(limiter.admit(`k${i}`).record).toBe(false);
    now = 3_600_001;
    expect(limiter.admit("next")).toEqual({ record: true, suppressed: 50 });
  });

  it("keeps the map within its key bound; a new key beyond it counts toward the cap", () => {
    const now = 0;
    const limiter = new RefusalAuditLimiter(() => now, { perKeyMs: 3_600_000, processCap: 100_000, maxKeys: 10_000 });
    for (let i = 0; i < 10_050; i++) limiter.admit(`k${i}`);
    expect(limiter.size).toBe(10_000);
    // Beyond the bound a key gets no entry: it is recorded again (within the cap).
    expect(limiter.admit("k10049").record).toBe(true);
  });
});
