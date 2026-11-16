// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The outbound policy's vectors for the Go server (ADR-0057; ADR-0059 step
 * 4.7, feature-parity decision 6), from this server's own code
 * (net/outbound.ts, net/outbound-check.ts, @varlatch/protocol):
 *
 *   go/server/outbound/testdata/ts-vectors.json: the class of every address
 *   form the class table handles (IPv4, IPv6, mapped, compatible, NAT64,
 *   link-local, CGNAT, the metadata services and the rest, and strings that
 *   are not addresses), the allow list parser's entries and refusals,
 *   doctor's warnings, the decision for a destination and its answers, the
 *   refusal sentences, and outbound check's suggestions.
 *
 * Everything here is deterministic: every run regenerates the vectors and
 * requires the committed file to equal them. After a change, regenerate:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-outbound-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { OUTBOUND_REFUSAL_LABELS, OUTBOUND_REFUSAL_MESSAGES, OUTBOUND_REFUSAL_REASONS, outboundRefusalMessage, OUTBOUND_REFUSED_GENERIC, OUTBOUND_HOST_NOTE } from "@varlatch/protocol";
import {
  allowListWarnings,
  classifyAddress,
  decide,
  destinationOf,
  OutboundAllowError,
  parseOutboundAllow,
  type AllowEntry,
} from "../src/net/outbound.js";

const FILE = new URL("../../../go/server/outbound/testdata/ts-vectors.json", import.meta.url);

const ADDRESSES = [
  // IPv4: every class, the edges of each range.
  "0.0.0.0", "0.255.255.255", "1.0.0.0", "1.1.1.1", "8.8.8.8", "9.255.255.255",
  "10.0.0.0", "10.255.255.255", "11.0.0.0", "100.63.255.255", "100.64.0.0", "100.127.255.255", "100.128.0.0",
  "100.100.100.200", "100.100.100.201", "127.0.0.1", "127.255.255.255", "128.0.0.0",
  "168.63.129.16", "168.63.129.17", "169.254.0.0", "169.254.169.254", "169.254.255.255", "169.255.0.0",
  "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
  "192.0.0.0", "192.0.0.255", "192.0.1.0", "192.0.2.1", "192.0.3.0", "192.88.99.1", "192.167.255.255", "192.168.0.1", "192.168.255.255", "192.169.0.0",
  "198.17.255.255", "198.18.0.0", "198.19.255.255", "198.20.0.0", "198.51.100.7", "203.0.113.9",
  "223.255.255.255", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
  // IPv6.
  "::", "::1", "::2", "2001:4860:4860::8888", "2606:4700:4700::1111", "fe80::1", "fe80::1%eth0", "febf:ffff::1", "fec0::1", "feff::1",
  "fc00::1", "fd12:3456::1", "fdff:ffff::1", "ff02::1", "ff00::", "100::1", "100::ffff:ffff:ffff:ffff", "100:0:0:1::",
  "2001::1", "2001:1ff:ffff::1", "2001:200::1", "2002::1", "2002:c0a8:101::1", "2001:db8::1", "3fff::1", "3fff:fff::1", "4000::1", "5f00::1",
  "64:ff9b::1.2.3.4", "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1", "64:ff9b:2::1",
  "fd00:ec2::254", "fd00:ec2::255",
  // IPv4-mapped and IPv4-compatible.
  "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "::ffff:7f00:1", "::ffff:169.254.169.254", "::ffff:0.0.0.0",
  "::127.0.0.1", "::10.0.0.1", "::8.8.8.8", "::0.0.0.1", "::0.0.0.2",
  // Spellings.
  "[::1]", "[2001:db8::1]", "FE80::1", "::FFFF:127.0.0.1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001",
  "2001:0db8:0000:0000:0000:0000:0000:0001",
  // Not addresses.
  "", "localhost", "example.com", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.04", "0x7f.0.0.1", "127.1", "::g", "1::2::3", "[1.2.3.4]", " 1.2.3.4", "1.2.3.4 ",
];

const ALLOW_SPECS = [
  "", " ", ",", "example.com", "Example.COM.", "*.example.com", "*.example.com:8443", "example.com:*", "example.com:443", "example.com:0", "example.com:65536",
  "example.com:-1", "example.com:08", "example.com:00443", "example.com:abc", "*.com", "*", "*.", "a..b", "-a.com", "a-.com", "1.2.3.4", "1.2.3.4:8080", "1.2.3.4:*",
  "10.0.0.0/8", "10.1.2.3/8", "10.0.0.0/8:443", "10.0.0.0/33", "10.0.0.0/08", "0.0.0.0/0", "::/0", "127.0.0.1/32", "127.0.0.0/8", "127.0.0.0/7", "169.254.169.254/32",
  "::1", "[::1]", "[::1]:8080", "[::1/128]", "[::1/128]:*", "::1/128", "::1/128:*", "fe80::/10", "[fe80::1%eth0]", "fe80::1%eth0", "::ffff:10.0.0.1", "::ffff:10.0.0.1/104",
  "[::ffff:10.0.0.1]", "224.0.0.0/4", "240.0.0.0/4:443", "localhost", "LOCALHOST", "my-host", "a.b.c.d.e", "999.1.1.1", "1.2.3.4/abc", "[1.2.3.4]", "host_name",
  "example.com,10.0.0.0/8, 192.168.1.10:8080 , *.corp.example", "1.2.3", "1.2.3.4.5", "x".repeat(64) + ".com", ("a".repeat(63) + ".").repeat(4) + "com",
  "xn--bcher-kva.example", "a:b:c", "[::1]:", "[::1]:x", "example.com:", "100.64.0.0/10", "fc00::/7", "[fd00::/8]:443",
];

function entryVector(e: AllowEntry): Record<string, unknown> {
  if (e.kind === "name") return { kind: "name", text: e.text, name: e.name, wildcard: e.wildcard, port: e.port };
  return { kind: "cidr", text: e.text, base: e.range.base.toString(16), family: e.range.family, prefix: e.range.prefix, port: e.port, hostOnly: e.hostOnly };
}

function parseVector(spec: string): Record<string, unknown> {
  try {
    const entries = parseOutboundAllow(spec);
    return { spec, entries: entries.map(entryVector), warnings: allowListWarnings(entries) };
  } catch (err) {
    if (!(err instanceof OutboundAllowError)) throw err;
    return { spec, error: err.message };
  }
}

/** Destinations and their answers, against one allow list each. */
const DECISIONS: { allow: string; url: string; addresses: string[] }[] = [];
{
  const lists = [
    "",
    "example.internal",
    "example.internal:8443",
    "*.corp.example",
    "10.0.0.0/8",
    "10.0.0.5/32:8080",
    "127.0.0.1/32",
    "127.0.0.0/7",
    "[::1/128]:*",
    "169.254.169.254/32",
    "0.0.0.0/0",
    "hooks.example.com:*,10.0.0.0/8:443",
    "plain.example",
    "::ffff:10.0.0.1",
    "100.64.0.0/10,fc00::/7",
  ];
  const cases: [string, string[]][] = [
    ["https://hooks.example.com/x", ["93.184.216.34"]],
    ["https://hooks.example.com/x", ["93.184.216.34", "2606:2800:220:1::1"]],
    ["https://hooks.example.com/x", ["93.184.216.34", "10.0.0.1"]],
    ["https://hooks.example.com/x", ["10.0.0.1"]],
    ["https://hooks.example.com/x", ["127.0.0.1"]],
    ["https://hooks.example.com/x", ["169.254.169.254"]],
    ["https://hooks.example.com/x", ["0.0.0.0"]],
    ["https://hooks.example.com/x", ["224.0.0.1", "10.0.0.1"]],
    ["https://hooks.example.com/x", ["127.0.0.1", "10.0.0.1"]],
    ["https://hooks.example.com/x", ["10.0.0.1", "192.168.1.1"]],
    ["https://hooks.example.com/x", ["not-an-address"]],
    ["https://hooks.example.com/x", []],
    ["https://hooks.example.com:8443/x", ["10.0.0.1"]],
    ["https://hooks.example.com:8443/x", ["93.184.216.34"]],
    ["http://hooks.example.com/x", ["93.184.216.34"]],
    ["http://hooks.example.com:8080/x", ["10.0.0.5"]],
    ["https://example.internal/x", ["10.0.0.1"]],
    ["https://example.internal:8443/x", ["10.0.0.1"]],
    ["https://example.internal./x", ["10.0.0.1"]],
    ["https://EXAMPLE.internal/x", ["10.0.0.1"]],
    ["https://example.internal/x", ["127.0.0.1"]],
    ["https://example.internal/x", ["93.184.216.34"]],
    ["http://example.internal/x", ["10.0.0.1"]],
    ["http://example.internal/x", ["93.184.216.34"]],
    ["https://a.corp.example/x", ["10.1.2.3"]],
    ["https://corp.example/x", ["10.1.2.3"]],
    ["https://a.b.corp.example/x", ["192.168.0.1"]],
    ["https://10.0.0.5/x", ["10.0.0.5"]],
    ["https://10.0.0.5:8080/x", ["10.0.0.5"]],
    ["http://10.0.0.5:8080/x", ["10.0.0.5"]],
    ["https://127.0.0.1/x", ["127.0.0.1"]],
    ["https://127.0.0.1:8443/x", ["127.0.0.1"]],
    ["http://127.0.0.1:8080/x", ["127.0.0.1"]],
    ["https://[::1]:9000/x", ["::1"]],
    ["https://[::ffff:127.0.0.1]/x", ["::ffff:127.0.0.1"]],
    ["https://[::ffff:10.0.0.1]/x", ["::ffff:10.0.0.1"]],
    ["https://169.254.169.254/latest", ["169.254.169.254"]],
    ["https://[64:ff9b::a9fe:a9fe]/x", ["64:ff9b::a9fe:a9fe"]],
    ["https://[fe80::1]/x", ["fe80::1"]],
    ["https://[fd12::1]/x", ["fd12::1"]],
    ["https://100.100.1.1/x", ["100.100.1.1"]],
    ["https://plain.example/x", ["93.184.216.34"]],
    ["http://plain.example/x", ["93.184.216.34"]],
    ["http://plain.example:8080/x", ["93.184.216.34"]],
    ["https://255.255.255.255/x", ["255.255.255.255"]],
    ["https://8.8.8.8/x", ["8.8.8.8"]],
    ["http://8.8.8.8/x", ["8.8.8.8"]],
  ];
  for (const allow of lists) for (const [url, addresses] of cases) DECISIONS.push({ allow, url, addresses });
}

function makeVectors() {
  return {
    comment:
      "The TypeScript server's outbound policy (net/outbound.ts) on these inputs; written by services/varlatchd/test/go-outbound-vectors.test.ts. Do not edit.",
    classes: ADDRESSES.map((address) => {
      try {
        return { address, class: classifyAddress(address) };
      } catch {
        return { address, class: null };
      }
    }),
    allow: ALLOW_SPECS.map(parseVector),
    decisions: DECISIONS.map(({ allow, url, addresses }) => {
      const destination = destinationOf(new URL(url));
      if (!destination) throw new Error(url);
      return { allow, url, destination, addresses, verdict: decide(parseOutboundAllow(allow), destination, addresses) };
    }),
    messages: OUTBOUND_REFUSAL_REASONS.map((reason) => ({
      reason,
      sentence: OUTBOUND_REFUSAL_MESSAGES[reason],
      label: OUTBOUND_REFUSAL_LABELS[reason],
      message: outboundRefusalMessage(reason),
    })),
    generic: OUTBOUND_REFUSED_GENERIC,
    hostNote: OUTBOUND_HOST_NOTE,
  };
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the outbound vectors", () => {
  it("writes ts-vectors.json", () => {
    writeFileSync(FILE, JSON.stringify(makeVectors(), null, 2) + "\n");
  });
});

describe("the outbound vectors are this server's", () => {
  it("ts-vectors.json equals what net/outbound.ts gives now", () => {
    expect(JSON.parse(readFileSync(FILE, "utf8"))).toEqual(JSON.parse(JSON.stringify(makeVectors())));
  });
});
