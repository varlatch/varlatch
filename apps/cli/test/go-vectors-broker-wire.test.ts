// SPDX-License-Identifier: Apache-2.0
import net from "node:net";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { startBroker, TUNNELS_PATH } from "../src/broker.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's Broker on the Agent's side of the wire (internal
 * docs/design/go-cli.md, slice 5.5a): a raw request, as bytes on a new
 * connection to a new Broker, and every byte the Broker answered before it
 * closed the connection (or 1.5 seconds passed), recorded from broker.ts
 * and Node.js's HTTP parser. The Go Broker is held to the same bytes but
 * for its documented differences (go/README.md). Date is written {{date}},
 * the proxy credential {{token}}, and a network error's text {{network}}
 * (its chunk's size {{size}}).
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-broker-wire.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/broker-wire.json", import.meta.url));

/** A destination nothing listens on: forwarding to it fails at once. */
const CLOSED = "127.0.0.1:9";

interface Case {
  name: string;
  /** The request; {{auth}} is a valid Proxy-Authorization header line, {{token}} the credential. */
  raw: string;
  strict?: boolean;
}

const T = TUNNELS_PATH;
const A = "{{auth}}";

function cases(): Case[] {
  const chunked = (body: string) => `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n${A}\r\n\r\n${body}`;
  return [
    { name: "tunnels", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "tunnels.http10", raw: `GET ${T} HTTP/1.0\r\n${A}\r\n\r\n` },
    { name: "tunnels.post", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n${A}\r\n\r\n` },
    { name: "auth.none", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\n\r\n` },
    { name: "auth.wrong", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic eDp5\r\n\r\n` },
    { name: "auth.lower-basic", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nproxy-authorization: basic {{basic}}\r\n\r\n` },
    { name: "auth.twice", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\nProxy-Authorization: Basic eDp5\r\n\r\n` },
    { name: "auth.wrong-first", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic eDp5\r\n${A}\r\n\r\n` },
    { name: "auth.two-spaces", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic  {{basic}}\r\n\r\n` },
    { name: "auth.bearer", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Bearer {{basic}}\r\n\r\n` },
    { name: "auth.other-user", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic {{other-user}}\r\n\r\n` },
    { name: "auth.none-before-body", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello` },
    { name: "parse.obs-fold", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n${A}\r\n\r\n` },
    { name: "parse.bare-lf", raw: `GET ${T} HTTP/1.1\nHost: x\n${A}\n\n` },
    { name: "parse.bare-lf-mixed", raw: `GET ${T} HTTP/1.1\r\nHost: x\n${A}\r\n\r\n` },
    { name: "parse.bare-cr", raw: `GET ${T} HTTP/1.1\r\nHost: x\rX: y\r\n${A}\r\n\r\n` },
    { name: "parse.cl-te", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n${A}\r\n\r\n0\r\n\r\n` },
    { name: "parse.cl-twice", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\n${A}\r\n\r\nabc` },
    { name: "parse.cl-differ", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n${A}\r\n\r\nabcd` },
    { name: "parse.cl-list", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 3, 3\r\n${A}\r\n\r\nabc` },
    { name: "parse.cl-sign", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: +3\r\n${A}\r\n\r\nabc` },
    { name: "parse.te-twice", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n${A}\r\n\r\n0\r\n\r\n` },
    { name: "parse.te-gzip", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n${A}\r\n\r\n` },
    { name: "parse.name-space", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX A: b\r\n${A}\r\n\r\n` },
    { name: "parse.space-before-colon", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A : b\r\n${A}\r\n\r\n` },
    { name: "parse.nul-value", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: a\u0000b\r\n${A}\r\n\r\n` },
    { name: "parse.ctl-value", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: a\u0001b\r\n${A}\r\n\r\n` },
    { name: "parse.del-value", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: a\u007fb\r\n${A}\r\n\r\n` },
    { name: "parse.tab-value", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: a\tb\r\n${A}\r\n\r\n` },
    { name: "parse.latin1-value", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: aé\r\n${A}\r\n\r\n` },
    { name: "parse.no-colon", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A\r\n${A}\r\n\r\n` },
    { name: "parse.leading-space", raw: `GET ${T} HTTP/1.1\r\n Host: x\r\n${A}\r\n\r\n` },
    { name: "parse.bad-method", raw: `G@T ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.lower-method", raw: `get ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.custom-method", raw: `FOO ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.space-in-target", raw: `GET /a b HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.two-spaces", raw: `GET  ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.no-version", raw: `GET ${T}\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "parse.http2-line", raw: `GET ${T} HTTP/2.0\r\n${A}\r\n\r\n` },
    { name: "parse.no-host", raw: `GET ${T} HTTP/1.1\r\n${A}\r\n\r\n` },
    { name: "parse.two-hosts", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nHost: y\r\n${A}\r\n\r\n` },
    { name: "parse.leading-crlf", raw: `\r\nGET ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "size.header-over", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: ${"a".repeat(17000)}\r\n${A}\r\n\r\n` },
    { name: "size.header-under", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\nX-A: ${"a".repeat(15000)}\r\n${A}\r\n\r\n` },
    { name: "size.line-over", raw: `GET /${"a".repeat(17000)} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "size.many-headers", raw: `GET ${T} HTTP/1.1\r\nHost: x\r\n${Array.from({ length: 2100 }, (_, i) => `X${i}: 1\r\n`).join("")}${A}\r\n\r\n` },
    { name: "size.body-declared-over", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: ${2 * 1024 * 1024 + 1}\r\n${A}\r\n\r\n` },
    { name: "size.body-chunked-over", raw: chunked(`200001\r\n${"a".repeat(2 * 1024 * 1024 + 1)}\r\n0\r\n\r\n`) },
    { name: "chunk.ok", raw: chunked("3\r\nabc\r\n0\r\n\r\n") },
    { name: "chunk.extension", raw: chunked("3;a=b\r\nabc\r\n0\r\n\r\n") },
    { name: "chunk.bad-size", raw: chunked("zz\r\nabc\r\n0\r\n\r\n") },
    { name: "chunk.no-crlf", raw: chunked("3\r\nabcX0\r\n\r\n") },
    { name: "chunk.trailer", raw: chunked("3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n") },
    { name: "route.origin-form", raw: `GET /other HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "route.ftp", raw: `GET ftp://x/ HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "route.strict", raw: `GET http://elsewhere.example/ HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n`, strict: true },
    { name: "route.strict-port", raw: `GET http://api.example.com:8443/ HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n`, strict: true },
    { name: "route.substitute-http", raw: `GET http://api.example.com:443/ HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {{placeholder}}\r\n${A}\r\n\r\n` },
    { name: "route.blocked", raw: `GET https://api.example.com/ HTTP/1.1\r\nHost: x\r\nX-Debug: {{placeholder}}\r\n${A}\r\n\r\n` },
    { name: "connect.no-auth", raw: `CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n` },
    { name: "connect.allowlisted", raw: `CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n${A}\r\n\r\n` },
    { name: "connect.allowlisted-upper", raw: `CONNECT API.Example.COM:443 HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "connect.strict", raw: `CONNECT elsewhere.example:443 HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n`, strict: true },
    { name: "connect.then-tunnels", raw: `CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n` },
    { name: "expect.continue", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nExpect: 100-continue\r\n${A}\r\n\r\n` },
    { name: "expect.other", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nExpect: something\r\n${A}\r\n\r\n` },
    { name: "expect.continue-no-auth", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n` },
    { name: "expect.other-no-auth", raw: `POST ${T} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nExpect: something\r\n\r\n` },
    { name: "size.cl-16-digits", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 1234567890123456\r\n${A}\r\n\r\n` },
    { name: "size.cl-20-digits", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n${A}\r\n\r\n` },
    { name: "size.cl-overflow", raw: `POST http://${CLOSED}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551616\r\n${A}\r\n\r\n` },
  ];
}

const PLACEHOLDER = `vlch_ph_v1_${"a".repeat(32)}`;

async function send(port: number, raw: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    const out: Buffer[] = [];
    const done = () => resolve(Buffer.concat(out));
    s.on("data", (d: Buffer) => out.push(d));
    s.on("error", done);
    s.on("close", done);
    s.write(raw);
    setTimeout(() => {
      s.destroy();
      done();
    }, 1500);
  });
}

async function record(k: Case) {
  const b = await startBroker({
    placeholders: new Map([[PLACEHOLDER, "API_KEY"]]),
    destinations: ["api.example.com:443", CLOSED],
    targets: { API_KEY: ["header:authorization"] },
    strict: k.strict ?? false,
    exercise: async () => {
      throw new Error("not exercised in these vectors");
    },
  });
  try {
    const basic = Buffer.from(`vlt:${b.token}`).toString("base64");
    const fill = (s: string) =>
      s
        .replaceAll("{{auth}}", `Proxy-Authorization: Basic ${basic}`)
        .replaceAll("{{basic}}", basic)
        .replaceAll("{{other-user}}", Buffer.from(`varlatch:${b.token}`).toString("base64"))
        .replaceAll("{{placeholder}}", PLACEHOLDER);
    // This case's request is a CONNECT; the reply recorded is the tunnels
    // route's on a new connection after it.
    let request = k.raw;
    if (k.name === "connect.then-tunnels") {
      await send(b.port, Buffer.from(fill(k.raw), "latin1"));
      request = `GET ${T} HTTP/1.1\r\nHost: x\r\n${A}\r\n\r\n`;
    }
    const reply = (await send(b.port, Buffer.from(fill(request), "latin1"))).toString("latin1");
    const normalized = reply
      .replace(/\r\nDate: [^\r]*\r\n/g, "\r\nDate: {{date}}\r\n")
      .replaceAll(b.token, "{{token}}")
      .replace(/[0-9a-f]+\r\nvarlatch-broker: (?:connect|getaddrinfo|read|write) [^\n]*\n/g, "{{size}}\r\nvarlatch-broker: {{network}}\n");
    return { name: k.name, raw: k.raw, ...(k.strict ? { strict: true } : {}), reply: normalized };
  } finally {
    await b.close();
  }
}

describe("Broker wire vectors (slice 5.5a)", () => {
  it("are recorded from broker.ts and Node.js's HTTP parser", async () => {
    const list = cases();
    expect(new Set(list.map((k) => k.name)).size).toBe(list.length);
    const recorded = [];
    for (const k of list) recorded.push(await record(k));
    const text = `{"comment":"Generated by apps/cli/test/go-vectors-broker-wire.test.ts from broker.ts and Node.js; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.","placeholder":${JSON.stringify(PLACEHOLDER)},"closed":${JSON.stringify(CLOSED)},\n"cases":[\n${recorded.map((k) => JSON.stringify(k)).join(",\n")}\n]}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "broker-wire.json is stale: regenerate it (see this file's comment)").toBe(true);
  }, 300_000);
});
