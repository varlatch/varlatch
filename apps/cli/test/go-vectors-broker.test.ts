// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startBroker, type BrokerEvent } from "../src/broker.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Scenario vectors for the Go CLI's Broker (internal docs/design/go-cli.md,
 * slice 5.5a; ADR-0039 tests 11 to 37 through the proxy), recorded from
 * broker.ts and scrub.ts: a Broker set up as the scenario says, a TLS
 * destination that answers with a script (raw bytes, pauses, a clean end
 * or a reset, a generated decompression bomb), and the Agent's request.
 * What is recorded:
 *
 * - the request the destination received: method, path, headers (names
 *   lower-cased, as a sorted list: the order and spelling on that
 *   connection are each Broker's own), body;
 * - the Agent's response, parsed: status, reason phrase, headers but those
 *   that frame the connection (Date, Connection, Keep-Alive,
 *   Transfer-Encoding), body, and whether it ended as framed (a missing
 *   terminating chunk is an abort);
 * - the Broker's events, and the values it holds afterwards.
 *
 * {{port}} is the destination's port (in the request and in what is
 * recorded, where a Content-Length counts its digits as {{port}}), {{auth}} a valid Proxy-Authorization
 * line, {{ph:ITEM}} the item's Placeholder. Every value is a test fixture's.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-broker.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/broker.json", import.meta.url));

const SECRET = "scrubvalueaaaaaaaaaaaaaa";
const OLD = "fx_live_retiring_value_0";
const DB = 'hunter2/db"pass word';
const PH: Record<string, string> = { API_KEY: `vlch_ph_v1_${"a".repeat(32)}`, DB_PASSWORD: `vlch_ph_v1_${"b".repeat(32)}`, OTHER: `vlch_ph_v1_${"d".repeat(32)}` };

type Step = { write: string } | { writeB64: string } | { fill: string; bytes: number } | { pause: number } | { end: true } | { reset: true } | { bomb: "gzip" | "deflate" | "br"; bytes: number; head: string };

interface Scenario {
  name: string;
  targets?: Record<string, string[]>;
  values?: Record<string, string>;
  exercise?: { targets?: Record<string, string[]>; withheld?: string[]; retiring?: Record<string, string>; values?: Record<string, string>; error?: { code?: string; message: string } };
  strict?: boolean;
  limits?: { maxDecodedBytes?: number; idleMs?: number; bufferedBytes?: number };
  request: string;
  upstream: Step[];
  /** Milliseconds the Agent waits for the whole response. */
  wait?: number;
  /** The Agent goes away this many milliseconds after sending. */
  agentLeavesAfter?: number;
}

const TARGETS = { API_KEY: ["header:authorization"], DB_PASSWORD: ["header:x-db"] };
const ok = (headers: string[], body: string) => `HTTP/1.1 200 OK\r\n${headers.map((h) => `${h}\r\n`).join("")}\r\n${body}`;
const get = (extra = "", path = "/v1/x") => `GET https://127.0.0.1:{{port}}${path} HTTP/1.1\r\nHost: x\r\n{{auth}}\r\nAuthorization: Bearer {{ph:API_KEY}}\r\n${extra}\r\n`;
const gz = (s: string, coding: "gzip" | "deflate" | "br") =>
  (coding === "gzip" ? zlib.gzipSync(s) : coding === "deflate" ? zlib.deflateSync(s) : zlib.brotliCompressSync(s)).toString("base64");

function scenarios(): Scenario[] {
  const list: Scenario[] = [
    // Substitution (tests 11 to 15 through the proxy)
    { name: "substitute.header", request: get(), upstream: [{ write: ok(["Content-Length: 2", "Content-Type: text/plain"], "ok") }, { end: true }] },
    { name: "substitute.two-items", request: get("X-Db: {{ph:DB_PASSWORD}}\r\n"), upstream: [{ write: ok(["Content-Length: 2"], "ok") }, { end: true }] },
    {
      name: "substitute.query",
      targets: { API_KEY: ["query:key"] },
      request: `GET https://127.0.0.1:{{port}}/v1/x?a=1&key={{ph:API_KEY}} HTTP/1.1\r\nHost: x\r\n{{auth}}\r\n\r\n`,
      values: { API_KEY: "s k/&=~é" },
      upstream: [{ write: ok(["Content-Length: 2"], "ok") }, { end: true }],
    },
    {
      name: "substitute.json",
      targets: { API_KEY: ["json:/auth/key"] },
      request: `POST https://127.0.0.1:{{port}}/v1/x HTTP/1.1\r\nHost: x\r\n{{auth}}\r\nContent-Type: application/json\r\nContent-Length: 63\r\n\r\n{ "a" : 1.50, "auth": {"key": "{{ph:API_KEY}}"} }`,
      values: { API_KEY: 'q"u\\o\nte</' },
      upstream: [{ write: ok(["Content-Length: 2"], "ok") }, { end: true }],
    },
    { name: "substitute.range-dropped", request: get("Range: bytes=0-10\r\nIf-Range: x\r\nAccept-Encoding: gzip, br\r\n"), upstream: [{ write: ok(["Content-Length: 2"], "ok") }, { end: true }] },
    { name: "substitute.stray", request: `POST https://127.0.0.1:{{port}}/v1/x HTTP/1.1\r\nHost: x\r\n{{auth}}\r\nAuthorization: Bearer {{ph:API_KEY}}\r\nContent-Type: text/plain\r\nContent-Length: 48\r\n\r\nlog: {{ph:API_KEY}}`, upstream: [{ write: ok(["Content-Length: 2"], "ok") }, { end: true }] },
    { name: "block.outside-target", request: get("X-Debug: {{ph:API_KEY}}\r\n"), upstream: [] },
    { name: "pass.no-placeholder", request: `GET https://127.0.0.1:{{port}}/v1/plain?q=1 HTTP/1.1\r\nHost: x\r\n{{auth}}\r\nAccept-Encoding: gzip\r\n\r\n`, upstream: [{ write: ok(["Content-Length: 5", "Content-Type: text/plain"], "plain") }, { end: true }] },
    { name: "pass.other-destination", request: `GET https://localhost:{{port}}/v1/plain HTTP/1.1\r\nHost: x\r\n{{auth}}\r\nAuthorization: Bearer {{ph:API_KEY}}\r\n\r\n`, upstream: [{ write: ok(["Content-Length: 5"], "plain") }, { end: true }] },
    { name: "strict.other-destination", strict: true, request: `GET https://localhost:{{port}}/ HTTP/1.1\r\nHost: x\r\n{{auth}}\r\n\r\n`, upstream: [] },
    // After exercise (test 17)
    { name: "after.unsafe-header", values: { API_KEY: "a\r\nX-Injected: 1" }, request: get(), upstream: [] },
    { name: "after.targets-differ", exercise: { targets: { API_KEY: ["header:x-other"], DB_PASSWORD: ["header:x-db"] } }, request: get(), upstream: [] },
    { name: "after.withheld", exercise: { withheld: ["API_KEY"], values: {} }, request: get(), upstream: [] },
    { name: "after.extra-item", exercise: { values: { API_KEY: SECRET, DB_PASSWORD: DB } }, request: get(), upstream: [] },
    { name: "exercise.maintenance", exercise: { error: { code: "MAINTENANCE", message: "maintenance" } }, request: get(), upstream: [] },
    { name: "exercise.error", exercise: { error: { message: "the Capability expired" } }, request: get(), upstream: [] },
    // Buffered responses (test 22)
    { name: "buffered.no-match", request: get(), upstream: [{ write: `HTTP/1.1 201 Created\r\nContent-Length: 5\r\nEtag: "x"\r\nX-A: 1\r\n\r\nhello` }, { end: true }] },
    { name: "buffered.match", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Length: ${`got ${SECRET}!`.length}\r\nEtag: "x"\r\nDigest: sha-256=x\r\nContent-Type: text/plain\r\n\r\ngot ${SECRET}!` }, { end: true }] },
    { name: "buffered.closed-early", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort` }, { end: true }] },
    { name: "buffered.incomplete-prefix", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nend scrubvalu` }, { end: true }] },
    // Streaming responses (test 23)
    ...(["gzip", "deflate", "br"] as const).map((coding) => ({
      name: `stream.${coding}`,
      request: get(),
      upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Encoding: ${coding}\r\nContent-Length: ${Buffer.from(gz(`a ${SECRET} b ${SECRET}`, coding), "base64").length}\r\nAccept-Ranges: bytes\r\n\r\n` }, { writeB64: gz(`a ${SECRET} b ${SECRET}`, coding) }, { end: true } as Step],
    })),
    { name: "stream.close-delimited", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npart one ${SECRET.slice(0, 10)}` }, { pause: 100 }, { write: `${SECRET.slice(10)} part two` }, { end: true }] },
    { name: "stream.chunked", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n${(SECRET.length + 1).toString(16)}\r\n ${SECRET}\r\n0\r\n\r\n` }, { end: true }] },
    { name: "stream.large-identity", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Length: ${3 * 1024 * 1024}\r\n\r\n` }, { fill: "x", bytes: 3 * 1024 * 1024 - SECRET.length }, { write: SECRET }, { end: true }] },
    // Codings the Broker cannot inspect (test 24)
    ...["compress", "gzip, br", "zstd"].map((coding) => ({
      name: `coding.${coding.replace(/[^a-z]+/g, "-")}`,
      request: get(),
      upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Encoding: ${coding}\r\nContent-Length: 2\r\n\r\nxx` }, { end: true } as Step],
    })),
    // Limits (tests 25 and 26)
    { name: "limit.decoded-exact", limits: { maxDecodedBytes: 4096 }, request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\n${"y".repeat(4096)}` }, { end: true }] },
    { name: "limit.decoded-over", limits: { maxDecodedBytes: 4096 }, request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\n${"y".repeat(4097)}` }, { end: true }] },
    ...(["gzip", "deflate", "br"] as const).map((coding) => ({
      name: `limit.bomb-${coding}`,
      request: get(),
      upstream: [{ bomb: coding, bytes: 80 * 1024 * 1024, head: `HTTP/1.1 200 OK\r\nContent-Encoding: ${coding}\r\n\r\n` } as Step, { end: true } as Step],
      wait: 20000,
    })),
    { name: "limit.idle-before-headers", limits: { idleMs: 300 }, request: get(), upstream: [{ pause: 1200 }], wait: 3000 },
    { name: "limit.idle-after-headers", limits: { idleMs: 300 }, request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\nstart` }, { pause: 1200 }, { write: "late" }], wait: 3000 },
    { name: "limit.gap-under", limits: { idleMs: 800 }, request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\nstart` }, { pause: 300 }, { write: " end" }, { end: true }], wait: 3000 },
    { name: "abort.reset-mid-stream", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\nstart ${SECRET.slice(0, 8)}` }, { pause: 100 }, { reset: true }] },
    { name: "abort.corrupt-gzip", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nnot gzip at all` }, { end: true }] },
    { name: "abort.agent-leaves", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\nstart` }, { pause: 1500 }, { write: "more" }], agentLeavesAfter: 400, wait: 2500 },
    { name: "hold.prefix-then-pause", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\nvalue: ${SECRET.slice(0, 12)}` }, { pause: 600 }, { write: `${SECRET.slice(12)} done` }, { end: true }], wait: 3000 },
    { name: "hold.clean-end-prefix", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\n\r\ntail ${SECRET.slice(0, 15)}` }, { end: true }] },
    // Coverage (tests 29 and 30)
    { name: "cover.head", request: get().replace(/^GET/, "HEAD"), upstream: [{ write: `HTTP/1.1 200 OK\r\nX-Echo: ${SECRET}\r\nContent-Length: 10\r\n\r\n` }, { end: true }] },
    { name: "cover.204", request: get(), upstream: [{ write: `HTTP/1.1 204 No Content\r\nX-Echo: ${SECRET}\r\n\r\n` }, { end: true }] },
    { name: "cover.304", request: get(), upstream: [{ write: `HTTP/1.1 304 Not Modified\r\nX-Echo: ${SECRET}\r\n\r\n` }, { end: true }] },
    { name: "cover.location-cookie", request: get(), upstream: [{ write: `HTTP/1.1 302 Found\r\nLocation: https://x/?k=${SECRET}\r\nSet-Cookie: a=${SECRET}\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n` }, { end: true }] },
    { name: "cover.reason", request: get(), upstream: [{ write: `HTTP/1.1 401 bad key ${SECRET}\r\nContent-Length: 0\r\n\r\n` }, { end: true }] },
    { name: "cover.encodings", request: get(), upstream: [{ write: ok([], `json ${JSON.stringify(DB)} pct ${encodeURIComponent(SECRET + "/")} b64 ${Buffer.from(SECRET).toString("base64")} url ${Buffer.from(SECRET).toString("base64url")} basic ${Buffer.from(`u:${SECRET}`).toString("base64")}`) }, { end: true }], values: { API_KEY: SECRET, DB_PASSWORD: DB } },
    { name: "cover.limits-left", request: get(), upstream: [{ write: ok([], `hex ${Buffer.from(SECRET).toString("hex")} esc \\u0073crubvalueaaaaaaaaaaaaaa`) }, { end: true }] },
    { name: "cover.retiring", exercise: { retiring: { API_KEY: OLD } }, request: get(), upstream: [{ write: ok([], `old ${OLD} new ${SECRET}`) }, { end: true }] },
    { name: "cover.short", values: { API_KEY: "short" }, request: get(), upstream: [{ write: ok([], "a short value") }, { end: true }] },
    { name: "cover.upgrade", request: get("Connection: Upgrade\r\nUpgrade: websocket\r\n"), upstream: [{ write: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" }, { pause: 300 }, { end: true }] },
    { name: "cover.marker-stripped", request: get(), upstream: [{ write: `HTTP/1.1 200 OK\r\nvarlatch-broker: refused\r\nContent-Length: 2\r\n\r\nok` }, { end: true }] },
  ];
  // The Content-Length of an Agent body is filled in by length.
  return list.map((s) => ({ ...s, request: s.request }));
}

let certDir: string;
let key: Buffer;
let cert: Buffer;
const originalCa = https.globalAgent.options.ca;
beforeAll(() => {
  certDir = mkdtempSync(join(tmpdir(), "varlatch-broker-vectors-"));
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", join(certDir, "key"), "-out", join(certDir, "cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
    { stdio: "ignore" },
  );
  key = readFileSync(join(certDir, "key"));
  cert = readFileSync(join(certDir, "cert"));
  https.globalAgent.options.ca = cert;
});
afterAll(() => {
  https.globalAgent.options.ca = originalCa;
  rmSync(certDir, { recursive: true, force: true });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The scripted destination: it records the request, then plays its steps. */
async function destination(steps: Step[]) {
  const received: Buffer[] = [];
  let connections = 0;
  // TLS over a TCP server of its own: a reset is the TCP connection's.
  const server = net.createServer((rawSocket) => {
    rawSocket.on("error", () => {});
    const socket = new tls.TLSSocket(rawSocket, { isServer: true, key, cert });
    connections++;
    let buf = Buffer.alloc(0);
    let started = false;
    socket.on("error", () => {});
    socket.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      const end = buf.indexOf("\r\n\r\n");
      if (started || end < 0) return;
      const head = buf.subarray(0, end).toString("latin1");
      const length = Number(/\r\ncontent-length: *(\d+)/i.exec(head)?.[1] ?? 0);
      if (buf.length < end + 4 + length) return;
      started = true;
      received.push(buf.subarray(0, end + 4 + length));
      void (async () => {
        for (const step of steps) {
          if (socket.destroyed) return;
          if ("write" in step) socket.write(Buffer.from(step.write, "latin1"));
          else if ("writeB64" in step) socket.write(Buffer.from(step.writeB64, "base64"));
          else if ("fill" in step) socket.write(Buffer.alloc(step.bytes, step.fill));
          else if ("pause" in step) await sleep(step.pause);
          else if ("end" in step) socket.end();
          else if ("reset" in step) rawSocket.resetAndDestroy();
          else if ("bomb" in step) {
            socket.write(Buffer.from(step.head, "latin1"));
            const zeros = Buffer.alloc(step.bytes);
            const body = step.bomb === "gzip" ? zlib.gzipSync(zeros) : step.bomb === "deflate" ? zlib.deflateSync(zeros) : zlib.brotliCompressSync(zeros);
            socket.write(body);
          }
        }
      })();
    });
  });
  server.on("error", () => {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as net.AddressInfo).port, received, connections: () => connections, close: () => server.close() };
}

/** The request as the destination received it, order-free. */
function parseReceived(raw: Buffer | undefined) {
  if (!raw) return null;
  const end = raw.indexOf("\r\n\r\n");
  const [line = "", ...lines] = raw.subarray(0, end).toString("latin1").split("\r\n");
  const [method, path] = line.split(" ");
  const headers = lines.map((l) => {
    const colon = l.indexOf(":");
    return [l.slice(0, colon).toLowerCase(), l.slice(colon + 1).trim()];
  });
  headers.sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : a[1]! < b[1]! ? -1 : a[1]! > b[1]! ? 1 : 0));
  return { method, path, headers, bodyB64: raw.subarray(end + 4).toString("base64") };
}

const FRAMING = new Set(["date", "connection", "keep-alive", "transfer-encoding"]);

/** The Agent's response, parsed: framing headers left out, the body de-chunked, and whether it ended as framed. */
function parseAgent(raw: Buffer, method: string) {
  const end = raw.indexOf("\r\n\r\n");
  if (end < 0) return { incomplete: raw.toString("latin1") };
  const [line = "", ...lines] = raw.subarray(0, end).toString("latin1").split("\r\n");
  const m = /^HTTP\/1\.1 (\d{3}) ?(.*)$/.exec(line);
  const all = lines.map((l) => {
    const colon = l.indexOf(":");
    return [l.slice(0, colon).toLowerCase(), l.slice(colon + 1).trim()] as [string, string];
  });
  const headers = all.filter(([n]) => !FRAMING.has(n)).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  let rest = raw.subarray(end + 4);
  const status = Number(m?.[1]);
  const chunked = all.some(([n, v]) => n === "transfer-encoding" && v.toLowerCase() === "chunked");
  const length = all.find(([n]) => n === "content-length")?.[1];
  let body = Buffer.alloc(0);
  let complete: boolean;
  if (method === "HEAD" || status === 204 || status === 304 || status === 100) complete = rest.length === 0;
  else if (chunked) {
    complete = false;
    const parts: Buffer[] = [];
    for (;;) {
      const lineEnd = rest.indexOf("\r\n");
      if (lineEnd < 0) break;
      const size = Number.parseInt(rest.subarray(0, lineEnd).toString("latin1"), 16);
      if (Number.isNaN(size)) break;
      if (size === 0) {
        complete = rest.subarray(lineEnd).toString("latin1").startsWith("\r\n\r\n");
        break;
      }
      if (rest.length < lineEnd + 2 + size + 2) {
        parts.push(rest.subarray(lineEnd + 2));
        break;
      }
      parts.push(rest.subarray(lineEnd + 2, lineEnd + 2 + size));
      rest = rest.subarray(lineEnd + 2 + size + 2);
    }
    body = Buffer.concat(parts);
  } else if (length !== undefined) {
    body = rest.subarray(0, Number(length));
    complete = rest.length === Number(length);
  } else {
    body = rest;
    complete = true;
  }
  const content = body.length > 4096 ? { bodySha256: createHash("sha256").update(body).digest("hex") } : { bodyB64: body.toString("base64") };
  return { status, reason: m?.[2] ?? "", headers, ...content, bodyLength: body.length, complete };
}

async function agent(port: number, raw: Buffer, wait: number, leaveAfter?: number): Promise<Buffer> {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    const out: Buffer[] = [];
    const done = () => resolve(Buffer.concat(out));
    s.on("data", (d: Buffer) => out.push(d));
    s.on("error", done);
    s.on("close", done);
    s.write(raw);
    if (leaveAfter !== undefined) setTimeout(() => s.destroy(), leaveAfter);
    setTimeout(() => {
      s.destroy();
      done();
    }, wait);
  });
}

async function record(sc: Scenario) {
  const dest = await destination(sc.upstream);
  const events: BrokerEvent[] = [];
  const targets = sc.targets ?? TARGETS;
  const values = sc.values ?? { API_KEY: SECRET, DB_PASSWORD: DB };
  const placeholders = new Map(Object.entries(PH).map(([item, ph]) => [ph, item]));
  let exercises = 0;
  const b = await startBroker({
    placeholders,
    destinations: [`127.0.0.1:${dest.port}`],
    targets,
    strict: sc.strict ?? false,
    report: (e) => events.push(e),
    ...(sc.limits ? { limits: sc.limits } : {}),
    exercise: async (_d, placements) => {
      exercises++;
      if (sc.exercise?.error) throw Object.assign(new Error(sc.exercise.error.message), sc.exercise.error.code ? { code: sc.exercise.error.code } : {});
      const given = sc.exercise?.values ?? Object.fromEntries(placements.map((p) => [p.item, values[p.item]!]));
      return {
        values: new Map(Object.entries(given)),
        targets: sc.exercise?.targets ?? targets,
        ...(sc.exercise?.withheld ? { withheld: sc.exercise.withheld } : {}),
        ...(sc.exercise?.retiring ? { retiring: new Map(Object.entries(sc.exercise.retiring)) } : {}),
      };
    },
  });
  try {
    const basic = Buffer.from(`vlt:${b.token}`).toString("base64");
    let text = sc.request.replaceAll("{{port}}", String(dest.port)).replaceAll("{{auth}}", `Proxy-Authorization: Basic ${basic}`);
    for (const [item, ph] of Object.entries(PH)) text = text.replaceAll(`{{ph:${item}}}`, ph);
    // A body's declared length is its own.
    text = text.replace(/Content-Length: \d+\r\n\r\n([\s\S]*)$/, (_, body: string) => `Content-Length: ${Buffer.byteLength(body, "latin1")}\r\n\r\n${body}`);
    const raw = await agent(b.port, Buffer.from(text, "latin1"), sc.wait ?? 2000, sc.agentLeavesAfter);
    await sleep(50);
    // The destination's port is each run's own: written {{port}}.
    const port = String(dest.port);
    const unport = (v: string) => v.replaceAll(port, "{{port}}");
    const received = dest.received[0] ? Buffer.from(unport(dest.received[0].toString("latin1")), "latin1") : undefined;
    // Normalized once parsed (a chunk's size counts the port's digits).
    const parsed = sc.agentLeavesAfter === undefined ? parseAgent(raw, sc.request.split(" ")[0]!) : null;
    if (parsed && "headers" in parsed) {
      parsed.headers = parsed.headers.map(([n, v]) => [n, unport(v)] as [string, string]);
      parsed.reason = unport(parsed.reason);
      if (parsed.bodyB64 !== undefined) parsed.bodyB64 = Buffer.from(unport(Buffer.from(parsed.bodyB64, "base64").toString("latin1")), "latin1").toString("base64");
    }
    return {
      ...sc,
      expect: {
        destination: parseReceived(received),
        agent: parsed,
        events,
        exercises,
        held: b.heldValues(),
      },
    };
  } finally {
    await b.close();
    dest.close();
  }
}

describe("Broker scenario vectors (slice 5.5a)", () => {
  it("are recorded from broker.ts and scrub.ts", async () => {
    const list = scenarios();
    expect(new Set(list.map((s) => s.name)).size).toBe(list.length);
    const recorded = [];
    for (const s of list) recorded.push(await record(s));
    const text = `{"comment":"Generated by apps/cli/test/go-vectors-broker.test.ts from broker.ts and scrub.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.","placeholders":${JSON.stringify(PH)},"secret":${JSON.stringify(SECRET)},\n"scenarios":[\n${recorded.map((k) => JSON.stringify(k)).join(",\n")}\n]}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "broker.json is stale: regenerate it (see this file's comment)").toBe(true);
  }, 600_000);
});
