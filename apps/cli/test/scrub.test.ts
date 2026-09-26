// SPDX-License-Identifier: Apache-2.0
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { generatePlaceholder, startBroker, type BrokerEvent, type RunningBroker } from "../src/broker.js";
import { Scrubber, SCRUB_LIMITS, Watchdog, relayScrubbed, type ScrubLimits } from "../src/scrub.js";

// ADR-0039 acceptance tests 21 to 30, 36, and 37: response scrubbing through
// a live Broker, observed as raw bytes on the Agent's connection so that
// framing and the terminating chunk are visible.

const SECRET = "scrubvalueaaaaaaaaaaaaaa";
const OLD = "fx_live_retiring_value_0";
const DB = "hunter2/db\"pass word";
const PH = generatePlaceholder();
const PH_DB = generatePlaceholder();

let tls: { key: Buffer; cert: Buffer };
let certDir: string;
const originalCa = https.globalAgent.options.ca;
beforeAll(() => {
  certDir = mkdtempSync(join(tmpdir(), "varlatch-scrub-test-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", join(certDir, "key"), "-out", join(certDir, "cert"),
    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
  tls = { key: readFileSync(join(certDir, "key")), cert: readFileSync(join(certDir, "cert")) };
  https.globalAgent.options.ca = tls.cert;
});
afterAll(() => {
  https.globalAgent.options.ca = originalCa;
  rmSync(certDir, { recursive: true, force: true });
});

const cleanups: (() => unknown)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

/** A TLS upstream that records request headers and closes cleanly. */
async function upstream(handler: Handler) {
  const seen: http.IncomingHttpHeaders[] = [];
  let closed = 0;
  const server = https.createServer(tls, (req, res) => {
    seen.push(req.headers);
    req.on("close", () => closed++);
    req.resume();
    req.on("end", () => handler(req, res));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => {
    server.closeAllConnections();
    server.close();
  });
  return { port: (server.address() as AddressInfo).port, seen, closed: () => closed };
}

async function broker(port: number, opts: { limits?: Partial<ScrubLimits>; retiring?: boolean; short?: boolean } = {}) {
  const events: BrokerEvent[] = [];
  const targets = { API_KEY: ["header:authorization"], DB_PASSWORD: ["header:x-db"] };
  const b = await startBroker({
    placeholders: new Map([[PH, "API_KEY"], [PH_DB, "DB_PASSWORD"]]),
    destinations: [`127.0.0.1:${port}`],
    targets,
    report: (e) => events.push(e),
    ...(opts.limits ? { limits: opts.limits } : {}),
    exercise: async (_d, placements) => ({
      values: new Map(placements.map((p) => [p.item, p.item === "API_KEY" ? (opts.short ? "short" : SECRET) : DB] as [string, string])),
      targets,
      ...(opts.retiring ? { retiring: new Map([["API_KEY", OLD]]) } : {}),
    }),
  });
  cleanups.push(b.close);
  return { broker: b, events };
}

interface AgentResponse {
  status: number;
  headers: [string, string][];
  body: Buffer;
  /** A chunked body ended with its terminating chunk, or a length body arrived in full. */
  complete: boolean;
  chunked: boolean;
  raw: Buffer;
}

/** The Agent's side: a raw absolute-URI proxy request, read until the connection closes. */
function agent(
  b: RunningBroker,
  url: string,
  opts: { method?: string; headers?: [string, string][]; substitute?: boolean; onData?: (all: Buffer, socket: net.Socket) => void } = {},
): Promise<AgentResponse> {
  return new Promise((resolve) => {
    const socket = net.connect(b.port, "127.0.0.1");
    const parts: Buffer[] = [];
    const head = [
      `${opts.method ?? "GET"} ${url} HTTP/1.1`,
      `Host: ${new URL(url).host}`,
      `Proxy-Authorization: Basic ${Buffer.from(`vlt:${b.token}`).toString("base64")}`,
      ...(opts.substitute === false ? [] : [`Authorization: Bearer ${PH}`]),
      ...(opts.headers ?? []).map(([n, v]) => `${n}: ${v}`),
      "Connection: close",
    ];
    socket.write(`${head.join("\r\n")}\r\n\r\n`);
    // A response is over when it is complete (the pass-through relay may keep
    // the connection open) or when the connection closes (an aborted one).
    let received = 0;
    let framing: { chunked: boolean; length: number | null; bodyAt: number } | null = null;
    socket.on("data", (c: Buffer) => {
      parts.push(c);
      received += c.length;
      if (opts.onData) opts.onData(Buffer.concat(parts), socket);
      if (!framing) {
        const all = Buffer.concat(parts);
        const split = all.indexOf("\r\n\r\n");
        if (split < 0) return;
        const head = parse(all.subarray(0, split + 4), opts.method === "HEAD");
        const noBody = opts.method === "HEAD" || head.status === 204 || head.status === 304;
        const length = header(head, "content-length")[0];
        framing = { chunked: head.chunked, length: noBody ? 0 : length !== undefined ? Number(length) : null, bodyAt: split + 4 };
      }
      const tail = c.subarray(-5).toString("latin1");
      if ((framing.chunked && tail === "0\r\n\r\n") || (!framing.chunked && framing.length !== null && received - framing.bodyAt >= framing.length)) {
        socket.destroy();
      }
    });
    const done = () => resolve(parse(Buffer.concat(parts), opts.method === "HEAD"));
    socket.on("close", done);
    socket.on("error", () => {});
  });
}

function parse(raw: Buffer, head = false): AgentResponse {
  const split = raw.indexOf("\r\n\r\n");
  // No complete header block (an empty reply included) is never a complete response.
  if (split < 0) return { status: 0, headers: [], body: Buffer.alloc(0), complete: false, chunked: false, raw };
  const lines = raw.subarray(0, split).toString("latin1").split("\r\n");
  const status = Number(lines[0]?.split(" ")[1] ?? 0);
  const headers = lines.slice(1).map((l) => [l.slice(0, l.indexOf(":")), l.slice(l.indexOf(":") + 1).trim()] as [string, string]);
  const get = (n: string) => headers.find(([k]) => k.toLowerCase() === n)?.[1];
  const rest = raw.subarray(split + 4);
  const chunked = get("transfer-encoding")?.toLowerCase() === "chunked";
  if (head || status === 204 || status === 304) return { status, headers, body: rest, complete: true, chunked, raw };
  if (!chunked) {
    const length = Number(get("content-length") ?? rest.length);
    return { status, headers, body: rest.subarray(0, length), complete: rest.length >= length, chunked, raw };
  }
  const body: Buffer[] = [];
  let at = 0;
  let complete = false;
  for (;;) {
    const eol = rest.indexOf("\r\n", at);
    if (eol < 0) break;
    const size = Number.parseInt(rest.subarray(at, eol).toString(), 16);
    if (Number.isNaN(size)) break;
    if (size === 0) {
      complete = rest.subarray(eol, eol + 4).toString() === "\r\n\r\n";
      break;
    }
    body.push(rest.subarray(eol + 2, Math.min(eol + 2 + size, rest.length)));
    if (eol + 2 + size + 2 > rest.length) break;
    at = eol + 2 + size + 2;
  }
  return { status, headers, body: Buffer.concat(body), complete, chunked, raw };
}

const header = (r: AgentResponse, name: string) => r.headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
const secretForms = (value: string) => [
  value,
  JSON.stringify(value).slice(1, -1),
  encodeURIComponent(value),
  Buffer.from(value).toString("base64").slice(0, -4),
];

describe("request adjustments (test 21)", () => {
  it("a substituted request asks for identity content and never a range; an unsubstituted one is untouched", async () => {
    const up = await upstream((_req, res) => res.writeHead(200, { "Content-Type": "text/plain" }).end(`echo ${SECRET}`));
    const { broker: b } = await broker(up.port);
    const url = `https://127.0.0.1:${up.port}/x`;
    const adjust: [string, string][] = [["Accept-Encoding", "gzip, br"], ["Range", "bytes=0-3"], ["If-Range", '"v1"']];
    const scrubbed = await agent(b, url, { headers: adjust });
    expect(up.seen[0]).toMatchObject({ "accept-encoding": "identity" });
    expect(up.seen[0]!.range).toBeUndefined();
    expect(up.seen[0]!["if-range"]).toBeUndefined();
    expect(scrubbed.body.toString()).toBe(`echo ${PH}`);

    const plain = await agent(b, url, { headers: adjust, substitute: false });
    expect(up.seen[1]).toMatchObject({ "accept-encoding": "gzip, br", range: "bytes=0-3", "if-range": '"v1"' });
    // Responses to requests that carried no Secret are relayed unchanged (test 36's limit).
    expect(plain.body.toString()).toBe(`echo ${SECRET}`);
  });
});

describe("buffered responses (test 22)", () => {
  it("with no match, status, headers, and body are relayed exactly", async () => {
    const headers: [string, string][] = [["ETag", '"abc"'], ["X-Custom", "one"], ["x-custom", "two"], ["Content-Type", "application/json"]];
    const up = await upstream((_req, res) => res.writeHead(201, "Made", [...headers, ["Content-Length", "11"]].flat()).end('{"ok":true}'));
    const { broker: b } = await broker(up.port);
    const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
    expect(r.raw.subarray(0, 21).toString()).toBe("HTTP/1.1 201 Made\r\nET");
    for (const pair of headers) expect(r.headers).toContainEqual(pair);
    expect(header(r, "content-length")).toEqual(["11"]);
    expect(r.body.toString()).toBe('{"ok":true}');
  });

  it("with a match, Content-Length is recomputed and validators and digests are removed", async () => {
    const body = `{"key":"${SECRET}","n":1}`;
    const up = await upstream((_req, res) =>
      res
        .writeHead(200, {
          "Content-Type": "application/json",
          ETag: '"abc"',
          "Content-MD5": "x",
          Digest: "sha-256=x",
          "Content-Digest": "sha-256=:x:",
          "Repr-Digest": "sha-256=:x:",
          "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
          "Content-Length": String(body.length),
        })
        .end(body),
    );
    const { broker: b, events } = await broker(up.port);
    const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
    expect(r.body.toString()).toBe(`{"key":"${PH}","n":1}`);
    expect(header(r, "content-length")).toEqual([String(r.body.length)]);
    for (const gone of ["etag", "content-md5", "digest", "content-digest", "repr-digest"]) expect(header(r, gone)).toEqual([]);
    expect(header(r, "last-modified")).toHaveLength(1);
    expect(r.chunked).toBe(false);
    expect(events).toContainEqual({ kind: "scrubbed", item: "API_KEY", count: 1 });
    expect(b.heldValues()).toBe(0);
  });

  it("a scanner failure gives a fresh 502 with none of the original headers", async () => {
    // The relay itself, with a scrubber whose scan throws.
    class Failing extends Scrubber {
      override matcher(): ReturnType<Scrubber["matcher"]> {
        if (this.calls++ > 0) throw new Error("scan failed");
        return super.matcher();
      }
      calls = 0;
    }
    const up = await upstream((_req, res) =>
      res.writeHead(200, { "X-Upstream": "yes", "Content-Type": "text/plain", "Content-Length": "4" }).end("body"),
    );
    const front = http.createServer((_req, res) => {
      https.get(`https://127.0.0.1:${up.port}/`, (upstreamRes) => {
        const scrubber = new Failing([{ item: "API_KEY", value: SECRET }], () => Buffer.from(PH), () => {});
        scrubber.calls = 1;
        const watchdog = new Watchdog(5000, () => {});
        relayScrubbed({ method: "GET", upstream: upstreamRes, res, scrubber, limits: SCRUB_LIMITS, watchdog, report: () => {} }).catch((err) => {
          res.writeHead(502, { "Content-Type": "text/plain" }).end(`varlatch-broker: ${(err as Error).message}\n`);
        });
      });
    });
    await new Promise<void>((resolve) => front.listen(0, "127.0.0.1", resolve));
    cleanups.push(() => front.close());
    const res = await fetch(`http://127.0.0.1:${(front.address() as AddressInfo).port}/`);
    expect(res.status).toBe(502);
    expect(res.headers.get("x-upstream")).toBeNull();
    expect(await res.text()).toContain("could not be scanned");
  });
});

describe("streaming responses (test 23)", () => {
  const codings: [string, (b: Buffer) => Buffer][] = [
    ["gzip", (b) => zlib.gzipSync(b)],
    ["deflate", (b) => zlib.deflateSync(b)],
    ["br", (b) => zlib.brotliCompressSync(b)],
    ["", (b) => b],
  ];

  for (const [coding, encode] of codings) {
    it(`${coding || "identity without a length"}: decoded, scrubbed, and re-framed as chunked identity`, async () => {
      const content = Buffer.from(`${"x".repeat(5000)}${SECRET}${"y".repeat(5000)}é`);
      const wire = encode(content);
      const up = await upstream((_req, res) => {
        res.writeHead(200, {
          ...(coding ? { "Content-Encoding": coding } : {}),
          ETag: '"e"',
          "Accept-Ranges": "bytes",
          Digest: "sha-256=x",
          "Content-Type": "application/octet-stream",
        });
        // Split the coded bytes, so the secret crosses chunk boundaries.
        for (let at = 0; at < wire.length; at += 97) res.write(wire.subarray(at, at + 97));
        res.end();
      });
      const { broker: b } = await broker(up.port);
      const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
      expect(r.status).toBe(200);
      expect(r.chunked).toBe(true);
      expect(r.complete).toBe(true);
      for (const gone of ["content-length", "accept-ranges", "etag", "digest", "content-encoding"]) expect(header(r, gone)).toEqual([]);
      expect(r.body.toString()).toBe(content.toString().replace(SECRET, PH));
      expect(b.heldValues()).toBe(0);
    });
  }

  it("with no match, the decoded content is identical", async () => {
    const content = Buffer.from(Array.from({ length: 20000 }, (_, i) => String.fromCharCode(32 + (i % 90))).join(""));
    const up = await upstream((_req, res) => {
      res.writeHead(200, { "Content-Encoding": "gzip" });
      res.end(zlib.gzipSync(content));
    });
    const { broker: b } = await broker(up.port);
    const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
    expect(r.complete).toBe(true);
    expect(r.body.equals(content)).toBe(true);
  });

  it("decompression is linear: a highly compressed 48 MiB body streams through (B-SC5)", async () => {
    const wire = zlib.gzipSync(Buffer.alloc(48 * 1024 * 1024, 0x61));
    const up = await upstream((_req, res) => res.writeHead(200, { "Content-Encoding": "gzip" }).end(wire));
    const { broker: b } = await broker(up.port);
    const started = performance.now();
    const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
    expect(r.complete).toBe(true);
    expect(r.body.length).toBe(48 * 1024 * 1024);
    expect(performance.now() - started).toBeLessThan(20_000);
  }, 30_000);
});

describe("codings the Broker cannot inspect (test 24)", () => {
  for (const coding of ["x-gzip", "gzip, br", "zstd", "compress"]) {
    it(`${coding}: 502 before any header`, async () => {
      const up = await upstream((_req, res) => res.writeHead(200, { "Content-Encoding": coding, "X-Upstream": "yes" }).end("zzz"));
      const { broker: b } = await broker(up.port);
      const r = await agent(b, `https://127.0.0.1:${up.port}/x`);
      expect(r.status).toBe(502);
      expect(header(r, "x-upstream")).toEqual([]);
      expect(r.body.toString()).toContain("cannot be inspected");
    });
  }
});

describe("limits at their boundaries (tests 25 and 26)", () => {
  const MIB64 = 64 * 1024 * 1024;
  for (const [size, complete] of [[MIB64, true], [MIB64 + 1, false]] as const) {
    it(`${size === MIB64 ? "exactly" : "one byte over"} 64 MiB of decoded content ${complete ? "completes" : "aborts"}`, async () => {
      expect(SCRUB_LIMITS.maxDecodedBytes).toBe(MIB64);
      const block = Buffer.alloc(1024 * 1024, 0x62);
      const up = await upstream((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        let sent = 0;
        const pump = () => {
          while (sent < size) {
            const piece = block.subarray(0, Math.min(block.length, size - sent));
            sent += piece.length;
            if (!res.write(piece)) return void res.once("drain", pump);
          }
          res.end();
        };
        pump();
      });
      const { broker: b, events } = await broker(up.port);
      const r = await agent(b, `https://127.0.0.1:${up.port}/big`);
      expect(r.complete).toBe(complete);
      if (complete) expect(r.body.length).toBe(MIB64);
      else {
        expect(r.body.length).toBeLessThanOrEqual(MIB64);
        expect(events).toContainEqual({ kind: "aborted", reason: `the response exceeds ${MIB64} bytes of decoded content` });
      }
      expect(b.heldValues()).toBe(0);
    }, 60_000);
  }

  it("a gap under the idle timeout continues, one over it aborts, and one before headers is a 502", async () => {
    const limits = { idleMs: 400 };
    const paced = (gap: number) => (_req: http.IncomingMessage, res: http.ServerResponse) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write("first ");
      setTimeout(() => res.end("second"), gap);
    };
    const quick = await upstream(paced(150));
    const ok = await agent((await broker(quick.port, { limits })).broker, `https://127.0.0.1:${quick.port}/`);
    expect(ok.complete).toBe(true);
    expect(ok.body.toString()).toBe("first second");

    const slow = await upstream(paced(900));
    const cut = await broker(slow.port, { limits });
    const aborted = await agent(cut.broker, `https://127.0.0.1:${slow.port}/`);
    expect(aborted.status).toBe(200);
    expect(aborted.complete).toBe(false);
    expect(cut.events).toContainEqual({ kind: "aborted", reason: "no data from the destination for 0.4 seconds" });

    const late = await upstream((_req, res) => setTimeout(() => res.writeHead(200).end("late"), 900));
    const before = await agent((await broker(late.port, { limits })).broker, `https://127.0.0.1:${late.port}/`);
    expect(before.status).toBe(502);
  });

  it("a decoder error or an upstream reset after headers aborts without a terminating chunk, and releases no held byte", async () => {
    const prefix = SECRET.slice(0, 12);
    // Sent in one piece, the decoder fails before it yields a byte; in two, usually after "data ".
    for (const pieces of [1, 2]) {
      const corrupt = await upstream((_req, res) => {
        res.writeHead(200, { "Content-Encoding": "gzip" });
        const good = zlib.gzipSync(Buffer.from(`data ${prefix}`));
        const body = Buffer.concat([good.subarray(0, good.length - 8), Buffer.from("garbage!garbage!")]);
        if (pieces === 1) res.end(body);
        else {
          res.write(body.subarray(0, good.length - 8));
          res.end(body.subarray(good.length - 8));
        }
      });
      const r1 = await agent((await broker(corrupt.port)).broker, `https://127.0.0.1:${corrupt.port}/`);
      expect(r1.status).toBe(200);
      expect(r1.complete).toBe(false);
      expect(r1.raw.includes(Buffer.from(prefix))).toBe(false);
    }

    const reset = await upstream((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write(`data ${prefix}`);
      setTimeout(() => res.socket?.destroy(), 100);
    });
    const r2 = await agent((await broker(reset.port)).broker, `https://127.0.0.1:${reset.port}/`);
    expect(r2.complete).toBe(false);
    expect(r2.body.toString()).toBe("data ");
  });
});

describe("hold-back (tests 27 and 28)", () => {
  it("a secret prefix followed by a long pause is held, never released on a timer", async () => {
    const prefix = SECRET.slice(0, 15);
    let resume: () => void = () => {};
    const up = await upstream((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write(`before ${prefix}`);
      resume = () => res.end(`${SECRET.slice(15)} after`);
    });
    const { broker: b } = await broker(up.port, { limits: { idleMs: 5000 } });
    let seenDuringPause = "";
    const pending = agent(b, `https://127.0.0.1:${up.port}/`, {
      onData: (all) => {
        seenDuringPause = parse(all).body.toString();
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 1500));
    expect(seenDuringPause).toBe("before ");
    resume();
    const r = await pending;
    expect(r.body.toString()).toBe(`before ${PH} after`);
  });

  it("an Agent disconnect cancels the upstream request and discards held bytes", async () => {
    const up = await upstream((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write(`x ${SECRET.slice(0, 10)}`);
    });
    const { broker: b } = await broker(up.port, { limits: { idleMs: 10_000 } });
    const r = await agent(b, `https://127.0.0.1:${up.port}/`, {
      onData: (all, socket) => {
        if (parse(all).body.toString() === "x ") socket.destroy();
      },
    });
    expect(r.raw.includes(Buffer.from(SECRET.slice(0, 10)))).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(up.closed()).toBe(1);
    expect(b.heldValues()).toBe(0);
  });

  for (const streaming of [false, true]) {
    it(`a clean end in a long prefix is relayed unchanged (${streaming ? "streaming" : "buffered"}), and reported by length`, async () => {
      const body = `tail ${SECRET.slice(0, -1)}`;
      const up = await upstream((_req, res) => {
        if (streaming) res.writeHead(200, { "Content-Type": "text/plain" }).end(body);
        else res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(body.length) }).end(body);
      });
      const { broker: b, events } = await broker(up.port);
      const r = await agent(b, `https://127.0.0.1:${up.port}/`);
      expect(r.chunked).toBe(streaming);
      expect(r.complete).toBe(true);
      expect(r.body.toString()).toBe(body);
      expect(events).toContainEqual({ kind: "incomplete-prefix", item: "API_KEY", length: SECRET.length - 1 });
    });
  }
});

describe("coverage (tests 29 and 30)", () => {
  it("scrubs whatever the content type, with a declared length or not", async () => {
    for (const type of [undefined, "application/octet-stream", "application/yaml", "text/event-stream"]) {
      const up = await upstream((_req, res) => {
        const body = `data: ${SECRET}\n\n`;
        res.writeHead(200, { ...(type ? { "Content-Type": type } : {}), "Content-Length": String(body.length) }).end(body);
      });
      const r = await agent((await broker(up.port)).broker, `https://127.0.0.1:${up.port}/`);
      expect(r.body.toString(), type).toBe(`data: ${PH}\n\n`);
    }
  });

  it("scrubs the headers of HEAD, 204, and 304 responses, and Location and Set-Cookie reflections", async () => {
    const up = await upstream((req, res) => {
      const status = req.url === "/204" ? 204 : req.url === "/304" ? 304 : req.url === "/302" ? 302 : 200;
      res.writeHead(status, {
        "X-Echo": `Bearer ${SECRET}`,
        Location: `https://example.com/cb?token=${encodeURIComponent(SECRET)}`,
        "Set-Cookie": [`s=${SECRET}; Path=/`, "other=1"],
      });
      res.end(req.method === "HEAD" || status === 204 || status === 304 ? undefined : "ok");
    });
    const { broker: b } = await broker(up.port);
    for (const [path, method] of [["/head", "HEAD"], ["/204", "GET"], ["/304", "GET"], ["/302", "GET"]] as const) {
      const r = await agent(b, `https://127.0.0.1:${up.port}${path}`, { method });
      expect(header(r, "x-echo"), path).toEqual([`Bearer ${PH}`]);
      expect(header(r, "location")[0]).toBe(`https://example.com/cb?token=${PH}`);
      expect(header(r, "set-cookie")).toEqual([`s=${PH}; Path=/`, "other=1"]);
      for (const form of secretForms(SECRET)) expect(r.raw.toString("latin1")).not.toContain(form);
    }
  });

  it("scrubs JSON-escaped, percent-encoded, and base64/base64url reflections, including Basic credentials", async () => {
    const basic = (lead: string) => Buffer.from(`${lead}user:${SECRET}`).toString("base64");
    const url = (lead: string) => Buffer.from(`${lead}${DB}`).toString("base64url");
    const reflections = [
      JSON.stringify({ db: DB }),
      JSON.stringify({ db: DB }).replace("/", "\\/"),
      encodeURIComponent(DB),
      basic(""), basic("x"), basic("xy"),
      url(""), url("x"), url("xy"),
    ];
    const up = await upstream((_req, res) => res.writeHead(200, { "Content-Type": "text/plain" }).end(reflections.join("\n")));
    const { broker: b } = await broker(up.port);
    const r = await agent(b, `https://127.0.0.1:${up.port}/`, { headers: [["X-Db", PH_DB]] });
    const lines = r.body.toString().split("\n");
    expect(lines[0]).toBe(`{"db":"${PH_DB}"}`);
    expect(lines[1]).toBe(`{"db":"${PH_DB}"}`);
    expect(lines[2]).toBe(PH_DB);
    expect(lines.slice(3, 6).every((l) => l.includes(PH) && !l.includes(PH_DB))).toBe(true);
    expect(lines.slice(6).every((l) => l.includes(PH_DB))).toBe(true);
  });

  it("leaves hex and arbitrary \\uXXXX encodings (the documented limit)", async () => {
    const hex = Buffer.from(SECRET).toString("hex");
    const unicode = [...SECRET].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
    const up = await upstream((_req, res) => res.writeHead(200, { "Content-Type": "text/plain" }).end(`${hex}\n${unicode}`));
    const r = await agent((await broker(up.port)).broker, `https://127.0.0.1:${up.port}/`);
    expect(r.body.toString()).toBe(`${hex}\n${unicode}`);
  });

  it("scrubs a rotating item's retiring value too, and names a value too short to scrub", async () => {
    const up = await upstream((_req, res) => res.writeHead(200, { "Content-Type": "text/plain" }).end(`old ${OLD} new ${SECRET}`));
    const { broker: b } = await broker(up.port, { retiring: true });
    const r = await agent(b, `https://127.0.0.1:${up.port}/`);
    expect(r.body.toString()).toBe(`old ${PH} new ${PH}`);

    const short = await broker(up.port, { short: true });
    await agent(short.broker, `https://127.0.0.1:${up.port}/`);
    expect(short.events).toContainEqual({ kind: "unscrubbable", item: "API_KEY" });
  });
});

describe("no retention and no bypass (tests 36 and 37)", () => {
  it("holds no value after a response completes or aborts", async () => {
    const up = await upstream((req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      if (req.url === "/abort") {
        res.write("partial");
        setTimeout(() => res.socket?.destroy(), 50);
      } else res.end(`reflect ${SECRET}`);
    });
    const { broker: b } = await broker(up.port);
    await agent(b, `https://127.0.0.1:${up.port}/done`);
    expect(b.heldValues()).toBe(0);
    await agent(b, `https://127.0.0.1:${up.port}/abort`);
    expect(b.heldValues()).toBe(0);
    // A later request without a Placeholder is not scrubbed: nothing is retained.
    const later = await agent(b, `https://127.0.0.1:${up.port}/done`, { substitute: false });
    expect(later.body.toString()).toBe(`reflect ${SECRET}`);
  });

  it("every response path to the Agent passes the matcher", async () => {
    const shapes: Record<string, Handler> = {
      buffered: (_q, s) => s.writeHead(200, { "Content-Length": String(SECRET.length + 2) }).end(`${SECRET}\n\n`),
      streamed: (_q, s) => {
        s.writeHead(200);
        for (const c of SECRET) s.write(c);
        s.end();
      },
      gzip: (_q, s) => s.writeHead(200, { "Content-Encoding": "gzip" }).end(zlib.gzipSync(SECRET)),
      deflate: (_q, s) => s.writeHead(200, { "Content-Encoding": "deflate" }).end(zlib.deflateSync(SECRET)),
      br: (_q, s) => s.writeHead(200, { "Content-Encoding": "br" }).end(zlib.brotliCompressSync(Buffer.from(SECRET))),
      header: (_q, s) => s.writeHead(200, { "X-Leak": SECRET, "Content-Length": "0" }).end(),
      redirect: (_q, s) => s.writeHead(307, { Location: `https://e.example/${SECRET}` }).end(),
      status: (_q, s) => s.writeHead(500, `Error ${SECRET}`, { "Content-Type": "text/plain" }).end(SECRET),
      trailer: (_q, s) => {
        s.writeHead(200, { Trailer: "X-Trail" });
        s.write("body");
        s.addTrailers({ "X-Trail": SECRET });
        s.end();
      },
      informational: (_q, s) => {
        s.writeProcessing();
        s.writeHead(200, { "Content-Type": "text/plain" }).end(SECRET);
      },
    };
    const up = await upstream((req, res) => shapes[req.url!.slice(1)]!(req, res));
    const { broker: b } = await broker(up.port);
    for (const shape of Object.keys(shapes)) {
      const r = await agent(b, `https://127.0.0.1:${up.port}/${shape}`);
      for (const form of secretForms(SECRET)) expect(r.raw.toString("latin1"), shape).not.toContain(form);
    }
    expect(b.heldValues()).toBe(0);
  });
});
