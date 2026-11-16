// SPDX-License-Identifier: Apache-2.0
/**
 * Step 4.9a's vectors (ADR-0059 step 4, feature-parity decision 3): the
 * Platform Adapters' recorded exchanges, which go/lib/sync replays against
 * its Go adapters.
 *
 * Writing runs this package's own adapter tests (adapters.test.ts and
 * coolifyCompose.test.ts) and the extra cases below with every adapter
 * method recorded: its arguments, each request it sends (method, URL,
 * headers, body) with the fake service's answer (status, headers, body, or
 * the error the fetch rejected with), each send check (shouldAbort) and
 * expiry report it makes, and its result or what it threw. A sealed
 * GitHub value is recorded as its length ("<sealed:N>"): its bytes are
 * random, and the `seal` vectors hold the construction to TypeScript's.
 *
 * Every run of this test replays the file through the TypeScript adapters,
 * with the recorded answers, and requires the same requests and results.
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/sync exec vitest run test/go-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import nacl from "tweetnacl";
import { afterAll, describe, expect, it, vi } from "vitest";

const rec = await vi.hoisted(async () => {
  const { AsyncLocalStorage } = await import("node:async_hooks");
  const { expect: currentExpect } = await import("vitest");
  return {
    writing: process.env.VARLATCH_WRITE_GO_VECTORS === "1",
    cases: [] as Record<string, unknown>[],
    /** Set inside a recorded call: what it calls is part of its case. */
    inside: new AsyncLocalStorage<true>(),
    testName: (): string => currentExpect.getState().currentTestName ?? "(outside a test)",
  };
});

// The module functions the tests call directly: recorded at the top level
// only (an adapter's own call of them is part of its case).
vi.mock("../src/coolifyCompose.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../src/coolifyCompose.js")>();
  return { ...mod, classifyComposeUsage: recordFunction(rec, "classifyComposeUsage", mod.classifyComposeUsage) };
});
vi.mock("../src/github.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../src/github.js")>();
  return { ...mod, parseTokenExpiration: recordFunction(rec, "parseTokenExpiration", mod.parseTokenExpiration) };
});

import { coolifyAdapter, convexAdapter, githubActionsAdapter, sealedBox, type AdapterRequest, type PlatformAdapter } from "../src/index.js";
import { classifyComposeUsage } from "../src/coolifyCompose.js";

const FILE = new URL("../../../go/lib/sync/testdata/ts-exchanges.json", import.meta.url);

// ---------------------------------------------------------------------------
// Encoding JavaScript values JSON cannot hold.

type Encoded = unknown;

function encode(v: unknown): Encoded {
  if (v === undefined) return { $undefined: true };
  if (typeof v === "number" && !Number.isFinite(v)) return { $number: String(v) };
  if (v instanceof Map) return { $map: [...v].map(([k, x]) => [encode(k), encode(x)]) };
  if (v instanceof Set) return { $set: [...v].map(encode) };
  if (v instanceof Uint8Array) return { $bytes: Buffer.from(v).toString("hex") };
  if (Array.isArray(v)) return v.map(encode);
  if (v !== null && typeof v === "object") {
    const out: Record<string, Encoded> = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = encode(x);
    return out;
  }
  return v;
}

function decode(v: Encoded): unknown {
  if (Array.isArray(v)) return v.map(decode);
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, Encoded>;
    if (o.$undefined === true) return undefined;
    if (typeof o.$number === "string") return Number(o.$number);
    if (Array.isArray(o.$map)) return new Map((o.$map as [Encoded, Encoded][]).map(([k, x]) => [decode(k), decode(x)]));
    if (Array.isArray(o.$set)) return new Set((o.$set as Encoded[]).map(decode));
    if (typeof o.$bytes === "string") return new Uint8Array(Buffer.from(o.$bytes, "hex"));
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(o)) out[k] = decode(x);
    return out;
  }
  return v;
}

/** What a call threw: an AdapterError in full, anything else by name (its message is V8's or the test's). */
function encodeThrow(err: unknown): Encoded {
  if (err instanceof Error) {
    return err.name === "AdapterError"
      ? { name: err.name, message: err.message, retryable: (err as { retryable?: boolean }).retryable }
      : { name: err.name };
  }
  return { value: encode(err) };
}

/** The error a fetch rejected with, through its causes: name, message, code. */
function encodeError(err: unknown, depth = 0): Encoded {
  if (depth > 4 || err === undefined || err === null) return null;
  if (typeof err !== "object") return { value: String(err) };
  const e = err as { name?: unknown; message?: unknown; code?: unknown; cause?: unknown };
  return {
    name: typeof e.name === "string" ? e.name : null,
    message: typeof e.message === "string" ? e.message : null,
    ...(e.code !== undefined ? { code: e.code } : {}),
    ...(e.cause !== undefined ? { cause: encodeError(e.cause, depth + 1) } : {}),
  };
}

function decodeError(e: Encoded): unknown {
  if (e === null || typeof e !== "object") return e;
  const x = e as { name: string | null; message: string | null; code?: unknown; cause?: Encoded; value?: string };
  if (x.value !== undefined) return x.value;
  const err = new Error(x.message ?? "");
  if (x.name !== null) Object.defineProperty(err, "name", { value: x.name, configurable: true, writable: true });
  if (x.code !== undefined) Object.assign(err, { code: x.code });
  if (x.cause !== undefined) Object.assign(err, { cause: decodeError(x.cause) });
  return err;
}

// ---------------------------------------------------------------------------
// One request on the wire.

interface WireRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

/** A sealed GitHub value as its length: its bytes are random. */
function normalizeBody(body: string | null): string | null {
  return body === null
    ? null
    : body.replace(/"encrypted_value":"([^"]*)"/g, (_m, b64: string) => `"encrypted_value":"<sealed:${Buffer.from(b64, "base64").length}>"`);
}

function wireRequest(input: unknown, init: RequestInit | undefined): WireRequest {
  const href = new URL(String(input));
  href.hash = "";
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
  return {
    method: init?.method ?? "GET",
    url: href.toString(),
    headers,
    body: normalizeBody(typeof init?.body === "string" ? init.body : null),
  };
}

interface WireAnswer {
  status: number;
  headers: [string, string][];
  body: string;
}

type Exchange = { request: WireRequest } & ({ response: WireAnswer } | { error: Encoded });

const NULL_BODY = new Set([101, 103, 204, 205, 304]);

function answer(a: WireAnswer): Response {
  return new Response(NULL_BODY.has(a.status) ? null : a.body, { status: a.status, headers: a.headers });
}

// ---------------------------------------------------------------------------
// Recording.

function encodeRequest(req: AdapterRequest): Encoded {
  return {
    baseIdentity: req.baseIdentity,
    destination: encode(req.destination),
    credential: req.credential,
    ...(req.credentialKind !== undefined ? { credentialKind: req.credentialKind } : {}),
    ...(req.timeoutMs !== undefined ? { timeoutMs: req.timeoutMs } : {}),
    ...(req.usage !== undefined ? { usage: encode(req.usage) } : {}),
    fetchImpl: req.fetchImpl !== undefined,
    shouldAbort: req.shouldAbort !== undefined,
    onCredentialExpiry: req.onCredentialExpiry !== undefined,
  };
}

function isRequest(v: unknown): v is AdapterRequest {
  return typeof v === "object" && v !== null && "baseIdentity" in v && "credential" in v;
}

function recordFunction<F extends (...args: never[]) => unknown>(r: typeof rec, fn: string, original: F): F {
  return ((...args: Parameters<F>) => {
    if (!r.writing || r.inside.getStore()) return original(...args);
    const c: Record<string, unknown> = { test: r.testName(), fn, args: encode(args) };
    try {
      const out = r.inside.run(true, () => original(...args));
      c.result = encode(out);
      r.cases.push(c);
      return out;
    } catch (err) {
      c.throws = encodeThrow(err);
      r.cases.push(c);
      throw err;
    }
  }) as F;
}

function recordAdapter(adapter: PlatformAdapter): void {
  const target = adapter as unknown as Record<string, unknown>;
  for (const key of Object.keys(target)) {
    const original = target[key];
    if (typeof original !== "function") continue;
    target[key] = function (this: unknown, ...args: unknown[]) {
      if (rec.inside.getStore()) return (original as (...a: unknown[]) => unknown).apply(this, args);
      const c: Record<string, unknown> = { test: rec.testName(), platform: adapter.platform, method: key };
      const exchanges: Exchange[] = [];
      const aborts: boolean[] = [];
      const expiry: string[] = [];
      if (isRequest(args[0])) {
        const req = args[0];
        c.request = encodeRequest(req);
        const wrapped: AdapterRequest = { ...req };
        const inner = req.fetchImpl;
        if (inner) {
          wrapped.fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
            const request = wireRequest(input, init);
            let res: Response;
            try {
              res = await inner(input, init);
            } catch (err) {
              exchanges.push({ request, error: encodeError(err) });
              throw err;
            }
            const body = await res.clone().text();
            exchanges.push({ request, response: { status: res.status, headers: [...res.headers], body } });
            return res;
          }) as typeof fetch;
        }
        if (req.shouldAbort) {
          const check = req.shouldAbort;
          wrapped.shouldAbort = async () => {
            const a = await check();
            aborts.push(a);
            return a;
          };
        }
        if (req.onCredentialExpiry) {
          const report = req.onCredentialExpiry;
          wrapped.onCredentialExpiry = (at) => {
            expiry.push(at);
            report(at);
          };
        }
        args = [wrapped, ...args.slice(1)];
        c.args = encode(args.slice(1));
      } else {
        c.args = encode(args);
      }
      const finish = () => {
        if (c.request) Object.assign(c, { exchanges, aborts, expiry });
        rec.cases.push(c);
      };
      let out: unknown;
      try {
        out = rec.inside.run(true, () => (original as (...a: unknown[]) => unknown).apply(this, args));
      } catch (err) {
        c.throws = encodeThrow(err);
        finish();
        throw err;
      }
      if (out instanceof Promise) {
        return out.then(
          (v) => {
            c.result = encode(v);
            finish();
            return v;
          },
          (err: unknown) => {
            c.throws = encodeThrow(err);
            finish();
            throw err;
          },
        );
      }
      c.result = encode(out);
      finish();
      return out;
    };
  }
}

// ---------------------------------------------------------------------------
// Replaying a case through the TypeScript adapters.

const ADAPTERS: Record<string, PlatformAdapter> = {
  "github-actions": githubActionsAdapter,
  coolify: coolifyAdapter,
  convex: convexAdapter,
};

interface Case {
  test: string;
  platform?: string;
  method?: string;
  fn?: string;
  request?: Record<string, Encoded>;
  args: Encoded[];
  exchanges?: Exchange[];
  aborts?: boolean[];
  expiry?: string[];
  result?: Encoded;
  throws?: Encoded;
}

async function replay(c: Case): Promise<Case> {
  const args = (c.args as Encoded[]).map(decode);
  const out: Case = { ...c };
  delete out.result;
  delete out.throws;
  let call: () => unknown;
  if (c.fn) {
    const fn = c.fn === "classifyComposeUsage" ? classifyComposeUsage : (await import("../src/github.js")).parseTokenExpiration;
    call = () => (fn as (...a: unknown[]) => unknown)(...args);
  } else {
    const adapter = ADAPTERS[c.platform as string] as unknown as Record<string, (...a: unknown[]) => unknown>;
    const method = adapter[c.method as string] as (...a: unknown[]) => unknown;
    if (c.request) {
      const r = c.request;
      const exchanges: Exchange[] = [];
      const aborts: boolean[] = [];
      const expiry: string[] = [];
      const script = [...(c.exchanges ?? [])];
      const answers = [...(c.aborts ?? [])];
      const req: AdapterRequest = {
        baseIdentity: r.baseIdentity as string,
        destination: decode(r.destination) as Record<string, string>,
        credential: r.credential as string,
        ...(r.credentialKind !== undefined ? { credentialKind: r.credentialKind as "token" | "github-app" } : {}),
        ...(r.timeoutMs !== undefined ? { timeoutMs: r.timeoutMs as number } : {}),
        ...(r.usage !== undefined ? { usage: decode(r.usage) as AdapterRequest["usage"] } : {}),
      };
      if (r.fetchImpl) {
        req.fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
          const request = wireRequest(input, init);
          const next = script.shift();
          if (!next) throw new Error(`unrecorded request: ${request.method} ${request.url}`);
          if ("error" in next) {
            exchanges.push({ request, error: next.error });
            throw decodeError(next.error);
          }
          exchanges.push({ request, response: next.response });
          return answer(next.response);
        }) as typeof fetch;
      }
      if (r.shouldAbort) {
        req.shouldAbort = async () => {
          const a = answers.shift() ?? false;
          aborts.push(a);
          return a;
        };
      }
      if (r.onCredentialExpiry) req.onCredentialExpiry = (at) => void expiry.push(at);
      Object.assign(out, { exchanges, aborts, expiry });
      call = () => method.apply(adapter, [req, ...args]);
    } else {
      call = () => method.apply(adapter, args);
    }
  }
  try {
    out.result = encode(await call());
  } catch (err) {
    out.throws = encodeThrow(err);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Vectors that are not adapter calls.

interface Seal {
  ephemeralSecret: string;
  recipient: string;
  message: string;
  sealed: string;
}

function sealVectors(): Seal[] {
  const out: Seal[] = [];
  const messages = ["", "postgres://user:pw@host/db", "é€😀", "x".repeat(300)];
  for (let i = 0; i < 6; i++) {
    const ephemeral = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(i * 37 + 1));
    const recipient = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(i * 11 + 200)).publicKey;
    const message = new TextEncoder().encode(messages[i % messages.length]);
    const spy = vi.spyOn(nacl.box, "keyPair").mockReturnValueOnce(ephemeral);
    const sealed = sealedBox(message, recipient);
    spy.mockRestore();
    const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
    out.push({ ephemeralSecret: hex(ephemeral.secretKey), recipient: hex(recipient), message: hex(message), sealed: hex(sealed) });
  }
  return out;
}

/** Buffer.from(s, "base64"): the public key's decoding. */
function base64Vectors(): { input: string; bytes: string }[] {
  const inputs = ["", "QQ==", "QUI=", "QUJD", "QUJDRA", "QU JD\nRA==", "a-b_c+d/", "ab=cd", "abcde", "!!!", "éQUJD", "QUJD\ud800RA", "ŁUJD"];
  return inputs.map((input) => ({ input, bytes: Buffer.from(input, "base64").toString("hex") }));
}

interface Vectors {
  comment: string;
  /** Long strings, stored once: a case holds {"$s": index}. A long repeat in one is {"$rep": [unit, count]} inside {"$cat": [...]}. */
  strings: Encoded[];
  seal: Seal[];
  base64: { input: string; bytes: string }[];
  cases: Case[];
}

const COMMENT =
  "Recorded by packages/sync/test/go-vectors.test.ts from the TypeScript adapters; go/lib/sync replays it. Regenerate, never edit.";

const LONG = 512;

/** A long string with its long repeats run-length coded. */
function compressRuns(text: string): Encoded {
  const parts: Encoded[] = [];
  let plain = "";
  for (let i = 0; i < text.length; ) {
    let best: [string, number] | null = null;
    for (let p = 1; p <= 16 && !best; p++) {
      const unit = text.slice(i, i + p);
      if (unit.length < p) break;
      let k = 1;
      while (text.startsWith(unit, i + k * p)) k++;
      if (k * p >= 256) best = [unit, k];
    }
    if (best) {
      if (plain) parts.push(plain);
      plain = "";
      parts.push({ $rep: best });
      i += best[0].length * best[1];
    } else {
      plain += text[i];
      i++;
    }
  }
  if (plain) parts.push(plain);
  return parts.length === 1 && typeof parts[0] === "string" ? parts[0] : { $cat: parts };
}

function expandRuns(v: Encoded): string {
  if (typeof v === "string") return v;
  return ((v as { $cat: Encoded[] }).$cat)
    .map((part) => (typeof part === "string" ? part : (part as { $rep: [string, number] }).$rep[0].repeat((part as { $rep: [string, number] }).$rep[1])))
    .join("");
}

function pack(v: Encoded, table: string[], index: Map<string, number>): Encoded {
  if (typeof v === "string" && v.length >= LONG) {
    let at = index.get(v);
    if (at === undefined) {
      at = table.push(v) - 1;
      index.set(v, at);
    }
    return { $s: at };
  }
  if (Array.isArray(v)) return v.map((x) => pack(x, table, index));
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, pack(x, table, index)]));
  return v;
}

function unpack(v: Encoded, table: string[]): Encoded {
  if (Array.isArray(v)) return v.map((x) => unpack(x, table));
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, Encoded>;
    if (typeof o.$s === "number" && Object.keys(o).length === 1) return table[o.$s];
    return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, unpack(x, table)]));
  }
  return v;
}

function writeVectors(cases: Case[]): void {
  const table: string[] = [];
  const index = new Map<string, number>();
  const packed = cases.map((c) => pack(c as unknown as Encoded, table, index));
  const line = (v: unknown) => JSON.stringify(v);
  const text = [
    "{",
    ` "comment": ${line(COMMENT)},`,
    ` "seal": ${line(sealVectors())},`,
    ` "base64": ${line(base64Vectors())},`,
    ` "strings": [\n${table.map((t) => "  " + line(compressRuns(t))).join(",\n")}\n ],`,
    ` "cases": [\n${packed.map((c) => "  " + line(c)).join(",\n")}\n ]`,
    "}",
    "",
  ].join("\n");
  writeFileSync(FILE, text);
}

function readVectors(): Vectors {
  const raw = JSON.parse(readFileSync(FILE, "utf8")) as Vectors;
  const table = raw.strings.map(expandRuns);
  return { ...raw, cases: raw.cases.map((c) => unpack(c as unknown as Encoded, table) as unknown as Case) };
}

if (rec.writing) {
  for (const adapter of [githubActionsAdapter, coolifyAdapter, convexAdapter]) recordAdapter(adapter);
  // The adapters' own tests, recorded as they run (their suites join this file's).
  await import("./adapters.test.js");
  await import("./coolifyCompose.test.js");
  await import("./go-vectors-extra.js");
  afterAll(() => writeVectors(rec.cases as unknown as Case[]));
}

describe.skipIf(rec.writing)("the Go vectors", () => {
  const load = readVectors;

  it("replay through the TypeScript adapters with the same requests and results", async () => {
    const file = load();
    expect(file.cases.length).toBeGreaterThan(300);
    for (const c of file.cases) {
      expect(await replay(c), c.test).toEqual(c);
    }
  });

  it("hold the sealed box and the key decoding to this code", () => {
    const file = load();
    expect(sealVectors()).toEqual(file.seal);
    expect(base64Vectors()).toEqual(file.base64);
  });
});
