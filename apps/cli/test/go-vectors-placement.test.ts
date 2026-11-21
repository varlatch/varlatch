// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { parseTarget, type Target } from "@varlatch/protocol";
import { describe, expect, it } from "vitest";
import { BODY_LIMIT, percentEncode, planPlacement, type RequestParts } from "../src/placement.js";
import { matchesSelectors, parseSelectors, sameTargets } from "../src/broker.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's Broker placement (internal docs/design/go-cli.md,
 * slice 5.5a; ADR-0039 Decisions 1 to 5), recorded from placement.ts and
 * broker.ts themselves:
 *
 * - placements: a request as the Agent sent it (header pairs in order, the
 *   raw query, the body), this run's Placeholders and the Capability's
 *   targets; what planPlacement decides (pass, block with its rule and
 *   message, or substitute with its placements and strays), and what each
 *   apply makes of the values given (the substituted request, or the rule
 *   and message it failed with). Every case of placement.test.ts, with fixed
 *   Placeholders, and more: lone surrogates, control characters and
 *   multi-byte text in values, every target kind with odd spellings;
 * - percentEncode: values and their encoding;
 * - selectors: parseSelectors and matchesSelectors on destinations;
 * - sameTargets: target sets compared whatever their order.
 *
 * Header values are JavaScript strings, as Node.js reads them (latin1, one
 * character per byte); bodies are base64, an applied body over 4 KiB its
 * length and SHA-256. Every value here is a test fixture's.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-placement.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/placement.json", import.meta.url));

const A = `vlch_ph_v1_${"a".repeat(32)}`;
const B = `vlch_ph_v1_${"b".repeat(32)}`;
const FOREIGN = `vlch_ph_v1_${"c".repeat(32)}`;
const PLACEHOLDERS: Record<string, string> = { [A]: "API_KEY", [B]: "DB_PASSWORD" };
const c = (...cps: number[]) => String.fromCharCode(...cps);
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

interface Case {
  name: string;
  headers?: [string, string][];
  query?: string | null;
  /** The body as UTF-8 text, or as base64 when `bodyB64`. */
  body?: string;
  bodyB64?: string;
  targets: Record<string, string[]>;
  /** Each apply attempt's values, when the plan substitutes. */
  applies?: Record<string, string>[];
}

function request(init: { headers?: [string, string][]; query?: string | null; json?: unknown; form?: string; type?: string; text?: string; type2?: string }): Pick<Case, "headers" | "query" | "body"> {
  const headers = [...(init.headers ?? [])];
  let body = init.text;
  if (init.json !== undefined) {
    body = typeof init.json === "string" ? init.json : JSON.stringify(init.json);
    headers.push(["Content-Type", init.type ?? "application/json"]);
  }
  if (init.form !== undefined) {
    body = init.form;
    headers.push(["Content-Type", init.type ?? "application/x-www-form-urlencoded"]);
  }
  if (init.type2 !== undefined) headers.push(["Content-Type", init.type2]);
  return { headers, query: init.query ?? null, ...(body === undefined ? {} : { body }) };
}

function cases(): Case[] {
  const auth = { API_KEY: ["header:authorization"] };
  const t1213 = { API_KEY: ["header:authorization", "query:key"] };
  const jsonKey = { API_KEY: ["json:/key"] };
  const pct = A.replace("_", "%5F");
  const escaped = A.replace("v", "\\u0076");
  const header: [string, string][] = [["Authorization", `Bearer ${A}`]];
  const both = { API_KEY: ["header:authorization", "json:/key"] };
  const list: Case[] = [
    // Test 11: substitution at each target kind
    { name: "header", ...request({ headers: [["Authorization", `Bearer ${A}`], ["X-Other", "keep me"]] }), targets: auth, applies: [{ API_KEY: "sk live/1" }] },
    { name: "query", ...request({ query: `a=%7e1&api_key=${A}&b=x+y` }), targets: { API_KEY: ["query:api_key"] }, applies: [{ API_KEY: "s k/&=~é" }] },
    { name: "json", ...request({ json: `{ "a" : 1.50,\n  "auth": {"key": "${A}"}, "list": ["x"] }` }), targets: { API_KEY: ["json:/auth/key"] }, applies: [{ API_KEY: 'q"u\\o\nte</' }] },
    { name: "json-pointer-escapes", ...request({ json: JSON.stringify({ "a/b": { "c~d": [0, A] } }) }), targets: { API_KEY: ["json:/a~1b/c~0d/1"] }, applies: [{ API_KEY: "v" }] },
    { name: "form", ...request({ form: `grant_type=client_credentials&client_secret=${A}&scope=a+b` }), targets: { API_KEY: ["form:client_secret"] }, applies: [{ API_KEY: "p+w d" }] },
    { name: "several", ...request({ headers: [["X-Api-Key", A]], json: { password: B } }), targets: { API_KEY: ["header:x-api-key"], DB_PASSWORD: ["json:/password", "header:x-db"] }, applies: [{ API_KEY: "k1", DB_PASSWORD: "p1" }] },
    { name: "targets-absent", ...request({ headers: [["X-Other", "1"]] }), targets: auth },
    // Tests 12 and 13: outside the targets
    { name: "outside.header", ...request({ headers: [["Authorization", `Bearer ${A}`], ["X-Debug", A]] }), targets: t1213 },
    { name: "outside.query-other", ...request({ query: `q=${A}` }), targets: t1213 },
    { name: "outside.query-prefix", ...request({ query: `key=x${A}` }), targets: t1213 },
    { name: "outside.query-name", ...request({ query: `${A}=1` }), targets: t1213 },
    { name: "outside.json-other", ...request({ json: { key: A, log: `sent ${A}` } }), targets: jsonKey },
    { name: "outside.json-suffix", ...request({ json: { key: `${A} ` } }), targets: jsonKey },
    { name: "outside.json-key", ...request({ json: { [A]: 1 } }), targets: jsonKey },
    { name: "stray.body", ...request({ headers: [["Authorization", `Bearer ${A}`]], text: `log: ${A}`, type2: "text/plain" }), targets: t1213, applies: [{ API_KEY: "v" }] },
    { name: "stray.no-target", ...request({ json: { note: B } }), targets: t1213 },
    { name: "foreign", ...request({ headers: [["X-Debug", FOREIGN]] }), targets: t1213 },
    // Test 14: each target at most once
    { name: "second-occurrence", ...request({ headers: [["Authorization", `${A} ${A}`]] }), targets: auth },
    { name: "two-targets", ...request({ headers: [["Authorization", A]], query: `key=${A}` }), targets: t1213, applies: [{ API_KEY: "v" }] },
    // Test 15: parser differentials
    { name: "duplicate-key", ...request({ json: `{"key":"${A}","key":"x"}` }), targets: jsonKey },
    { name: "duplicate-key.nested", ...request({ json: `{"key":"${A}","o":{"a":1,"a":2}}` }), targets: jsonKey },
    { name: "duplicate-key.escaped", ...request({ json: `{"key":"${A}","\\u006bey":"x"}` }), targets: jsonKey },
    { name: "invalid.trailing-comma", ...request({ json: `{"key":"${A}",}` }), targets: jsonKey },
    { name: "invalid.trailing-content", ...request({ json: `{"key":"${A}"} x` }), targets: jsonKey },
    { name: "invalid.deep", ...request({ json: `{"key":"${A}","d":${"[".repeat(400)}${"]".repeat(400)}}` }), targets: jsonKey },
    { name: "repeated-header", ...request({ headers: [["Authorization", A], ["authorization", "x"]] }), targets: auth },
    { name: "folded-header", ...request({ headers: [["Authorization", `Bearer\r\n ${A}`]] }), targets: auth },
    { name: "repeated-name.query", ...request({ query: `api_key=${A}&api_key=x` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "repeated-name.query-encoded", ...request({ query: `api_key=${A}&api%5Fkey=x` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "repeated-name.form-encoded", ...request({ form: `api_key=${A}&api%5fkey=x` }), targets: { API_KEY: ["form:api_key"] } },
    { name: "repeated-name.space", ...request({ query: `api+key=${A}&api%20key=x` }), targets: { API_KEY: ["query:api key"] } },
    { name: "separator.query", ...request({ query: `api_key=${A};x=1` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "separator.form", ...request({ form: `api_key=${A};x=1` }), targets: { API_KEY: ["form:api_key"] } },
    { name: "encoded.query", ...request({ query: `api_key=${pct}` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "encoded.query-beside", ...request({ query: `api_key=${A}&x=${pct}` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "encoded.json-beside", ...request({ json: `{"key":"${A}","x":"${escaped}"}` }), targets: jsonKey },
    { name: "encoded.json", ...request({ json: `{"key":"${escaped}"}` }), targets: jsonKey },
    { name: "encoded.form", ...request({ form: `a=${pct}` }), targets: { API_KEY: ["form:a"] } },
    { name: "content-type.text", ...request({ json: { key: A }, type: "text/plain" }), targets: jsonKey },
    { name: "content-type.form", ...request({ form: `key=${A}` }), targets: jsonKey },
    { name: "content-type.none", ...request({ text: JSON.stringify({ key: A }) }), targets: jsonKey },
    { name: "content-type.repeated", ...request({ json: { key: A }, headers: [["Content-Type", "application/json"]] }), targets: jsonKey },
    { name: "charset.latin1", ...request({ json: { key: A }, type: "application/json; charset=iso-8859-1" }), targets: jsonKey },
    { name: "charset.utf8-quoted", ...request({ json: { key: A }, type: 'application/json; charset="UTF-8"' }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    {
      name: "not-utf8",
      headers: [["Content-Type", "application/json"]],
      query: null,
      bodyB64: Buffer.concat([Buffer.from(`{"key":"${A}","n":"`), Buffer.from([0xe9]), Buffer.from('"}')]).toString("base64"),
      targets: jsonKey,
    },
    { name: "content-encoding.gzip", ...request({ json: { key: A }, headers: [["Content-Encoding", "gzip"]] }), targets: jsonKey },
    { name: "content-encoding.identity", ...request({ json: { key: A }, headers: [["Content-Encoding", "identity"]] }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    // A body target constrains every request carrying the Placeholder
    { name: "body-target.malformed", ...request({ headers: header, json: "{not json" }), targets: both },
    { name: "body-target.text", ...request({ headers: header, text: "plain", type2: "text/plain" }), targets: both },
    { name: "body-target.gzip", ...request({ headers: [...header, ["Content-Encoding", "gzip"]], json: { other: 1 } }), targets: both },
    { name: "body-target.valid", ...request({ headers: header, json: { other: 1 } }), targets: both, applies: [{ API_KEY: "v" }] },
    { name: "body-target.absent", ...request({ headers: header }), targets: both, applies: [{ API_KEY: "v" }] },
    { name: "header-only.bad-body", ...request({ headers: header, text: "{not json", type2: "application/json" }), targets: auth, applies: [{ API_KEY: "v" }] },
    // Test 17: after exercise
    { name: "after.unsafe-and-missing", ...request({ headers: [["Authorization", A]] }), targets: auth, applies: [{ API_KEY: "a\r\nX-Injected: 1" }, { API_KEY: "a\nb" }, { API_KEY: "a\0b" }, {}] },
    { name: "after.body-limit", ...request({ json: { key: A, filler: "x".repeat(BODY_LIMIT - 200) } }), targets: jsonKey, applies: [{ API_KEY: "v".repeat(500) }, { API_KEY: "v" }] },
    // More: values of every shape at each kind, odd spellings
    {
      name: "values.header",
      ...request({ headers: [["Authorization", `Token ${A};x`]] }),
      targets: auth,
      applies: [{ API_KEY: `t${c(0xd83d)}x` }, { API_KEY: "tab\there" }, { API_KEY: `é-${c(0xff)}` }],
    },
    {
      name: "values.query",
      ...request({ query: `api_key=${A}` }),
      targets: { API_KEY: ["query:api_key"] },
      applies: [{ API_KEY: `lone${c(0xd800)}-${c(0xdc00)}` }, { API_KEY: `${c(0x1f600)}` }, { API_KEY: "!'()*~-_." }, { API_KEY: `ctl${c(1, 0x7f)}` }],
    },
    {
      name: "values.json",
      ...request({ json: { key: A } }),
      targets: jsonKey,
      applies: [{ API_KEY: `lone${c(0xd800)}x${c(0xdfff)}` }, { API_KEY: `ctl${c(0, 1, 0x1f, 0x7f, 0x2028, 0x2029)}` }, { API_KEY: "\b\f\n\r\t\"\\/" }, { API_KEY: "é😀" }],
    },
    {
      name: "values.form",
      ...request({ form: `client_secret=${A}` }),
      targets: { API_KEY: ["form:client_secret"] },
      applies: [{ API_KEY: `a b+c&d=e%f${c(0xd800)}` }],
    },
    { name: "header.case", ...request({ headers: [["AUTHORIZATION", A]] }), targets: auth, applies: [{ API_KEY: "v" }] },
    { name: "json.unicode-before", ...request({ json: `{"é😀":"x","key":"${A}"}` }), targets: jsonKey, applies: [{ API_KEY: `z${c(0x1f600)}` }] },
    { name: "json.whitespace", ...request({ json: ` \t\r\n{"key" :\n"${A}" }\n` }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    { name: "json.numbers", ...request({ json: `{"n":[-0,1.5e+3,2E-1,0.0],"t":true,"f":false,"z":null,"key":"${A}"}` }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    { name: "json.bad-number", ...request({ json: `{"n":01,"key":"${A}"}` }), targets: jsonKey },
    { name: "json.control", ...request({ json: `{"key":"${A}","x":"a\tb"}` }), targets: jsonKey },
    { name: "json.bad-escape", ...request({ json: `{"key":"${A}","x":"\\x"}` }), targets: jsonKey },
    { name: "json.unterminated", ...request({ json: `{"key":"${A}` }), targets: jsonKey },
    { name: "json.key-not-string", ...request({ json: `{key:"${A}"}` }), targets: jsonKey },
    { name: "json.missing-colon", ...request({ json: `{"key" "${A}"}` }), targets: jsonKey },
    { name: "json.unterminated-array", ...request({ json: `{"key":"${A}","a":[1 2]}` }), targets: jsonKey },
    { name: "json.empty", ...request({ json: `{"key":"${A}","o":{},"a":[]}` }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    { name: "json.depth-256", ...request({ json: `{"key":"${A}","d":${"[".repeat(255)}${"]".repeat(255)}}` }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    { name: "json.depth-257", ...request({ json: `{"key":"${A}","d":${"[".repeat(256)}${"]".repeat(256)}}` }), targets: jsonKey },
    { name: "json.bom", ...request({ json: `﻿{"key":"${A}"}` }), targets: jsonKey },
    { name: "query.no-value", ...request({ query: `flag&api_key=${A}` }), targets: { API_KEY: ["query:api_key"] }, applies: [{ API_KEY: "v" }] },
    { name: "query.empty-name", ...request({ query: `=1&api_key=${A}` }), targets: { API_KEY: ["query:api_key"] }, applies: [{ API_KEY: "v" }] },
    { name: "query.bad-percent", ...request({ query: `api_key=${A}&x=%zz` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "query.plus-placeholder", ...request({ query: `api_key=+${A}` }), targets: { API_KEY: ["query:api_key"] } },
    { name: "query.untargeted", ...request({ query: `x=${A}` }), targets: auth },
    { name: "form.charset", ...request({ form: `client_secret=${A}`, type: "application/x-www-form-urlencoded; charset=utf-8" }), targets: { API_KEY: ["form:client_secret"] }, applies: [{ API_KEY: "v" }] },
    { name: "form.json-type", ...request({ form: `client_secret=${A}`, type: "application/json" }), targets: { API_KEY: ["form:client_secret"] } },
    { name: "media.case", ...request({ json: { key: A }, type: "Application/JSON" }), targets: jsonKey, applies: [{ API_KEY: "v" }] },
    { name: "header.latin1", ...request({ headers: [["Authorization", `${c(0xe9)} ${A}`]] }), targets: auth, applies: [{ API_KEY: "v" }] },
    { name: "two-items.order", ...request({ headers: [["X-Db", B], ["Authorization", A]] }), targets: { API_KEY: ["header:authorization"], DB_PASSWORD: ["header:x-db"] }, applies: [{ API_KEY: "k", DB_PASSWORD: "p" }, { API_KEY: "k" }] },
    { name: "decoded-only", ...request({ query: `x=${pct}` }), targets: auth },
    { name: "unicode-escape-only", ...request({ headers: [["X", escaped]] }), targets: auth },
  ];
  return list;
}

const enc = (b: Buffer) => (b.length > 4096 ? { bodyLength: b.length, bodySha256: sha(b) } : { bodyB64: b.toString("base64") });

function record(k: Case) {
  const body = k.bodyB64 !== undefined ? Buffer.from(k.bodyB64, "base64") : Buffer.from(k.body ?? "", "utf8");
  const parts: RequestParts = { headers: k.headers ?? [], query: k.query ?? null, body };
  const targets = new Map<string, Target[]>(Object.entries(k.targets).map(([item, list]) => [item, list.map((t) => parseTarget(t))]));
  const plan = planPlacement(parts, new Map(Object.entries(PLACEHOLDERS)), targets);
  const input = { name: k.name, headers: parts.headers, query: parts.query, ...enc(body), targets: k.targets };
  if (plan.kind === "pass") return { ...input, plan: { kind: "pass", strays: plan.strays } };
  if (plan.kind === "block") return { ...input, plan: { kind: "block", status: plan.status, rule: plan.rule, message: plan.message } };
  const applies = (k.applies ?? []).map((values) => {
    const r = plan.apply(new Map(Object.entries(values)));
    if (!r.ok) return { values, ok: false, rule: r.rule, message: r.message };
    return { values, ok: true, headers: r.headers, query: r.query, ...enc(r.body) };
  });
  return { ...input, plan: { kind: "substitute", placements: plan.placements, strays: plan.strays }, applies };
}

describe("Broker placement vectors (slice 5.5a)", () => {
  it("are recorded from placement.ts and broker.ts", () => {
    const list = cases();
    expect(new Set(list.map((k) => k.name)).size).toBe(list.length);
    const encodings = ["", "s k/&=~é", "s k/&=~é!*'()", "a+b c", `lone${c(0xd83d)}`, `${c(0xdc00)}${c(0xd800)}`, "😀", "\u0000\u007f\u0080", "~-._ABCxyz019"].map((value) => ({
      value,
      encoded: percentEncode(value),
    }));
    const selectorLists = [
      ["api.example.com:443", "*.example.org:443", "[::1]:8443", "127.0.0.1:80", "API.Upper.COM:443"],
      ["bad", "no-port:", ":443", "*.:443", "[::1]", "host:x", "host:1.5", "*.wild.example:8080"],
    ];
    const probes: [string, number][] = [
      ["api.example.com", 443],
      ["API.EXAMPLE.COM.", 443],
      ["api.example.com", 80],
      ["x.example.org", 443],
      ["a.b.example.org", 443],
      ["example.org", 443],
      ["[::1]", 8443],
      ["::1", 8443],
      ["127.0.0.1", 80],
      ["1.2.3.4", 443],
      ["api.upper.com", 443],
      ["deep.wild.example", 8080],
      ["no-port", 0],
      ["host", Number.NaN],
    ];
    const selectors = selectorLists.map((raw) => ({
      raw,
      parsed: parseSelectors(raw),
      matches: probes.map(([host, port]) => ({ host, port: Number.isNaN(port) ? null : port, match: matchesSelectors(parseSelectors(raw), host, port) })),
    }));
    const sets: [Record<string, string[]>, Record<string, string[]>][] = [
      [{ A: ["header:x", "query:y"] }, { A: ["query:y", "header:x"] }],
      [{ A: ["header:x"], B: ["json:/k"] }, { B: ["json:/k"], A: ["header:x"] }],
      [{ A: ["header:x"] }, { A: ["header:x", "header:x"] }],
      [{ A: ["header:x"] }, { A: ["header:y"] }],
      [{ A: [] }, {}],
      [{}, {}],
    ];
    const vectors = {
      comment: "Generated by apps/cli/test/go-vectors-placement.test.ts from placement.ts and broker.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      bodyLimit: BODY_LIMIT,
      placeholders: PLACEHOLDERS,
      percentEncode: encodings,
      selectors,
      sameTargets: sets.map(([a, b]) => ({ a, b, same: sameTargets(a, b) })),
      cases: list.map(record),
    };
    const text = `{"comment":${JSON.stringify(vectors.comment)},"bodyLimit":${vectors.bodyLimit},"placeholders":${JSON.stringify(vectors.placeholders)},\n"percentEncode":${JSON.stringify(vectors.percentEncode)},\n"selectors":${JSON.stringify(vectors.selectors)},\n"sameTargets":${JSON.stringify(vectors.sameTargets)},\n"cases":[\n${vectors.cases.map((k) => JSON.stringify(k)).join(",\n")}\n]}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "placement.json is stale: regenerate it (see this file's comment)").toBe(true);
  });
});
