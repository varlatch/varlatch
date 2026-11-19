// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Readable, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  MIN_LENGTH,
  StreamMatcher,
  StreamScanner,
  findWhole,
  labelledFormsOf,
  scrubWhole,
  type Occurrence,
  type SecretEntry,
} from "@varlatch/matcher";
import { OutputRedaction, redactionMarker, type RedactionMode } from "../src/redact.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's matcher and output redaction (internal
 * docs/design/go-cli.md, slice 5.4a and decision 10), recorded from
 * packages/matcher and redact.ts themselves:
 *
 * - forms: every registered form of a value, with its name;
 * - cases: an input streamed through StreamMatcher and StreamScanner. The
 *   output is the same at every byte split (checked here, and again by the
 *   Go test) and equals scrubWhole's; each chunking's steps record what each
 *   push emitted and what stayed held, so Go is held to the same hold-back,
 *   not only to the same final bytes. Inputs: every case of
 *   packages/matcher's tests and of redact.test.ts, seeded adversarial
 *   inputs (overlapping Secrets over a small alphabet, every encoded form at
 *   every base64 alignment, multi-byte and lone-surrogate text, binary),
 *   many Secrets, and long inputs (stored as repeated parts, their outputs
 *   by SHA-256);
 * - redactions: OutputRedaction's notices and relays (two streams, an
 *   interrupt, a failing stream), chunk boundaries kept as given.
 *
 * Every value here is a test fixture's, or random text the generators made.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-matcher.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/matcher.json", import.meta.url));

const c = (...cps: number[]) => String.fromCodePoint(...cps);
const bytes = (s: string) => Buffer.from(s, "utf8");
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const sha = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

/** Every split point and byte by byte, below this many bytes. */
const EVERY_SPLIT = 400;

function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

interface Part {
  text?: string;
  bytes?: Uint8Array;
  repeat?: number;
}
interface Case {
  name: string;
  entries: SecretEntry[];
  parts: Part[];
}

const partBytes = (p: Part) => (p.bytes ? Buffer.from(p.bytes) : bytes(p.text ?? ""));
const assemble = (parts: Part[]) => Buffer.concat(parts.flatMap((p) => Array.from({ length: p.repeat ?? 1 }, () => partBytes(p))));
const simple = (name: string, entries: SecretEntry[], input: string | Uint8Array): Case => ({
  name,
  entries,
  parts: [typeof input === "string" ? { text: input } : { bytes: input }],
});

// --- the cases ------------------------------------------------------------------------

const json = (v: string) => JSON.stringify(v).slice(1, -1);
const LONE = `token-${c(0xd83d)}-value-${c(0xde00)}-end`;

function unitCases(): Case[] {
  const api = [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }];
  const b64z = Buffer.from("zzzzzzzzzzzz").toString("base64");
  const parts7 = ["AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDDDDDD", "EEEEEEEE", "FFFFFFFF", "GGGGGGGG"];
  // A PEM-shaped block whose label is no key type: the case needs a value
  // spanning lines, and a private-key header in a vector file would be a
  // secret scanner's finding (and is one nothing should allow-list).
  const label = "FAKE KEY";
  const pem = `-----BEGIN ${label}-----\nFAKEKEYDATA0FAKEKEY\nFAKEKEYDATA1FAKEKEY\n-----END ${label}-----`;
  const escapedValue = 'a???/value>>>"zz';
  const slashed = `token-${c(0xd83d)}/value-end`;
  return [
    // matcher.test.ts
    simple("forms.basic-header", [{ item: "KEY", value: "valueaaaaaaaaaaaaa" }], `Authorization: Basic ${Buffer.from("user:valueaaaaaaaaaaaaa").toString("base64")}`),
    simple("short.value", [{ item: "SHORT", value: "1234567" }], "x1234567y"),
    simple("surrogate.json-body", [{ item: "TOKEN", value: LONE }], `{"token":"${json(LONE)}","n":1}`),
    simple("surrogate.json-slash", [{ item: "TOKEN", value: slashed }], `{"t":"${json(slashed).replace(/\//g, "\\/")}"}`),
    simple("surrogate.child-output", [{ item: "TOKEN", value: LONE }], `log ${bytes(LONE).toString("utf8")} done`),
    simple("stream.clean-multibyte", api, `h${c(0xe9)}llo w${c(0xf6)}rld ${c(0x2713)} nothing secret here`),
    simple("stream.split-value", api, "token=valueaaaaaaaaaaaaa; ok"),
    simple("stream.held-prefix", api, "abc valueaaaaaaa"),
    simple("overlap.suffix-prefix", [{ item: "A", value: "xxxxYYYY" }, { item: "B", value: "YYYYzzzz" }], "..xxxxYYYYzzzz.."),
    simple("overlap.nested", [{ item: "A", value: "outer-12345678-outer" }, { item: "B", value: "12345678" }], "[outer-12345678-outer]"),
    simple("overlap.extends-left", [{ item: "B", value: "bcdefghi" }, { item: "A", value: "abcdefghij" }], "-abcdefghij-"),
    simple("overlap.touching", [{ item: "A", value: "AAAAAAAA" }, { item: "B", value: "BBBBBBBB" }], "AAAAAAAABBBBBBBB"),
    simple("overlap.same-value-two-names", [{ item: "ZETA", value: "same-value-1234" }, { item: "ALPHA", value: "same-value-1234" }], "x same-value-1234 y"),
    simple("overlap.raw-and-base64", [{ item: "S2", value: "zzzzzzzzzzzz" }, { item: "S1", value: `${b64z.slice(-4)}ABCDEFGH` }], `>${b64z}ABCDEFGH<`),
    simple("overlap.chain", [{ item: "P", value: "abababab" }], `start ${"ab".repeat(60)} end`),
    simple("overlap.chain-short", [{ item: "P", value: "abababab" }], `start ${"ab".repeat(12)} end`),
    simple("end.pending-region", [{ item: "A", value: "abcdefgh" }, { item: "B", value: "efghijkl" }], "hello abcdefgh"),
    simple("bound.diverging", [{ item: "A", value: "0123456789" }, { item: "B", value: "89abcdefgh" }], "0123456789abcdefgh!"),
    simple("bound.diverging-2", [{ item: "A", value: "0123456789" }, { item: "B", value: "89abcdefgh" }], "0123456789zz"),
    simple("bound.diverging-3", [{ item: "A", value: "0123456789" }, { item: "B", value: "89abcdefgh" }], "0123456789"),
    simple("bound.seven-pending", [...parts7.map((value, i) => ({ item: `S${i}`, value })), { item: "LONG", value: `${parts7.join("")}!` }], parts7.join("")),
    simple("bound.longest-wins", [{ item: "SHORT", value: "abcdefgh" }, { item: "LONG", value: "abcdefghij" }], "<abcdefghij>"),
    simple(
      "bound.span-merges-three",
      [{ item: "R1", value: "11111111" }, { item: "R2", value: "22222222" }, { item: "SPAN", value: "11112222222233" }, { item: "PREFIX", value: "1111111122222222333333" }],
      "1111111122222222333!",
    ),
    simple("clean.almost-prefixes", [{ item: "K", value: "never-present-9999" }], `${c(0xfc)}n${c(0xef)}c${c(0xf6)}d${c(0xe9)} text with never-present-999 almost-prefixes never-present-99`),
    // scanner.test.ts
    simple("scan.multibyte-value", [{ item: "DB_PASS", value: `p${c(0xe4)}ssword-XYZ-123` }], `x=p${c(0xe4)}ssword-XYZ-123\n`),
    simple(
      "scan.every-form",
      [{ item: "K", value: escapedValue }],
      [escapedValue, json(escapedValue).replace(/\//g, "\\/"), encodeURIComponent(escapedValue), Buffer.from(`user:${escapedValue}`).toString("base64"), Buffer.from(`ab${escapedValue}`).toString("base64url")].join(" | "),
    ),
    simple("scan.nested-url", [{ item: "DATABASE_URL", value: "postgres://app:hunter2-hunter2@db/app" }, { item: "DB_PASS", value: "hunter2-hunter2" }], "url=postgres://app:hunter2-hunter2@db/app"),
    simple("scan.twins", [{ item: "BETA", value: "same-value-1234" }, { item: "ALPHA", value: "same-value-1234" }], "x same-value-1234 y"),
    simple("scan.pem", [{ item: "TLS_KEY", value: pem }], `header\n${pem}\ntrailer\n`),
    simple("scan.no-prefix", api, "nothing here\n"),
    simple("scan.short-and-long", [{ item: "PIN", value: "1234567" }, { item: "API_KEY", value: "valueaaaaaaaaaaaaa" }], "1234567 1234567 valueaaaaaaaaaaaaa"),
    simple("scan.surrogate-json-and-raw", [{ item: "KEY", value: LONE }], `{"key":"${json(LONE)}"}\nKEY=${bytes(LONE).toString("utf8")}\n`),
  ];
}

/** redact.test.ts's inputs, as stream cases. */
function redactCases(): Case[] {
  const binary = Uint8Array.from([0x1f, 0x8b, 0x08, 0xff, 0x00, 0x80, 0xc3]);
  const token = [{ item: "API_TOKEN", value: "tokenvalue-aaaaaaaa" }];
  const pass = `p${c(0xe4)}ssword-XYZ-123`;
  const out: Case[] = [
    simple("redact.binary-none", [], binary),
    simple("redact.binary-absent", token, binary),
    { name: "redact.binary-value", entries: token, parts: [{ bytes: binary }, { text: "tokenvalue-aaaaaaaa" }, { bytes: binary }, { bytes: Uint8Array.from([0xc3]) }] },
    { name: "redact.every-byte", entries: [{ item: "K", value: "tokenvalue-aaaaaaaa" }], parts: [{ bytes: Uint8Array.from({ length: 256 }, (_, i) => i), repeat: 4 }] },
    simple("redact.multibyte-split", [{ item: "DB_PASS", value: pass }], `token=${pass}\n`),
    simple("redact.multibyte-around", [{ item: "DB_PASS", value: pass }], `${c(0xfc)}n${c(0xef)} ${c(0x2713)} ${pass} ${c(0x1f441)} ${c(0xe9)}`),
    simple("redact.long-prefix-end", [{ item: "API_TOKEN", value: "super-secret-token-12345" }], "log line\nsuper-secret-token-1234"),
  ];
  const wrappers: [string, string, string][] = [
    ["eye", `${c(0x1f441)} `, ` ${c(0x1f441)}`],
    ["eye-tight", c(0x1f441), c(0x1f441)],
    ["marker", "[REDACTED:API_TOKEN]", "[REDACTED:API_TOKEN]"],
    ["marker-open", "[REDACTED:", ""],
    ["ansi", `${c(0x1b)}[31m`, `${c(0x1b)}[0m`],
    ["osc", `${c(0x1b)}]0;title${c(7)}`, `${c(0x1b)}]0;title${c(7)}`],
    ["nul", c(0), c(0)],
    ["zwj", c(0x200d), c(0x200d)],
    ["ci", "::stop-commands::x\n", "\n::x::"],
    ["backslash", "\\", "\\"],
  ];
  for (const [name, before, after] of wrappers) out.push(simple(`redact.wrapper.${name}`, token, `${before}tokenvalue-aaaaaaaa${after}`));
  const quoted = 'quo"te\\slash-1';
  const multiline = "line-one\nline-two";
  const symbols = "us@er/pa+ss=wd&x";
  const entries = [{ item: "QUOTED", value: quoted }, { item: "MULTILINE", value: multiline }, { item: "SYMBOLS", value: symbols }];
  for (const { item, value } of entries) {
    out.push(simple(`redact.encoded.${item}.raw`, entries, value));
    out.push(simple(`redact.encoded.${item}.json`, entries, `{"v":"${json(value)}"}`));
    out.push(simple(`redact.encoded.${item}.json-slash`, entries, `{"v":"${json(value).replace(/\//g, "\\/")}"}`));
    out.push(simple(`redact.encoded.${item}.percent`, entries, `?v=${encodeURIComponent(value)}&`));
    out.push(simple(`redact.encoded.${item}.percent-lower`, entries, `?v=${encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, (e) => e.toLowerCase())}&`));
    for (const encoding of ["base64", "base64url"] as const) {
      for (const lead of ["", "u", "us"]) {
        out.push(simple(`redact.encoded.${item}.${encoding}.${lead.length}`, entries, `Basic ${Buffer.from(`${lead}${value}:tail`).toString(encoding)}\n`));
      }
    }
  }
  const a = "abcdefXYZ123";
  const b = "XYZ123uvwxyz";
  out.push(simple("redact.overlap.a-first", [{ item: "A", value: a }, { item: "B", value: b }], `<${a.slice(0, 6)}${b}>`));
  out.push(simple("redact.overlap.b-first", [{ item: "B", value: b }, { item: "A", value: a }], `<${a.slice(0, 6)}${b}>`));
  out.push(simple("redact.short", [{ item: "SHORT_REF", value: "q7" }, { item: "SHORT_ID", value: "k9" }, { item: "SEVEN", value: "1234567" }], "the fox exited; ref q7; id k9; pin 1234567"));
  out.push(simple("redact.bytes-not-chars", [{ item: "EIGHT", value: "12345678" }, { item: "FOUR_CHARS", value: c(0xe4, 0xe4, 0xe4, 0xe4) }], `x 12345678 ${c(0xe4, 0xe4, 0xe4, 0xe4)} y`));
  return out;
}

/** Seeded adversarial inputs: overlaps, encodings, Unicode, binary. */
function fuzzCases(): Case[] {
  const out: Case[] = [];
  // Overlapping Secrets over a small alphabet (matcher.test.ts test 34, scanner's).
  for (let seed = 1; seed <= 120; seed++) {
    const r = rng(seed);
    const alphabet = ["a", "b", "c", c(0xe9), "/", '"', " ", "\n"];
    const word = (min: number, max: number) => {
      let w = "";
      const n = min + Math.floor(r() * (max - min + 1));
      while (w.length < n) w += alphabet[Math.floor(r() * alphabet.length)]!;
      return w;
    };
    const entries = Array.from({ length: 1 + Math.floor(r() * 4) }, (_, i) => ({ item: `S${i}`, value: word(8, 14) }));
    let input = "";
    while (input.length < 80) input += r() < 0.4 ? entries[Math.floor(r() * entries.length)]!.value : word(1, 6);
    out.push(simple(`fuzz.overlap.${seed}`, entries, input));
  }
  // Every encoded form, inserted whole or cut, among multi-byte text (redact.test.ts's fuzzing, wider).
  const wide = ["a", "b", "z", "0", " ", "/", '"', "\n", "\\", "+", "=", "&", "%", c(0xe9), c(0xdf), c(0x2713), c(0x20ac), c(0x1f441), c(0x1d11e)];
  const encodings = (value: string) => {
    const raw = bytes(value);
    // Percent-encoding carries the delivered text (a lone surrogate as U+FFFD), as the matcher registers it.
    const delivered = raw.toString("utf8");
    const forms = [json(value), json(value).replace(/\//g, "\\/"), encodeURIComponent(delivered), encodeURIComponent(delivered).replace(/%[0-9A-F]{2}/g, (e) => e.toLowerCase())];
    for (const lead of ["", "u", "us"]) {
      const enc = Buffer.concat([bytes(lead), raw, bytes(":t")]);
      forms.push(enc.toString("base64"), enc.toString("base64url"));
    }
    return forms;
  };
  for (let seed = 1; seed <= 120; seed++) {
    const r = rng(seed * 7919);
    const word = (min: number, max: number) => {
      let w = "";
      const n = min + Math.floor(r() * (max - min + 1));
      for (let i = 0; i < n; i++) w += wide[Math.floor(r() * wide.length)]!;
      return w;
    };
    const entries = Array.from({ length: 1 + Math.floor(r() * 4) }, (_, i) => ({ item: `S${i}`, value: word(3, 12) }));
    if (seed % 10 === 0) entries.push({ item: "LONE", value: `x${c(0xd800)}${word(6, 8)}${c(0xdfff)}` });
    let text = "";
    while (bytes(text).length < 120) {
      const pick = entries[Math.floor(r() * entries.length)]!.value;
      const roll = r();
      if (roll < 0.2) text += pick;
      else if (roll < 0.4) {
        const forms = encodings(pick);
        text += forms[Math.floor(r() * forms.length)];
      } else if (roll < 0.5) text += pick.slice(0, 1 + Math.floor(r() * Math.max(1, pick.length - 1)));
      else text += word(1, 6);
    }
    out.push(simple(`fuzz.encoded.${seed}`, entries, text));
  }
  // Binary input with Secrets inside, cut through characters.
  for (let seed = 1; seed <= 30; seed++) {
    const r = rng(seed * 104729);
    const value = `bin-${seed}-${Math.floor(r() * 1e9).toString(36)}-v`;
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < 6; i++) {
      chunks.push(Uint8Array.from({ length: 1 + Math.floor(r() * 20) }, () => Math.floor(r() * 256)));
      if (r() < 0.6) chunks.push(bytes(r() < 0.5 ? value : value.slice(0, 5)));
    }
    out.push({ name: `fuzz.binary.${seed}`, entries: [{ item: "BIN", value }], parts: chunks.map((b) => ({ bytes: b })) });
  }
  return out;
}

/** Many Secrets, and long inputs. */
function scaleCases(): Case[] {
  const many = Array.from({ length: 400 }, (_, i) => ({ item: `ITEM_${String(i).padStart(3, "0")}`, value: `secret-${String(i).padStart(3, "0")}-${(i * 2654435761 >>> 0).toString(36)}` }));
  const r = rng(424242);
  let manyInput = "";
  for (let i = 0; i < 300; i++) manyInput += r() < 0.5 ? many[Math.floor(r() * many.length)]!.value + " " : `secret-${Math.floor(r() * 999)} `;
  const emoji = c(0x1f511).repeat(3) + "-key-" + c(0x1f511);
  return [
    simple("scale.many-secrets", many, manyInput),
    { name: "long.chain", entries: [{ item: "P", value: "abababab" }], parts: [{ text: "start " }, { text: "ab", repeat: 60_000 }, { text: " end" }] },
    { name: "long.same-byte", entries: [{ item: "A", value: "aaaaaaaa" }], parts: [{ text: "a", repeat: 100_000 }] },
    { name: "long.never-completes", entries: [{ item: "A", value: "aaaaaaaab" }], parts: [{ text: "a", repeat: 100_000 }] },
    { name: "long.held-prefixes", entries: [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }], parts: [{ text: "valueaaaaaa x ", repeat: 10_000 }] },
    { name: "long.secrets-everywhere", entries: [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }, { item: "B", value: "aaaaaaaaaaaaZZ" }], parts: [{ text: "valueaaaaaaaaaaaaaZZ|", repeat: 8_000 }] },
    { name: "long.unicode", entries: [{ item: "K", value: emoji }], parts: [{ text: `${c(0x1f511)}${emoji}${c(0xe9)}`, repeat: 5_000 }] },
    { name: "long.many-secrets", entries: many, parts: [{ text: manyInput, repeat: 40 }] },
  ];
}

// --- recording ------------------------------------------------------------------------

const marker = redactionMarker;

function streamThrough(entries: SecretEntry[], input: Buffer, cuts: number[]) {
  const matcher = new StreamMatcher(entries, marker);
  const steps: { out: Buffer; held: number; pending: number; hold: number }[] = [];
  let at = 0;
  for (const cut of [...cuts, input.length]) {
    const out = Buffer.from(matcher.push(input.subarray(at, cut)));
    at = cut;
    expect(matcher.pendingRegions).toBeLessThanOrEqual(1 + Math.floor(matcher.hold / 8));
    steps.push({ out, held: matcher.heldBytes, pending: matcher.pendingRegions, hold: matcher.hold });
  }
  const end = matcher.end();
  return { steps, end, matcher, output: Buffer.concat([...steps.map((s) => s.out), Buffer.from(end.output)]) };
}

function scanThrough(entries: SecretEntry[], input: Buffer, cuts: number[]) {
  const scanner = new StreamScanner(entries);
  const steps: Occurrence[][] = [];
  let at = 0;
  for (const cut of [...cuts, input.length]) {
    steps.push(scanner.push(input.subarray(at, cut)));
    at = cut;
  }
  return { steps, end: scanner.end(), scanner };
}

const occ = (o: Occurrence) => [o.entry, o.form, o.start, o.end];
const occKey = (o: Occurrence) => `${o.start}:${o.end}:${o.entry}:${o.form}`;
const occHash = (list: Occurrence[]) => sha(list.map(occKey).sort().join("\n"));

function randomCuts(r: () => number, length: number, count: number): number[] {
  const cuts = new Set<number>();
  for (let i = 0; i < count && length > 1; i++) cuts.add(1 + Math.floor(r() * (length - 1)));
  return [...cuts].sort((x, y) => x - y);
}

function record(k: Case, index: number) {
  const input = assemble(k.parts);
  const long = input.length > 4096;
  const whole = streamThrough(k.entries, input, []);
  // The whole-input reference and the stream agree.
  expect(whole.output.equals(Buffer.from(scrubWhole(input, k.entries, marker))), k.name).toBe(true);
  if (input.length <= EVERY_SPLIT) {
    for (let cut = 1; cut < input.length; cut++) expect(streamThrough(k.entries, input, [cut]).output.equals(whole.output), `${k.name} at ${cut}`).toBe(true);
  }
  const r = rng(1000 + index);
  const chunkings: number[][] = [];
  // Byte by byte for the hand-written cases (the Go test splits every case
  // at every byte itself, against the recorded output); random cuts for all.
  const fuzz = k.name.startsWith("fuzz.");
  if (!fuzz && input.length <= 96) chunkings.push(Array.from({ length: Math.max(0, input.length - 1) }, (_, i) => i + 1));
  for (let i = 0; i < (fuzz ? 2 : 3); i++) chunkings.push(randomCuts(r, input.length, long ? 60 : 1 + Math.floor(r() * 10)));
  const recorded = chunkings.map((cuts) => {
    const run = streamThrough(k.entries, input, cuts);
    expect(run.output.equals(whole.output), `${k.name} chunked`).toBe(true);
    return long
      ? { cuts }
      : { cuts, steps: run.steps.map((s) => ({ out: b64(s.out), held: s.held, pending: s.pending, hold: s.hold })), end: b64(Buffer.from(run.end.output)) };
  });
  const scanWhole = scanThrough(k.entries, input, []);
  const occurrences = scanWhole.steps.flat();
  expect(occurrences.map(occKey).sort()).toEqual(findWhole(input, k.entries).map(occKey).sort());
  const scanChunkings = recorded.map(({ cuts }) => {
    const run = scanThrough(k.entries, input, cuts);
    expect(run.steps.flat().map(occKey).sort()).toEqual(occurrences.map(occKey).sort());
    return long ? { cuts } : { cuts, steps: run.steps.map((s) => s.map(occ)) };
  });
  const replaced = Object.fromEntries([...whole.matcher.replaced.entries()].sort(([a], [b]) => (a < b ? -1 : 1)));
  return {
    name: k.name,
    entries: k.entries.map((e) => ({ item: e.item, value: e.value })),
    parts: k.parts.map((p) => ({ base64: b64(partBytes(p)), ...(p.repeat ? { repeat: p.repeat } : {}) })),
    ...(long ? { outputSha256: sha(whole.output), outputLength: whole.output.length } : { output: b64(whole.output) }),
    skipped: whole.matcher.skipped,
    replaced,
    incompletePrefix: whole.end.incompletePrefix,
    chunkings: recorded,
    scan: {
      ...(long ? { occurrencesSha256: occHash(occurrences), occurrenceCount: occurrences.length } : { occurrences: occurrences.map(occ) }),
      end: scanWhole.end.incompletePrefix,
      skipped: scanWhole.scanner.skipped,
      skippedEntries: scanWhole.scanner.skippedEntries,
      maxLength: scanWhole.scanner.maxLength,
      chunkings: scanChunkings,
    },
  };
}

// --- redaction relays -----------------------------------------------------------------

interface RelayCase {
  name: string;
  entries: SecretEntry[];
  mode: RedactionMode;
  interrupt?: boolean;
  streams: { chunks: Uint8Array[]; fail?: boolean }[];
}

function sink() {
  const chunks: Buffer[] = [];
  const dest = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  return { dest, output: () => Buffer.concat(chunks) };
}

function source(chunks: Uint8Array[], fail: boolean): Readable {
  async function* generate() {
    for (const chunk of chunks) yield Buffer.from(chunk);
    if (fail) throw new Error("read failed");
  }
  return Readable.from(generate());
}

async function relayCase(k: RelayCase) {
  const redaction = new OutputRedaction(k.entries, k.mode);
  if (k.interrupt) redaction.interrupt();
  const sinks = k.streams.map(() => sink());
  await redaction.relay(k.streams.map((s, i) => [source(s.chunks, s.fail ?? false), sinks[i]!.dest]));
  return {
    name: k.name,
    entries: k.entries,
    mode: k.mode,
    ...(k.interrupt ? { interrupt: true } : {}),
    notices: redaction.notices(),
    skipped: redaction.skipped,
    streams: k.streams.map((s, i) => ({ chunks: s.chunks.map(b64), ...(s.fail ? { fail: true } : {}), output: b64(sinks[i]!.output()) })),
  };
}

function relayCases(): RelayCase[] {
  const value = "super-secret-token-12345";
  const token = [{ item: "API_TOKEN", value }];
  const parts = (...s: string[]) => s.map(bytes);
  const short = [{ item: "SHORT_REF", value: "q7" }, { item: "SHORT_ID", value: "k9" }, { item: "SEVEN", value: "1234567" }];
  return [
    { name: "relay.split", entries: token, mode: "redact", streams: [{ chunks: parts("token=su", value.slice(2, 11), `${value.slice(11)}\n`) }] },
    { name: "relay.held-at-clean-end", entries: token, mode: "redact", streams: [{ chunks: parts(`log line\n${value.slice(0, -1)}`) }] },
    { name: "relay.interrupted-discards-held", entries: token, mode: "redact", interrupt: true, streams: [{ chunks: parts(`log line\n${value.slice(0, -1)}`) }] },
    { name: "relay.interrupted-still-masks", entries: token, mode: "redact", interrupt: true, streams: [{ chunks: parts(`stopping: ${value}\n`) }] },
    { name: "relay.failing-stream", entries: token, mode: "redact", streams: [{ chunks: parts(`partial ${value.slice(0, 10)}`), fail: true }] },
    { name: "relay.two-streams", entries: token, mode: "redact", streams: [{ chunks: parts(`o ${value.slice(0, 5)}`, `${value.slice(5)} o\n`) }, { chunks: parts(`e ${value.slice(0, 8)}`) }] },
    { name: "relay.nothing-delivered", entries: [], mode: "redact", streams: [{ chunks: parts(`anything at all ${c(0x2713)}`) }] },
    { name: "relay.short-values", entries: short, mode: "redact", streams: [{ chunks: parts("the fox exited; ref q7; id k9; pin 1234567") }] },
    { name: "relay.assisted-short", entries: [...short, ...token], mode: "assisted", streams: [{ chunks: parts(`pin 1234567 ${value}`) }] },
    { name: "relay.assisted-none", entries: [], mode: "assisted", streams: [{ chunks: parts("clean") }] },
    { name: "relay.assisted-all-long", entries: token, mode: "assisted", streams: [{ chunks: parts(`${value} and ${value.slice(0, 7)}`) }, { chunks: parts(value) }] },
    { name: "relay.byte-by-byte", entries: token, mode: "redact", streams: [{ chunks: [...bytes(`x ${value} y ${value.slice(0, 9)}`)].map((b) => Uint8Array.of(b)) }] },
  ];
}

describe("Go CLI vectors: the matcher and output redaction", () => {
  it("matcher.json is packages/matcher's and redact.ts's answers", async () => {
    const formValues = [
      'a/b"c d+e=f?',
      'a/b"c d+e=f?xyz',
      "plainvalue123",
      "1234567",
      "12345678",
      LONE,
      `paired-${c(0x1f600)}-ok`,
      `a/b"c d+e=f?${c(0x1f600)}`,
      `line-one\nline-two${c(0x2028)}${c(0x7f)}${c(1)}`,
      `${c(0xd800)}${c(0xdbff)}${c(0xdc00)}x-y/z`,
      `us@er/pa+ss=wd&x~*'()!-_.`,
      c(0xe4, 0xe4, 0xe4, 0xe4),
      "x".repeat(300),
    ];
    const forms = formValues.map((value) => ({ value, forms: labelledFormsOf(value).map((f) => ({ form: f.form, text: Buffer.from(f.bytes).toString("utf8") })) }));
    const cases = [...unitCases(), ...redactCases(), ...fuzzCases(), ...scaleCases()];
    expect(new Set(cases.map((k) => k.name)).size).toBe(cases.length);
    const relays = [];
    for (const k of relayCases()) relays.push(await relayCase(k));
    const vectors = {
      comment: "Generated by apps/cli/test/go-vectors-matcher.test.ts from packages/matcher and redact.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      minLength: MIN_LENGTH,
      forms,
      cases: cases.map(record),
      relays,
    };
    // One case per line: a large generated file, compact.
    const text = `{"comment":${JSON.stringify(vectors.comment)},"minLength":${vectors.minLength},"forms":${JSON.stringify(vectors.forms)},\n"cases":[\n${vectors.cases.map((k) => JSON.stringify(k)).join(",\n")}\n],\n"relays":[\n${vectors.relays.map((k) => JSON.stringify(k)).join(",\n")}\n]}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "matcher.json is stale: regenerate it (see this file's comment)").toBe(true);
  }, 600_000);
});
