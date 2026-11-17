// SPDX-License-Identifier: Apache-2.0
/**
 * A differential fuzz of the Compose reader (ADR-0059 step 4.9a): mutants
 * of every classifyComposeUsage input the vectors hold (ts-exchanges.json),
 * with awkward characters and forms inserted or swapped in, each with this
 * package's verdict. go/lib/sync's TestComposeFuzzDifferential reads the
 * file and fails on any mutant where Go's verdict is more confident than
 * TypeScript's (the other way, unreadable in Go, is the safe side).
 * Opt-in, not part of CI:
 *
 *   VARLATCH_COMPOSE_FUZZ=<file> [VARLATCH_COMPOSE_FUZZ_SEED=1] [VARLATCH_COMPOSE_FUZZ_COUNT=6000] \
 *     pnpm --filter @varlatch/sync exec vitest run test/go-compose-fuzz.test.ts
 *   (cd go && VARLATCH_COMPOSE_FUZZ=<file> go test ./lib/sync -run TestComposeFuzzDifferential)
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, it } from "vitest";
import { classifyComposeUsage } from "../src/coolifyCompose.js";

const OUT = process.env.VARLATCH_COMPOSE_FUZZ;
const FILE = new URL("../../../go/lib/sync/testdata/ts-exchanges.json", import.meta.url);

type Encoded = unknown;

function encode(v: unknown): Encoded {
  if (v === undefined) return { $undefined: true };
  if (v instanceof Map) return { $map: [...v].map(([k, x]) => [encode(k), encode(x)]) };
  if (Array.isArray(v)) return v.map(encode);
  if (v !== null && typeof v === "object") {
    const out: Record<string, Encoded> = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = encode(x);
    return out;
  }
  return v;
}

function expandRuns(v: Encoded): string {
  if (typeof v === "string") return v;
  return ((v as { $cat: Encoded[] }).$cat)
    .map((part) => (typeof part === "string" ? part : (part as { $rep: [string, number] }).$rep[0].repeat((part as { $rep: [string, number] }).$rep[1])))
    .join("");
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

/** mulberry32: the same mutants for the same seed. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const AWKWARD = [
  // Line breaks of every kind, controls, byte order marks, surrogates.
  "\n", "\r\n", "\r", "\u0085", " ", " ", "\t", "\u000b", "\f", "\u0000", "\u001b", "\u007f", "\u0080", "\u009f",
  "﻿", "￾", "￿", "\ud800", "\udc00", " ", "　",
  // Indicators and properties.
  "\"", "'", "#", " #", " # c", "&a ", "*a", "!", "! ", "!!str ", "!!binary ", "!!merge ", "!e!x ", "%", "%YAML 1.2\n---\n", "%TAG ! x\n---\n",
  "<<: ", "<<: *a\n", "<<", "---", "\n---\n", "...", "\n...\n", "- ", "? ", ": ", ":", ",", "[", "]", "{", "}", "|", ">", "|-\n  x\n", ">\n  a\n  b\n",
  "|2\n   x\n", "\\", "\\\n", "@", "`", "~", "null", "yes", "0o17", "0x1F", ".inf",
  // Indentation and line structure.
  "        ", "\n        ", "\n  ", "\n\t", " \n", "\n\n",
  // Multi-line scalars and flow collections.
  "\"a\nb\"", "'a\nb'", "\"a\r\nb\"", "'a\r\n  b'", "\"a\\\n b\"", "a\n b", "{a: 1,\nb: 2}", "[x,\ny]", "{a: [1, {b: c}]}", "[[[[x]]]]",
  // Compose forms.
  "${FOO}", "$FOO", "$$FOO", "${FOO:-x}", "FOO", "FOO=x", "- FOO=x\n", "env_file: .env\n", "environment:\n  FOO: x\n", "services:\n  app:\n    image: x\n",
];

/** Inserted at a flow collection's delimiters: implicit and explicit keys, adjacent colons. */
const FLOW_PUNCTUATION = [
  ":", "?", ": ", " :", "?:", "::", ":,", "? ", "?,", "7:", ":x", "x:", "a:b", "? a", "? a: b", ": :", "{a:b}", "[a:b]", "{? a}", "{a: b:}", "{7:, x: y}",
];

function mutate(text: string, rand: () => number): string {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
  const at = () => Math.floor(rand() * (text.length + 1));
  let out = text;
  const n = 1 + Math.floor(rand() * 3);
  for (let k = 0; k < n; k++) {
    const i = Math.min(at(), out.length);
    const lines = out.split("\n");
    const li = Math.floor(rand() * lines.length);
    switch (Math.floor(rand() * 10)) {
      case 0:
      case 1:
        out = out.slice(0, i) + pick(AWKWARD) + out.slice(i);
        break;
      case 2:
        out = out.slice(0, i) + pick(AWKWARD) + out.slice(i + 1);
        break;
      case 3:
        out = out.slice(0, i) + out.slice(i + 1 + Math.floor(rand() * 3));
        break;
      case 4: // re-indent a line
        lines[li] = pick(["", " ", "  ", "   ", "    ", "      ", "\t", "          "]) + lines[li]!.trimStart();
        out = lines.join("\n");
        break;
      case 5: // join a line with the next
        if (li < lines.length - 1) lines.splice(li, 2, lines[li]! + pick(["", " ", "  "]) + lines[li + 1]!.trimStart());
        out = lines.join("\n");
        break;
      case 6: // split a line, the rest at another indentation
        out = out.slice(0, i) + pick(["\n", "\r\n", "\n ", "\n  ", "\n    ", "\n        "]) + out.slice(i);
        break;
      case 8:
      case 9: { // ':' and '?' at a flow collection's delimiters, keys and values
        const at = out.split("").flatMap((c, j) => ("{}[],".includes(c) ? [j] : [])); // UTF-16 units, as slice counts
        const j = at.length > 0 ? at[Math.floor(rand() * at.length)]! + (rand() < 0.5 ? 0 : 1) : i;
        out = out.slice(0, j) + pick(FLOW_PUNCTUATION) + out.slice(j);
        break;
      }
      default: // duplicate a line
        lines.splice(li, 0, lines[li]!);
        out = lines.join("\n");
    }
  }
  return out;
}

describe.skipIf(!OUT)("the Compose reader's differential fuzz", () => {
  it("writes mutants with this package's verdicts", () => {
    const root = JSON.parse(readFileSync(FILE, "utf8")) as { strings: Encoded[]; cases: Encoded[] };
    const table = root.strings.map(expandRuns);
    const seeds: [string, string, number, string[]][] = [];
    for (const packed of root.cases) {
      const c = unpack(packed, table) as { fn?: string; args?: unknown[] };
      const [raw, generated, version, names] = c.args ?? [];
      if (c.fn === "classifyComposeUsage" && typeof raw === "string" && typeof generated === "string" && typeof version === "number" && Array.isArray(names)) {
        seeds.push([raw, generated, version, names as string[]]);
      }
    }
    const rand = prng(Number(process.env.VARLATCH_COMPOSE_FUZZ_SEED ?? "1"));
    const count = Number(process.env.VARLATCH_COMPOSE_FUZZ_COUNT ?? "6000");
    const seen = new Set<string>();
    const mutants: Encoded[] = [];
    for (let tries = 0; mutants.length < count && tries < count * 4; tries++) {
      const [raw0, generated0, version, names0] = seeds[Math.floor(rand() * seeds.length)]!;
      const raw = rand() < 0.9 ? mutate(raw0, rand) : raw0;
      const generated = rand() < 0.2 ? mutate(generated0, rand) : generated0;
      const names = rand() < 0.3 ? [...names0, "FOO"] : names0;
      const key = JSON.stringify([raw, generated, version, names]);
      if (seen.has(key)) continue;
      seen.add(key);
      const m: Record<string, Encoded> = { raw, generated, version, names };
      try {
        m.result = encode(classifyComposeUsage(raw, generated, version, names));
      } catch (err) {
        m.throws = { name: (err as Error).name };
      }
      mutants.push(m);
    }
    writeFileSync(OUT!, JSON.stringify({ seeds: seeds.length, mutants }) + "\n");
  }, 600_000);
});
