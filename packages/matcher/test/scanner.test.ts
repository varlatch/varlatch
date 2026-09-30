// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  MIN_LENGTH,
  StreamMatcher,
  StreamScanner,
  findWhole,
  formsOf,
  labelledFormsOf,
  scrubWhole,
  type Occurrence,
  type SecretEntry,
} from "../src/index.js";

/**
 * The scanner is the reporting side of the shared matcher: the same forms,
 * minimum length, and automaton as `StreamMatcher`, reporting every complete
 * occurrence with its entry, form, and byte range instead of replacing it.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const bytes = (s: string) => enc.encode(s);
const text = (b: Uint8Array) => dec.decode(b);

type Found = Omit<Occurrence, "item"> & { item: string };

function key(o: Found): string {
  return `${o.start}:${o.end}:${o.entry}:${o.form}`;
}

function sorted(list: Found[]): string[] {
  return list.map(key).sort();
}

/** Scan `input` in the given chunks, then end cleanly. */
function scan(entries: SecretEntry[], input: Uint8Array, splits: number[], scanner = new StreamScanner(entries)) {
  const found: Occurrence[] = [];
  let at = 0;
  for (const cut of [...splits, input.length]) {
    const chunk = input.subarray(at, cut);
    const before = scanner.offset;
    const got = scanner.push(chunk);
    // Every occurrence completes inside the chunk that reported it.
    for (const o of got) {
      expect(o.end).toBeGreaterThan(before);
      expect(o.end).toBeLessThanOrEqual(before + chunk.length);
    }
    found.push(...got);
    at = cut;
  }
  return { found, end: scanner.end() };
}

/** Every single split point, plus byte by byte, must find what the whole-input search finds. */
function everySplit(entries: SecretEntry[], input: string): Found[] {
  const data = bytes(input);
  const expected = findWhole(data, entries);
  const runs = [scan(entries, data, []).found];
  for (let cut = 1; cut < data.length; cut++) runs.push(scan(entries, data, [cut]).found);
  runs.push(scan(entries, data, Array.from({ length: data.length - 1 }, (_, i) => i + 1)).found);
  for (const found of runs) expect(sorted(found)).toEqual(sorted(expected));
  return expected;
}

/** Scrub with the scanner's occurrences, using the scrubber's regions and tie-break. */
function scrubFromOccurrences(input: Uint8Array, found: Found[], replacement: (item: string) => Uint8Array): string {
  const matches = [...found].sort((a, b) => a.start - b.start || b.end - a.end);
  const regions: { start: number; end: number; members: Found[] }[] = [];
  for (const m of matches) {
    const last = regions[regions.length - 1];
    if (last && m.start < last.end) {
      last.end = Math.max(last.end, m.end);
      last.members.push(m);
    } else regions.push({ start: m.start, end: m.end, members: [m] });
  }
  const out: number[] = [];
  let at = 0;
  for (const region of regions) {
    for (; at < region.start; at++) out.push(input[at]!);
    const winner = [...region.members].sort(
      (a, b) =>
        a.start - b.start ||
        b.end - b.start - (a.end - a.start) ||
        Buffer.compare(Buffer.from(a.item), Buffer.from(b.item)),
    )[0]!;
    for (const b of replacement(winner.item)) out.push(b);
    at = region.end;
  }
  for (; at < input.length; at++) out.push(input[at]!);
  return text(Uint8Array.from(out));
}

describe("labelled forms", () => {
  it("names every form, and formsOf returns exactly the same bytes in the same order", () => {
    const value = 'a/b"c d+e=f?xyz';
    const labelled = labelledFormsOf(value);
    expect(labelled.map((f) => text(f.bytes))).toEqual(formsOf(value).map(text));
    const byText = new Map(labelled.map((f) => [text(f.bytes), f.form]));
    expect(byText.get(value)).toBe("raw");
    expect(byText.get('a/b\\"c d+e=f?xyz')).toBe("json");
    expect(byText.get('a\\/b\\"c d+e=f?xyz')).toBe("json");
    expect(byText.get("a%2Fb%22c%20d%2Be%3Df%3Fxyz")).toBe("percent");
    expect(byText.get("a%2fb%22c%20d%2be%3df%3fxyz")).toBe("percent");
    expect(new Set(labelled.map((f) => f.form))).toEqual(new Set(["raw", "json", "percent", "base64", "base64url"]));
  });

  it("reports the first name when two forms have the same bytes", () => {
    // No character needs escaping: raw, JSON, and percent are one form, named raw.
    const labelled = labelledFormsOf("plainvalue123");
    expect(labelled.filter((f) => text(f.bytes) === "plainvalue123").map((f) => f.form)).toEqual(["raw"]);
  });
});

describe("scanner occurrences at every split", () => {
  const entries = [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }];

  it("finds a value split across chunks, with its byte range", () => {
    const found = everySplit(entries, "token=valueaaaaaaaaaaaaa; ok");
    expect(found).toEqual([{ entry: 0, item: "API_KEY", form: "raw", start: 6, end: 24 }]);
  });

  it("finds a multi-byte value split inside a character", () => {
    const multi = [{ item: "DB_PASS", value: "pässword-XYZ-123" }];
    const found = everySplit(multi, "x=pässword-XYZ-123\n");
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ item: "DB_PASS", form: "raw", start: 2, end: 2 + bytes("pässword-XYZ-123").length });
  });

  it("finds every encoded form and names it", () => {
    const value = 'a???/value>>>"zz';
    const input = [
      value,
      JSON.stringify(value).slice(1, -1).replace(/\//g, "\\/"),
      encodeURIComponent(value),
      Buffer.from(`user:${value}`).toString("base64"),
      Buffer.from(`ab${value}`).toString("base64url"),
    ].join(" | ");
    const found = everySplit([{ item: "K", value }], input);
    expect(new Set(found.map((f) => f.form))).toEqual(new Set(["raw", "json", "percent", "base64", "base64url"]));
  });

  it("reports overlapping and nested occurrences of different Secrets separately", () => {
    const nested = [
      { item: "DATABASE_URL", value: "postgres://app:hunter2-hunter2@db/app" },
      { item: "DB_PASS", value: "hunter2-hunter2" },
    ];
    const found = everySplit(nested, "url=postgres://app:hunter2-hunter2@db/app");
    expect(found.map((f) => f.item).sort()).toEqual(["DATABASE_URL", "DB_PASS"]);
    const overlap = [
      { item: "A", value: "xxxxYYYY" },
      { item: "B", value: "YYYYzzzz" },
    ];
    expect(everySplit(overlap, "..xxxxYYYYzzzz..").map((f) => [f.item, f.start, f.end])).toEqual([
      ["A", 2, 10],
      ["B", 6, 14],
    ]);
  });

  it("reports the same value under two names as two occurrences", () => {
    const twins = [
      { item: "BETA", value: "same-value-1234" },
      { item: "ALPHA", value: "same-value-1234" },
    ];
    expect(everySplit(twins, "x same-value-1234 y").map((f) => f.item).sort()).toEqual(["ALPHA", "BETA"]);
  });

  it("finds a value spanning lines (a PEM body) as one occurrence", () => {
    // Assembled at runtime so that no source line is a key header.
    const label = ["PRIVATE", "KEY"].join(" ");
    const pem = `-----BEGIN ${label}-----\nFAKEKEYDATA0FAKEKEY\nFAKEKEYDATA1FAKEKEY\n-----END ${label}-----`;
    const found = everySplit([{ item: "TLS_KEY", value: pem }], `header\n${pem}\ntrailer\n`);
    expect(found.filter((f) => f.form === "raw")).toEqual([
      { entry: 0, item: "TLS_KEY", form: "raw", start: 7, end: 7 + pem.length },
    ]);
  });
});

describe("complete occurrences only", () => {
  const entries = [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }];

  it("a stream ending in a long prefix of a value reports no occurrence, only the prefix length", () => {
    const { found, end } = scan(entries, bytes("abc valueaaaaaaa"), [6]);
    expect(found).toEqual([]);
    expect(end.incompletePrefix).toEqual({ entry: 0, item: "API_KEY", length: "valueaaaaaaa".length });
  });

  it("a stream ending cleanly reports no prefix", () => {
    expect(scan(entries, bytes("nothing here\n"), []).end.incompletePrefix).toBeNull();
  });

  it("reset starts a new stream: offsets restart and no state carries over", () => {
    const scanner = new StreamScanner(entries);
    expect(scanner.push(bytes("valueaaaaa"))).toEqual([]);
    scanner.reset();
    // Without the reset, these bytes would complete the value.
    expect(scanner.push(bytes("aaaaaaaa"))).toEqual([]);
    expect(scanner.end().incompletePrefix).toBeNull();
    scanner.reset();
    expect(scanner.push(bytes("valueaaaaaaaaaaaaa")).map((o) => [o.start, o.end])).toEqual([[0, 18]]);
    const closed = new StreamScanner(entries);
    closed.end();
    expect(() => closed.push(bytes("x"))).toThrow();
    expect(() => closed.end()).toThrow();
  });
});

describe("short values", () => {
  it("are not registered and are named, like the scrubber's", () => {
    const entries = [
      { item: "PIN", value: "1234567" },
      { item: "API_KEY", value: "valueaaaaaaaaaaaaa" },
    ];
    const scanner = new StreamScanner(entries);
    expect(MIN_LENGTH).toBe(8);
    expect(scanner.skipped).toEqual(["PIN"]);
    expect(scanner.skippedEntries).toEqual([0]);
    expect(scanner.skipped).toEqual(new StreamMatcher(entries, bytes).skipped);
    expect(scanner.push(bytes("1234567 1234567"))).toEqual([]);
    expect(scanner.maxLength).toBe(Math.max(...formsOf("valueaaaaaaaaaaaaa").map((f) => f.length)));
  });
});

describe("the scanner finds exactly what the scrubber replaces", () => {
  function rng(seed: number) {
    let s = seed >>> 0;
    return () => {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 2 ** 32;
    };
  }
  const replacement = (item: string) => bytes(`<${item}>`);

  it("for random overlapping values and random chunkings", () => {
    const alphabet = ["a", "b", "c", "é", "/", '"', " ", "\n"];
    for (let seed = 1; seed <= 300; seed++) {
      const r = rng(seed);
      const pick = () => alphabet[Math.floor(r() * alphabet.length)]!;
      const word = (min: number, max: number) => {
        let w = "";
        const n = min + Math.floor(r() * (max - min + 1));
        while (w.length < n) w += pick();
        return w;
      };
      const entries: SecretEntry[] = Array.from({ length: 1 + Math.floor(r() * 4) }, (_, i) => ({
        item: `S${i}`,
        value: word(8, 14),
      }));
      let input = "";
      while (input.length < 80) {
        input += r() < 0.4 ? entries[Math.floor(r() * entries.length)]!.value : word(1, 6);
      }
      const data = bytes(input);
      const expected = findWhole(data, entries);
      for (let trial = 0; trial < 6; trial++) {
        const cuts = new Set<number>();
        for (let i = 0; i < 1 + Math.floor(r() * 8); i++) cuts.add(1 + Math.floor(r() * (data.length - 1)));
        const { found } = scan(entries, data, [...cuts].sort((a, b) => a - b));
        expect(sorted(found), `seed ${seed}`).toEqual(sorted(expected));
      }
      // The same matches drive the scrubber: replacing the scanner's
      // occurrences by the scrubber's rule gives the scrubber's output.
      const scrubbed = text(scrubWhole(data, entries, replacement));
      expect(scrubFromOccurrences(data, expected, replacement), `seed ${seed}`).toBe(scrubbed);
      const streamed = new StreamMatcher(entries, replacement);
      const out = Buffer.concat([streamed.push(data), streamed.end().output]);
      expect(text(out), `seed ${seed}`).toBe(scrubbed);
    }
  });
});

describe("a stored value with an unpaired surrogate", () => {
  it("is found in a file that holds it as JSON escapes, and as UTF-8 carries it", () => {
    const stored = "token-\uD83D-value-\uDE00-end";
    const escaped = JSON.stringify(stored).slice(1, -1);
    // Split at every offset, as every scanner test is.
    const found = everySplit([{ item: "KEY", value: stored }], `{"key":"${escaped}"}\nKEY=${text(bytes(stored))}\n`);
    expect(found.map((o) => o.form).sort()).toEqual(["json", "raw"]);
  });
});
