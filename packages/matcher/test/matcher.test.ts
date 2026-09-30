// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { MIN_LENGTH, StreamMatcher, deliveredText, formsOf, scrubWhole, type SecretEntry } from "../src/index.js";

/**
 * ADR-0039 Decisions 17 to 19, and acceptance tests 31 to 35: forms,
 * overlap regions and the tie-break, the hold-back and its bound, the clean
 * end, and streaming-versus-whole-input equivalence.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const bytes = (s: string) => enc.encode(s);
const text = (b: Uint8Array) => dec.decode(b);
const replacement = (item: string) => bytes(`<${item}>`);

/** Stream `input` through a fresh matcher in the given chunk sizes, then end cleanly. */
function stream(entries: SecretEntry[], input: Uint8Array, splits: number[]) {
  const matcher = new StreamMatcher(entries, replacement);
  const parts: Uint8Array[] = [];
  let at = 0;
  for (const cut of [...splits, input.length]) {
    parts.push(matcher.push(input.subarray(at, cut)));
    at = cut;
    // ADR-0039 Decision 19: at most 1 + floor(d / 8) pending regions.
    expect(matcher.pendingRegions).toBeLessThanOrEqual(1 + Math.floor(matcher.hold / 8));
  }
  const end = matcher.end();
  parts.push(end.output);
  return { output: Buffer.concat(parts), end, matcher };
}

/** Every single split point, plus byte-by-byte, must give the reference output. */
function everySplit(entries: SecretEntry[], input: string) {
  const data = bytes(input);
  const expected = Buffer.from(scrubWhole(data, entries, replacement));
  const outputs = [stream(entries, data, []).output];
  for (let cut = 1; cut < data.length; cut++) outputs.push(stream(entries, data, [cut]).output);
  outputs.push(stream(entries, data, Array.from({ length: data.length - 1 }, (_, i) => i + 1)).output);
  for (const output of outputs) expect(text(output)).toBe(text(expected));
  return text(expected);
}

describe("forms (Decision 17)", () => {
  it("covers raw, JSON-escaped (with and without \\/), percent, and base64/base64url at every alignment", () => {
    const value = 'a/b"c d+e=f?';
    const forms = formsOf(value).map(text);
    expect(forms).toContain(value);
    expect(forms).toContain('a/b\\"c d+e=f?');
    expect(forms).toContain('a\\/b\\"c d+e=f?');
    expect(forms).toContain("a%2Fb%22c%20d%2Be%3Df%3F");
    expect(forms).toContain("a%2fb%22c%20d%2be%3df%3f");
    // Inside a longer base64 string at any alignment, the value's core is found.
    for (const lead of ["", "x", "xy"]) {
      for (const encoding of ["base64", "base64url"] as const) {
        const encoded = Buffer.from(`${lead}${value}tail`).toString(encoding);
        expect(forms.some((f) => encoded.includes(f))).toBe(true);
      }
    }
  });

  it("finds user:secret inside a Basic header", () => {
    const secret = "valueaaaaaaaaaaaaa";
    const header = `Authorization: Basic ${Buffer.from(`user:${secret}`).toString("base64")}`;
    const scrubbed = text(scrubWhole(bytes(header), [{ item: "KEY", value: secret }], replacement));
    expect(scrubbed).toContain("<KEY>");
    expect(scrubbed).not.toContain(Buffer.from(`user:${secret}`).toString("base64"));
  });

  it("registers nothing for a value under 8 bytes, and names the item (test 35)", () => {
    expect(MIN_LENGTH).toBe(8);
    expect(formsOf("1234567")).toEqual([]);
    const matcher = new StreamMatcher([{ item: "SHORT", value: "1234567" }], replacement);
    expect(matcher.skipped).toEqual(["SHORT"]);
    const out = matcher.push(bytes("x1234567y"));
    expect(text(Buffer.concat([out, matcher.end().output]))).toBe("x1234567y");
  });
});

describe("a stored value with an unpaired surrogate", () => {
  // JSON can carry "\ud83d" alone; UTF-8 cannot, so every delivery replaces it with U+FFFD.
  const stored = "token-\uD83D-value-\uDE00-end";
  const delivered = "token-\uFFFD-value-\uFFFD-end";

  it("is registered as a command receives it, and no form throws", () => {
    expect(deliveredText(stored)).toBe(delivered);
    expect(deliveredText("paired-😀-ok")).toBe("paired-😀-ok");
    expect(() => formsOf(stored)).not.toThrow();
    const forms = formsOf(stored).map(text);
    expect(forms).toContain(delivered);
    expect(forms).toContain(encodeURIComponent(delivered));
    // Before the fix, the percent form threw while the matcher was built (the negative control).
    expect(() => encodeURIComponent(stored)).toThrow(URIError);
  });

  it("is masked in output a command writes from its environment, split anywhere", () => {
    // What a child writes: the stored value encoded to UTF-8, which replaces each surrogate.
    const child = `log ${text(bytes(stored))} done`;
    expect(child).toBe(`log ${delivered} done`);
    expect(everySplit([{ item: "TOKEN", value: stored }], child)).toBe("log <TOKEN> done");
  });
});

describe("streaming basics", () => {
  const entries = [{ item: "API_KEY", value: "valueaaaaaaaaaaaaa" }];

  it("relays clean input byte-exact, including multi-byte characters", () => {
    expect(everySplit(entries, "héllo wörld ✓ nothing secret here")).toBe("héllo wörld ✓ nothing secret here");
  });

  it("replaces a value split across chunks", () => {
    expect(everySplit(entries, "token=valueaaaaaaaaaaaaa; ok")).toBe("token=<API_KEY>; ok");
  });

  it("holds a possible prefix and never releases it without more input (no timer)", () => {
    const matcher = new StreamMatcher(entries, replacement);
    expect(text(matcher.push(bytes("abc valueaaaaaaa")))).toBe("abc ");
    // Nothing is released until more input arrives or the stream ends.
    expect(matcher.heldBytes).toBe("valueaaaaaaa".length);
  });

  it("abort discards held bytes and releases nothing", () => {
    const matcher = new StreamMatcher(entries, replacement);
    expect(text(matcher.push(bytes("abc valueaaaaaaa")))).toBe("abc ");
    matcher.abort();
    expect(() => matcher.end()).toThrow();
  });

  it("at a clean end, an incomplete prefix is released and reported by name and length", () => {
    const { output, end } = stream(entries, bytes("abc valueaaaaaaa"), [6]);
    expect(text(output)).toBe("abc valueaaaaaaa");
    expect(end.incompletePrefix).toEqual({ item: "API_KEY", length: "valueaaaaaaa".length });
  });
});

describe("adversarial overlaps at every split (test 31)", () => {
  it("a suffix of A equal to a prefix of B: one region, A's replacement", () => {
    const entries = [
      { item: "A", value: "xxxxYYYY" },
      { item: "B", value: "YYYYzzzz" },
    ];
    expect(everySplit(entries, "..xxxxYYYYzzzz..")).toBe("..<A>..");
  });

  it("B nested inside A: A's replacement", () => {
    const entries = [
      { item: "A", value: "outer-12345678-outer" },
      { item: "B", value: "12345678" },
    ];
    expect(everySplit(entries, "[outer-12345678-outer]")).toBe("[<A>]");
  });

  it("a longer match that starts earlier but completes later extends the region left", () => {
    const entries = [
      { item: "B", value: "bcdefghi" },
      { item: "A", value: "abcdefghij" },
    ];
    expect(everySplit(entries, "-abcdefghij-")).toBe("-<A>-");
  });

  it("touching matches stay two regions", () => {
    const entries = [
      { item: "A", value: "AAAAAAAA" },
      { item: "B", value: "BBBBBBBB" },
    ];
    expect(everySplit(entries, "AAAAAAAABBBBBBBB")).toBe("<A><B>");
  });

  it("the same value under two names: the name that sorts first", () => {
    const entries = [
      { item: "ZETA", value: "same-value-1234" },
      { item: "ALPHA", value: "same-value-1234" },
    ];
    expect(everySplit(entries, "x same-value-1234 y")).toBe("x <ALPHA> y");
  });

  it("a raw form of one Secret overlapping the base64 form of another", () => {
    const b64 = Buffer.from("zzzzzzzzzzzz").toString("base64"); // enp6enp6enp6enp6
    const entries = [
      { item: "S2", value: "zzzzzzzzzzzz" },
      { item: "S1", value: `${b64.slice(-4)}ABCDEFGH` },
    ];
    expect(everySplit(entries, `>${b64}ABCDEFGH<`)).toBe(">" + "<S2>" + "<");
  });

  it("a chain of overlapping matches longer than any pattern: one region, bounded memory", () => {
    const entries = [{ item: "P", value: "abababab" }];
    const chain = "ab".repeat(60);
    const matcher = new StreamMatcher(entries, replacement);
    let emitted = "";
    for (const ch of `start ${chain}`) {
      emitted += text(matcher.push(bytes(ch)));
      expect(matcher.heldBytes).toBeLessThanOrEqual(8);
      expect(matcher.pendingRegions).toBeLessThanOrEqual(1 + Math.floor(matcher.hold / 8));
    }
    // Output stalls during the chain: nothing of it has been emitted.
    expect(emitted).toBe("start ");
    emitted += text(matcher.push(bytes(" end")));
    emitted += text(matcher.end().output);
    expect(emitted).toBe("start <P> end");
    expect(everySplit(entries, `start ${"ab".repeat(12)} end`)).toBe("start <P> end");
  });
});

describe("the clean end with a pending region (test 32)", () => {
  // A's tail `efgh` is also a proper prefix of B, so when the stream ends
  // right after A, A's region is still pending and the retained suffix lies
  // inside it.
  const entries = [
    { item: "A", value: "abcdefgh" },
    { item: "B", value: "efghijkl" },
  ];

  it("emits the region as its replacement and never re-emits covered bytes", () => {
    const input = bytes("hello abcdefgh");
    for (let cut = 0; cut <= input.length; cut++) {
      const { output, end } = stream(entries, input, cut === 0 || cut === input.length ? [] : [cut]);
      expect(text(output)).toBe("hello <A>");
      expect(text(output)).not.toContain("efgh");
      expect(end.incompletePrefix).toEqual({ item: "B", length: 4 });
    }
  });

  it("before the end, the pending region is not emitted", () => {
    const matcher = new StreamMatcher(entries, replacement);
    expect(text(matcher.push(bytes("hello abcdefgh")))).toBe("hello ");
    expect(matcher.pendingRegions).toBe(1);
    expect(matcher.hold).toBe(4);
  });
});

describe("the pending-region bound and the exact tie-break (test 33)", () => {
  it("a region that begins before the retained suffix, continued and diverging", () => {
    const entries = [
      { item: "A", value: "0123456789" },
      { item: "B", value: "89abcdefgh" },
    ];
    const matcher = new StreamMatcher(entries, replacement);
    expect(text(matcher.push(bytes("0123456789")))).toBe("");
    // The region [0, 10) is pending, and begins 8 bytes before the retained suffix `89`.
    expect(matcher.hold).toBe(2);
    expect(matcher.pendingRegions).toBe(1);
    expect(everySplit(entries, "0123456789abcdefgh!")).toBe("<A>!");
    expect(everySplit(entries, "0123456789zz")).toBe("<A>zz");
    expect(everySplit(entries, "0123456789")).toBe("<A>");
  });

  it("reaches but never exceeds 1 + floor(d / 8) pending regions", () => {
    // Seven touching 8-byte Secrets form the prefix of a longer one, so all
    // seven regions stay pending inside the retained suffix.
    const parts = ["AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDDDDDD", "EEEEEEEE", "FFFFFFFF", "GGGGGGGG"];
    const entries = [
      ...parts.map((value, i) => ({ item: `S${i}`, value })),
      { item: "LONG", value: `${parts.join("")}!` },
    ];
    const matcher = new StreamMatcher(entries, replacement);
    let max = 0;
    for (const ch of parts.join("")) {
      matcher.push(bytes(ch));
      max = Math.max(max, matcher.pendingRegions);
      expect(matcher.pendingRegions).toBeLessThanOrEqual(1 + Math.floor(matcher.hold / 8));
    }
    expect(max).toBe(7);
    expect(text(matcher.end().output)).toBe(parts.map((_, i) => `<S${i}>`).join(""));
  });

  it("same start, different completion times: the longest wins", () => {
    const entries = [
      { item: "SHORT", value: "abcdefgh" },
      { item: "LONG", value: "abcdefghij" },
    ];
    expect(everySplit(entries, "<abcdefghij>")).toBe("<<LONG>>");
  });

  it("one match spanning two pending regions merges all three; the minimum key wins", () => {
    const entries = [
      { item: "R1", value: "11111111" },
      { item: "R2", value: "22222222" },
      { item: "SPAN", value: "11112222222233" },
      { item: "PREFIX", value: "1111111122222222333333" },
    ];
    // R1 and R2 touch and stay pending (they prefix PREFIX); SPAN overlaps both.
    expect(everySplit(entries, "1111111122222222333!")).toBe("<R1>3!");
  });
});

describe("streaming equals the whole-input reference (test 34)", () => {
  // A seeded generator, so a failure reproduces.
  function rng(seed: number) {
    let s = seed >>> 0;
    return () => {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 2 ** 32;
    };
  }

  it("for random overlapping patterns and every chunking", () => {
    const alphabet = ["a", "b", "c", "é", "/", '"', " "];
    for (let seed = 1; seed <= 300; seed++) {
      const r = rng(seed);
      const pick = () => alphabet[Math.floor(r() * alphabet.length)]!;
      const word = (min: number, max: number) => {
        let w = "";
        const n = min + Math.floor(r() * (max - min + 1));
        while (w.length < n) w += pick();
        return w;
      };
      // Secrets share a small alphabet, so overlaps are forced.
      const entries: SecretEntry[] = Array.from({ length: 1 + Math.floor(r() * 4) }, (_, i) => ({
        item: `S${i}`,
        value: word(8, 14),
      }));
      let input = "";
      while (input.length < 80) {
        input += r() < 0.4 ? entries[Math.floor(r() * entries.length)]!.value : word(1, 6);
      }
      const data = bytes(input);
      const expected = text(scrubWhole(data, entries, replacement));
      // Random chunkings, and byte by byte.
      for (let trial = 0; trial < 6; trial++) {
        const cuts = new Set<number>();
        for (let i = 0; i < 1 + Math.floor(r() * 8); i++) cuts.add(1 + Math.floor(r() * (data.length - 1)));
        const { output } = stream(entries, data, [...cuts].sort((a, b) => a - b));
        expect(text(output), `seed ${seed}`).toBe(expected);
      }
      const byteByByte = stream(entries, data, Array.from({ length: data.length - 1 }, (_, i) => i + 1));
      expect(text(byteByByte.output), `seed ${seed}`).toBe(expected);
      // No registered raw value survives.
      for (const { value } of entries) expect(expected.includes(value), `seed ${seed}`).toBe(false);
    }
  });

  it("clean input arrives byte-exact under every chunking", () => {
    const entries = [{ item: "K", value: "never-present-9999" }];
    const input = "ünïcödé text with never-present-999 almost-prefixes never-present-99";
    expect(everySplit(entries, input)).toBe(input);
  });
});
