// SPDX-License-Identifier: Apache-2.0
import { Readable, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { MIN_LENGTH, formsOf, scrubWhole, type SecretEntry } from "@varlatch/matcher";
import { OutputRedaction, deliveredSecrets, redactRefusal, redactionMarker } from "../src/redact.js";
import { runStrict } from "../src/strictRun.js";

/**
 * Output redaction for `varlatch run --redact`: the required regression
 * cases A-R1 to A-R8 and seeded fuzzing, against the shared matcher through
 * the same relay the run uses. The spawned end-to-end cases are in
 * redact-run.test.ts.
 */

const bytes = (s: string) => Buffer.from(s, "utf8");
const marker = (item: string) => `[REDACTED:${item}]`;

/** A destination that records what it receives. */
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

/** Relay chunks with exactly these boundaries through redaction, to a clean end. */
async function relay(entries: SecretEntry[], chunks: Uint8Array[]): Promise<Buffer> {
  const redaction = new OutputRedaction(entries);
  const { dest, output } = sink();
  // Object mode keeps every chunk boundary as given.
  await redaction.relay([[Readable.from(chunks.map((c) => Buffer.from(c))), dest]]);
  return output();
}

function cut(input: Uint8Array, at: number[]): Uint8Array[] {
  const parts: Uint8Array[] = [];
  let from = 0;
  for (const to of [...at, input.length]) {
    parts.push(input.subarray(from, to));
    from = to;
  }
  return parts;
}

/** Every single split offset, and byte by byte, must give `expected`. */
async function everySplit(entries: SecretEntry[], input: Uint8Array, expected: Uint8Array): Promise<void> {
  expect(Buffer.from(await relay(entries, [input]))).toEqual(Buffer.from(expected));
  for (let at = 1; at < input.length; at++) {
    expect(Buffer.from(await relay(entries, cut(input, [at]))), `split at ${at}`).toEqual(Buffer.from(expected));
  }
  const byteByByte = cut(
    input,
    Array.from({ length: Math.max(0, input.length - 1) }, (_, i) => i + 1),
  );
  expect(Buffer.from(await relay(entries, byteByByte))).toEqual(Buffer.from(expected));
}

/** A source whose next chunk waits for the test. */
function gatedSource() {
  const queue: (Buffer | null)[] = [];
  let wake: (() => void) | null = null;
  async function* generate() {
    for (;;) {
      while (queue.length === 0) await new Promise<void>((resolve) => (wake = resolve));
      const next = queue.shift()!;
      if (next === null) return;
      yield next;
    }
  }
  const push = (chunk: Buffer | null) => {
    queue.push(chunk);
    wake?.();
    wake = null;
  };
  return { source: Readable.from(generate()), push };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("the redaction set", () => {
  it("is exactly the sensitive values delivered in the child's environment", () => {
    const items = [
      { name: "DELIVERED", sensitive: true, value: "delivered-value-1" },
      { name: "PLAIN", sensitive: false, value: "plain-value-12345" },
      { name: "WITHHELD", sensitive: true, value: null },
      { name: "INHERITED", sensitive: true, value: "stored-value-9999" },
    ];
    // WITHHELD and INHERITED reach the child from the parent environment, not from Varlatch.
    const env = { DELIVERED: "delivered-value-1", PLAIN: "plain-value-12345", WITHHELD: "from-the-shell", INHERITED: "from-the-shell" };
    expect(deliveredSecrets(items, env)).toEqual([{ item: "DELIVERED", value: "delivered-value-1" }]);
  });

  it("in a strict run, only Secrets the strict retrieval delivered: not inherited, withheld, or default values", async () => {
    const item = (name: string, fields: Record<string, unknown> = {}) => ({
      name,
      required: { kind: "never" },
      sensitive: true,
      type: "string",
      ...fields,
    });
    const stored = [
      { name: "DELIVERED", sensitive: true, value: "delivered-value-1" },
      { name: "OUTSIDE", sensitive: true, value: "outside-contract-1" },
      { name: "PLAIN", sensitive: false, value: "plain-value-12345" },
      { name: "WITHHELD", sensitive: true, value: null },
    ].map((i) => ({ ...i, source: "self", versionId: `ver_${i.name}` }));
    const retrieval = {
      environmentId: "env_1",
      manifest: {
        manifestVersion: 1,
        projectId: "prj_1",
        environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
        contract: { revisionId: "rev_1", contentHash: "sha256:abc", semanticsVersion: 2 },
        items: stored.map((i) => ({ name: i.name, source: i.source, valueRowId: `val_${i.name}`, versionId: i.versionId })),
      },
      stateDigest: `sha256:${"0".repeat(64)}`,
      contract: {
        schemaVersion: 1,
        semanticsVersion: 2,
        items: [item("DELIVERED"), item("PLAIN", { sensitive: false }), item("WITHHELD"), item("DEFAULTED", { defaultValue: "default-value-1" })],
      },
      items: stored,
      callerView: { withheld: [{ name: "WITHHELD", reason: "permission", requires: "secret.reveal" }], unexpanded: [], contractWithheld: false },
      validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
    };
    let received: SecretEntry[] = [];
    const code = await runStrict(
      {
        meta: async () => ({ serverVersion: "0.11.0", capabilities: ["retrieval.strict"] }),
        strictRetrieval: async () => retrieval as never,
      },
      {
        organization: "acme",
        project: "web",
        environment: "development",
        allowInherited: ["WITHHELD"],
        parent: { WITHHELD: "inherited-value-1" },
        start: async (env, secrets) => {
          expect(env.WITHHELD).toBe("inherited-value-1");
          expect(env.DEFAULTED).toBe("default-value-1");
          received = secrets;
          return 0;
        },
        log: () => {},
      },
    );
    expect(code).toBe(0);
    expect(received).toEqual([
      { item: "DELIVERED", value: "delivered-value-1" },
      { item: "OUTSIDE", value: "outside-contract-1" },
    ]);
  });

  it("the replacement is the item's name only", () => {
    expect(Buffer.from(redactionMarker("API_TOKEN")).toString()).toBe("[REDACTED:API_TOKEN]");
  });
});

describe("A-R1: binary output is byte-exact", () => {
  const binary = Uint8Array.from([0x1f, 0x8b, 0x08, 0xff, 0x00, 0x80, 0xc3]);

  it("with no registered values, at every split", async () => {
    await everySplit([], binary, binary);
  });

  it("with registered values that do not occur, at every split", async () => {
    await everySplit([{ item: "API_TOKEN", value: "tokenvalue-aaaaaaaa" }], binary, binary);
  });

  it("with a value inside binary data: only the value is replaced", async () => {
    const value = "tokenvalue-aaaaaaaa";
    const input = Buffer.concat([binary, bytes(value), binary, Buffer.from([0xc3])]);
    const expected = Buffer.concat([binary, bytes(marker("API_TOKEN")), binary, Buffer.from([0xc3])]);
    await everySplit([{ item: "API_TOKEN", value }], input, expected);
  });

  it("every byte value passes through unchanged", async () => {
    const all = Uint8Array.from({ length: 256 * 4 }, (_, i) => i % 256);
    expect(Buffer.from(await relay([{ item: "K", value: "tokenvalue-aaaaaaaa" }], cut(all, [1, 7, 255, 256, 700])))).toEqual(
      Buffer.from(all),
    );
  });
});

describe("A-R2: a multi-byte value split inside a character", () => {
  const value = "pässword-XYZ-123";
  const entries = [{ item: "DB_PASS", value }];

  it("is masked when the write boundary falls between c3 and a4", async () => {
    const input = bytes(`token=${value}\n`);
    const inside = input.indexOf(0xc3) + 1;
    expect(input[inside]).toBe(0xa4);
    const out = await relay(entries, cut(input, [inside]));
    expect(out.toString()).toBe(`token=${marker("DB_PASS")}\n`);
  });

  it("is masked at every split, and clean multi-byte text around it is byte-exact", async () => {
    await everySplit(entries, bytes(`ünï ✓ ${value} 👁 é`), bytes(`ünï ✓ ${marker("DB_PASS")} 👁 é`));
  });
});

describe("A-R3: a value written in parts with delays", () => {
  const value = "super-secret-token-12345";
  const entries = [{ item: "API_TOKEN", value }];

  it("is never released on a timer, however long the pause", async () => {
    const redaction = new OutputRedaction(entries);
    const { dest, output } = sink();
    const { source, push } = gatedSource();
    const done = redaction.relay([[source, dest]]);
    push(bytes(`token=${value.slice(0, 2)}`));
    // A redactor that flushes held bytes after 100 ms leaks here; wait well past that.
    await sleep(300);
    expect(output().toString()).toBe("token=");
    push(bytes(value.slice(2, 11)));
    await sleep(300);
    expect(output().toString()).toBe("token=");
    push(bytes(`${value.slice(11)}\n`));
    push(null);
    await done;
    expect(output().toString()).toBe(`token=${marker("API_TOKEN")}\n`);
  });

  it("a clean end with a long prefix and no complete match releases it unchanged", async () => {
    const input = bytes(`log line\n${value.slice(0, -1)}`);
    await everySplit(entries, input, input);
  });

  it("an interrupted run discards the held prefix; nothing is released", async () => {
    const redaction = new OutputRedaction(entries);
    const { dest, output } = sink();
    const { source, push } = gatedSource();
    const done = redaction.relay([[source, dest]]);
    push(bytes(`log line\n${value.slice(0, -1)}`));
    await settle();
    expect(output().toString()).toBe("log line\n");
    redaction.interrupt();
    push(null);
    await done;
    expect(output().toString()).toBe("log line\n");
  });

  it("after an interrupt, final output is still relayed and redacted", async () => {
    const redaction = new OutputRedaction(entries);
    const { dest, output } = sink();
    const { source, push } = gatedSource();
    const done = redaction.relay([[source, dest]]);
    redaction.interrupt();
    push(bytes(`stopping: ${value}\n`));
    push(null);
    await done;
    expect(output().toString()).toBe(`stopping: ${marker("API_TOKEN")}\n`);
  });

  it("a destination that closes discards held bytes and stops reading, as a closed pipe would", async () => {
    const redaction = new OutputRedaction(entries);
    let writes = 0;
    const dest = new Writable({
      write(_chunk, _encoding, callback) {
        writes++;
        callback(writes > 1 ? Object.assign(new Error("write EPIPE"), { code: "EPIPE" }) : null);
      },
    });
    const { source, push } = gatedSource();
    const done = redaction.relay([[source, dest]]);
    push(bytes("first\n"));
    await settle();
    push(bytes(`second\n${value.slice(0, 6)}`));
    await settle();
    expect(source.destroyed).toBe(true);
    push(null);
    await done;
    // The held prefix was never written: only the two attempts before the failure.
    expect(writes).toBe(2);
  });

  it("a stream that fails discards held bytes", async () => {
    const redaction = new OutputRedaction(entries);
    const { dest, output } = sink();
    async function* failing() {
      yield bytes(`partial ${value.slice(0, 10)}`);
      throw new Error("read failed");
    }
    await redaction.relay([[Readable.from(failing()), dest]]);
    expect(output().toString()).toBe("partial ");
  });

  it("stdout and stderr are relayed independently: each ends on its own", async () => {
    const redaction = new OutputRedaction(entries);
    const out = sink();
    const err = sink();
    await redaction.relay([
      [Readable.from([bytes(`o ${value.slice(0, 5)}`), bytes(`${value.slice(5)} o\n`)]), out.dest],
      [Readable.from([bytes(`e ${value.slice(0, 8)}`)]), err.dest],
    ]);
    expect(out.output().toString()).toBe(`o ${marker("API_TOKEN")} o\n`);
    // Only a prefix reached stderr, and its stream ended cleanly: byte-exact.
    expect(err.output().toString()).toBe(`e ${value.slice(0, 8)}`);
  });
});

describe("A-R4: no sequence in the child's output disables masking", () => {
  const value = "tokenvalue-aaaaaaaa";
  const entries = [{ item: "API_TOKEN", value }];
  const wrappers: [string, string, string][] = [
    ["an eye marker with spaces", "👁 ", " 👁"],
    ["an eye marker without spaces", "👁", "👁"],
    ["a replacement marker", "[REDACTED:API_TOKEN]", "[REDACTED:API_TOKEN]"],
    ["an unterminated replacement marker", "[REDACTED:", ""],
    ["ANSI colour codes", "\x1b[31m", "\x1b[0m"],
    ["an OSC sequence", "\x1b]0;title\x07", "\x1b]0;title\x07"],
    ["NUL bytes", "\0", "\0"],
    ["a zero-width joiner", "‍", "‍"],
    ["CI command words", "::stop-commands::x\n", "\n::x::"],
    ["a backslash escape", "\\", "\\"],
  ];

  it.each(wrappers)("%s", async (_name, before, after) => {
    const input = bytes(`${before}${value}${after}`);
    await everySplit(entries, input, bytes(`${before}${marker("API_TOKEN")}${after}`));
  });
});

describe("A-R5: encoded forms are masked", () => {
  // A value with `"` and `\`, a multi-line value, and one with `@ / + = &`.
  const quoted = 'quo"te\\slash-1';
  const multiline = "line-one\nline-two";
  const symbols = "us@er/pa+ss=wd&x";
  const entries = [
    { item: "QUOTED", value: quoted },
    { item: "MULTILINE", value: multiline },
    { item: "SYMBOLS", value: symbols },
  ];
  const json = (v: string) => JSON.stringify(v).slice(1, -1);
  const b64 = (s: string, encoding: "base64" | "base64url") => Buffer.from(s).toString(encoding);
  const cases: [string, string, string][] = [];
  for (const { item, value } of entries) {
    cases.push([`${item}: raw`, value, marker(item)]);
    if (json(value) !== value) cases.push([`${item}: JSON-escaped`, `{"v":"${json(value)}"}`, `{"v":"${marker(item)}"}`]);
    if (value.includes("/")) {
      const escaped = json(value).replace(/\//g, "\\/");
      cases.push([`${item}: JSON-escaped with \\/`, `{"v":"${escaped}"}`, `{"v":"${marker(item)}"}`]);
    }
    cases.push([`${item}: percent-encoded`, `?v=${encodeURIComponent(value)}&`, `?v=${marker(item)}&`]);
    const lower = encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, (e) => e.toLowerCase());
    if (lower !== encodeURIComponent(value)) cases.push([`${item}: percent-encoded, lower-case hex`, `?v=${lower}&`, `?v=${marker(item)}&`]);
  }

  it.each(cases)("%s", async (_name, input, expected) => {
    await everySplit(entries, bytes(input), bytes(expected));
  });

  // Inside a longer base64 or base64url string, at each of the three byte
  // alignments (for example `user:secret` in a Basic credential): the value's
  // characters are gone, whatever surrounds them.
  const encodings = ["base64", "base64url"] as const;
  it.each(entries.flatMap(({ item, value }) => encodings.flatMap((e) => ["", "u", "us"].map((lead) => [item, value, e, lead] as const))))(
    "%s: %s inside %s after %j",
    async (item, value, encoding, lead) => {
      const encoded = b64(`${lead}${value}:tail`, encoding);
      const out = (await relay(entries, [bytes(`Basic ${encoded}\n`)])).toString();
      expect(out).toContain(marker(item));
      for (const form of formsOf(value)) expect(out).not.toContain(Buffer.from(form).toString());
      // Streaming agrees with the whole-input reference at every split.
      const input = bytes(`Basic ${encoded}\n`);
      await everySplit(entries, input, scrubWhole(input, entries, redactionMarker));
    },
  );
});

describe("A-R6: overlapping values", () => {
  const a = "abcdefXYZ123";
  const b = "XYZ123uvwxyz";

  it.each([
    ["A declared first", [{ item: "A", value: a }, { item: "B", value: b }]],
    ["B declared first", [{ item: "B", value: b }, { item: "A", value: a }]],
  ])("the union of the overlapping ranges is masked (%s)", async (_name, entries) => {
    await everySplit(entries, bytes(`<${a.slice(0, 6)}${b}>`), bytes(`<${marker("A")}>`));
    const out = (await relay(entries, [bytes(`${a.slice(0, 6)}${b}`)])).toString();
    expect(out).not.toContain("uvwxyz");
    expect(out).not.toContain("abcdef");
  });
});

describe("A-R7: short values", () => {
  it(`a value under ${MIN_LENGTH} bytes is not registered, and its item is named`, async () => {
    const entries = [
      { item: "SHORT_REF", value: "q7" },
      { item: "SHORT_ID", value: "k9" },
      { item: "SEVEN", value: "1234567" },
    ];
    const redaction = new OutputRedaction(entries);
    expect(redaction.skipped).toEqual(["SEVEN", "SHORT_ID", "SHORT_REF"]);
    const notices = redaction.notices().join("\n");
    expect(notices).toContain("SEVEN, SHORT_ID, SHORT_REF");
    for (const { value } of entries) expect(notices).not.toContain(value);
    const input = bytes("the fox exited; ref q7; id k9; pin 1234567");
    await everySplit(entries, input, input);
  });

  it(`the limit is ${MIN_LENGTH} bytes, not characters`, async () => {
    const entries = [
      { item: "EIGHT", value: "12345678" },
      { item: "FOUR_CHARS", value: "ääää" },
    ];
    expect(new OutputRedaction(entries).skipped).toEqual([]);
    await everySplit(entries, bytes("x 12345678 ääää y"), bytes(`x ${marker("EIGHT")} ${marker("FOUR_CHARS")} y`));
  });

  it("the replacement shows no character of the value", async () => {
    const value = "abcdefghijklmnop";
    const out = (await relay([{ item: "API_TOKEN", value }], [bytes(`<${value}>`)])).toString();
    expect(out).toBe(`<${marker("API_TOKEN")}>`);
  });

  it("a run with nothing delivered says so, and relays byte-exact", async () => {
    expect(new OutputRedaction([]).notices()).toEqual([
      "varlatch: --redact: no Secret was delivered to this run, so there is nothing to mask",
    ]);
    const input = bytes("anything at all ✓");
    await everySplit([], input, input);
  });
});

describe("A-R8: the decision table", () => {
  // --redact is opt-in; without it the child inherits the terminal and nothing is piped.
  const table: [boolean, boolean, boolean, RegExp | null][] = [
    [false, false, false, null],
    [false, true, false, /stdout is a terminal/],
    [false, false, true, /stderr is a terminal/],
    [false, true, true, /stdout and stderr are terminals/],
    [true, false, false, /does not apply to --agent-safe runs/],
    [true, true, false, /does not apply to --agent-safe runs/],
    [true, false, true, /does not apply to --agent-safe runs/],
    [true, true, true, /does not apply to --agent-safe runs/],
  ];

  it.each(table)("agent-safe %s, stdout TTY %s, stderr TTY %s", (agentSafe, stdoutIsTTY, stderrIsTTY, refusal) => {
    const message = redactRefusal({ agentSafe, stdoutIsTTY, stderrIsTTY });
    if (refusal === null) expect(message).toBeNull();
    else expect(message).toMatch(refusal);
  });
});

describe("seeded fuzzing", () => {
  function rng(seed: number) {
    let s = seed >>> 0;
    return () => {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 2 ** 32;
    };
  }
  // Mixed widths: ASCII, two-, three-, and four-byte characters.
  const alphabet = ["a", "b", "z", "0", " ", "/", '"', "\n", "é", "ß", "✓", "€", "👁", "𝄞"];

  function word(r: () => number, min: number, max: number) {
    const n = min + Math.floor(r() * (max - min + 1));
    let w = "";
    for (let i = 0; i < n; i++) w += alphabet[Math.floor(r() * alphabet.length)]!;
    return w;
  }

  /** Random cut points, anywhere, including inside characters. */
  function chunking(r: () => number, length: number) {
    const cuts = new Set<number>();
    const count = Math.floor(r() * 12);
    for (let i = 0; i < count && length > 1; i++) cuts.add(1 + Math.floor(r() * (length - 1)));
    return [...cuts].sort((x, y) => x - y);
  }

  it("clean input arrives byte-exact under random chunking at every offset", async () => {
    for (let seed = 1; seed <= 40; seed++) {
      const r = rng(seed);
      const entries = Array.from({ length: 1 + Math.floor(r() * 3) }, (_, i) => ({ item: `S${i}`, value: `${word(r, 6, 10)}#${i}#` }));
      // Clean text: never contains `#`, so no form of any value; but it
      // does contain long prefixes of the values, which are held and then
      // released.
      let text = "";
      while (Buffer.byteLength(text) < 60) {
        text += r() < 0.3 ? entries[Math.floor(r() * entries.length)]!.value.split("#")[0]! : word(r, 1, 5);
      }
      const input = bytes(text);
      expect(scrubWhole(input, entries, redactionMarker)).toEqual(Uint8Array.from(input));
      for (let at = 1; at < input.length; at++) {
        expect(Buffer.from(await relay(entries, cut(input, [at]))), `seed ${seed}, split ${at}`).toEqual(input);
      }
      for (let trial = 0; trial < 10; trial++) {
        expect(Buffer.from(await relay(entries, cut(input, chunking(r, input.length)))), `seed ${seed}`).toEqual(input);
      }
    }
  });

  it("no value is ever emitted, in any registered form, and the result matches the whole-input reference", async () => {
    const forms = (value: string) => {
      const encoded = [JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString("base64")];
      return [value, ...encoded];
    };
    let tested = 0;
    for (let seed = 1; seed <= 200; seed++) {
      const r = rng(seed * 7919);
      const entries: SecretEntry[] = Array.from({ length: 1 + Math.floor(r() * 3) }, (_, i) => ({
        item: `S${i}`,
        value: word(r, 3, 10),
      })).filter((e) => Buffer.byteLength(e.value) >= MIN_LENGTH);
      if (entries.length === 0) continue;
      tested++;
      let text = "";
      while (text.length < 80) {
        const pick = entries[Math.floor(r() * entries.length)]!.value;
        const roll = r();
        if (roll < 0.25) text += pick;
        else if (roll < 0.35) text += forms(pick)[1 + Math.floor(r() * 3)];
        else if (roll < 0.45) text += pick.slice(0, 1 + Math.floor(r() * (pick.length - 1)));
        else text += word(r, 1, 6);
      }
      const input = bytes(text);
      const expected = Buffer.from(scrubWhole(input, entries, redactionMarker));
      for (let trial = 0; trial < 8; trial++) {
        const out = Buffer.from(await relay(entries, cut(input, chunking(r, input.length))));
        expect(out, `seed ${seed}`).toEqual(expected);
      }
      const byteByByte = cut(input, Array.from({ length: input.length - 1 }, (_, i) => i + 1));
      const out = Buffer.from(await relay(entries, byteByByte));
      expect(out, `seed ${seed}`).toEqual(expected);
      for (const { value } of entries) {
        for (const form of formsOf(value)) expect(out.includes(Buffer.from(form)), `seed ${seed}`).toBe(false);
      }
    }
    expect(tested).toBeGreaterThan(150);
  });
});
