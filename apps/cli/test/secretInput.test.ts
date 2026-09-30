// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  SecretInputError,
  describeGenerated,
  generateValue,
  parseGenerateSpec,
  parseValueSource,
  readValueFile,
  valueFromBytes,
} from "../src/secretInput.js";

describe("parseValueSource", () => {
  it("takes exactly one source", () => {
    expect(parseValueSource(["set", "API_KEY", "v"])).toEqual({ kind: "argument", value: "v" });
    expect(parseValueSource(["set", "API_KEY", "--stdin"])).toEqual({ kind: "stdin" });
    expect(parseValueSource(["set", "API_KEY", "--from-file", "k.pem"])).toEqual({ kind: "file", path: "k.pem" });
    expect(parseValueSource(["set", "API_KEY", "--generate", "hex:32"])).toEqual({ kind: "generate", spec: { encoding: "hex", size: 32 } });
    expect(parseValueSource(["set", "API_KEY"])).toEqual({ kind: "prompt" });
    expect(parseValueSource(["set", "API_KEY", "-e", "prod"])).toEqual({ kind: "prompt" });
    expect(parseValueSource(["rotate", "API_KEY", "--grace", "60", "--stdin"])).toEqual({ kind: "stdin" });
  });

  it("keeps a value that starts with a dash", () => {
    expect(parseValueSource(["set", "API_KEY", "-x9-value", "-e", "dev"])).toEqual({ kind: "argument", value: "-x9-value" });
  });

  it("refuses two sources", () => {
    expect(() => parseValueSource(["set", "API_KEY", "v", "--stdin"])).toThrow(SecretInputError);
    expect(() => parseValueSource(["set", "API_KEY", "--stdin", "--generate", "hex:32"])).toThrow(/one way only/);
  });
});

describe("--generate", () => {
  it.each([
    ["hex:32", /^[0-9a-f]{64}$/],
    ["base64:48", /^[A-Za-z0-9+/]{64}$/],
    ["base64url:24", /^[A-Za-z0-9_-]{32}$/],
    ["alnum:40", /^[A-Za-z0-9]{40}$/],
  ])("%s produces a fresh value of the stated shape", (raw, shape) => {
    const spec = parseGenerateSpec(raw);
    const a = generateValue(spec);
    const b = generateValue(spec);
    expect(a).toMatch(shape);
    expect(a).not.toBe(b);
  });

  it("refuses weak or oversized values and unknown encodings", () => {
    expect(() => parseGenerateSpec("hex:8")).toThrow(/from 16 to 4096 bytes/);
    expect(() => parseGenerateSpec("alnum:12")).toThrow(/from 22 to 4096 characters/);
    expect(() => parseGenerateSpec("hex:5000")).toThrow(SecretInputError);
    expect(() => parseGenerateSpec("uuid")).toThrow(/hex:<bytes>/);
  });

  it("describes the generator, never the value", () => {
    expect(describeGenerated({ encoding: "hex", size: 32 })).toBe("hex, 32 random bytes");
  });
});

describe("values from standard input or a file", () => {
  it("removes one trailing line break", () => {
    expect(valueFromBytes(Buffer.from("s3cr3t\n"), "standard input")).toBe("s3cr3t");
    expect(valueFromBytes(Buffer.from("s3cr3t\r\n"), "standard input")).toBe("s3cr3t");
    expect(valueFromBytes(Buffer.from("a\nb\n\n"), "standard input")).toBe("a\nb\n");
  });

  it("refuses empty input, NUL bytes, and invalid UTF-8, never quoting the input", () => {
    expect(() => valueFromBytes(Buffer.from("\n"), "standard input")).toThrow(/is empty/);
    expect(() => valueFromBytes(Buffer.from("s3cr3t\0x"), "standard input")).toThrow(/NUL byte/);
    expect(() => valueFromBytes(Buffer.from([0x73, 0xff, 0x33]), "standard input")).toThrow(/not valid UTF-8/);
    try {
      valueFromBytes(Buffer.from("s3cr3t\0x"), "standard input");
    } catch (err) {
      expect((err as Error).message).not.toContain("s3cr3t");
    }
  });

  it("reads a file, naming it (not its content) when it cannot", () => {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-input-"));
    writeFileSync(join(dir, "key"), "-----BEGIN KEY-----\nabc\n-----END KEY-----\n");
    expect(readValueFile(join(dir, "key"))).toBe("-----BEGIN KEY-----\nabc\n-----END KEY-----");
    expect(() => readValueFile(join(dir, "absent"))).toThrow(/cannot read .*absent \(ENOENT\)/);
  });
});
