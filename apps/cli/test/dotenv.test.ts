// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { DotenvParseError, parseDotenv } from "../src/dotenv.js";

describe("parseDotenv", () => {
  it("reads the common forms", () => {
    const source = [
      "# a comment",
      "",
      "PLAIN=value",
      "export EXPORTED=yes",
      "SPACED = around ",
      "EMPTY=",
      "COMMENTED=kept # dropped",
      "HASHED=a#b",
      "SINGLE='lit $X \\n'",
      'DOUBLE="tab\\there \\"q\\" back\\\\slash"',
      "TICK=`x y`",
      'TRAILING="v" # comment',
      "URL=postgres://u:p@h/db?x=1",
    ].join("\n");
    expect(Object.fromEntries(parseDotenv(source).map((e) => [e.name, e.value]))).toEqual({
      PLAIN: "value",
      EXPORTED: "yes",
      SPACED: "around",
      EMPTY: "",
      COMMENTED: "kept",
      HASHED: "a#b",
      SINGLE: "lit $X \\n",
      DOUBLE: 'tab\there "q" back\\slash',
      TICK: "x y",
      TRAILING: "v",
      URL: "postgres://u:p@h/db?x=1",
    });
  });

  it("reads quoted values across lines, CRLF files, and a byte-order mark, with line numbers", () => {
    const source = '﻿A=1\r\nKEY="-----BEGIN-----\nline\\n-----END-----"\r\nB=2\r\n';
    const entries = parseDotenv(source);
    expect(entries).toEqual([
      { name: "A", value: "1", line: 1 },
      { name: "KEY", value: "-----BEGIN-----\nline\n-----END-----", line: 2 },
      { name: "B", value: "2", line: 4 },
    ]);
  });

  it("expands nothing", () => {
    expect(parseDotenv("A=${B}\nC=\"$D\"")).toEqual([
      { name: "A", value: "${B}", line: 1 },
      { name: "C", value: "$D", line: 2 },
    ]);
  });

  it.each([
    ["no equals sign", "SECRET_VALUE_HERE", 1, "expected NAME=value"],
    ["not a name", "\n=s3cr3t-value", 2, "expected NAME=value"],
    ["an unclosed quote", 'A="s3cr3t-value\nmore', 1, "a quoted value is not closed"],
    ["text after the quote", "A='s3cr3t' tail", 1, "unexpected text after a closing quote"],
  ])("reports %s by line and reason, never the text", (_what, source, line, reason) => {
    let error: unknown;
    try {
      parseDotenv(source);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(DotenvParseError);
    expect((error as DotenvParseError).line).toBe(line);
    expect((error as Error).message).toBe(`line ${line}: ${reason}`);
    expect((error as Error).message).not.toMatch(/s3cr3t|SECRET_VALUE/);
  });
});

describe("decodeStrict", () => {
  it("returns valid UTF-8 as text and names the first invalid line otherwise", async () => {
    const { decodeStrict, ImportError } = await import("../src/importCommand.js");
    expect(decodeStrict(Buffer.from("A=é\nB=😀\n"), ".env")).toBe("A=é\nB=😀\n");
    const bad = Buffer.concat([Buffer.from("A=1\nB=2\nC=x"), Buffer.from([0xc3, 0x28]), Buffer.from("\n")]);
    expect(() => decodeStrict(bad, ".env")).toThrow(ImportError);
    expect(() => decodeStrict(bad, ".env")).toThrow(".env line 3: not valid UTF-8 text. Nothing was imported.");
    // A truncated sequence at the very end of the file.
    expect(() => decodeStrict(Buffer.from([0x41, 0x3d, 0xe2, 0x82]), ".env")).toThrow(".env line 1:");
  });
});
