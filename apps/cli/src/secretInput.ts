// SPDX-License-Identifier: Apache-2.0
import { randomBytes, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * Where `values set` and `values rotate` take a value from (ADR-0043
 * Decision 2): the command line, standard input, a file, a generator, or a
 * hidden prompt on a terminal. Every path except the command line keeps the
 * value out of shell history, process lists, and a coding agent's context.
 * No message here ever contains a value or any part of one.
 */

export class SecretInputError extends Error {
  override name = "SecretInputError";
}

export type ValueSource =
  | { kind: "argument"; value: string }
  | { kind: "stdin" }
  | { kind: "file"; path: string }
  | { kind: "generate"; spec: GenerateSpec }
  | { kind: "prompt" };

export type GenerateEncoding = "hex" | "base64" | "base64url" | "alnum";

export interface GenerateSpec {
  encoding: GenerateEncoding;
  /** Random bytes for hex and base64; characters for alnum. */
  size: number;
}

/** The flags of `values set` and `values rotate` that take a value, and those that do not. */
const VALUED_FLAGS = new Set(["--from-file", "--generate", "--grace", "--environment", "-e", "--server"]);
const BARE_FLAGS = new Set(["--stdin"]);

/** At least 128 bits of randomness; at most what fits comfortably in an environment. */
const MIN_BYTES = 16;
const MIN_ALNUM = 22; // 22 characters of 62 carry about 131 bits
const MAX_SIZE = 4096;

export const GENERATE_FORMS = "hex:<bytes>, base64:<bytes>, base64url:<bytes>, or alnum:<characters>";

export function parseGenerateSpec(raw: string): GenerateSpec {
  const match = /^(hex|base64|base64url|alnum):([0-9]+)$/.exec(raw);
  if (!match) throw new SecretInputError(`--generate expects ${GENERATE_FORMS}, for example hex:32`);
  const encoding = match[1] as GenerateEncoding;
  const size = Number(match[2]);
  const min = encoding === "alnum" ? MIN_ALNUM : MIN_BYTES;
  if (size < min || size > MAX_SIZE) {
    const unit = encoding === "alnum" ? "characters" : "bytes";
    throw new SecretInputError(`--generate ${encoding}: the size must be from ${min} to ${MAX_SIZE} ${unit}`);
  }
  return { encoding, size };
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** A new random value from the operating system's CSPRNG. */
export function generateValue(spec: GenerateSpec): string {
  switch (spec.encoding) {
    case "hex":
      return randomBytes(spec.size).toString("hex");
    case "base64":
      return randomBytes(spec.size).toString("base64");
    case "base64url":
      return randomBytes(spec.size).toString("base64url");
    case "alnum": {
      // randomInt is uniform: no modulo bias.
      let out = "";
      for (let i = 0; i < spec.size; i++) out += ALNUM[randomInt(ALNUM.length)];
      return out;
    }
  }
}

/** How a generated value is described: the generator only. */
export function describeGenerated(spec: GenerateSpec): string {
  return `${spec.encoding}, ${spec.size} ${spec.encoding === "alnum" ? "characters" : "random bytes"}`;
}

/**
 * The value source of `values set <ITEM> [<value>]` or `values rotate <ITEM>
 * [<new-value>]`: `args` starts with the subcommand and the item. At most one
 * source; none means the hidden prompt.
 */
export function parseValueSource(args: string[]): ValueSource {
  const sources: ValueSource[] = [];
  const candidate = args[2];
  if (candidate !== undefined && !VALUED_FLAGS.has(candidate) && !BARE_FLAGS.has(candidate)) {
    sources.push({ kind: "argument", value: candidate });
  }
  for (let i = 2; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--stdin") sources.push({ kind: "stdin" });
    if (arg === "--from-file" || arg === "--generate") {
      const value = args[i + 1];
      if (value === undefined) throw new SecretInputError(`${arg} needs a value`);
      sources.push(arg === "--from-file" ? { kind: "file", path: value } : { kind: "generate", spec: parseGenerateSpec(value) });
    }
    if (VALUED_FLAGS.has(arg as string)) i++;
  }
  if (sources.length > 1) {
    throw new SecretInputError("give the value one way only: as an argument, --stdin, --from-file <path>, or --generate <spec>");
  }
  return sources[0] ?? { kind: "prompt" };
}

/**
 * Text read from standard input or a file: one trailing line break (LF or
 * CRLF) is removed, as `echo` and most editors add one. The value must be
 * valid UTF-8 without NUL bytes, since it is delivered in an environment
 * variable, and must not be empty.
 */
export function valueFromBytes(bytes: Buffer, from: string): string {
  if (bytes.includes(0)) throw new SecretInputError(`${from} contains a NUL byte, which an environment variable cannot hold`);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) throw new SecretInputError(`${from} is not valid UTF-8 text`);
  const value = text.endsWith("\r\n") ? text.slice(0, -2) : text.endsWith("\n") ? text.slice(0, -1) : text;
  if (value.length === 0) throw new SecretInputError(`${from} is empty; nothing was stored`);
  return value;
}

export async function readAll(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  return Buffer.concat(chunks);
}

export function readValueFile(path: string): string {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? "an error";
    throw new SecretInputError(`cannot read ${path} (${code})`);
  }
  return valueFromBytes(bytes, path);
}

/**
 * Read one line from the terminal without echoing it. Ctrl-C ends the
 * command (exit 130, nothing stored); Ctrl-D on an empty line and Enter on
 * an empty line both mean no value.
 */
export function promptHidden(question: string): Promise<string> {
  const input = process.stdin;
  const output = process.stderr;
  return new Promise((resolve, reject) => {
    let value = "";
    output.write(question);
    input.setRawMode(true);
    input.resume();
    input.setEncoding("utf8");
    const finish = (done: () => void) => {
      input.setRawMode(false);
      input.pause();
      input.off("data", onData);
      output.write("\n");
      done();
    };
    const onData = (data: string) => {
      for (const ch of data) {
        if (ch === "\u0003") {
          return finish(() => {
            output.write("varlatch: cancelled; nothing was stored\n");
            process.exit(130);
          });
        }
        if (ch === "\r" || ch === "\n" || ch === "\u0004") {
          return finish(() =>
            value.length > 0 ? resolve(value) : reject(new SecretInputError("no value entered; nothing was stored")),
          );
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    input.on("data", onData);
  });
}
