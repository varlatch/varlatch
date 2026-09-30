// SPDX-License-Identifier: Apache-2.0
import type { Readable, Writable } from "node:stream";
import { MIN_LENGTH, StreamMatcher, type SecretEntry } from "@varlatch/matcher";

/**
 * Output redaction: `varlatch run --redact` (ADR-0038 Decision 10), and the
 * default for `varlatch run` in assisted mode (ADR-0043 Decision 4).
 *
 * The child's stdout and stderr are pipes; each passes through its own
 * shared matcher (ADR-0039 Decisions 17 to 19), registered with exactly the
 * sensitive values delivered to the child in this run, and each complete
 * match is written as `[REDACTED:<item>]`. Nothing is fetched to build the
 * set.
 *
 * - Bytes, never text: nothing is decoded or re-encoded, so binary output
 *   and a multi-byte character split across writes pass through the matcher
 *   unchanged unless they contain a match.
 * - Held bytes (a possible start of a value) are never released on a timer.
 *   At a clean end of a stream they are released unchanged, because they can
 *   no longer complete a match. If the run was interrupted before the stream
 *   ended, or the destination closed, they are discarded.
 * - The replacement carries the item's name only, and nothing the child
 *   writes can switch masking off.
 *
 * It protects what the output is written to (a CI log, a file, a
 * transcript). It is not a defense against a child that deliberately leaks
 * what it was given.
 */

/** What replaces a match: the item's name, and no character of its value. */
export function redactionMarker(item: string): Uint8Array {
  return Buffer.from(`[REDACTED:${item}]`, "utf8");
}

export interface DeliveredItem {
  name: string;
  sensitive: boolean;
  value?: string | null;
}

/**
 * The redaction set: the sensitive values Varlatch delivered in `env`, and
 * nothing else. A value the child received from the parent environment
 * instead (an inherited or withheld item) was not delivered in this run.
 */
export function deliveredSecrets(items: Iterable<DeliveredItem>, env: NodeJS.ProcessEnv): SecretEntry[] {
  const secrets: SecretEntry[] = [];
  for (const item of items) {
    if (!item.sensitive || typeof item.value !== "string") continue;
    if (env[item.name] !== item.value) continue;
    secrets.push({ item: item.name, value: item.value });
  }
  return secrets;
}

/**
 * Why `--redact` refuses to start, or null. Checked before anything is
 * fetched, so a refused run discloses nothing.
 */
export function redactRefusal(opts: { agentSafe: boolean; stdoutIsTTY: boolean; stderrIsTTY: boolean }): string | null {
  if (opts.agentSafe) {
    return (
      "--redact does not apply to --agent-safe runs: the Agent receives Placeholders, not Secrets, " +
      "so no Secret is delivered to it to mask, and an agent-safe run never fetches Secrets to build a filter"
    );
  }
  const terminals = [opts.stdoutIsTTY ? "stdout" : null, opts.stderrIsTTY ? "stderr" : null].filter((s) => s !== null);
  if (terminals.length === 0) return null;
  return (
    `--redact works only when stdout and stderr are pipes or files, and ${terminals.join(" and ")} ` +
    `${terminals.length === 1 ? "is a terminal" : "are terminals"}. Redirect both, for example: ` +
    "varlatch run --redact -- <command> 2>&1 | tee run.log"
  );
}

/**
 * Write one chunk and wait until the destination has taken it: the child's
 * pipe is read no faster than the output is written, and nothing is still
 * queued when the run exits. False when the destination failed.
 */
function write(dest: Writable, chunk: Uint8Array): Promise<boolean> {
  return new Promise((resolve) => {
    dest.write(chunk, (err) => resolve(!err));
  });
}

/**
 * Which feature turned redaction on: `--redact` (ADR-0038 Decision 10), or
 * assisted mode (ADR-0043 Decision 4), where it is the default and a short
 * value reaches the redactor only when the operator allowed it.
 */
export type RedactionMode = "redact" | "assisted";

export class OutputRedaction {
  private interrupted = false;
  private readonly entries: SecretEntry[];
  private readonly mode: RedactionMode;
  /** Items whose value is too short to register; they pass through unchanged. */
  readonly skipped: string[];

  constructor(entries: SecretEntry[], mode: RedactionMode = "redact") {
    this.entries = entries;
    this.mode = mode;
    this.skipped = [...new Set(this.matcher().skipped)].sort();
  }

  private matcher(): StreamMatcher {
    return new StreamMatcher(this.entries, redactionMarker);
  }

  /** What the run says on stderr before the child starts: names only. */
  notices(): string[] {
    if (this.mode === "assisted") {
      // Silent when there is nothing to mask: assisted mode is the default for every run.
      if (this.skipped.length === 0) return [];
      return [
        `varlatch: allowed with --allow-unmasked, so not masked (shorter than ${MIN_LENGTH} bytes): ${this.skipped.join(", ")}`,
      ];
    }
    if (this.entries.length === 0) {
      return ["varlatch: --redact: no Secret was delivered to this run, so there is nothing to mask"];
    }
    if (this.skipped.length === 0) return [];
    return [
      `varlatch: --redact does not mask values shorter than ${MIN_LENGTH} bytes; these pass through unchanged: ${this.skipped.join(", ")}`,
    ];
  }

  /**
   * `varlatch run` was interrupted (a signal it forwards to the child): from
   * now on, a stream's held bytes are discarded when it ends.
   */
  interrupt(): void {
    this.interrupted = true;
  }

  /** Relay each source to its destination; resolves when every source has ended and its output was written. */
  async relay(pairs: [Readable, Writable][]): Promise<void> {
    await Promise.all(pairs.map(([source, dest]) => this.relayOne(source, dest)));
  }

  private async relayOne(source: Readable, dest: Writable): Promise<void> {
    const matcher = this.matcher();
    let closed = false;
    // The destination went away (a closed pipe): stop reading, as a direct
    // pipe would, so the child's next write to it fails.
    const onError = () => {
      closed = true;
      source.destroy();
    };
    dest.on("error", onError);
    let clean = true;
    try {
      for await (const chunk of source) {
        const out = matcher.push(chunk as Buffer);
        if (out.length > 0 && !closed && !(await write(dest, out))) onError();
      }
    } catch {
      clean = false;
    }
    if (clean && !closed && !this.interrupted) {
      // A clean end: what is still held cannot complete a match.
      const end = matcher.end();
      if (end.output.length > 0) await write(dest, end.output);
    } else {
      matcher.abort();
    }
    dest.off("error", onError);
  }
}
