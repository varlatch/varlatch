// SPDX-License-Identifier: Apache-2.0
import { Automaton } from "./automaton.js";
import { labelledFormsOf, type FormName } from "./forms.js";
import type { SecretEntry } from "./matcher.js";

/**
 * The reporting side of the shared matcher, for local secret scanning.
 *
 * It registers exactly what `StreamMatcher` registers (the same forms, the
 * same minimum length, the same automaton) and finds the same complete
 * matches, but it replaces nothing and emits no bytes: it reports every
 * complete occurrence, with its entry, its form, and its byte range.
 *
 * - Overlapping occurrences are all reported. A scrubber needs one
 *   replacement per overlap region; a scan reports what is there, so a
 *   Secret contained in another Secret's value is reported as well.
 * - Only complete occurrences are reported. The scanner holds no bytes: the
 *   automaton state alone carries a possible start of a value across
 *   chunks, so an occurrence split across chunks is found once it completes.
 * - At the end, a trailing possible start of a value is reported by entry
 *   and length only, never as bytes, and it is not an occurrence.
 */

export interface Occurrence {
  /** Index of the entry in the list the scanner was built from. */
  entry: number;
  item: string;
  form: FormName;
  /** Byte offset of the first byte, from the start of the stream. */
  start: number;
  /** Byte offset just past the last byte. */
  end: number;
}

export interface ScanEnd {
  /** A trailing possible start of a registered value, by entry and length; never bytes. */
  incompletePrefix: { entry: number; item: string; length: number } | null;
}

interface Pattern {
  entry: number;
  form: FormName;
  length: number;
}

export class StreamScanner {
  private readonly automaton: Automaton;
  private readonly patterns: Pattern[] = [];
  /** Item names by entry; the values themselves are kept only as automaton patterns. */
  private readonly items: string[];
  private state = 0;
  private now = 0;
  private closed = false;
  /** Items whose value is too short to be registered, in entry order. */
  readonly skipped: string[] = [];
  /** Indexes of the entries that were not registered. */
  readonly skippedEntries: number[] = [];
  /** The longest registered form in bytes: no occurrence is longer. */
  readonly maxLength: number;

  constructor(entries: readonly SecretEntry[]) {
    this.items = entries.map((e) => e.item);
    const bytes: Uint8Array[] = [];
    entries.forEach(({ item, value }, entry) => {
      const forms = labelledFormsOf(value);
      if (forms.length === 0) {
        this.skipped.push(item);
        this.skippedEntries.push(entry);
        return;
      }
      for (const { form, bytes: formBytes } of forms) {
        bytes.push(formBytes);
        this.patterns.push({ entry, form, length: formBytes.length });
      }
    });
    this.maxLength = this.patterns.reduce((n, p) => Math.max(n, p.length), 0);
    this.automaton = new Automaton(bytes);
  }

  /** Bytes consumed since the start (or the last reset). */
  get offset(): number {
    return this.now;
  }

  /** Start a new stream with the same registered values. */
  reset(): void {
    this.state = 0;
    this.now = 0;
    this.closed = false;
  }

  /** Consume a chunk; returns the occurrences that complete inside it, in order of their end. */
  push(chunk: Uint8Array): Occurrence[] {
    if (this.closed) throw new Error("scanner already closed");
    const found: Occurrence[] = [];
    const base = this.now;
    let state = this.state;
    for (let i = 0; i < chunk.length; i++) {
      state = this.automaton.step(state, chunk[i]!);
      const refs = this.automaton.matches(state);
      for (let r = 0; r < refs.length; r++) {
        const pattern = this.patterns[refs[r]!.id]!;
        const end = base + i + 1;
        found.push({
          entry: pattern.entry,
          item: this.items[pattern.entry]!,
          form: pattern.form,
          start: end - pattern.length,
          end,
        });
      }
    }
    this.state = state;
    this.now = base + chunk.length;
    return found;
  }

  /** A clean end: no occurrence can complete any more. */
  end(): ScanEnd {
    if (this.closed) throw new Error("scanner already closed");
    this.closed = true;
    const held = this.automaton.heldPrefixOf(this.state);
    const length = this.automaton.hold(this.state);
    if (held < 0 || length === 0) return { incompletePrefix: null };
    const entry = this.patterns[held]!.entry;
    return { incompletePrefix: { entry, item: this.items[entry]!, length } };
  }
}
