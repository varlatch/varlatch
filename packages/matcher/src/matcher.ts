// SPDX-License-Identifier: Apache-2.0
import { Automaton } from "./automaton.js";
import { formsOf } from "./forms.js";

/**
 * The streaming secret matcher (ADR-0039 Decisions 17 to 19).
 *
 * - Every occurrence of every registered form is found, overlapping ones
 *   included. A region is a maximal union of matches that share at least
 *   one byte; matches that only touch stay separate.
 * - Each region is replaced by exactly one replacement: that of the match
 *   with the minimum key `(start, -length, item)`, which is the earliest
 *   start, then the longest, then the item name that sorts first.
 * - Only what can still change is held: the raw bytes not covered by any
 *   region in the last `hold` bytes, and the pending regions (as metadata,
 *   never as bytes). Everything before `min(now - hold, earliest pending
 *   region start)` is final and is emitted.
 * - Nothing is ever released on a timer. At a clean end, pending regions
 *   are emitted as replacements and only the held bytes outside every
 *   region are released. `abort()` discards everything held.
 */

export interface SecretEntry {
  /** The name reported in diagnostics and used for tie-breaks. */
  item: string;
  value: string;
}

interface Pattern {
  item: string;
  length: number;
}

/** The ordering key of a match: earliest start, then longest, then first name. */
interface Key {
  start: number;
  length: number;
  item: string;
}

function less(a: Key, b: Key): boolean {
  if (a.start !== b.start) return a.start < b.start;
  if (a.length !== b.length) return a.length > b.length;
  return Buffer.compare(Buffer.from(a.item), Buffer.from(b.item)) < 0;
}

type Segment =
  | { kind: "raw"; start: number; bytes: Buffer }
  | { kind: "region"; start: number; end: number; key: Key };

export interface EndReport {
  /** The final bytes. */
  output: Uint8Array;
  /** An incomplete trailing prefix of a registered value, by item and length; never bytes. */
  incompletePrefix: { item: string; length: number } | null;
}

export class StreamMatcher {
  private readonly automaton: Automaton;
  private readonly patterns: Pattern[] = [];
  private readonly replacement: (item: string) => Uint8Array;
  private state = 0;
  private now = 0;
  private segments: Segment[] = [];
  private closed = false;
  /** Items whose value is too short to be registered (ADR-0039 Decision 17). */
  readonly skipped: string[] = [];
  /** How many regions were replaced, by winning item. */
  readonly replaced = new Map<string, number>();

  constructor(entries: SecretEntry[], replacement: (item: string) => Uint8Array) {
    this.replacement = replacement;
    const bytes: Uint8Array[] = [];
    for (const { item, value } of entries) {
      const forms = formsOf(value);
      if (forms.length === 0) {
        this.skipped.push(item);
        continue;
      }
      for (const form of forms) {
        bytes.push(form);
        this.patterns.push({ item, length: form.length });
      }
    }
    this.automaton = new Automaton(bytes);
  }

  /** Pending regions right now (instrumentation for the bound in ADR-0039 Decision 19). */
  get pendingRegions(): number {
    return this.segments.filter((s) => s.kind === "region").length;
  }

  /** Raw bytes held right now. */
  get heldBytes(): number {
    return this.segments.reduce((n, s) => n + (s.kind === "raw" ? s.bytes.length : 0), 0);
  }

  /** The current hold length `d`. */
  get hold(): number {
    return this.automaton.hold(this.state);
  }

  /**
   * Consume a chunk; returns the bytes that are final. Matches are found
   * byte by byte and merged afterwards: the merge is order-independent, and
   * `now - hold` never decreases, so emitting once per chunk gives the same
   * bytes as emitting after every byte.
   */
  push(chunk: Uint8Array): Uint8Array {
    if (this.closed) throw new Error("matcher already closed");
    const data = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    const base = this.now;
    const found: Key[] = [];
    let state = this.state;
    for (let i = 0; i < data.length; i++) {
      state = this.automaton.step(state, data[i]!);
      const refs = this.automaton.matches(state);
      for (let r = 0; r < refs.length; r++) {
        const pattern = this.patterns[refs[r]!.id]!;
        found.push({ start: base + i + 1 - pattern.length, length: pattern.length, item: pattern.item });
      }
    }
    this.state = state;
    this.now = base + data.length;
    if (data.length > 0) this.segments.push({ kind: "raw", start: base, bytes: data });
    for (const match of found) this.addMatch(match);
    const out: Buffer[] = [];
    this.emitFinal(this.now - this.automaton.hold(state), out);
    // What is still held is at most `hold` bytes: copy it, never keep the caller's buffer.
    this.segments = this.segments.map((s) => (s.kind === "raw" ? { ...s, bytes: Buffer.from(s.bytes) } : s));
    return Buffer.concat(out);
  }

  /** A clean end: no match can complete any more. */
  end(): EndReport {
    if (this.closed) throw new Error("matcher already closed");
    this.closed = true;
    const out: Buffer[] = [];
    for (const segment of this.segments) this.emitSegment(segment, out);
    this.segments = [];
    const heldPattern = this.automaton.heldPrefixOf(this.state);
    const hold = this.automaton.hold(this.state);
    return {
      output: Buffer.concat(out),
      incompletePrefix: heldPattern >= 0 && hold > 0 ? { item: this.patterns[heldPattern]!.item, length: hold } : null,
    };
  }

  /** Cancellation, an aborted stream, or a timeout: discard everything held, release nothing. */
  abort(): void {
    this.closed = true;
    this.segments = [];
  }

  /** Merge a match into the pending segments. */
  private addMatch(match: Key): void {
    const start = match.start;
    const end = match.start + match.length;
    let merged: { start: number; end: number; key: Key } = { start, end, key: match };
    const kept: Segment[] = [];
    for (const segment of this.segments) {
      if (segment.kind === "region") {
        // Overlap means sharing at least one byte; touching is not overlap.
        if (segment.start < end && start < segment.end) {
          merged = {
            start: Math.min(merged.start, segment.start),
            end: Math.max(merged.end, segment.end),
            key: less(segment.key, merged.key) ? segment.key : merged.key,
          };
          continue;
        }
        kept.push(segment);
        continue;
      }
      // Raw bytes inside the match are covered from now on; keep the rest.
      const rawEnd = segment.start + segment.bytes.length;
      if (rawEnd <= start || segment.start >= end) {
        kept.push(segment);
        continue;
      }
      if (segment.start < start) {
        kept.push({ kind: "raw", start: segment.start, bytes: segment.bytes.subarray(0, start - segment.start) });
      }
      if (rawEnd > end) {
        kept.push({ kind: "raw", start: end, bytes: segment.bytes.subarray(end - segment.start) });
      }
    }
    const region: Segment = { kind: "region", start: merged.start, end: merged.end, key: merged.key };
    // Keep segments ordered by start.
    let at = kept.findIndex((s) => s.start > region.start);
    if (at < 0) at = kept.length;
    kept.splice(at, 0, region);
    this.segments = kept;
  }

  /** Emit every segment that ends before `boundary`, in order. */
  private emitFinal(boundary: number, out: Buffer[]): void {
    while (this.segments.length > 0) {
      const first = this.segments[0]!;
      if (first.kind === "region") {
        if (first.end > boundary) return;
        this.emitSegment(first, out);
        this.segments.shift();
        continue;
      }
      const finalCount = Math.min(first.bytes.length, boundary - first.start);
      if (finalCount <= 0) return;
      out.push(first.bytes.subarray(0, finalCount));
      if (finalCount === first.bytes.length) this.segments.shift();
      else {
        this.segments[0] = { kind: "raw", start: first.start + finalCount, bytes: first.bytes.subarray(finalCount) };
        return;
      }
    }
  }

  private emitSegment(segment: Segment, out: Buffer[]): void {
    if (segment.kind === "raw") {
      out.push(segment.bytes);
      return;
    }
    const item = segment.key.item;
    this.replaced.set(item, (this.replaced.get(item) ?? 0) + 1);
    const replacement = this.replacement(item);
    out.push(Buffer.from(replacement.buffer, replacement.byteOffset, replacement.byteLength));
  }
}
