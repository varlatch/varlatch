// SPDX-License-Identifier: Apache-2.0

/**
 * A byte-level Aho-Corasick automaton. Besides the usual goto, failure, and
 * output links, each state records `hold`: the length of the longest suffix
 * of the input so far that is a proper prefix of some pattern (the deepest
 * state on its failure chain that still has children). ADR-0039 Decision 19
 * proves that no future match can include a byte more than `hold` bytes
 * before the current end.
 */

export interface PatternRef {
  /** Index into the pattern list the automaton was built from. */
  id: number;
  length: number;
}

export class Automaton {
  private readonly next: Map<number, number>[] = [new Map()];
  private readonly fail: number[] = [0];
  private readonly depth: number[] = [0];
  /** Patterns ending exactly at a state. */
  private readonly own: PatternRef[][] = [[]];
  /** The nearest state on the failure chain (excluding itself) that ends a pattern. */
  private readonly outputLink: number[] = [-1];
  private readonly holdDepth: number[] = [0];
  /** Some pattern id reachable below a state with children (for diagnostics). */
  private readonly below: number[] = [-1];

  constructor(patterns: Uint8Array[]) {
    patterns.forEach((pattern, id) => {
      let state = 0;
      for (const byte of pattern) {
        let to = this.next[state]!.get(byte);
        if (to === undefined) {
          to = this.next.length;
          this.next.push(new Map());
          this.fail.push(0);
          this.depth.push(this.depth[state]! + 1);
          this.own.push([]);
          this.outputLink.push(-1);
          this.holdDepth.push(0);
          this.below.push(-1);
          this.next[state]!.set(byte, to);
        }
        if (this.below[state] === -1) this.below[state] = id;
        state = to;
      }
      this.own[state]!.push({ id, length: pattern.length });
    });
    // Breadth-first: failure links, output links, and hold depths.
    const queue: number[] = [];
    for (const child of this.next[0]!.values()) queue.push(child);
    for (let i = 0; i < queue.length; i++) {
      const state = queue[i]!;
      const f = this.fail[state]!;
      this.outputLink[state] = this.own[f]!.length > 0 ? f : this.outputLink[f]!;
      this.holdDepth[state] = this.next[state]!.size > 0 ? this.depth[state]! : this.holdDepth[f]!;
      for (const [byte, child] of this.next[state]!) {
        let g = f;
        while (g !== 0 && !this.next[g]!.has(byte)) g = this.fail[g]!;
        const to = this.next[g]!.get(byte);
        this.fail[child] = to !== undefined && to !== child ? to : 0;
        queue.push(child);
      }
    }
    this.holdDepth[0] = 0;
  }

  step(state: number, byte: number): number {
    let s = state;
    for (;;) {
      const to = this.next[s]!.get(byte);
      if (to !== undefined) return to;
      if (s === 0) return 0;
      s = this.fail[s]!;
    }
  }

  /** Every pattern that ends at `state`. */
  matches(state: number): PatternRef[] {
    const found: PatternRef[] = [...this.own[state]!];
    for (let s = this.outputLink[state]!; s > 0; s = this.outputLink[s]!) found.push(...this.own[s]!);
    return found;
  }

  hold(state: number): number {
    return this.holdDepth[state]!;
  }

  /** A pattern that the held suffix at `state` is a proper prefix of, or -1. */
  heldPrefixOf(state: number): number {
    let s = state;
    while (s !== 0 && this.next[s]!.size === 0) s = this.fail[s]!;
    return s === 0 ? -1 : this.below[s]!;
  }
}
