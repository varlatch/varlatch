// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, expect } from "vitest";
import { takeAccessCoverageNotes } from "../../src/domain/requestaccess.js";
import { takeLockViolations } from "./lock-trace.js";

// Every transaction the lock-order check enforces (lock-trace.ts) and that
// broke amendment E's order, or wrote before its request's
// passkey-verification checkpoint, fails the test that ran it.
afterEach(() => {
  const violations = takeLockViolations();
  expect(
    violations.map((v) => `${v.label}: ${v.problems.join("; ")}`),
    "transactions that broke the lock order (ADR-0054 amendment E) or wrote before passkey-verification's checkpoint",
  ).toEqual([]);
  // A protected effect before its passkey-verification checkpoint, or a
  // route other than an effect-free read left to the request's end
  // (ADR-0054 Decision 7, src/domain/requestaccess.ts).
  expect(takeAccessCoverageNotes(), "passkey-verification checkpoints missing").toEqual([]);
});
