// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, expect } from "vitest";
import { takeLockViolations } from "./lock-trace.js";

// Every transaction the lock-order check enforces (lock-trace.ts) and that
// broke amendment E's order fails the test that ran it.
afterEach(() => {
  const violations = takeLockViolations();
  expect(
    violations.map((v) => `${v.label}: ${v.problems.join("; ")}`),
    "transactions that broke the lock order (ADR-0054 amendment E)",
  ).toEqual([]);
});
