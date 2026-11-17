// SPDX-License-Identifier: Apache-2.0
// The plan's order (plan.mjs): what a run's order must keep.
import assert from "node:assert/strict";
import { test } from "node:test";
import { BULK_AUDIT_SUITES, PLAN } from "../plan.mjs";

const position = (suite) => PLAN.findIndex((e) => e.suite === suite);

test("the sync suite runs before every suite that writes audit events in bulk (TypeScript defect 10)", () => {
  const sync = position("sync");
  assert.ok(sync >= 0, "the plan has no sync suite");
  assert.ok(BULK_AUDIT_SUITES.length > 0);
  for (const bulk of BULK_AUDIT_SUITES) {
    const at = position(bulk);
    // A bulk suite renamed or dropped from the plan must leave this list too.
    assert.ok(at >= 0, `BULK_AUDIT_SUITES names ${bulk}, which the plan does not run`);
    assert.ok(sync < at, `the sync suite runs after ${bulk}, which writes audit events in bulk: a TypeScript target's trigger scan (500 events a pass) would hold its value changes back`);
  }
});

test("the sync suite runs after the seed, whose credential it uses", () => {
  assert.ok(PLAN.findIndex((e) => e.setup === "seed") < position("sync"));
});
