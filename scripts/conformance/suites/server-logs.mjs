#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * No secret plaintext reaches the server's logs (design doc Phase 3 §1.18):
 * after the dashboard suites, the value the runner seeded must not appear in
 * the target's `logs`.
 *
 *   server-logs.mjs <seeded value>      (run by scripts/conformance/run.mjs)
 */
import { reporter, tryTargetOp } from "../suite-kit.mjs";

const [value] = process.argv.slice(2);
if (!value) {
  console.error("Usage: server-logs.mjs <seeded value>");
  process.exit(64);
}
const { check, finish } = reporter();
const logs = tryTargetOp("logs");
check(
  "server-logs.no-secret-plaintext",
  "no secret plaintext in the server's logs",
  logs.status === 0 && !logs.stdout.includes(value),
  logs.status === 0 ? "" : `the logs operation exited ${logs.status}`,
);
finish();
