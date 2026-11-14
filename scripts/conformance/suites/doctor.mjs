#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The read-only `varlatch doctor` of the TypeScript installation
 * (ADR-0035 D8), run by the CLI under test on the host against the
 * disposable Compose project: its mandatory checks pass, browser
 * reachability is reported unknown, and it writes no audit event. ts-stack
 * checks: the Go server's own `doctor` replaces them (ADR-0059 step 6).
 *
 *   doctor.mjs      (run by scripts/conformance/run.mjs)
 */
import { spawnSync } from "node:child_process";
import { cliPath, reporter, targetOp } from "../suite-kit.mjs";

const { check, error, finish, supports } = reporter();
try {
  // One feature group: every check here reads `varlatch doctor`'s report.
  if (!supports("doctor")) finish();
  // The host CLI resolves the project the way plain `docker compose` does
  // in --dir; point it at the disposable project through Compose's own
  // environment variables.
  const { dir, env } = JSON.parse(targetOp("ts-stack", ["compose-env"]));
  const before = JSON.parse(targetOp("probe", ["audit-event-count"]));
  const doctor = spawnSync(process.execPath, [cliPath(), "doctor", "--dir", dir, "--json", "--wait", "30"], {
    env: { ...process.env, ...env },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const after = JSON.parse(targetOp("probe", ["audit-event-count"]));
  let checks = {};
  try {
    checks = Object.fromEntries(JSON.parse(doctor.stdout).checks.map((c) => [c.id, c]));
  } catch {
    error(`doctor printed no JSON report (exit ${doctor.status}): ${(doctor.stdout + doctor.stderr).trim().slice(-500)}`);
  }
  check("doctor.exits-0", "doctor exits 0 (no mandatory failure)", doctor.status === 0, `exit ${doctor.status}`);
  const passes = {
    "services.running": "doctor.services-running",
    "secret-plane.ready": "doctor.secret-plane-ready",
    "config.public-url": "doctor.config-public-url",
    "mirror.catch-up": "doctor.mirror-catch-up",
    "application-plane.functions": "doctor.application-plane-functions",
    "release.pending-upgrade": "doctor.release-pending-upgrade",
  };
  for (const [doctorId, id] of Object.entries(passes)) {
    const c = checks[doctorId] ?? {};
    check(id, `doctor: ${doctorId} passes`, c.status === "pass", c.detail ?? "missing");
  }
  check("doctor.browser-reachability-unknown", "doctor: browser reachability is reported unknown", checks["realtime.browser"]?.status === "unknown");
  check("doctor.no-audit-events", "doctor wrote no audit events", before === after, `${before} -> ${after}`);
} catch (err) {
  error(`doctor: ${err.message}`);
}
finish();
