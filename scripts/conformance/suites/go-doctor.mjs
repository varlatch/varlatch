#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The read-only doctor of a Go installation (ADR-0059 step 6, slice 6.5),
 * on its own host: `varlatchd admin doctor --json`, the host command
 * `varlatch doctor` fronts, against the running installation. It answers
 * through the daemon's control socket, readiness and the public URL pass,
 * a browser's reach is reported unknown, no mandatory check fails, and it
 * writes no audit event. The replacements of the TypeScript doctor
 * suite's ts-stack checks (go-server checks).
 *
 *   go-doctor.mjs      (run by scripts/conformance/run.mjs)
 */
import { reporter, targetOp } from "../suite-kit.mjs";

const { check, error, finish } = reporter();
try {
  const before = JSON.parse(targetOp("probe", ["audit-event-count"]));
  const { status, report, stderr } = JSON.parse(targetOp("go-host", ["doctor"], { timeoutMs: 180_000 }));
  const after = JSON.parse(targetOp("probe", ["audit-event-count"]));
  if (!report) error(`doctor printed no JSON report (exit ${status}): ${stderr}`);
  const checks = Object.fromEntries((report?.checks ?? []).map((c) => [c.id, c]));
  const failed = (report?.checks ?? []).filter((c) => c.class === "mandatory" && c.status === "fail").map((c) => `${c.id}: ${c.detail ?? ""}`);
  check("go-doctor.exits-0", "doctor exits 0 (no mandatory failure)", status === 0 && failed.length === 0, `exit ${status}; ${failed.join("; ")}`);
  check("go-doctor.services-running", "doctor: varlatchd answered on its control socket", report?.via === "daemon", `via ${report?.via}`);
  for (const [doctorId, id] of [["secret-plane.ready", "go-doctor.secret-plane-ready"], ["config.public-url", "go-doctor.config-public-url"]]) {
    const c = checks[doctorId] ?? {};
    check(id, `doctor: ${doctorId} passes`, c.status === "pass", c.detail ?? "missing");
  }
  check("go-doctor.browser-reachability-unknown", "doctor: browser reachability is reported unknown", checks["realtime.browser"]?.status === "unknown");
  check("go-doctor.no-audit-events", "doctor wrote no audit events", before === after, `${before} -> ${after}`);
} catch (err) {
  error(`go-doctor: ${err.message}`);
}
finish();
