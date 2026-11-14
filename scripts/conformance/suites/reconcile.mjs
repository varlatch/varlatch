#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Application Plane reconciliation on the TypeScript stack (ADR-0035 D3/D4;
 * no admin key anywhere): the Convex deploy job derives its own deployment
 * authority, deploys once, and changes nothing on an unchanged installation.
 * ts-stack checks: the Go server has no Convex.
 *
 *   reconcile.mjs      (run by scripts/conformance/run.mjs)
 */
import { reporter, tryTargetOp } from "../suite-kit.mjs";

const { check, error, finish } = reporter({ detailOnFailure: true });
const compose = (...args) => tryTargetOp("ts-stack", ["compose", ...args]);

// `up --build` skips profiled services, and `run` reuses a cached image, so
// rebuild explicitly or a newly added Convex function ships stale source.
const built = compose("--profile", "deploy", "build", "convex-deploy");
if (built.status !== 0) {
  error(`building convex-deploy failed: ${built.stderr.trim().slice(-500)}`);
  finish();
}
const first = compose("--profile", "deploy", "run", "--rm", "convex-deploy");
console.log(first.stdout.trimEnd());
if (first.status !== 0) {
  error(`the first reconcile exited ${first.status}: ${first.stderr.trim().slice(-500)}`);
  finish();
}
check("reconcile.derives-deployment-authority", "the reconcile job derives its admin key inside the job", /deployment authority derived/.test(first.stdout), "admin key was not derived inside the job");
check("reconcile.first-run-deploys", "the first reconcile deploys the functions", /reconcile: deployed functions/.test(first.stdout), "first reconcile did not deploy");
const second = compose("--profile", "deploy", "run", "--rm", "convex-deploy");
if (second.status !== 0) {
  error(`the second reconcile exited ${second.status}: ${second.stderr.trim().slice(-500)}`);
  finish();
}
check(
  "reconcile.unchanged-installation-no-op",
  "a reconcile of an unchanged installation changes nothing",
  /nothing to change/.test(second.stdout),
  `reconcile of an unchanged installation changed something: ${second.stdout.trim()}`,
);
finish();
