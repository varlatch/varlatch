// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { wrapper } from "../targets/go-container.mjs";

/**
 * Runs the go-container wrapper with args, docker replaced by a stand-in on
 * PATH (a file of its own, never a link) that records its arguments, one
 * invocation a line; the recorded invocations.
 */
function run(args, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "go-container-test-"));
  try {
    const bin = join(dir, "bin");
    const log = join(dir, "docker.log");
    spawnSync("mkdir", [bin]);
    writeFileSync(join(bin, "docker"), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(log)}\n[ "$1" != inspect ] || exit 1\n`, { mode: 0o755 });
    const file = join(dir, "varlatchd");
    writeFileSync(file, wrapper("varlatchd-image:test"), { mode: 0o755 });
    const r = spawnSync(file, args, { encoding: "utf8", env: { PATH: `${bin}:/usr/bin:/bin`, ...env } });
    assert.equal(r.status, 0, r.stderr);
    return readFileSync(log, "utf8").trim().split("\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The nightly go-container job's cli-download-on checks (go.yml): serve-cli's
// release is prepared with `admin conformance-sign-release <dir> <version>`,
// no --config, so the wrapper must mount the release's directory itself
// (that directory alone, not the installation's Root KEK, data or
// configuration); and varlatchd serves it from
// VARLATCH_CONFORMANCE_CLI_RELEASE, which must reach the container.
test("conformance-sign-release runs with only its release directory mounted, at its own path", () => {
  const install = "/tmp/conformance-go-AbC123";
  const release = `${install}/cli-release.staging`;
  const calls = run(["admin", "conformance-sign-release", release, "0.0.0-check.1"]);
  const runCall = calls.find((c) => c.startsWith("run "));
  assert.ok(runCall, calls.join("\n"));
  assert.match(runCall, new RegExp(`-v ${release.replaceAll(".", "\\.")}:${release.replaceAll(".", "\\.")} `));
  assert.equal(runCall.match(/ -v /g)?.length, 1, runCall);
  assert.doesNotMatch(runCall, new RegExp(`-v ${install}:`));
  assert.match(runCall, /--name vl-conformance-conformance-go-abc123-sign-admin-\d+ /);
  assert.match(runCall, / admin conformance-sign-release \/tmp\/conformance-go-AbC123\/cli-release\.staging 0\.0\.0-check\.1$/);
});

test("serve and admin containers take VARLATCH_CONFORMANCE_CLI_RELEASE from the environment", () => {
  const install = "/tmp/conformance-go-XyZ";
  for (const args of [["serve", "--config", `${install}/varlatchd.conf`], ["admin", "status", "--config", `${install}/varlatchd.conf`]]) {
    const calls = run(args, { VARLATCH_CONFORMANCE_CLI_RELEASE: `${install}/cli-release` });
    const runCall = calls.find((c) => c.startsWith("run "));
    assert.ok(runCall, calls.join("\n"));
    assert.match(runCall, / -e VARLATCH_CONFORMANCE_CLI_RELEASE /, args[0]);
    assert.match(runCall, new RegExp(`-v ${install}:${install} `), args[0]);
  }
});

test("a probe outside any installation mounts nothing", () => {
  const calls = run(["admin", "conformance-probe"]);
  const runCall = calls.find((c) => c.startsWith("run "));
  assert.ok(runCall, calls.join("\n"));
  assert.doesNotMatch(runCall, / -v /);
});

test("every docker run uses a read-only root filesystem with no tmpfs", () => {
  const install = "/tmp/conformance-go-Ro1";
  const cases = [
    ["serve", "--config", `${install}/varlatchd.conf`],
    ["admin", "status", "--config", `${install}/varlatchd.conf`],
    ["admin", "conformance-sign-release", `${install}/cli-release.staging`, "0.0.0-check.1"],
    ["admin", "conformance-probe"],
  ];
  for (const args of cases) {
    const calls = run(args);
    const runCall = calls.find((c) => c.startsWith("run "));
    assert.ok(runCall, calls.join("\n"));
    assert.match(runCall, / --read-only /, args.join(" "));
    assert.doesNotMatch(runCall, /--tmpfs/, args.join(" "));
  }
});
