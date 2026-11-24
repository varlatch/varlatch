// SPDX-License-Identifier: Apache-2.0
// scripts/ci-pull-image.sh, with a docker and a sleep of the test's own
// first on PATH: nothing is pulled and nothing waits.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { OBJECT_STORE_IMAGE, pullObjectStore } from "../targets/compose-stack.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCRIPT = join(REPO, "scripts/ci-pull-image.sh");
const IMAGE = `registry.test/a/minio@sha256:${"1".repeat(64)}`;
const OTHER = `postgres:17.6@sha256:${"2".repeat(64)}`;
const ERROR_500 = `Error response from daemon: unknown: failed to resolve reference "${IMAGE}": unexpected status from HEAD request to https://registry.test/v2/a/minio/manifests/sha256:${"1".repeat(64)}: 500 Internal Server Error`;

/**
 * Runs the script. `present` are the images here already; `answers` what
 * each pull answers in turn: "" is a success, anything else an error's text
 * (the last repeats). The result's `calls` are docker's and sleep's, in order.
 */
function run(args, { present = [], answers = [""] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ci-pull-image-"));
  try {
    const at = (name) => join(dir, name);
    writeFileSync(at("present"), present.map((p) => `${p}\n`).join(""));
    answers.forEach((a, i) => writeFileSync(at(`answer-${i + 1}`), a));
    writeFileSync(at("docker"), `#!/bin/sh
echo "docker $*" >> "${dir}/calls"
case "$1" in
image) grep -qxF "$3" "${dir}/present"; exit $? ;;
pull)
  n=$(( $(cat "${dir}/n" 2> /dev/null || echo 0) + 1 )); echo "$n" > "${dir}/n"
  [ "$n" -le ${answers.length} ] || n=${answers.length}
  if [ -s "${dir}/answer-$n" ]; then cat "${dir}/answer-$n" >&2; exit 1; fi
  echo "$3" ;;
*) exit 99 ;;
esac
`);
    writeFileSync(at("sleep"), `#!/bin/sh\necho "sleep $*" >> "${dir}/calls"\n`);
    for (const f of ["docker", "sleep"]) chmodSync(at(f), 0o755);
    const r = spawnSync("bash", [SCRIPT, ...args], { encoding: "utf8", env: { PATH: `${dir}:${process.env.PATH}` } });
    const calls = existsSync(at("calls")) ? readFileSync(at("calls"), "utf8").trim().split("\n") : [];
    return { status: r.status, stderr: r.stderr, stdout: r.stdout, calls };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const pulls = (r) => r.calls.filter((c) => c.startsWith("docker pull"));
const sleeps = (r) => r.calls.filter((c) => c.startsWith("sleep")).map((c) => Number(c.slice(6)));

test("an image that is here is not pulled", () => {
  const r = run([IMAGE], { present: [IMAGE], answers: ["must not be asked"] });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.calls, [`docker image inspect ${IMAGE}`]);
});

test("a pull that works is made once, by the digest", () => {
  const r = run([IMAGE]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.calls, [`docker image inspect ${IMAGE}`, `docker pull --quiet ${IMAGE}`]);
  assert.equal(r.stdout, "");
});

test("a registry's bad moment is tried again", () => {
  const passing = [
    ERROR_500,
    "docker: error from registry: rpc error: code = Unknown desc = Error 1040: Too many connections",
    "toomanyrequests: You have reached your unauthenticated pull rate limit.",
    "unexpected status: 429 Too Many Requests",
    "Get \"https://registry.test/v2/\": dial tcp: lookup registry.test: no such host",
    "read tcp 10.0.0.1:5: connection reset by peer",
    "unexpected EOF",
    "received unexpected HTTP status: 503 Service Unavailable",
    "net/http: TLS handshake timeout",
  ];
  for (const error of passing) {
    const r = run([IMAGE], { answers: [error, ""] });
    assert.equal(r.status, 0, `${error}: ${r.stderr}`);
    assert.equal(pulls(r).length, 2, error);
    assert.deepEqual(sleeps(r), [5], error);
    assert.ok(r.stderr.includes(error), "the error is shown");
  }
});

test("five tries, then it fails", () => {
  const r = run([IMAGE], { answers: [ERROR_500] });
  assert.equal(r.status, 1);
  assert.equal(pulls(r).length, 5);
  assert.deepEqual(sleeps(r), [5, 15, 30, 60]);
  assert.match(r.stderr, /could not be pulled/);
  const last = run([IMAGE], { answers: [ERROR_500, ERROR_500, ERROR_500, ERROR_500, ""] });
  assert.equal(last.status, 0, "the fifth try counts");
});

test("what another try cannot change fails at once", () => {
  const permanent = [
    "Error response from daemon: manifest unknown",
    `Error response from daemon: manifest for ${IMAGE} not found: manifest unknown: manifest unknown`,
    `Error response from daemon: failed to resolve reference "${IMAGE}": ${IMAGE}: not found`,
    "Error response from daemon: pull access denied for a/minio, repository does not exist or may require 'docker login'",
    "Error response from daemon: unauthorized: authentication required",
    "unexpected status from HEAD request to https://registry.test/v2/a: 403 Forbidden",
    "unexpected status from HEAD request to https://registry.test/v2/a: 404 Not Found",
    "no matching manifest for linux/arm64/v8 in the manifest list entries",
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
  ];
  for (const error of permanent) {
    const r = run([IMAGE], { answers: [error, ""] });
    assert.equal(r.status, 1, error);
    assert.equal(pulls(r).length, 1, error);
    assert.deepEqual(sleeps(r), [], error);
  }
});

test("several images, each on its own; the first that fails ends it", () => {
  const r = run([IMAGE, OTHER], { present: [IMAGE] });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(pulls(r), [`docker pull --quiet ${OTHER}`]);
  const failed = run([IMAGE, OTHER], { answers: ["manifest unknown"] });
  assert.equal(failed.status, 1);
  assert.deepEqual(pulls(failed), [`docker pull --quiet ${IMAGE}`]);
});

test("only an image by its digest, checked before anything is pulled", () => {
  const digest = `sha256:${"1".repeat(64)}`;
  for (const args of [[], ["minio"], ["minio:latest"], ["minio@sha256:abc"], [`minio@${digest.toUpperCase()}`], [`--all-tags@${digest}`], [`a b@${digest}`], [IMAGE, "minio:latest"]]) {
    const r = run(args);
    assert.equal(r.status, 64, args.join(" "));
    assert.deepEqual(r.calls, [], args.join(" "));
  }
});

test("the conformance targets' object store pulls its image so, and says why it could not", () => {
  const dir = mkdtempSync(join(tmpdir(), "ci-pull-image-"));
  const path = process.env.PATH;
  try {
    process.env.PATH = `${dir}:${path}`;
    const docker = (body) => {
      writeFileSync(join(dir, "docker"), `#!/bin/sh\necho "$*" >> "${dir}/calls"\n${body}\n`);
      chmodSync(join(dir, "docker"), 0o755);
    };
    docker("exit 0");
    pullObjectStore();
    assert.equal(readFileSync(join(dir, "calls"), "utf8"), `image inspect ${OBJECT_STORE_IMAGE}\n`);
    docker('[ "$1" = image ] || echo "manifest unknown" >&2\nexit 1');
    assert.throws(() => pullObjectStore(), /pulling the object store's image failed: .*manifest unknown/s);
  } finally {
    process.env.PATH = path;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CI pulls the MinIO image its tests start", () => {
  for (const file of [".github/workflows/go.yml", ".github/workflows/ci.yml", "services/varlatchd/test/audit-export.test.ts"]) {
    const named = readFileSync(join(REPO, file), "utf8").match(/cgr\.dev\/chainguard\/minio@sha256:[0-9a-f]{64}/g) ?? [];
    assert.deepEqual([...new Set(named)], [OBJECT_STORE_IMAGE], file);
  }
});
