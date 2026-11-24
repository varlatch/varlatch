// SPDX-License-Identifier: Apache-2.0
// scripts/ci-pull-image.sh, with a docker and a sleep of the test's own
// first on PATH: nothing is pulled and nothing waits.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { OBJECT_STORE_IMAGE, pullObjectStore } from "../targets/compose-stack.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCRIPT = join(REPO, "scripts/ci-pull-image.sh");
const IMAGE = `registry.test/a/minio@sha256:${"1".repeat(64)}`;
const OTHER = `postgres:17.6@sha256:${"2".repeat(64)}`;
const ID = IMAGE.split("@")[1];
const TAR = `${"1".repeat(64)}.tar`;
const ERROR_500 = `Error response from daemon: unknown: failed to resolve reference "${IMAGE}": unexpected status from HEAD request to https://registry.test/v2/a/minio/manifests/sha256:${"1".repeat(64)}: 500 Internal Server Error`;

/**
 * Runs the script. `present` are the images here already, by name or ID;
 * `answers` what each pull answers in turn: "" is a success, anything else
 * an error's text (the last repeats). `cache`: CI_IMAGE_CACHE is a directory
 * holding these files; `loads`: the IDs a load brings here, or an Error it
 * answers; `saves` false: a save fails; `broken`: no container can be made
 * of a loaded image; `answersId`: the ID every image says it has. The result's `calls` are docker's
 * and sleep's, in order; `cached` the cache's files after it.
 */
function run(args, { present = [], answers = [""], cache, loads = [], saves = true, broken = false, answersId } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ci-pull-image-"));
  try {
    const at = (name) => join(dir, name);
    writeFileSync(at("present"), present.map((p) => `${p}\n`).join(""));
    answers.forEach((a, i) => writeFileSync(at(`answer-${i + 1}`), a));
    if (cache) {
      mkdirSync(at("cache"));
      for (const [name, text] of Object.entries(cache)) writeFileSync(join(at("cache"), name), text);
    }
    writeFileSync(at("loads"), loads instanceof Error ? loads.message : loads.map((p) => `${p}\n`).join(""));
    writeFileSync(at("docker"), `#!/bin/sh
echo "docker $*" >> "${dir}/calls"
case "$1" in
image)
  for last; do :; done
  if [ "$2" = rm ]; then
    for i; do grep -vxF -- "$i" "${dir}/present" > "${dir}/left"; mv "${dir}/left" "${dir}/present"; done
    exit 0
  fi
  grep -qxF -- "$last" "${dir}/present" || exit 1
  [ "$3" != --format ] || echo "${answersId ?? "$last"}" ;;
load) ${loads instanceof Error ? `cat "${dir}/loads" >&2; exit 1` : `cat "${dir}/loads" >> "${dir}/present"; echo "Loaded image ID: $(tail -n 1 "${dir}/loads")"`} ;;
create) ${broken ? 'echo "failed to extract layer: not found" >&2; exit 1' : "echo container-1"} ;;
rm) ;;
save) ${saves ? 'echo "saved $4" > "$3"' : 'echo half > "$3"; echo "no space left on device" >&2; exit 1'} ;;
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
    const r = spawnSync("bash", [SCRIPT, ...args], { encoding: "utf8", env: { PATH: `${dir}:${process.env.PATH}`, ...(cache ? { CI_IMAGE_CACHE: at("cache") } : {}) } });
    const calls = existsSync(at("calls")) ? readFileSync(at("calls"), "utf8").trim().split("\n") : [];
    return { status: r.status, stderr: r.stderr, stdout: r.stdout, calls: calls.map((c) => c.replaceAll(dir, "")), cached: cache && Object.fromEntries(readdirSync(at("cache")).map((f) => [f, readFileSync(join(at("cache"), f), "utf8")])) };
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
  assert.equal(r.stdout, `${IMAGE}\n`);
});

test("a pull that works is made once, by the digest", () => {
  const r = run([IMAGE]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.calls, [`docker image inspect ${IMAGE}`, `docker image inspect --format {{.Id}} ${ID}`, `docker pull --quiet ${IMAGE}`]);
  assert.equal(r.stdout, `${IMAGE}\n`);
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
  assert.equal(r.stdout, `${IMAGE}\n${OTHER}\n`, "a line for each");
});

test("the cache's image is loaded, and started by its ID, only as the pinned image", () => {
  const minio = OBJECT_STORE_IMAGE.split("@")[1];
  const config = "sha256:a1477d311e9fdbf40a1e6fcb62c391b1e826a9897decb27341d6310294abed8a";
  const tar = `${minio.slice(7)}.tar`;
  // The containerd image store's ID, and the older store's, which is the
  // configuration's digest.
  for (const id of [minio, config]) {
    const r = run([OBJECT_STORE_IMAGE], { cache: { [tar]: "a tar" }, loads: [id], answers: ["must not be asked"] });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, `${id}\n`);
    assert.deepEqual(r.calls.filter((c) => !c.startsWith("docker image")),
      [`docker load --quiet --input /cache/${tar}`, `docker create --pull never ${id} true`, "docker rm --force --volumes container-1"]);
    // Loaded already: nothing again.
    const again = run([OBJECT_STORE_IMAGE], { present: [id], cache: { [tar]: "a tar" }, answers: ["must not be asked"] });
    assert.equal(again.stdout, `${id}\n`);
    assert.ok(again.calls.every((c) => c.startsWith("docker image")), again.calls.join("\n"));
  }
  // What answers to the ID says its own.
  const alias = run([IMAGE], { present: [ID], answersId: `sha256:${"4".repeat(64)}` });
  assert.equal(pulls(alias).length, 1);
  // Another image's configuration is not this one's.
  const other = run([IMAGE], { cache: { [TAR]: "a tar" }, loads: [config] });
  assert.equal(other.stdout, `${IMAGE}\n`);
  assert.equal(pulls(other).length, 1);
});

test("a cache that holds something else, or nothing that loads, is not used: the image is pulled", () => {
  const wrong = run([IMAGE], { cache: { [TAR]: "a tar" }, loads: ["registry.test/a/minio:latest", `sha256:${"3".repeat(64)}`] });
  assert.equal(wrong.status, 0, wrong.stderr);
  assert.equal(wrong.stdout, `${IMAGE}\n`);
  assert.match(wrong.stderr, /::warning::.*refused: what the cache holds is not registry\.test.*333/);
  assert.equal(pulls(wrong).length, 1);
  // What it names itself is not looked at, nor left for the next call.
  const named = run([IMAGE, IMAGE], { cache: { [TAR]: "a tar" }, loads: [IMAGE], answers: ["manifest unknown"] });
  assert.equal(named.status, 1);
  assert.equal(named.stdout, "");
  assert.ok(named.calls.includes(`docker image rm --force ${IMAGE}`));
  const after = run([IMAGE], { cache: { [TAR]: "a tar" }, loads: [IMAGE] });
  assert.equal(after.status, 0, after.stderr);
  assert.equal(pulls(after).length, 1);
  // The right ID, and a layer missing (a damaged tar).
  const part = run([IMAGE, IMAGE], { cache: { [TAR]: "a tar" }, loads: [ID], broken: true, answers: ["manifest unknown"] });
  assert.equal(part.status, 1);
  assert.equal(part.stdout, "");
  assert.match(part.stderr, /failed to extract layer[^]*refused/);
  assert.ok(part.calls.includes(`docker image rm --force ${IMAGE} ${ID}`));
  const pulled = run([IMAGE], { cache: { [TAR]: "a tar" }, loads: [ID], broken: true });
  assert.equal(pulled.stdout, `${IMAGE}\n`);
  assert.equal(pulls(pulled).length, 1);
  const corrupt = run([IMAGE], { cache: { [TAR]: "half" }, loads: new Error("short read: unexpected EOF"), answers: [ERROR_500, ""] });
  assert.equal(corrupt.status, 0, corrupt.stderr);
  assert.match(corrupt.stderr, /could not be loaded from the cache: short read/);
  assert.equal(pulls(corrupt).length, 2, "with its retries");
  // Another image's tar is not looked at; a directory that is not there either.
  const none = run([IMAGE], { cache: { [`${"2".repeat(64)}.tar`]: "a tar" }, loads: [ID] });
  assert.ok(!none.calls.some((c) => c.startsWith("docker load")));
  // No cache: none is read or written.
  assert.ok(!run([IMAGE]).calls.some((c) => /^docker (load|save)/.test(c)));
});

test("a pulled image is saved for the cache, whole or not at all, and never fails for it", () => {
  const r = run([IMAGE], { cache: {} });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${IMAGE}\n`);
  assert.deepEqual(r.cached, { [TAR]: `saved ${IMAGE}\n` });
  const full = run([IMAGE], { cache: {}, saves: false });
  assert.equal(full.status, 0, full.stderr);
  assert.equal(full.stdout, `${IMAGE}\n`);
  assert.deepEqual(full.cached, {});
  // One not pulled now is not saved; a pull that fails saves nothing.
  assert.deepEqual(run([IMAGE], { cache: {}, present: [IMAGE] }).cached, {});
  assert.deepEqual(run([IMAGE], { cache: {}, answers: ["manifest unknown"] }).cached, {});
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
    assert.equal(pullObjectStore(), OBJECT_STORE_IMAGE);
    assert.equal(readFileSync(join(dir, "calls"), "utf8"), `image inspect ${OBJECT_STORE_IMAGE}\n`);
    docker('[ "$1" = image ] || echo "manifest unknown" >&2\nexit 1');
    assert.throws(() => pullObjectStore(), /pulling the object store's image failed: .*manifest unknown/s);
  } finally {
    process.env.PATH = path;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CI pulls the MinIO image its tests start", () => {
  for (const file of [".github/actions/minio-image/action.yml", ".github/workflows/go.yml", ".github/workflows/ci.yml", "services/varlatchd/test/audit-export.test.ts"]) {
    const named = readFileSync(join(REPO, file), "utf8").match(/cgr\.dev\/chainguard\/minio@sha256:[0-9a-f]{64}/g) ?? [];
    assert.deepEqual([...new Set(named)], [OBJECT_STORE_IMAGE], file);
  }
});

/** A workflow's jobs: their name and text. */
function jobs(file) {
  const text = readFileSync(join(REPO, file), "utf8");
  const [, body] = text.split(/^jobs:\n/m);
  return body.split(/^(?=  [a-z0-9-]+:\n)/m).filter((j) => /^  [a-z0-9-]+:/.test(j)).map((j) => [j.match(/^  ([a-z0-9-]+):/)[1], j]);
}

test("every job that starts MinIO has its image from the cache first", () => {
  const starts = /run\.mjs --target|run\.mjs "\$@"|ci-e2e\.sh --shard|go-binary\.test\.mjs|ci-pull-image\.sh cgr|chainguard\/minio@/;
  const found = [];
  for (const file of [".github/workflows/ci.yml", ".github/workflows/go.yml", ".github/workflows/conformance.yml", ".github/workflows/release.yml"]) {
    for (const [name, text] of jobs(file)) {
      const steps = text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
      const first = steps.search(starts);
      if (first < 0) continue;
      const uses = steps.indexOf("uses: ./.github/actions/minio-image");
      assert.ok(uses >= 0 && uses < first, `${file}: ${name}`);
      found.push(name);
    }
  }
  assert.deepEqual(found.sort(), ["cell", "e2e", "e2e-cli", "gate", "go", "go-binary", "go-binary-go-cli", "go-container", "test-server"]);
});

test("only a run on main saves the cache, under the key of the pinned digest", () => {
  const action = readFileSync(join(REPO, ".github/actions/minio-image/action.yml"), "utf8");
  const saves = action.split(/^ {4}- /m).filter((s) => s.includes("actions/cache/save@"));
  assert.equal(saves.length, 1);
  assert.match(saves[0], /^if: github\.ref == 'refs\/heads\/main' && /);
  assert.ok(action.includes("key=ci-image-$RUNNER_OS-$RUNNER_ARCH-${IMAGE##*@sha256:}"));
  for (const uses of action.match(/uses: .*/g)) assert.match(uses, /@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6\.1\.0$/);
});
