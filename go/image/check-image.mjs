// SPDX-License-Identifier: Apache-2.0
/**
 * The single-container image of a Go installation (ADR-0059 Decision 8;
 * internal docs/design/go-step6.md, decision 9, slice 6.10a), checked as a
 * container: the Go line's replacement of scripts/test-backup-compose.mjs.
 *
 *   node go/image/check-image.mjs <image>
 *
 * <image> is in the local Docker (go/image/build.sh --load). In order:
 *
 *   1. its configuration (docker image inspect): the nonroot user, the
 *      entrypoint and command, the data directory a volume, the license
 *      label, and an environment with no key in it; varlatchd and the CLI
 *      both run and name the same version
 *   2. a key in the environment is refused: serve exits 78 naming the
 *      variable, never its value, whether the variable holds the Root KEK
 *      or the Backup Encryption Key or is a key or passphrase variable
 *      name; varlatchd admin and the CLI in the image refuse the same way
 *   3. an installation as an operator runs it: a new volume for the data
 *      directory (the image user's, mode 0700), the keys as files on a
 *      volume of their own, the configuration read-only, the default user,
 *      a read-only root filesystem; ready, and as that user
 *   4. no key in the running container's environment: neither in `docker
 *      inspect` nor in /proc/1/environ, read from a container that shares
 *      its PID namespace (CAP_SYS_PTRACE alone; no privilege)
 *   5. the recovery gate holds in the volume: a maintenance lease taken in
 *      one container isolates the next container on the same volume (503
 *      MAINTENANCE, /readyz not ready) until it is ended
 *   6. a backup taken in the container restores into a new volume through
 *      the image alone, and the restored installation serves, its canary
 *      opened by the same Root KEK
 *
 * Every container and volume it makes is named vl-image-test-<run>-*, and
 * it removes exactly those. Keys are random, made inside a container from
 * /dev/urandom; this script never prints one. Docker only; no privileges.
 *
 * VARLATCH_TEST_SLOWDOWN (a whole number, 1 by default) multiplies every
 * wait: the release checks the arm64 image under emulation where no arm64
 * runner is available (.github/workflows/release.yml, go-image-arm64).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

const BUSYBOX = "busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";
const IMAGE_USER = "65532:65532";
const CONF_DIR = "/etc/varlatch";
const CONF = `${CONF_DIR}/varlatchd.conf`;
const DATA = "/var/lib/varlatch";
/** The key and passphrase variable names varlatchd refuses (go/lib/keyenv/keyenv.go Variables). */
const KEY_VARIABLES = ["VARLATCH_KEK", "VARLATCH_KEK_PASSPHRASE", "VARLATCH_ROOT_KEK", "VARLATCH_BEK", "VARLATCH_BEK_PASSPHRASE", "VARLATCH_BACKUP_KEY"];
const EXIT_CONFIG = 78;
const SLOWDOWN = Number.parseInt(process.env.VARLATCH_TEST_SLOWDOWN || "1", 10);
if (!Number.isInteger(SLOWDOWN) || SLOWDOWN < 1) {
  console.error("VARLATCH_TEST_SLOWDOWN must be a whole number of at least 1");
  process.exit(2);
}
/** A wait, scaled by VARLATCH_TEST_SLOWDOWN. */
const wait = (ms) => ms * SLOWDOWN;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const image = process.argv[2];
if (!image) {
  console.error("Usage: node go/image/check-image.mjs <image>");
  process.exit(2);
}
const run = randomBytes(4).toString("hex");
const prefix = `vl-image-test-${run}`;
const containers = new Set();
const volumes = new Set();

function docker(args, { input, allowFail = false } = {}) {
  const r = spawnSync("docker", args, { encoding: "utf8", input, timeout: wait(120_000) });
  if (!allowFail && r.status !== 0) {
    throw new Error(`docker ${args.slice(0, 2).join(" ")} exited ${r.status ?? r.signal}: ${(r.stderr || r.stdout).trim().slice(0, 600)}`);
  }
  return r;
}
function volume(name) {
  const v = `${prefix}-${name}`;
  volumes.add(v);
  docker(["volume", "create", v]);
  return v;
}
function containerName(name) {
  const c = `${prefix}-${name}`;
  containers.add(c);
  return c;
}
/** A one-off container that runs to its end and is removed. */
function once(name, args, opts) {
  return docker(["run", "--rm", "--name", containerName(name), ...args], opts);
}
function busybox(name, mounts, script, opts) {
  return once(name, [...(opts?.input === undefined ? [] : ["-i"]), ...mounts.flatMap((m) => ["-v", m]), "--entrypoint", "sh", BUSYBOX, "-c", script], opts);
}
function remove(name) {
  docker(["rm", "-fv", name], { allowFail: true });
}

/** Starts varlatchd from the image, detached, on a loopback port: its name and origin. */
async function serve(name, data, keys, conf) {
  const c = containerName(name);
  // A read-only root filesystem: varlatchd writes only to the data volume.
  docker(["run", "-d", "--name", c, "--read-only", "-p", "127.0.0.1:0:8686", "-v", `${data}:${DATA}`, "-v", `${keys}:/keys:ro`, "-v", `${conf}:${CONF_DIR}:ro`, image]);
  const port = docker(["port", c, "8686/tcp"]).stdout.trim().split("\n")[0].split(":").pop();
  return { c, origin: `http://127.0.0.1:${port}` };
}
async function readyz(origin) {
  return fetch(`${origin}/readyz`, { signal: AbortSignal.timeout(wait(2_000)) }).then(
    (r) => r.status,
    () => 0,
  );
}
/** Waits until /readyz answers `status` (or the container stops). */
async function until(server, status, what) {
  const deadline = Date.now() + wait(30_000);
  let last = 0;
  while (Date.now() < deadline) {
    last = await readyz(server.origin);
    if (last === status) return;
    if (docker(["inspect", "-f", "{{.State.Running}}", server.c]).stdout.trim() !== "true") break;
    await sleep(250);
  }
  const logs = docker(["logs", "--tail", "40", server.c], { allowFail: true });
  throw new Error(`${what}: /readyz answered ${last}, not ${status}\n${logs.stdout}${logs.stderr}`);
}
function admin(server, args) {
  return docker(["exec", server.c, "/opt/varlatch/varlatchd", "admin", ...args, "--config", CONF]).stdout;
}

function config(dir) {
  return [
    "# Written by go/image/check-image.mjs for one run.",
    "listen = 0.0.0.0:8686",
    "public_url = http://localhost:8686",
    `data_dir = ${dir}`,
    "root_kek_file = /keys/root-kek",
    "backup_key_file = /keys/backup-key",
    "backup_interval = off",
    "",
  ].join("\n");
}

/** Every encoding of a key a value could carry it in (go/lib/keyenv/keyenv.go Refusal's forms). */
function forms(hexKey) {
  const raw = Buffer.from(hexKey, "hex");
  const b64 = raw.toString("base64");
  const url = raw.toString("base64url");
  return [hexKey, hexKey.toUpperCase(), b64, b64.replace(/=+$/, ""), url, `${url}${"=".repeat((4 - (url.length % 4)) % 4)}`];
}
function assertNoKey(environ, keys, where) {
  for (const kv of environ) {
    const [name, ...rest] = kv.split("=");
    const value = rest.join("=");
    assert.ok(!KEY_VARIABLES.includes(name.toUpperCase()), `${where}: the key variable ${name} is in the environment`);
    for (const [what, hexKey] of Object.entries(keys)) {
      // The variable's name, never the value: an assertion message is output.
      assert.ok(!forms(hexKey).some((f) => value.includes(f)), `${where}: ${name} holds ${what}`);
    }
  }
}

async function main() {
  // 1. The image's configuration.
  const cfg = JSON.parse(docker(["image", "inspect", "--format", "{{json .Config}}", image]).stdout);
  assert.equal(cfg.User, IMAGE_USER, "the image user");
  assert.deepEqual(cfg.Entrypoint, ["/opt/varlatch/varlatchd"], "the entrypoint");
  assert.deepEqual(cfg.Cmd, ["serve", "--config", CONF], "the command");
  assert.deepEqual(Object.keys(cfg.Volumes ?? {}), [DATA], "the data directory is the one volume");
  assert.deepEqual(Object.keys(cfg.ExposedPorts ?? {}), ["8686/tcp"], "the port");
  assert.equal(cfg.Labels?.["org.opencontainers.image.licenses"], "AGPL-3.0-or-later AND Apache-2.0", "the license label");
  assert.deepEqual((cfg.Env ?? []).map((e) => e.split("=")[0]).sort(), ["PATH", "SSL_CERT_FILE", "VARLATCH_IMAGE"], "the image's environment");
  const version = cfg.Labels?.["org.opencontainers.image.version"];
  assert.ok(version, "the version label");
  assert.equal(once("version-d", [image, "--version"]).stdout.trim(), `varlatchd ${version}`, "varlatchd's version");
  assert.equal(once("version-cli", ["--entrypoint", "/opt/varlatch/varlatch", image, "--version"]).stdout.trim(), `varlatch ${version}`, "the CLI's version");
  console.log("ok 1 the image's configuration");

  // The keys, as files on a volume of their own, the image user's, 0400;
  // and the configuration, on another.
  const keys = volume("keys");
  busybox("keygen", [`${keys}:/keys`], "umask 277; for k in root-kek backup-key; do od -An -tx1 -N32 /dev/urandom | tr -d ' \\n' > /keys/$k; echo >> /keys/$k; done; chown 65532:65532 /keys/root-kek /keys/backup-key");
  // Read back for the environment checks only; never printed.
  const keyText = busybox("keyread", [`${keys}:/keys:ro`], "cat /keys/root-kek; echo; cat /keys/backup-key").stdout.split("\n").filter(Boolean);
  assert.equal(keyText.length, 2, "two keys");
  const keyHex = { "the Root KEK": keyText[0], "the Backup Encryption Key": keyText[1] };
  const conf = volume("conf");
  busybox("conf", [`${conf}:${CONF_DIR}`], `cat > ${CONF}; chmod 0444 ${CONF}`, { input: config(DATA) });

  // 2. A key in the environment is refused before anything is served.
  const refusedData = volume("refused-data");
  const mounts = (data) => ["-v", `${data}:${DATA}`, "-v", `${keys}:/keys:ro`, "-v", `${conf}:${CONF_DIR}:ro`];
  const refusals = [
    ["the Root KEK as hex", `APP_SETTING=${keyHex["the Root KEK"]}`],
    ["the Backup Encryption Key as base64", `APP_SETTING=${Buffer.from(keyHex["the Backup Encryption Key"], "hex").toString("base64")}`],
    ...KEY_VARIABLES.map((v) => [`the key variable name ${v}`, `${v}=a-value-of-its-own`]),
  ];
  let n = 0;
  const runs = [
    ["varlatchd serve", [], []],
    ["varlatchd admin", [], ["admin", "kek", "verify", "--config", CONF]],
    ["the CLI", ["--entrypoint", "/opt/varlatch/varlatch"], ["--version"]],
  ];
  for (const [who, entry, args] of runs) {
    for (const [label, env] of refusals) {
      n += 1;
      const r = once(`refused-${n}`, [...mounts(refusedData), "-e", env, ...entry, image, ...args], { allowFail: true });
      const name = env.split("=")[0];
      const value = env.slice(name.length + 1);
      const shown = `${r.stdout}${r.stderr}`;
      // The output, as an assertion message, only with the value taken out.
      const said = shown.split(value).join("[VALUE]").trim().slice(0, 300);
      assert.equal(r.status, EXIT_CONFIG, `${who}, ${label}: exit ${r.status}, not ${EXIT_CONFIG}: ${said}`);
      assert.match(r.stderr, new RegExp(`environment variable ${name}\\b`), `${who}, ${label}: the refusal names the variable: ${said}`);
      assert.ok(!shown.includes(value), `${who}, ${label}: the refusal shows the value`);
      for (const hexKey of Object.values(keyHex)) assert.ok(!forms(hexKey).some((f) => shown.includes(f)), `${who}, ${label}: the refusal shows a key`);
    }
  }
  console.log("ok 2 a key in the environment is refused");

  // 3. An installation as an operator runs it.
  const data = volume("data");
  const first = await serve("serve-1", data, keys, conf);
  await until(first, 200, "a new installation");
  const stat = busybox("stat", [`${data}:/d:ro`], "stat -c '%u:%g %a' /d").stdout.trim();
  assert.equal(stat, `${IMAGE_USER} 700`, "the data volume is the image user's alone");
  const pidStatus = once("status", ["--pid", `container:${first.c}`, "--user", IMAGE_USER, "--entrypoint", "cat", BUSYBOX, "/proc/1/status"]).stdout;
  assert.match(pidStatus, /^Uid:\s+65532\s+65532\s+65532\s+65532$/m, "varlatchd runs as the image user");
  assert.match(pidStatus, /^Gid:\s+65532\s+65532\s+65532\s+65532$/m, "varlatchd runs as the image group");
  console.log("ok 3 an installation as an operator runs it, as the image user");

  // 4. No key in the running container's environment.
  const inspected = JSON.parse(docker(["inspect", "--format", "{{json .Config.Env}}", first.c]).stdout);
  assertNoKey(inspected, keyHex, "docker inspect");
  // Reading another process's environment is a ptrace read, which the
  // kernel refuses even to the same user here. So this one reader
  // container, and only it, runs as root with every capability dropped but
  // CAP_SYS_PTRACE: not privileged, and nothing else gets the capability.
  // varlatchd's own container keeps Docker's defaults.
  const environ = once("environ", ["--pid", `container:${first.c}`, "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--entrypoint", "cat", BUSYBOX, "/proc/1/environ"]).stdout.split("\0").filter(Boolean);
  assert.ok(environ.some((e) => e.startsWith("PATH=")), "/proc/1/environ was read");
  assertNoKey(environ, keyHex, "/proc/1/environ");
  console.log("ok 4 no key in docker inspect or /proc/1/environ");

  // 5. The recovery gate holds in the volume, across containers.
  const lease = JSON.parse(admin(first, ["maintenance", "begin", "--ttl", "10m"]));
  const leaseId = lease.id ?? lease.leaseId;
  assert.ok(leaseId, `the lease has an id: ${Object.keys(lease).join(", ")}`);
  remove(first.c);
  const second = await serve("serve-2", data, keys, conf);
  await until(second, 503, "a container on a volume with a lease");
  const api = await fetch(`${second.origin}/v1/organizations`, { signal: AbortSignal.timeout(wait(5_000)) });
  assert.equal(api.status, 503, "the API under the lease");
  assert.equal((await api.json()).error?.code, "MAINTENANCE", "the API answers MAINTENANCE");
  admin(second, ["maintenance", "end", leaseId]);
  await until(second, 200, "the lease ended");
  console.log("ok 5 the recovery gate holds in the volume across containers");

  // 6. A backup in the container restores into a new volume.
  const backup = JSON.parse(admin(second, ["backup", "run", "--json"]));
  assert.ok(backup.archiveId ?? backup.path, "the backup names its archive");
  remove(second.c);
  const archives = volume("archives");
  busybox("copy", [`${data}:/src:ro`, `${archives}:/in`], "set -e; set -- /src/backups/*.vltbak; [ $# -eq 1 ]; cp \"$1\" /in/archive.vltbak; chown 65532:65532 /in/archive.vltbak");
  const restored = volume("restored");
  once("restore", [...mounts(restored), "-v", `${archives}:/in:ro`, image, "admin", "backup", "restore", "--in", "/in/archive.vltbak", "--config", CONF]);
  const third = await serve("serve-3", restored, keys, conf);
  await until(third, 200, "the restored installation");
  admin(third, ["kek", "verify"]);
  console.log("ok 6 a backup restores into a new volume through the image alone");
}

let failed = false;
try {
  await main();
  console.log(`PASS: ${image}`);
} catch (err) {
  failed = true;
  console.error(`FAIL: ${err.message}`);
} finally {
  for (const c of containers) remove(c);
  for (const v of volumes) docker(["volume", "rm", v], { allowFail: true });
}
process.exit(failed ? 1 : 0);
