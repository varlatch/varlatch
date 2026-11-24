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
 *   7. an installation is used: with a read-only root filesystem and no
 *      tmpfs anywhere (the one writable place is the data volume), a
 *      passkey is enrolled, values are set, replaced, rotated and deleted,
 *      a large import spills SQLite's journals into temporary files, a
 *      project is deleted, a backup is taken and restored. Three times: as
 *      the README's docker run; as infra/coolify/varlatchd.compose.yml runs
 *      it (that file itself, through docker compose); and without the
 *      image's SQLITE_TMPDIR, where varlatchd finds the place by itself
 *   8. with nowhere to write a temporary file, serve refuses to start and
 *      says what to set
 *
 * Every container and volume it makes is named vl-image-test-<run>-*, and
 * it removes exactly those. Keys are random, made inside a container from
 * /dev/urandom; this script never prints one, nor a link, a session or a
 * credential. Docker and its compose plugin only; no privileges.
 *
 * VARLATCH_TEST_SLOWDOWN (a whole number, 1 by default) multiplies every
 * wait: the release checks the arm64 image under emulation where no arm64
 * runner is available (.github/workflows/release.yml, go-image-arm64).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BUSYBOX = "busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";
const IMAGE_USER = "65532:65532";
const CONF_DIR = "/etc/varlatch";
const CONF = `${CONF_DIR}/varlatchd.conf`;
const DATA = "/var/lib/varlatch";
/** The key and passphrase variable names varlatchd refuses (go/lib/keyenv/keyenv.go Variables). */
const KEY_VARIABLES = ["VARLATCH_KEK", "VARLATCH_KEK_PASSPHRASE", "VARLATCH_ROOT_KEK", "VARLATCH_BEK", "VARLATCH_BEK_PASSPHRASE", "VARLATCH_BACKUP_KEY"];
const EXIT_CONFIG = 78;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "../..");
const COMPOSE = "infra/coolify/varlatchd.compose.yml";
/** The configuration's public_url: passkeys and sessions are bound to it. */
const PUBLIC_URL = "http://localhost:8686";
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

function docker(args, { input, allowFail = false, env } = {}) {
  const r = spawnSync("docker", args, { encoding: "utf8", input, timeout: wait(120_000), env });
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
async function serve(name, data, keys, conf, options = []) {
  const c = containerName(name);
  // A read-only root filesystem: varlatchd writes only to the data volume.
  docker(["run", "-d", "--name", c, "--read-only", ...options, "-p", "127.0.0.1:0:8686", "-v", `${data}:${DATA}`, "-v", `${keys}:/keys:ro`, "-v", `${conf}:${CONF_DIR}:ro`, image]);
  return started(c);
}
function started(c) {
  const port = docker(["port", c, "8686/tcp"]).stdout.trim().split("\n")[0].split(":").pop();
  return { c, origin: `http://127.0.0.1:${port}` };
}
/**
 * Starts varlatchd as the Coolify Compose file runs it: that file, with an
 * override for what only this run knows (the image, the port, the volumes
 * behind its three mounts' paths); every option is the file's own.
 */
async function serveCompose(name, data, keys) {
  const c = containerName(name);
  const dir = mkdtempSync(join(tmpdir(), "vl-image-test-"));
  try {
    const conf = join(dir, "varlatchd.conf");
    writeFileSync(conf, config(DATA), { mode: 0o444 });
    const override = join(dir, "override.json");
    writeFileSync(
      override,
      JSON.stringify({
        services: { varlatchd: { image, container_name: c, network_mode: "bridge", restart: "no", ports: ["127.0.0.1:0:8686"], volumes: [`data:${DATA}`, "keys:/keys:ro"] } },
        volumes: { data: { external: true, name: data }, keys: { external: true, name: keys } },
      }),
    );
    // The configuration is the file's own bind mount, of this host's file.
    const env = { ...process.env, VARLATCH_VARLATCHD_DIGEST: `sha256:${"0".repeat(64)}`, VARLATCH_CONFIG_FILE: conf };
    docker(["compose", "-p", c, "-f", join(REPO, COMPOSE), "-f", override, "up", "-d", "--no-build", "--pull", "never"], { env });
  } finally {
    composeDirs.push(dir);
  }
  return started(c);
}
const composeDirs = [];
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
    `public_url = ${PUBLIC_URL}`,
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

/**
 * A browser on the installation: its cookies and CSRF token, requests with
 * the public URL's Host and Origin to the published port. An answer other
 * than `expect` fails with its status and error code only.
 */
function browser(server) {
  const cookies = new Map();
  const at = new URL(server.origin);
  let csrf = "";
  let bearer = "";
  const send = (method, path, body) =>
    new Promise((resolve, reject) => {
      const text = body === undefined ? "" : JSON.stringify(body);
      const req = request(
        {
          host: at.hostname,
          port: at.port,
          method,
          path,
          timeout: wait(60_000),
          headers: {
            Host: new URL(PUBLIC_URL).host,
            ...(cookies.size ? { Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
            ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
            ...(method === "GET" ? {} : { Origin: PUBLIC_URL, "Varlatch-CSRF": csrf }),
            ...(body === undefined ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) }),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("error", reject);
          res.on("end", () => {
            for (const c of res.headers["set-cookie"] ?? []) {
              const [pair] = c.split(";");
              const i = pair.indexOf("=");
              if (/max-age=0|max-age=-/i.test(c)) cookies.delete(pair.slice(0, i));
              else cookies.set(pair.slice(0, i), pair.slice(i + 1));
            }
            const raw = Buffer.concat(chunks).toString("utf8");
            let json = null;
            try {
              json = raw ? JSON.parse(raw) : null;
            } catch {
              // Not JSON: the status says enough.
            }
            resolve({ status: res.statusCode, json });
          });
        },
      );
      req.on("timeout", () => req.destroy(new Error("no answer in time")));
      req.on("error", (e) => reject(new Error(`${method} ${path}: ${e.message}`)));
      req.end(text);
    });
  const call = async (what, method, path, body, expect = [200, 201, 204]) => {
    const r = await send(method, path, body);
    assert.ok(expect.includes(r.status), `${what}: ${method} ${path} answered ${r.status} ${r.json?.error?.code ?? ""}`);
    return r.json;
  };
  return {
    call,
    async session() {
      csrf = (await call("the session", "GET", "/auth/session")).csrfToken;
      assert.ok(csrf, "the session has a CSRF token");
    },
    /** As the dashboard: the session's bearer, which /v1 takes. */
    async signedIn() {
      await this.session();
      const minted = await call("the session's bearer", "POST", "/auth/varlatch-token");
      bearer = minted.token ?? minted.bearer;
      assert.ok(bearer, `a bearer is minted: ${Object.keys(minted).join(", ")}`);
    },
  };
}

const cborBytes = (b) => Buffer.concat([b.length < 24 ? Buffer.from([0x40 + b.length]) : b.length < 256 ? Buffer.from([0x58, b.length]) : Buffer.from([0x59, b.length >> 8, b.length & 255]), b]);
const cborText = (t) => Buffer.concat([Buffer.from([0x60 + t.length]), Buffer.from(t)]);

/** A software authenticator's answer to a registration (attestation "none", ES256), as a browser posts it. */
function attest(options) {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const id = randomBytes(16);
  const cose = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]), // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x
    cborBytes(Buffer.from(jwk.x, "base64url")),
    Buffer.from([0x22]), // -3: y
    cborBytes(Buffer.from(jwk.y, "base64url")),
  ]);
  const authData = Buffer.concat([
    createHash("sha256").update(options.rp.id).digest(),
    Buffer.from([0x45]), // user present, user verified, attested credential data
    Buffer.alloc(4 + 16), // the counter, the AAGUID
    Buffer.from([0, id.length]),
    id,
    cose,
  ]);
  const attestation = Buffer.concat([Buffer.from([0xa3]), cborText("fmt"), cborText("none"), cborText("attStmt"), Buffer.from([0xa0]), cborText("authData"), cborBytes(authData)]);
  const clientData = JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: PUBLIC_URL, crossOrigin: false });
  return {
    id: id.toString("base64url"),
    rawId: id.toString("base64url"),
    type: "public-key",
    clientExtensionResults: {},
    response: { clientDataJSON: Buffer.from(clientData).toString("base64url"), attestationObject: attestation.toString("base64url"), transports: ["internal"] },
  };
}

/** Uses a new installation: a write of every kind. */
async function use(server, what) {
  const b = browser(server);
  // The first passkey, from the bootstrap link (never printed).
  const token = /\/enroll#(\S+)/.exec(admin(server, ["bootstrap"]))?.[1];
  assert.ok(token, `${what}: bootstrap prints an enrollment link`);
  await b.session();
  const registration = await b.call("the registration options", "POST", "/auth/passkey/registration/options", { token });
  const registered = await b.call(`${what}: enrolling the first passkey`, "POST", "/auth/passkey/registration", { response: attest(registration.publicKey), name: "check" });
  assert.equal(registered.signedIn, true, `${what}: the enrolment signs in`);
  await b.signedIn();

  const org = await b.call(`${what}: an organization`, "POST", "/v1/organizations", { name: "Check", slug: "check" });
  const at = `/v1/organizations/${org.id}`;
  const projects = [];
  for (const slug of ["kept", "deleted"]) {
    const project = await b.call(`${what}: a project`, "POST", `${at}/projects`, { name: slug, slug, contractAuthority: "managed" });
    const environment = await b.call(`${what}: an environment`, "POST", `${at}/projects/${project.id}/environments`, { name: "development", tier: "development" });
    projects.push({ project, values: `${at}/projects/${project.id}/environments/${environment.id}` });
  }
  for (const { values } of projects) {
    await b.call(`${what}: a value`, "PUT", `${values}/values/ONE`, { value: "first" });
    await b.call(`${what}: a replaced value`, "PUT", `${values}/values/ONE`, { value: "second" });
    // A large import, twice (new, then every one replaced): each is one
    // transaction over many pages, whose journal is past what SQLite keeps
    // in memory (64 KiB).
    for (const round of [1, 2]) {
      const changes = Array.from({ length: 200 }, (_, i) => ({ op: "set", item: `ITEM_${i}`, value: `${round}-${i}-`.padEnd(4096, "x") }));
      const done = await b.call(`${what}: a large import, round ${round}`, "POST", `${values}/changes`, { changes });
      assert.equal(done.results.length, 200, `${what}: every change of the import is answered`);
    }
    await b.call(`${what}: a rotation begun`, "POST", `${values}/values/ONE/rotations`, { value: "third" });
    await b.call(`${what}: a rotation completed`, "POST", `${values}/values/ONE/rotations/complete`);
    await b.call(`${what}: a deleted value`, "DELETE", `${values}/values/ITEM_0`);
    const found = await b.call(`${what}: a search`, "GET", `${at}/config-items?q=ITEM&limit=100`);
    assert.ok(found.items.length > 0, `${what}: the search finds the items`);
  }
  await b.call(`${what}: a deleted project`, "DELETE", `${at}/projects/${projects[1].project.id}`);
  const left = await b.call(`${what}: the projects`, "GET", `${at}/projects`);
  assert.deepEqual(left.items.map((p) => p.slug), ["kept"], `${what}: one project is left`);
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
  assert.deepEqual((cfg.Env ?? []).map((e) => e.split("=")[0]).sort(), ["PATH", "SQLITE_TMPDIR", "SSL_CERT_FILE", "VARLATCH_IMAGE"], "the image's environment");
  assert.ok(cfg.Env.includes(`SQLITE_TMPDIR=${DATA}`), "SQLite's temporary files go to the data directory");
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
  once("restore", ["--read-only", ...mounts(restored), "-v", `${archives}:/in:ro`, image, "admin", "backup", "restore", "--in", "/in/archive.vltbak", "--config", CONF]);
  const third = await serve("serve-3", restored, keys, conf);
  await until(third, 200, "the restored installation");
  admin(third, ["kek", "verify"]);
  // Held until the host operator resumes it; ready meanwhile.
  assert.equal(JSON.parse(admin(third, ["restore", "status"])).held, true, "the restored installation is held");
  admin(third, ["restore", "resume"]);
  assert.deepEqual(JSON.parse(admin(third, ["restore", "status"])), { held: false }, "it is resumed");
  remove(third.c);
  console.log("ok 6 a backup restores into a new volume through the image alone");

  // 7. An installation is used, nothing writable but the data volume.
  for (const [what, label, start, options] of [
    ["docker run", "run", (name, d) => serve(name, d, keys, conf), []],
    [COMPOSE, "compose", (name, d) => serveCompose(name, d, keys), ["--user", IMAGE_USER, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]],
    ["docker run without SQLITE_TMPDIR", "bare", (name, d) => serve(name, d, keys, conf, ["-e", "SQLITE_TMPDIR="]), ["-e", "SQLITE_TMPDIR="]],
  ]) {
    const used = volume(`used-${label}`);
    const server = await start(`used-${label}`, used);
    await until(server, 200, `a new installation (${what})`);
    const host = JSON.parse(docker(["inspect", "--format", "{{json .HostConfig}}", server.c]).stdout);
    assert.equal(host.ReadonlyRootfs, true, `${what}: a read-only root filesystem`);
    assert.deepEqual(Object.keys(host.Tmpfs ?? {}), [], `${what}: no tmpfs`);
    if (label === "compose") {
      assert.deepEqual(host.CapDrop, ["ALL"], `${what}: every capability dropped`);
      assert.deepEqual(host.SecurityOpt, ["no-new-privileges:true"], `${what}: no new privileges`);
    }
    await use(server, what);

    // A backup, restored by the image with the same options.
    JSON.parse(admin(server, ["backup", "run", "--json"]));
    remove(server.c);
    const made = volume(`made-${label}`);
    busybox(`copy-${label}`, [`${used}:/src:ro`, `${made}:/in`], "set -e; set -- /src/backups/*.vltbak; [ $# -eq 1 ]; cp \"$1\" /in/archive.vltbak; chown 65532:65532 /in/archive.vltbak");
    const back = volume(`back-${label}`);
    once(`restore-${label}`, ["--read-only", ...options, ...mounts(back), "-v", `${made}:/in:ro`, image, "admin", "backup", "restore", "--in", "/in/archive.vltbak", "--config", CONF]);
    const again = await start(`back-${label}`, back);
    await until(again, 200, `the restored installation (${what})`);
    admin(again, ["kek", "verify"]);
    remove(again.c);
    console.log(`ok 7 an installation is used, backed up and restored (${what})`);
  }

  // 8. Nowhere to write a temporary file: refused, in words.
  const shut = volume("shut");
  const before = await serve("shut-1", shut, keys, conf);
  await until(before, 200, "an installation before its data directory is closed");
  docker(["stop", "-t", "30", before.c]);
  remove(before.c);
  busybox("shut", [`${shut}:/d`], "chmod 0500 /d");
  const refused = once("shut-2", ["--read-only", "-e", "SQLITE_TMPDIR=", ...mounts(shut), image], { allowFail: true });
  assert.notEqual(refused.status, 0, "serve starts with nowhere to write");
  const why = `${refused.stdout}${refused.stderr}`;
  assert.match(why, /varlatchd does not start: SQLite has no directory for its temporary files/, `the refusal: ${why.slice(0, 400)}`);
  assert.match(why, /set SQLITE_TMPDIR/, "the refusal says what to set");
  console.log("ok 8 with nowhere to write a temporary file, serve refuses to start");
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
  for (const d of composeDirs) rmSync(d, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
