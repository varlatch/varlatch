// SPDX-License-Identifier: Apache-2.0
/**
 * The fake GitHub (lib/platform-fakes.cjs) takes on its repository
 * endpoints only what GitHub takes: the suites' fine-grained tokens and
 * installation tokens it minted, within their narrowing. An App's JWT, no
 * Authorization header or a token it did not mint is refused, so a server
 * that minted the right token but sent something else would fail the sync
 * suite rather than pass it.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const FAKES = fileURLToPath(new URL("../lib/platform-fakes.cjs", import.meta.url));
let dir;
let child;
let ports;

const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.once("error", reject);
  s.listen(0, "127.0.0.1", () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});

const control = (op) => fetch(`http://127.0.0.1:${ports.control}/_github`, { method: "POST", body: JSON.stringify(op) }).then((r) => r.json());

/** A request to the fake as api.github.com: its status. */
const github = (method, path, authorization, body) => new Promise((resolve, reject) => {
  const r = request({
    host: "127.0.0.1", port: ports.https, method, path, servername: "api.github.com", rejectUnauthorized: false,
    headers: { host: "api.github.com", ...(authorization ? { authorization } : {}) },
  }, (res) => {
    let text = "";
    res.on("data", (c) => (text += c));
    res.on("end", () => resolve({ status: res.statusCode, body: text ? JSON.parse(text) : null }));
  });
  r.on("error", reject);
  if (body) r.write(JSON.stringify(body));
  r.end();
});

/** An App JWT signed with pem, as varlatchd signs one. */
function jwt(issuer, pem) {
  const now = Math.floor(Date.now() / 1000);
  const part = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const head = `${part({ alg: "RS256", typ: "JWT" })}.${part({ iat: now - 60, exp: now + 540, iss: issuer })}`;
  return `Bearer ${head}.${createSign("RSA-SHA256").update(head).sign(pem).toString("base64url")}`;
}

/** How long the fakes may take to answer after they start: a loaded CI runner is slow to start a process. */
const START_MS = 30_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Starts the fakes and waits until their control port answers, polling it
 * until START_MS. One that exits first is started again on other ports (a
 * free port can be taken between freePort and its listen), up to three
 * times; one that does not answer in time fails with its exit, or that it
 * still runs, and its stderr.
 */
async function startFakes(script = FAKES, startMs = START_MS) {
  let last = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    ports = { https: await freePort(), control: await freePort() };
    child = spawn(process.execPath, [script, String(ports.https), String(ports.control), join(dir, "cert.pem"), join(dir, "key.pem"), dir], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    let exited = null;
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (c) => (stderr = (stderr + c).slice(-4000)));
    child.on("exit", (code, signal) => (exited = signal ? `killed by ${signal}` : `exited ${code}`));
    const ready = () => fetch(`http://127.0.0.1:${ports.control}/_state`, { signal: AbortSignal.timeout(2000) }).then((r) => r.ok, () => false);
    for (const end = Date.now() + startMs; Date.now() < end && exited === null; await sleep(100)) {
      if (await ready()) return;
    }
    if (exited === null && (await ready())) return;
    last = `${exited ?? `still running after ${startMs} ms`}, ports ${ports.https}/${ports.control}; stderr: ${stderr.trim() || "(empty)"}`;
    if (exited === null) {
      child.kill();
      break;
    }
  }
  throw new Error(`the fake platforms did not start: ${last}`);
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "platform-fakes-test-"));
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", "/CN=api.github.com", "-addext", "subjectAltName=DNS:api.github.com",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  await startFakes();
});

after(() => {
  child?.kill();
  rmSync(dir, { recursive: true, force: true });
});

test("the fake GitHub's repository writes take a suite's fine-grained token or a minted installation token, nothing else", async () => {
  const owner = { login: "acme-apps", id: 77, type: "Organization" };
  const { pem } = await control({ op: "app", app: { id: 4242, slug: "varlatch-test", clientId: "Iv1.test", owner } });
  const { installationId } = await control({ op: "install", appId: 4242, account: owner, repos: ["api", "web"] });
  const app = jwt("Iv1.test", pem);
  const minted = await github("POST", `/app/installations/${installationId}/access_tokens`, app, { repositories: ["api"], permissions: { secrets: "write" } });
  assert.equal(minted.status, 201);
  const token = `token ${minted.body.token}`;
  const write = (repo, authorization) => github("PUT", `/repos/acme-apps/${repo}/actions/secrets/X`, authorization, { encrypted_value: "abc", key_id: "conformance-key" });
  const read = (repo, authorization) => github("GET", `/repos/acme-apps/${repo}/actions/secrets/public-key`, authorization);
  const remove = (repo, authorization) => github("DELETE", `/repos/acme-apps/${repo}/actions/secrets/X`, authorization);

  // Refused: the App's JWT, no Authorization header, a token the fake did
  // not mint, another scheme; inside the installation and outside it.
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" });
  for (const [what, authorization] of [["the App's JWT", app], ["no Authorization header", undefined], ["an unknown installation token", "token ghs_notminted"],
    ["a JWT of another key", jwt("Iv1.test", other)], ["a Basic credential", "Basic Y29uZm9ybWFuY2UteDp5"], ["a bare token", "conformance-x"]]) {
    for (const repo of ["api", "web", "elsewhere"]) {
      assert.equal((await write(repo, authorization)).status, 401, `${what}, ${repo}: write`);
      assert.equal((await read(repo, authorization)).status, 401, `${what}, ${repo}: public key`);
      assert.equal((await remove(repo, authorization)).status, 401, `${what}, ${repo}: delete`);
    }
  }
  // The minted token within its narrowing only.
  assert.equal((await read("api", token)).status, 200);
  assert.equal((await write("api", token)).status, 201);
  assert.equal((await write("web", token)).status, 403, "outside the token's repositories");
  assert.equal((await write("elsewhere", token)).status, 403, "outside the installation");
  // A suite's fine-grained token, as the sync suite's Connection uses one.
  assert.equal((await write("anything", "Bearer conformance-sync-1")).status, 201);
  assert.equal((await write("anything", "token conformance-sync-1")).status, 204);
  // On the App fixture's repositories (in the installation) a fine-grained
  // token is refused: a server that minted the right token but sent its
  // configured one on an App write fails.
  for (const repo of ["api", "web"]) {
    for (const authorization of ["Bearer conformance-sync-1", "token conformance-sync-1"]) {
      assert.equal((await write(repo, authorization)).status, 403, `${authorization} on ${repo}: write`);
      assert.equal((await read(repo, authorization)).status, 403, `${authorization} on ${repo}: public key`);
      assert.equal((await remove(repo, authorization)).status, 403, `${authorization} on ${repo}: delete`);
    }
  }
  // A held repository: a write waits unanswered until released, then lands.
  await control({ op: "hold", repo: "acme-apps/api" });
  const pending = write("api", token);
  let state = {};
  for (let i = 0; i < 50 && !(state.held ?? []).length; i++) {
    await new Promise((r) => setTimeout(r, 50));
    state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  }
  assert.deepEqual(state.held, [{ repo: "acme-apps/api", name: "X", connected: true }]);
  const writesHeld = state.writes["acme-apps/api"];
  assert.deepEqual(await control({ op: "release", repo: "acme-apps/api" }), { released: ["X"], abandoned: [] });
  assert.equal((await pending).status, 204, "the held write is answered once released");
  for (let i = 0; i < 50 && !(state.deliveries ?? []).some((d) => d.delivered !== null); i++) {
    await new Promise((r) => setTimeout(r, 50));
    state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  }
  assert.equal(state.writes["acme-apps/api"], writesHeld + 1);
  assert.deepEqual(state.deliveries, [{ repo: "acme-apps/api", name: "X", delivered: true }], "the released write was delivered");
  assert.deepEqual(state.held, []);
  // A held write whose client disconnects (its request timed out) is
  // abandoned: shown as no longer connected, never answered, stored or
  // counted when released.
  await control({ op: "hold", repo: "acme-apps/api" });
  const before = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  const gone = request({
    host: "127.0.0.1", port: ports.https, method: "PUT", path: "/repos/acme-apps/api/actions/secrets/LATE", servername: "api.github.com", rejectUnauthorized: false,
    headers: { host: "api.github.com", authorization: token },
  });
  gone.on("error", () => {});
  gone.end(JSON.stringify({ encrypted_value: "abc", key_id: "conformance-key" }));
  state = {};
  for (let i = 0; i < 50 && !(state.held ?? []).length; i++) {
    await new Promise((r) => setTimeout(r, 50));
    state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  }
  assert.deepEqual(state.held, [{ repo: "acme-apps/api", name: "LATE", connected: true }]);
  gone.destroy();
  for (let i = 0; i < 50 && state.held[0]?.connected !== false; i++) {
    await new Promise((r) => setTimeout(r, 50));
    state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  }
  assert.deepEqual(state.held, [{ repo: "acme-apps/api", name: "LATE", connected: false }], "a disconnected client shows");
  assert.deepEqual(await control({ op: "release", repo: "acme-apps/api" }), { released: [], abandoned: ["LATE"] });
  state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  assert.equal(state.writes["acme-apps/api"], before.writes["acme-apps/api"], "an abandoned write is not counted");
  assert.ok(!(state.github["acme-apps/api"] ?? []).includes("LATE"), "an abandoned write is not stored");
  assert.deepEqual(state.abandoned, [{ repo: "acme-apps/api", name: "LATE" }]);
  // The race: the client goes away and the release comes at once, in
  // either order. The accounting stays consistent: a write abandoned at the
  // release is never counted, and a released one is counted exactly when
  // its answer was fully written (delivered), whatever the order.
  for (let round = 0; round < 10; round++) {
    await control({ op: "hold", repo: "acme-apps/api" });
    const writesRace = (await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json())).writes["acme-apps/api"];
    const racing = request({
      host: "127.0.0.1", port: ports.https, method: "PUT", path: `/repos/acme-apps/api/actions/secrets/RACE${round}`, servername: "api.github.com", rejectUnauthorized: false,
      headers: { host: "api.github.com", authorization: token },
    });
    racing.on("error", () => {});
    racing.end(JSON.stringify({ encrypted_value: "abc", key_id: "conformance-key" }));
    // Polled until a deadline, not a count: a loaded runner is slow.
    for (const end = Date.now() + 10_000; Date.now() < end; await sleep(20)) {
      const st = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
      if (st.held.length) break;
    }
    racing.destroy();
    const out = await control({ op: "release", repo: "acme-apps/api" });
    const name = `RACE${round}`;
    // Until the write's state is terminal: abandoned, or delivered true or false.
    let st = {};
    let delivery;
    for (const end = Date.now() + 10_000; Date.now() < end; await sleep(20)) {
      st = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
      delivery = st.deliveries?.find((d) => d.name === name);
      if (out.abandoned.includes(name) || (delivery && delivery.delivered !== null)) break;
    }
    if (out.abandoned.includes(name)) {
      assert.equal(st.writes["acme-apps/api"], writesRace, `round ${round}: an abandoned write was counted`);
      assert.equal(delivery, undefined, `round ${round}: an abandoned write has a delivery`);
    } else {
      assert.ok(out.released.includes(name) && delivery && delivery.delivered !== null, `round ${round}: no terminal state: ${JSON.stringify({ out, delivery })}`);
      assert.equal(st.writes["acme-apps/api"], writesRace + (delivery.delivered ? 1 : 0), `round ${round}: counted ${delivery.delivered ? "without" : "despite"} its delivery`);
    }
  }
  // The App's own endpoints take its JWT, and never an installation token.
  assert.equal((await github("GET", "/app", app)).status, 200);
  assert.equal((await github("GET", "/app", token)).status, 401);
});

// A fake that does not start says why: its exit (after the retries a
// taken port earns) or that it still runs, and its stderr. The real fakes'
// child and ports are put back afterwards.
test("fakes that do not start say how they ended and what they wrote", async () => {
  const kept = { child, ports };
  try {
    const exits = join(dir, "exits.cjs");
    writeFileSync(exits, 'process.stderr.write("listen EADDRINUSE: address already in use\\n"); process.exit(3);\n');
    await assert.rejects(startFakes(exits), /the fake platforms did not start: exited 3, ports \d+\/\d+; stderr: listen EADDRINUSE/);
    const hangs = join(dir, "hangs.cjs");
    writeFileSync(hangs, 'process.stderr.write("still loading\\n"); setInterval(() => {}, 1000);\n');
    await assert.rejects(startFakes(hangs, 500), /did not start: still running after 500 ms, .*stderr: still loading/);
  } finally {
    ({ child, ports } = kept);
  }
});
