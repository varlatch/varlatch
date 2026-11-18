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
import { mkdtempSync, rmSync } from "node:fs";
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

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "platform-fakes-test-"));
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", "/CN=api.github.com", "-addext", "subjectAltName=DNS:api.github.com",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  ports = { https: await freePort(), control: await freePort() };
  child = spawn(process.execPath, [FAKES, String(ports.https), String(ports.control), join(dir, "cert.pem"), join(dir, "key.pem"), dir], { stdio: "ignore" });
  for (let i = 0; i < 50; i++) {
    if (await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.ok, () => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("the fake platforms did not start");
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
  // A held repository: a write waits unanswered until released, then lands.
  await control({ op: "hold", repo: "acme-apps/api" });
  const pending = write("api", token);
  let state = {};
  for (let i = 0; i < 50 && !(state.held ?? []).length; i++) {
    await new Promise((r) => setTimeout(r, 50));
    state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  }
  assert.deepEqual(state.held, [{ repo: "acme-apps/api", name: "X" }]);
  const writesHeld = state.writes["acme-apps/api"];
  assert.deepEqual((await control({ op: "release", repo: "acme-apps/api" })).released, ["X"]);
  assert.equal((await pending).status, 204, "the held write is answered once released");
  state = await fetch(`http://127.0.0.1:${ports.control}/_state`).then((r) => r.json());
  assert.equal(state.writes["acme-apps/api"], writesHeld + 1);
  assert.deepEqual(state.held, []);
  // The App's own endpoints take its JWT, and never an installation token.
  assert.equal((await github("GET", "/app", app)).status, 200);
  assert.equal((await github("GET", "/app", token)).status, 401);
});
