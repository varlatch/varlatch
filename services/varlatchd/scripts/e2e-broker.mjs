#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live E2E for the credential broker (ADR-0022): agent-safe run against the
 * clean-room stack with a real TLS upstream. Asserts the design-doc list:
 * no plaintext or reusable credential in the agent env; substitution to the
 * allowed TLS destination; placeholders (not secrets) to unauthorized and
 * redirect targets; CONNECT refusal; grant/capability revocation, expiry and
 * rotation semantics; audit contents; no plaintext in audit export.
 * (Tailnet-at-exercise is unit-tested; the clean-room stack has no tailnet.)
 *
 * Usage: node scripts/e2e-broker.mjs <server-url> <admin-token>
 */
import { spawn, execFileSync } from "node:child_process";
import http from "node:http";
import https from "node:https";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [server, adminToken] = process.argv.slice(2);
if (!server || !adminToken) {
  console.error("Usage: e2e-broker.mjs <server-url> <admin-token>");
  process.exit(1);
}
const cliPath = new URL("../../../apps/cli/dist/main.js", import.meta.url).pathname;

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || !detail ? "" : ` — ${detail}`}`);
  if (!ok) failures += 1;
}

async function api(method, path, body, token = adminToken) {
  const res = await fetch(`${server}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

// --- setup: identities, grant, TLS upstream, decoy upstream -----------------

const broker = (await api("POST", "/v1/organizations/acme/identities", { name: "e2e broker", kind: "broker" })).json;
const agent = (await api("POST", "/v1/organizations/acme/identities", { name: "e2e agent", kind: "agent" })).json;
check("agent identity created with no credential", agent.credential === null);

const projectId = (await api("GET", "/v1/organizations/acme/projects/api")).json.id;
const grant = (await api("POST", "/v1/organizations/acme/grants", {
  subjectIdentityId: agent.id,
  scope: { kind: "project", projectId },
  actions: ["secret.use"],
})).json;

const SECRET = "postgres://dev-db"; // seeded DATABASE_URL in development

const certDir = mkdtempSync(join(tmpdir(), "broker-e2e-cert-"));
execFileSync("openssl", [
  "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
  "-keyout", join(certDir, "key.pem"), "-out", join(certDir, "cert.pem"),
  "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
]);

const tlsRequests = [];
const tlsUpstream = https.createServer(
  { key: readFileSync(join(certDir, "key.pem")), cert: readFileSync(join(certDir, "cert.pem")) },
  (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      tlsRequests.push({ url: req.url, auth: req.headers.authorization, body });
      if (req.url === "/redirect") {
        res.writeHead(302, { Location: `http://127.0.0.1:${decoyPort}/stolen` }).end();
      } else {
        res.writeHead(200, { "Content-Type": "application/json" }).end('{"ok":true}');
      }
    });
  },
);
await new Promise((r) => tlsUpstream.listen(0, "127.0.0.1", r));
const tlsPort = tlsUpstream.address().port;

const decoyRequests = [];
const decoyUpstream = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    decoyRequests.push({ url: req.url, auth: req.headers.authorization, body });
    res.writeHead(200).end("decoy");
  });
});
await new Promise((r) => decoyUpstream.listen(0, "127.0.0.1", r));
const decoyPort = decoyUpstream.address().port;

// --- agent-safe run ---------------------------------------------------------

const repoDir = mkdtempSync(join(tmpdir(), "broker-e2e-repo-"));
const configDir = mkdtempSync(join(tmpdir(), "broker-e2e-cfg-"));
const cliEnv = {
  ...process.env,
  VARLATCH_CONFIG_DIR: configDir,
  NODE_EXTRA_CA_CERTS: join(certDir, "cert.pem"),
  VARLATCH_BROKER_CREDENTIAL: broker.credential,
};
const run = (args, opts = {}) =>
  new Promise((resolve) => {
    const child = spawn("node", [cliPath, ...args], { cwd: repoDir, env: cliEnv, ...opts });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("exit", (code) => resolve({ code, out }));
  });

await run(["init", "--org", "acme", "--project", "api", "--server", server]);
const login = await run(["login", "--server", server, "--token", adminToken]);
if (!/Logged in/.test(login.out)) {
  console.error(`FAIL  cli login: ${login.out}`);
  process.exit(1);
}

// Earlier suites rewrite PORT; assert against the current authoritative value.
const effective = (await api(
  "GET",
  "/v1/organizations/acme/projects/api/environments/development/effective-configuration?include=values",
)).json;
const portValue = effective.items.find((i) => i.name === "PORT")?.value;

// Every stored Secret needs a target or an omit (ADR-0039 Decision 8). This
// run targets DATABASE_URL and omits the rest, including one stored here
// with a stale copy in the operator's shell that must not reach the Agent.
await api("PUT", "/v1/organizations/acme/projects/api/environments/development/values/E2E_OMITTED", { value: "omitted-e2e-secret" });
const omitted = [
  ...new Set([...effective.items.filter((i) => i.sensitive && i.name !== "DATABASE_URL").map((i) => i.name), "E2E_OMITTED"]),
];
const targetArgs = [
  "--target", "DATABASE_URL=header:authorization",
  "--target", "DATABASE_URL=json:/dsn",
  ...omitted.flatMap((name) => ["--omit", name]),
];

// The agent process: asserts its own environment, then exercises the proxy.
const agentScript = join(repoDir, "agent.mjs");
writeFileSync(agentScript, `
import http from "node:http";
const results = {};
const envText = JSON.stringify(process.env);
results.noPlaintext = !envText.includes(${JSON.stringify(SECRET)});
results.noBearer = !/vlt_(svc|cli|web|agr)_/.test(envText.replace(process.env.VARLATCH_E2E ?? "", ""));
results.placeholder = /^vlch_ph_v1_[0-9a-f]{32}$/.test(process.env.DATABASE_URL ?? "");
results.plainValue = process.env.PORT === ${JSON.stringify(portValue)};
results.omittedAbsent = process.env.E2E_OMITTED === undefined && !envText.includes("omitted-e2e-secret") && !envText.includes("shell-copy");
results.nodeProxy = process.env.NODE_USE_ENV_PROXY === "1";
const proxy = new URL(process.env.HTTPS_PROXY);
const proxyAuth = "Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64");
const ph = process.env.DATABASE_URL;

function viaProxy(target, { method = "GET", headers = {}, body, auth = true } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: proxy.hostname, port: proxy.port, method, path: target,
        headers: { ...(auth ? { "Proxy-Authorization": proxyAuth } : {}), ...headers } },
      (res) => { let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode, body: b, location: res.headers.location })); },
    );
    req.on("error", reject);
    req.end(body);
  });
}

// 1. Substituted request to the allowed TLS destination.
const ok = await viaProxy("https://localhost:${tlsPort}/charge", {
  method: "POST",
  headers: { Authorization: "Bearer " + ph, "Content-Type": "application/json" },
  body: JSON.stringify({ dsn: ph }),
});
results.allowedStatus = ok.status;

// 1b. A Placeholder outside its targets in a targeted surface blocks, before exercise.
const outside = await viaProxy("https://localhost:${tlsPort}/outside", {
  headers: { Authorization: "Bearer " + ph, "X-Debug": ph },
});
results.outside = outside.status + ":" + outside.body;

// 1c. A stray in an untargeted surface (the query) is forwarded unchanged.
const stray = await viaProxy("https://localhost:${tlsPort}/stray?note=" + ph, { headers: { Authorization: "Bearer " + ph } });
results.strayStatus = stray.status;

// 2. Placeholder (never the secret) to a non-allowlisted host.
await viaProxy("http://127.0.0.1:${decoyPort}/exfil", { headers: { Authorization: "Bearer " + ph } });

// 3. Redirect is relayed, not followed.
const redir = await viaProxy("https://localhost:${tlsPort}/redirect", { headers: { Authorization: "Bearer " + ph } });
results.redirectRelayed = redir.status === 302 && String(redir.location).includes("/stolen");
// A naive client following it goes through the proxy again -> unauthorized target gets the placeholder.
await viaProxy("http://127.0.0.1:${decoyPort}/stolen", { headers: { Authorization: "Bearer " + ph } });

// 4. CONNECT to the secret-using destination is refused with the diagnostic.
results.connect = await new Promise((resolve) => {
  const req = http.request({ host: proxy.hostname, port: proxy.port, method: "CONNECT",
    path: "localhost:${tlsPort}", headers: { "Proxy-Authorization": proxyAuth } });
  req.on("connect", (res, socket, head) => { socket.destroy(); resolve(res.statusCode + ":" + head.toString()); });
  req.on("error", (e) => resolve("error:" + e.message));
  req.end();
});

// 5. The proxy rejects requests without the per-run token.
results.noAuthStatus = (await viaProxy("http://127.0.0.1:${decoyPort}/x", { auth: false })).status;

console.log("AGENT_RESULTS " + JSON.stringify(results));
`);

// Without a target or an omit for every stored Secret, nothing starts and nothing is issued.
const CAPS = "/v1/organizations/acme/projects/api/environments/development/capabilities";
const capsBefore = (await api("GET", CAPS, null, broker.credential)).json.items.length;
const untargeted = await run(["run", "--agent-safe", "--agent", "e2e agent", "--allow-host", `localhost:${tlsPort}`, "--", "node", "-e", "console.log('STARTED')"]);
check("a run with an untargeted Secret refuses to start, naming the item and the flags",
  untargeted.code !== 0 && !untargeted.out.includes("STARTED") &&
    untargeted.out.includes("DATABASE_URL has no substitution target: add --target DATABASE_URL=header:authorization"),
  untargeted.out);
check("the refused run issued no Capability", (await api("GET", CAPS, null, broker.credential)).json.items.length === capsBefore);

const agentRun = await run([
  "run", "--agent-safe", "--agent", "e2e agent", "--allow-host", `localhost:${tlsPort}`, ...targetArgs,
  "--", "node", agentScript,
], { env: { ...cliEnv, DATABASE_URL: "shell-copy", E2E_OMITTED: "shell-copy" } });
const resultsLine = agentRun.out.split("\n").find((l) => l.startsWith("AGENT_RESULTS "));
if (!resultsLine) {
  console.error(`FAIL  agent-safe run produced no results (exit ${agentRun.code}):\n${agentRun.out}`);
  process.exit(1);
}
const r = JSON.parse(resultsLine.slice("AGENT_RESULTS ".length));
check("agent env contains no stored Secret plaintext", r.noPlaintext);
check("agent holds no reusable Varlatch credential", r.noBearer);
check("Secret injected as an opaque placeholder", r.placeholder);
check("non-sensitive value injected as plaintext", r.plainValue);
check("an omitted Secret and the shell's stale copies never reach the Agent", r.omittedAbsent);
check("the run names the inherited Secrets it removed", /removed Secrets inherited from this shell[^\n]*E2E_OMITTED/.test(agentRun.out), agentRun.out);
check("Node's fetch is pointed at the Broker (NODE_USE_ENV_PROXY=1)", r.nodeProxy);
check("a Placeholder outside its targets blocks with a diagnostic naming item and location",
  r.outside.startsWith("403:") && r.outside.includes('DATABASE_URL: placeholder at header "x-debug", which is not a target'), r.outside);
check("the blocked request never reached the destination", !tlsRequests.some((q) => q.url === "/outside"));
check("a stray Placeholder in an untargeted surface is forwarded unchanged",
  r.strayStatus === 200 && tlsRequests.some((q) => q.url.startsWith("/stray?note=vlch_ph_v1_") && q.auth === `Bearer ${SECRET}`));
check("allowed inspectable request succeeded through the broker", r.allowedStatus === 200, `status ${r.allowedStatus}`);
check("proxy requires the per-run token", r.noAuthStatus === 407, `status ${r.noAuthStatus}`);
check("redirect relayed to the agent, not followed", r.redirectRelayed);
check("CONNECT to secret-using destination refused with diagnostic",
  String(r.connect).startsWith("502") && String(r.connect).includes("intentionally does not MITM"), r.connect);

const charge = tlsRequests.find((q) => q.url === "/charge");
check("upstream received the real credential over TLS",
  charge?.auth === `Bearer ${SECRET}` && JSON.parse(charge?.body ?? "{}").dsn === SECRET);
check("redirect request itself carried the real credential to the allowed host",
  tlsRequests.find((q) => q.url === "/redirect")?.auth === `Bearer ${SECRET}`);
check("unauthorized host received only placeholders, never the secret",
  decoyRequests.length === 2 &&
    decoyRequests.every((q) => /^Bearer vlch_ph_v1_/.test(q.auth ?? "") && !q.body.includes(SECRET)));

// --- agent metadata-credential mode (ADR-0023) ------------------------------

await api("POST", "/v1/organizations/acme/grants", {
  subjectIdentityId: agent.id,
  scope: { kind: "project", projectId },
  actions: ["config.metadata.read"],
});

const metaScript = join(repoDir, "agent-meta.mjs");
writeFileSync(metaScript, `
const results = {};
results.token = process.env.VARLATCH_TOKEN ?? "";
results.hasAgentToken = /^vlt_agr_/.test(results.token);
const base = process.env.VARLATCH_SERVER;
const headers = { Authorization: "Bearer " + results.token };
const res = await fetch(base + "/v1/organizations/acme/projects/api/environments/development/effective-configuration", { headers });
const body = await res.text();
results.metadataStatus = res.status;
results.seesItems = body.includes("DATABASE_URL");
results.noPlaintextInMetadata = !body.includes(${JSON.stringify(SECRET)});
const write = await fetch(base + "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL", {
  method: "PUT", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ value: "evil" }),
});
results.writeStatus = write.status;
console.log("META_RESULTS " + JSON.stringify(results));
`);

const metaRun = await run([
  "run", "--agent-safe", "--agent", "e2e agent", "--allow-host", `localhost:${tlsPort}`, ...targetArgs,
  "--agent-metadata", "--", "node", metaScript,
]);
const metaLine = metaRun.out.split("\n").find((l) => l.startsWith("META_RESULTS "));
if (!metaLine) {
  console.error(`FAIL  metadata-credential run produced no results (exit ${metaRun.code}):\n${metaRun.out}`);
  process.exit(1);
}
const m = JSON.parse(metaLine.slice("META_RESULTS ".length));
check("metadata mode injects a short-lived agent-run bearer", m.hasAgentToken);
check("agent reads configuration metadata directly", m.metadataStatus === 200 && m.seesItems, `status ${m.metadataStatus}`);
check("metadata response carries no Secret plaintext", m.noPlaintextInMetadata);
check("agent-run credential is read-only at the HTTP layer", m.writeStatus === 403, `status ${m.writeStatus}`);
const afterRun = await fetch(
  `${server}/v1/organizations/acme/projects/api/environments/development/effective-configuration`,
  { headers: { Authorization: `Bearer ${m.token}` } },
);
check("agent-run credential is revoked when the run exits", afterRun.status === 401, `status ${afterRun.status}`);

// --- exercise-time semantics via the API (broker credential) ----------------

const CAP_BASE = CAPS;
const issue = () =>
  api("POST", CAP_BASE, {
    agentIdentityId: agent.id,
    items: ["DATABASE_URL"],
    destinations: [`localhost:${tlsPort}`],
    targets: { DATABASE_URL: ["header:authorization"] },
    ttlSeconds: 600,
  }, broker.credential);
const exercise = (cap, placements = [{ item: "DATABASE_URL", target: "header:authorization" }]) =>
  api("POST", `${CAP_BASE}/${cap.id}/exercises`, {
    capabilitySecret: cap.secret,
    destination: { host: "localhost", port: tlsPort },
    placements,
  }, broker.credential);

const targetless = await api("POST", CAP_BASE, {
  agentIdentityId: agent.id, items: ["DATABASE_URL"], destinations: [`localhost:${tlsPort}`], ttlSeconds: 600,
}, broker.credential);
check("issuance without targets is refused, naming the minimum CLI version",
  targetless.status === 422 && String(targetless.json?.error?.message).includes("0.11.0"), JSON.stringify(targetless.json));

const runCap = (await issue()).json;
check("issuance records and returns the targets", JSON.stringify(runCap.targets) === JSON.stringify({ DATABASE_URL: ["header:authorization"] }));
const unplaced = await exercise(runCap, [{ item: "DATABASE_URL", target: "json:/dsn" }]);
check("an exercise naming a target the Capability does not hold is denied",
  unplaced.status === 403 && unplaced.json?.error?.details?.reason === "placement-not-targeted");
check("exercise succeeds while the Grant stands", (await exercise(runCap)).status === 200);

await api("DELETE", `/v1/organizations/acme/grants/${grant.id}`);
check("revoking secret.use denies the very next exercise", (await exercise(runCap)).status === 403);
const regrant = (await api("POST", "/v1/organizations/acme/grants", {
  subjectIdentityId: agent.id, scope: { kind: "project", projectId }, actions: ["secret.use"],
})).json;

await api("DELETE", `${CAP_BASE}/${runCap.id}`, null, broker.credential);
check("revoking the Capability denies the next exercise", (await exercise(runCap)).status === 403);

const shortCap = (await api("POST", CAP_BASE, {
  agentIdentityId: agent.id, items: ["DATABASE_URL"], destinations: [`localhost:${tlsPort}`],
  targets: { DATABASE_URL: ["header:authorization"] }, ttlSeconds: 1,
}, broker.credential)).json;
await new Promise((r2) => setTimeout(r2, 1500));
check("expired Capability fails closed", (await exercise(shortCap)).status === 403);

await api("PUT", "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL",
  { value: "postgres://dev-db-rotated" });
const rotCap = (await issue()).json;
const rotated = (await exercise(rotCap)).json;
check("rotation is picked up at the next exercise (Model B)",
  rotated.items?.[0]?.value === "postgres://dev-db-rotated");
await api("PUT", "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL",
  { value: SECRET }); // restore for later suites
void regrant;

// --- reference expansion at exercise (ADR-0026) -----------------------------

const VALUES = "/v1/organizations/acme/projects/api/environments/development/values";
await api("PUT", `${VALUES}/API_KEY`, { value: "ak_e2e" });
await api("PUT", `${VALUES}/DATABASE_URL`, { value: "postgres://app:${API_KEY}@host:${PORT}/app" });

const unboundCap = (await issue()).json; // items: DATABASE_URL only
const unbound = await exercise(unboundCap);
check("unbound secret reference denies the exercise",
  unbound.status === 403 && unbound.json?.error?.details?.cause === "secret-not-bound",
  `status ${unbound.status} cause ${unbound.json?.error?.details?.cause}`);

const boundIssue = () => api("POST", CAP_BASE, {
  agentIdentityId: agent.id,
  items: ["DATABASE_URL", "API_KEY"],
  destinations: [`localhost:${tlsPort}`],
  targets: { DATABASE_URL: ["header:authorization"], API_KEY: ["header:x-api-key"] },
  ttlSeconds: 600,
}, broker.credential);
const noPlainCap = (await boundIssue()).json;
const noPlain = await exercise(noPlainCap);
check("plain reference without config.value.read denies the exercise",
  noPlain.status === 403 && noPlain.json?.error?.details?.cause === "plain-read-denied",
  `status ${noPlain.status} cause ${noPlain.json?.error?.details?.cause}`);

await api("POST", "/v1/organizations/acme/grants", {
  subjectIdentityId: agent.id, scope: { kind: "project", projectId }, actions: ["config.value.read"],
});
const refPort = (await api("GET",
  "/v1/organizations/acme/projects/api/environments/development/effective-configuration?include=values",
)).json.items.find((i) => i.name === "PORT")?.value;
const expandedCap = (await boundIssue()).json;
const expanded = (await exercise(expandedCap)).json;
check("bound-secret and authorized plain references expand at exercise",
  expanded.items?.find((i) => i.name === "DATABASE_URL")?.value ===
    `postgres://app:ak_e2e@host:${refPort}/app`,
  expanded.items?.find((i) => i.name === "DATABASE_URL")?.value);
check("only the placed Secret is returned; the bound dependency is not",
  JSON.stringify(expanded.items?.map((i) => i.name)) === JSON.stringify(["DATABASE_URL"]));

await api("PUT", `${VALUES}/DATABASE_URL`, { value: SECRET }); // restore for later suites
await api("DELETE", `${VALUES}/E2E_OMITTED`);

// --- audit ------------------------------------------------------------------

const exportRes = await fetch(`${server}/v1/organizations/acme/audit-events/export`, {
  headers: { Authorization: `Bearer ${adminToken}` },
});
const ndjson = await exportRes.text();
const events = ndjson.trim().split("\n").map((l) => JSON.parse(l));
const exercised = events.filter((e) => e.eventType === "capability.exercised");
const good = exercised.find((e) => e.metadata?.items?.startsWith("DATABASE_URL@ver_"));
check("exercise audit identifies agent, broker, destination, item@version",
  good !== undefined &&
    good.actorIdentityId === broker.id &&
    good.resource?.agentIdentityId === agent.id &&
    good.metadata?.destination === `localhost:${tlsPort}`);
check("denial audit records the internal reason",
  events.some((e) => e.eventType === "capability.denied" && e.metadata?.reason === "authz-denied"));
check("issuance audit records the targets, exercise audit the placements",
  events.some((e) => e.eventType === "capability.issued" && e.metadata?.targets === "DATABASE_URL=header:authorization;DATABASE_URL=json:/dsn") &&
    exercised.some((e) => e.metadata?.placements === "DATABASE_URL=header:authorization;DATABASE_URL=json:/dsn"));
check("a bound dependency is audited as a reference expansion before it is decrypted",
  events.some((e) => e.eventType === "secret.disclosed" && e.metadata?.mode === "reference-expansion" && String(e.metadata?.items).startsWith("API_KEY@ver_")));
check("audit export contains no secret plaintext",
  !ndjson.includes(SECRET) && !ndjson.includes("dev-db-rotated") && !ndjson.includes("omitted-e2e-secret"));

tlsUpstream.close();
decoyUpstream.close();

if (failures > 0) {
  console.error(`FAIL  broker E2E: ${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("broker E2E complete");
