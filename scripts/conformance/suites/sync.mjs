#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Sync Targets delivered by the server's converge engine (ADR-0031,
 * ADR-0050), against fake GitHub, Coolify and Convex services (the
 * platform-fakes capability: lib/platform-fakes.cjs, which the target's
 * own host names lead to and its outbound allow list lets through). The
 * engine runs every 30 seconds; the suite waits for it.
 *
 * In an Organization of its own: a Project whose Contract has a Secret and
 * plain items, their values, Connections to the three platforms, and
 * Targets: a GitHub repository (every item, orphans removed), a Coolify
 * application (two items, redeployed on change), a Coolify service and the
 * Convex deployment. Then: a successful push; the redeploy debt paid (the
 * application runs what it stores); the credential's expiry the platform
 * reported; a partial failure and its backoff; pushSyncTarget; a deletion;
 * the pause fence; drift found and put back by a repair pass, with its
 * audit event; and the repair cycle closing.
 *
 *   sync.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { randomBytes } from "node:crypto";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: sync.mjs <origin> <api token>");
  process.exit(64);
}
const kit = reporter({ detailOnFailure: true });
const { check, error, finish } = kit;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, { body } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "varlatch-conformance-sync",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON: kept as text for the detail.
  }
  return { status: res.status, json, text };
}

const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text}`);
  return r.json;
};

const fakes = () => JSON.parse(targetOp("platform-fakes", ["state"]));

/** Waits until `done()` holds (it may read the fakes or the API), for up to `ms`; answers the last value. */
async function waitFor(done, ms = PASS_MS) {
  const deadline = Date.now() + ms;
  for (;;) {
    const got = await done();
    if (got || Date.now() > deadline) return got;
    await sleep(2000);
  }
}

// A converge's whole time: a pass every 30 seconds, and the next.
const PASS_MS = 75_000;
const APP = "/applications/app-conformance";
const SERVICE = "/services/svc-conformance";

const suffix = randomBytes(4).toString("hex");
const slug = `sync-${suffix}`;
const base = `/v1/organizations/${slug}`;
const env = `${base}/projects/api/environments/production`;
const repo = `acme/api-${suffix}`;

try {
  ok(await api("GET", "/v1/me"), "whoami");
  const hosts = JSON.parse(targetOp("platform-fakes", ["start"]));
  ok(await api("POST", "/v1/organizations", { body: { name: "Sync suite", slug } }), "creating the Organization");
  ok(await api("POST", `${base}/projects`, { body: { slug: "api", name: "API", contractAuthority: "managed" } }), "creating the Project");
  ok(await api("POST", `${base}/projects/api/environments`, { body: { name: "production", tier: "production" } }), "creating the environment");
  const items = [["API_KEY", true], ["BROKEN_TOKEN", false], ["DEBUG", false], ["PORT", false]]
    .map(([name, sensitive]) => ({ name, required: { kind: "never" }, sensitive, type: "string" }));
  const revision = ok(await api("POST", `${base}/projects/api/contract/revisions`, { body: { contract: { schemaVersion: 1, items } } }), "pushing the Contract");
  ok(await api("POST", `${base}/projects/api/contract/revisions/${revision.id}/activate`, { body: {} }), "activating the Contract");
  const put = async (name, value) => ok(await api("PUT", `${env}/values/${name}`, { body: { value } }), `setting ${name}`);
  await put("API_KEY", `key-${suffix}`);
  await put("DEBUG", "false");
  await put("PORT", "8080");

  const connection = async (name, platform, baseIdentity, credential) =>
    ok(await api("POST", `${base}/platform-connections`, { body: { platform, baseIdentity, name, credential } }), `creating the ${name} Connection`).id;
  // A credential the fake GitHub answers with an expiry date.
  const gh = await connection("GitHub", "github-actions", hosts.github, `conformance-expiring-${suffix}`);
  const coolify = await connection("Coolify", "coolify", hosts.coolify, `conformance-coolify-${suffix}`);
  const convex = await connection("Convex", "convex", hosts.convex, `prod:conformance-${suffix}`);
  const target = async (what, connectionId, destination, mapping, extra = {}) =>
    ok(await api("POST", `${env}/sync-targets`, { body: { connectionId, destination, mapping, ...extra } }), `creating the ${what} Target`).id;
  const tGh = await target("GitHub", gh, { repo: repo.split("/")[1] }, { kind: "wildcard" }, { removeOrphans: true });
  const tApp = await target("Coolify application", coolify, { applicationUuid: "app-conformance" },
    { kind: "explicit", items: [{ name: "PORT" }, { name: "API_KEY" }] }, { redeploy: true });
  await target("Coolify service", coolify, { serviceUuid: "svc-conformance" }, { kind: "wildcard", exclude: ["BROKEN_*"] });
  const tConvex = await target("Convex", convex, {}, { kind: "wildcard", exclude: ["BROKEN_*"] }, { removeOrphans: true });
  const targetOf = async (id) => ok(await api("GET", `${env}/sync-targets/${id}`), "reading a Target");

  // A successful push: every platform holds what its Target maps.
  const want = { API_KEY: `key-${suffix}`, DEBUG: "false", PORT: "8080" };
  const converged = await waitFor(() => {
    const s = fakes();
    const ghNames = s.github[repo] ?? [];
    return ["API_KEY", "DEBUG", "PORT"].every((n) => ghNames.includes(n)) &&
      s.coolify[APP]?.PORT === "8080" && s.coolify[APP]?.API_KEY === want.API_KEY &&
      Object.entries(want).every(([k, v]) => s.coolify[SERVICE]?.[k] === v && s.convex[k] === v) && s;
  });
  const results = await Promise.all([tGh, tApp, tConvex].map(targetOf));
  check(
    "sync.push-converges",
    "every Target's destination holds what its mapping selects, and each Target reports its run succeeded",
    Boolean(converged) && results.every((t) => /^(ok|converged)/.test(t.lastResult ?? "") && t.failureCount === 0),
    JSON.stringify({ fakes: converged && { github: converged.github, coolify: converged.coolify, convex: Object.keys(converged.convex) }, results: results.map((t) => [t.lastResult, t.failureCount]) }),
  );

  // The redeploy debt: the application, which redeploys on change, runs
  // what it stores.
  const running = await waitFor(() => {
    const s = fakes();
    return s.running[APP]?.PORT === "8080" && s.running[APP]?.API_KEY === want.API_KEY && s;
  });
  check("sync.redeploy-paid", "a Target that redeploys on change has its application redeployed: it runs what it stores", Boolean(running),
    JSON.stringify(fakes().running));

  // The credential's expiry, as the fake GitHub reported it.
  const ghConnection = ok(await api("GET", `${base}/platform-connections/${gh}`), "reading the GitHub Connection");
  check("sync.credential-expiry", "the expiry a platform reports for a stored credential is recorded on its Connection",
    ghConnection.credentialExpiresAt === "2031-01-01T00:00:00.000Z", JSON.stringify(ghConnection.credentialExpiresAt));

  // A partial failure: GitHub refuses one name; the others stay, the
  // Target is degraded and backs off; the other Targets do not mind.
  await put("BROKEN_TOKEN", "zzz");
  const degraded = await waitFor(async () => {
    const t = await targetOf(tGh);
    return /BROKEN_TOKEN \(HTTP 500\)/.test(t.lastResult ?? "") && t.failureCount >= 1 && t;
  });
  const others = await Promise.all([tApp, tConvex].map(targetOf));
  check(
    "sync.partial-failure",
    "a name the platform refuses degrades its Target and counts a failure; its other names stay, and other Targets are unaffected",
    Boolean(degraded) && ["API_KEY", "DEBUG", "PORT"].every((n) => fakes().github[repo]?.includes(n)) && others.every((t) => t.failureCount === 0),
    JSON.stringify({ degraded: degraded && [degraded.lastResult, degraded.failureCount], others: others.map((t) => [t.lastResult, t.failureCount]) }),
  );

  // pushSyncTarget: the backoff cleared, the Target due at once.
  ok(await api("DELETE", `${env}/values/BROKEN_TOKEN`), "removing the refused value");
  const pushed = await api("POST", `${env}/sync-targets/${tGh}/push`, { body: {} });
  const recovered = await waitFor(async () => {
    const t = await targetOf(tGh);
    return t.failureCount === 0 && /^(ok|converged)/.test(t.lastResult ?? "") && t;
  });
  check("sync.push-scheduled", "pushSyncTarget answers 202 and the Target runs again at the next pass, its backoff cleared",
    pushed.status === 202 && pushed.json?.scheduled === true && Boolean(recovered), JSON.stringify({ status: pushed.status, body: pushed.json, recovered: recovered?.lastResult }));

  // A deletion: a removed value leaves the destinations of Targets that
  // remove orphans.
  ok(await api("DELETE", `${env}/values/DEBUG`), "removing DEBUG");
  const deleted = await waitFor(() => {
    const s = fakes();
    return !(s.github[repo] ?? []).includes("DEBUG") && !("DEBUG" in s.convex) && s;
  });
  check("sync.deletion", "a value removed from the environment is deleted from the destinations of Targets that remove orphans",
    Boolean(deleted), JSON.stringify(deleted ? {} : { github: fakes().github[repo], convex: Object.keys(fakes().convex) }));

  // The pause fence: a paused Target sends nothing, then resumes.
  const paused = await api("POST", `${env}/sync-targets/${tConvex}/pause?wait=true`, { body: {} });
  const before = fakes().requests.length;
  await put("PORT", "9090");
  await waitFor(() => fakes().coolify[APP]?.PORT === "9090");
  await sleep(35_000); // one more pass, in which the paused Target would have run
  const sentWhilePaused = fakes().requests.slice(before).filter((r) => r.host === "convex.conformance.test");
  const resumed = ok(await api("POST", `${env}/sync-targets/${tConvex}/resume`, { body: {} }), "resuming the Convex Target");
  const caughtUp = await waitFor(() => fakes().convex.PORT === "9090");
  check(
    "sync.pause-fence",
    "a paused Target answers paused once no run of it can send, sends nothing while paused, and converges once resumed",
    paused.status === 200 && paused.json?.state === "paused" && paused.json?.drained === true && sentWhilePaused.length === 0 &&
      resumed.state === "active" && Boolean(caughtUp),
    JSON.stringify({ paused: paused.json?.state, drained: paused.json?.drained, sentWhilePaused, resumed: resumed.state, convexPort: fakes().convex.PORT }),
  );

  // Drift: a value changed and redeployed behind Varlatch's back (the
  // application stores and runs it) is found by a repair pass, recorded
  // and put back, and the application redeployed with it. The Target
  // starts settled and the probe moves only its last repair into the
  // past, so only the periodic repair schedule can make it due.
  const settled = await waitFor(async () => (await targetOf(tApp)).needsSync === false);
  const baseline = fakes().requests.length;
  JSON.parse(targetOp("platform-fakes", ["drift", APP, "API_KEY", "changed-outside"]));
  const drifted = fakes();
  const due = JSON.parse(targetOp("probe", ["sync-repair-due", tApp]));
  const appRequests = (s) => s.requests.slice(baseline).filter((r) => r.path.startsWith("/api/v1/applications/app-conformance"));
  // The repair: a write of the application's variables, then a redeploy
  // after it, and the application runs the value Varlatch stores. The
  // redeploy is a run's last call, so once it is seen the run sends nothing
  // more.
  const repaired = await waitFor(() => {
    const s = fakes();
    const sent = appRequests(s);
    const write = sent.findIndex((r) => (r.method === "PATCH" || r.method === "POST") && /\/envs(\/|\?|$)/.test(r.path));
    const redeploy = sent.findIndex((r, i) => i > write && /\/(start|restart)(\?|$)/.test(r.path));
    return write >= 0 && redeploy > write && s.coolify[APP]?.API_KEY === want.API_KEY && s.running[APP]?.API_KEY === want.API_KEY &&
      { write: `${sent[write].method} ${sent[write].path}`, redeploy: `${sent[redeploy].method} ${sent[redeploy].path}` };
  });
  const drift = (await targetOf(tApp)).lastDrift;
  const events = ok(await api("GET", `${base}/audit-events?eventType=sync.drift_detected&limit=100`), "listing drift events").items;
  const event = events.find((e) => e.resource?.targetId === tApp);
  check(
    "sync.drift-put-back",
    "a repair pass finds a value changed on the platform, records sync.drift_detected (names, never values) and the Target's last drift, puts the value back and redeploys the application",
    Boolean(settled) && drifted.coolify[APP]?.API_KEY === "changed-outside" && drifted.running[APP]?.API_KEY === "changed-outside" &&
      due.needsSync === false && due.nextAttemptAt === null &&
      Boolean(repaired) && drift?.count === 1 && JSON.stringify(drift?.names) === '["API_KEY"]' && Boolean(event) &&
      event.metadata?.changed === "API_KEY" && !JSON.stringify(event).includes("changed-outside") && !JSON.stringify(event).includes(want.API_KEY),
    JSON.stringify({ settled: Boolean(settled), due, repaired, running: fakes().running[APP]?.API_KEY === want.API_KEY, drift, event: event && { metadata: event.metadata } }),
  );

  // The repair cycle closes: once repaired (its run ended with the
  // redeploy above), the Target is not due again.
  const after = fakes().requests.length;
  await sleep(65_000); // two passes
  const sentAfter = fakes().requests.slice(after).filter((r) => r.path.startsWith("/api/v1/applications/app-conformance"));
  check("sync.repair-cycle-closes", "after its repair pass a converged Target is not due again: the next passes send its destination nothing",
    sentAfter.length === 0, JSON.stringify(sentAfter));
} catch (err) {
  error(err instanceof Error ? err.message : String(err));
}
finish();
