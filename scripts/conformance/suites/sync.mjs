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
 * Then the GitHub App (ADR-0047), against the fake GitHub's App side:
 * the manifest flow (a registration started, GitHub's code converted into
 * the App, the state consumed once); an App GitHub created on another
 * account refused; an App imported by its id and key; the App's
 * installations; a Connection on an installation, whose Target is pushed
 * with installation tokens narrowed to its repository; the key rotated;
 * under admin-step-up at enforce, a pending conversion discarded, and one
 * ended by the hourly sweep once its hour is over; and the App removed.
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
/** The fake GitHub's App side (lib/platform-fakes.cjs, POST /_github). */
const github = (op) => JSON.parse(targetOp("platform-fakes", ["github", JSON.stringify(op)]));

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
// The engine's trigger scan reads this many audit events a pass, as the
// TypeScript engine's (SCAN_BATCH), a pass every 30 seconds.
const SCAN_BATCH = 500;
const PASS_INTERVAL_MS = 30_000;

/**
 * Waits until the engine's trigger scan has read every audit event written
 * so far, so that a value changed before it has reached the engine. The
 * scan reads SCAN_BATCH events a pass: after the suites that ran before
 * this one in the same server, a change waits behind their events for as
 * many passes as they fill. The deadline is those passes and two more.
 * Answers the position, or null if the deadline passed.
 */
async function scanned() {
  const position = () => JSON.parse(targetOp("probe", ["sync-trigger-position"]));
  const { cursor, latest } = position();
  const passes = Math.ceil(Math.max(0, latest - cursor) / SCAN_BATCH) + 2;
  return waitFor(() => {
    const p = position();
    return p.cursor >= latest && p;
  }, passes * PASS_INTERVAL_MS);
}
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
  const seenBroken = await scanned();
  const degraded = await waitFor(async () => {
    const t = await targetOf(tGh);
    return /BROKEN_TOKEN \(HTTP 500\)/.test(t.lastResult ?? "") && t.failureCount >= 1 && t;
  });
  const others = await Promise.all([tApp, tConvex].map(targetOf));
  check(
    "sync.partial-failure",
    "a name the platform refuses degrades its Target and counts a failure; its other names stay, and other Targets are unaffected",
    Boolean(seenBroken) && Boolean(degraded) && ["API_KEY", "DEBUG", "PORT"].every((n) => fakes().github[repo]?.includes(n)) && others.every((t) => t.failureCount === 0),
    JSON.stringify({ scanned: seenBroken, degraded: degraded && [degraded.lastResult, degraded.failureCount], others: others.map((t) => [t.lastResult, t.failureCount]) }),
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
  const seenDeletion = await scanned();
  const deleted = await waitFor(() => {
    const s = fakes();
    return !(s.github[repo] ?? []).includes("DEBUG") && !("DEBUG" in s.convex) && s;
  });
  check("sync.deletion", "a value removed from the environment is deleted from the destinations of Targets that remove orphans",
    Boolean(seenDeletion) && Boolean(deleted),
    JSON.stringify(deleted && seenDeletion ? {} : { scanned: seenDeletion, github: fakes().github[repo], convex: Object.keys(fakes().convex) }));

  // The pause fence: a paused Target sends nothing, then resumes.
  const paused = await api("POST", `${env}/sync-targets/${tConvex}/pause?wait=true`, { body: {} });
  const before = fakes().requests.length;
  await put("PORT", "9090");
  const seenPort = await scanned();
  await waitFor(() => fakes().coolify[APP]?.PORT === "9090");
  await sleep(35_000); // one more pass, in which the paused Target would have run
  const sentWhilePaused = fakes().requests.slice(before).filter((r) => r.host === "convex.conformance.test");
  const resumed = ok(await api("POST", `${env}/sync-targets/${tConvex}/resume`, { body: {} }), "resuming the Convex Target");
  const caughtUp = await waitFor(() => fakes().convex.PORT === "9090");
  check(
    "sync.pause-fence",
    "a paused Target answers paused once no run of it can send, sends nothing while paused, and converges once resumed",
    Boolean(seenPort) && paused.status === 200 && paused.json?.state === "paused" && paused.json?.drained === true && sentWhilePaused.length === 0 &&
      resumed.state === "active" && Boolean(caughtUp),
    JSON.stringify({ scanned: seenPort, paused: paused.json?.state, drained: paused.json?.drained, sentWhilePaused, resumed: resumed.state, convexPort: fakes().convex.PORT }),
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

  // ---- The GitHub App (ADR-0047).
  const appNumber = 7000 + Number.parseInt(suffix.slice(0, 4), 16);
  const owner = { login: `acme-apps-${suffix}`, id: 9100 + Number.parseInt(suffix.slice(4), 16), type: "Organization" };
  const account = { login: owner.login, type: "organization" };
  const fakeApp = (n) => ({ id: appNumber + n, slug: `varlatch-${suffix}-${n}`, clientId: `Iv1.conf${suffix}${n}`, owner });
  const appOrg = async (name) => {
    const s = `${name}-${suffix}`;
    ok(await api("POST", "/v1/organizations", { body: { name, slug: s } }), `creating the Organization ${s}`);
    return `/v1/organizations/${s}`;
  };
  const start = async (o) => ok(await api("POST", `${o}/github-app/registrations`, { body: { account } }), "starting a registration");

  // The manifest flow: a registration started, GitHub's code converted into
  // the App (its key kept, never shown), the state consumed once.
  const A = await appOrg("sync-app");
  const started = await start(A);
  github({ op: "manifest-code", code: `code-${suffix}-1`, app: fakeApp(1) });
  const completed = await api("POST", `${A}/github-app/registrations/complete`, { body: { state: started.state, code: `code-${suffix}-1` } });
  const again = await api("POST", `${A}/github-app/registrations/complete`, { body: { state: started.state, code: `code-${suffix}-1` } });
  const stored = await api("GET", `${A}/github-app`);
  check(
    "sync.github-app-registered",
    "a registration started for a GitHub account names GitHub's form and a single-use state; completing it with GitHub's code stores the App GitHub handed over, never showing its key, and the state cannot complete again",
    typeof started.state === "string" && started.account?.login === account.login && typeof started.manifest === "object" &&
      String(started.action ?? "").startsWith(`https://github.com/organizations/${account.login}/settings/apps/new`) &&
      completed.status === 201 && completed.json?.outcome === "registered" && completed.json.app?.githubAppId === fakeApp(1).id &&
      completed.json.app.slug === fakeApp(1).slug && completed.json.app.owner?.type === "organization" &&
      stored.status === 200 && stored.json?.githubAppId === fakeApp(1).id && !stored.text.includes("PRIVATE KEY") && !completed.text.includes("PRIVATE KEY") &&
      again.status === 410 && again.json?.error?.code === "CONSUMED" && fakes().codesUsed.includes(`code-${suffix}-1`),
    JSON.stringify({ started: { action: started.action, account: started.account }, completed: completed.status, outcome: completed.json?.outcome, app: completed.json?.app, again: [again.status, again.json?.error?.code], stored: stored.status }),
  );

  // Its installations, read as the App; a Connection on one; a Target on
  // that Connection pushed with installation tokens narrowed to its
  // repository.
  const appRepo = `app-${suffix}`;
  const { installationId } = github({ op: "install", appId: fakeApp(1).id, account: owner, repos: [appRepo, `other-${suffix}`] });
  const listing = ok(await api("GET", `${A}/github-app/installations`), "listing the installations");
  const listed = (listing.items ?? []).find((i) => i.installationId === installationId);
  check("sync.github-app-installations", "the App's installations are listed as GitHub answers them to the App, each with its account",
    listing.check?.status === "ok" && listed?.account?.login === owner.login && listed.repositorySelection === "selected" && listed.suspended === false,
    JSON.stringify(listing));
  const AE = `${A}/projects/api/environments/production`;
  ok(await api("POST", `${A}/projects`, { body: { slug: "api", name: "API", contractAuthority: "managed" } }), "creating the App Organization's Project");
  ok(await api("POST", `${A}/projects/api/environments`, { body: { name: "production", tier: "production" } }), "creating its environment");
  const appItems = ["APP_TOKEN", "APP_MODE"].map((name) => ({ name, required: { kind: "never" }, sensitive: name === "APP_TOKEN", type: "string" }));
  const appRevision = ok(await api("POST", `${A}/projects/api/contract/revisions`, { body: { contract: { schemaVersion: 1, items: appItems } } }), "its Contract");
  ok(await api("POST", `${A}/projects/api/contract/revisions/${appRevision.id}/activate`, { body: {} }), "activating it");
  ok(await api("PUT", `${AE}/values/APP_TOKEN`, { body: { value: `t-${suffix}` } }), "setting APP_TOKEN");
  const appConnection = await api("POST", `${A}/platform-connections`, { body: { credentialKind: "github-app", installationId, name: "App" } });
  const mintsBefore = fakes().mints.length;
  const appTarget = appConnection.status === 201
    ? ok(await api("POST", `${AE}/sync-targets`, { body: { connectionId: appConnection.json.id, destination: { repo: appRepo }, mapping: { kind: "wildcard" } } }), "creating the App Target").id
    : null;
  const appPushed = appTarget && await waitFor(() => {
    const s = fakes();
    return (s.github[`${owner.login}/${appRepo}`] ?? []).includes("APP_TOKEN") && s;
  });
  const appMints = fakes().mints.slice(mintsBefore).filter((m) => m.installationId === installationId);
  check(
    "sync.github-app-connection-pushes",
    "a Connection on an installation of the App takes the installation's account as its base identity, and its Target is pushed with installation tokens minted narrowed to the Target's repository",
    appConnection.status === 201 && appConnection.json?.credentialKind === "github-app" && appConnection.json.installationId === installationId &&
      appConnection.json.githubAppId === stored.json?.id && appConnection.json.baseIdentity === owner.login && Boolean(appPushed) &&
      appMints.length > 0 && appMints.every((m) => JSON.stringify(m.repositories) === JSON.stringify([appRepo.toLowerCase()])) &&
      !(fakes().github[`${owner.login}/other-${suffix}`] ?? []).length,
    JSON.stringify({ connection: [appConnection.status, appConnection.json?.credentialKind, appConnection.json?.baseIdentity, appConnection.json?.error], pushed: Boolean(appPushed), mints: appMints }),
  );

  // The key rotated: a key GitHub does not know is refused; the new one is
  // taken, the old one deleted on GitHub, and the Target pushed with it.
  const { pem: stranger } = github({ op: "app", app: fakeApp(9) });
  const refusedKey = await api("POST", `${A}/github-app/key`, { body: { privateKey: stranger, expectedVersion: stored.json?.version } });
  const { pem: newPem } = github({ op: "add-key", appId: fakeApp(1).id });
  const rotated = await api("POST", `${A}/github-app/key`, { body: { privateKey: newPem, expectedVersion: stored.json?.version } });
  const stale = await api("POST", `${A}/github-app/key`, { body: { privateKey: newPem, expectedVersion: stored.json?.version } });
  // Every other key is deleted on GitHub: only the new one signs now, so
  // the next push shows the rotation took.
  const keysLeft = github({ op: "keep-only-key", appId: fakeApp(1).id, pem: newPem }).keys;
  ok(await api("PUT", `${AE}/values/APP_MODE`, { body: { value: "rotated" } }), "setting APP_MODE");
  const afterRotation = await waitFor(() => (fakes().github[`${owner.login}/${appRepo}`] ?? []).includes("APP_MODE"));
  check(
    "sync.github-app-key-rotation",
    "rotating the App's key verifies the new key as the App first (a key GitHub does not know is refused, nothing changes), takes it at the App's version, refuses a stale version, and pushes with it",
    refusedKey.status === 200 && refusedKey.json?.outcome === "failed" && rotated.status === 200 && rotated.json?.outcome === "rotated" &&
      rotated.json.app?.version === stored.json.version + 1 && stale.status === 409 && Boolean(afterRotation) && keysLeft === 1,
    JSON.stringify({ refused: [refusedKey.status, refusedKey.json?.outcome], rotated: [rotated.status, rotated.json?.outcome, rotated.json?.app?.version], stale: stale.status, pushed: Boolean(afterRotation) }),
  );

  // The App removed: its Connection revoked, its Target disabled.
  const removed = await api("DELETE", `${A}/github-app?appId=${encodeURIComponent(stored.json?.id ?? "")}`);
  const gone = await api("GET", `${A}/github-app`);
  const connectionAfter = appConnection.json?.id ? await api("GET", `${A}/platform-connections/${appConnection.json.id}`) : { status: 0 };
  const targetAfter = appTarget ? await api("GET", `${AE}/sync-targets/${appTarget}`) : { status: 0 };
  check(
    "sync.github-app-removed",
    "removing the App revokes every Connection on it and disables their Targets; the Organization has no App afterwards",
    removed.status === 204 && (gone.status === 404 || gone.json === null) &&
      (connectionAfter.status === 404 || typeof connectionAfter.json?.revokedAt === "string") &&
      (targetAfter.status === 404 || targetAfter.json?.state === "disabled" || typeof targetAfter.json?.revokedAt === "string"),
    JSON.stringify({ removed: removed.status, gone: [gone.status, gone.json], connection: [connectionAfter.status, connectionAfter.json?.revokedAt], target: [targetAfter.status, targetAfter.json?.state] }),
  );

  // An App GitHub created on another account is refused and nothing is
  // kept; then an App imported by its id and private key.
  const B = await appOrg("sync-app-import");
  const elsewhere = await start(B);
  github({ op: "manifest-code", code: `code-${suffix}-2`, app: { ...fakeApp(2), owner: { login: `someone-${suffix}`, id: 9999, type: "User" } } });
  const mismatch = await api("POST", `${B}/github-app/registrations/complete`, { body: { state: elsewhere.state, code: `code-${suffix}-2` } });
  const noneKept = await api("GET", `${B}/github-app`);
  check(
    "sync.github-app-owner-mismatch",
    "an App GitHub created on another account than the one named is refused with where to delete it, and nothing is kept",
    mismatch.status === 200 && mismatch.json?.outcome === "refused" && mismatch.json.reason === "owner-mismatch" &&
      typeof mismatch.json.deleteUrl === "string" && mismatch.json.deleteUrl.includes(fakeApp(2).slug) && (noneKept.status === 404 || noneKept.json === null),
    JSON.stringify({ mismatch: [mismatch.status, mismatch.json?.outcome, mismatch.json?.reason, mismatch.json?.deleteUrl], kept: [noneKept.status, noneKept.json] }),
  );
  const { pem: importPem } = github({ op: "app", app: fakeApp(3) });
  const wrongPair = await api("POST", `${B}/github-app/import`, { body: { appId: fakeApp(3).id, privateKey: stranger } });
  const imported = await api("POST", `${B}/github-app/import`, { body: { appId: fakeApp(3).id, privateKey: importPem } });
  check(
    "sync.github-app-import",
    "an App is imported by its id and private key, verified as the App first: a key that does not sign for it is refused; the slug, client id and owner come from GitHub",
    wrongPair.status === 200 && wrongPair.json?.outcome === "failed" && imported.status === 201 && imported.json?.outcome === "registered" &&
      imported.json.app?.githubAppId === fakeApp(3).id && imported.json.app.slug === fakeApp(3).slug && imported.json.app.clientId === fakeApp(3).clientId &&
      imported.json.app.owner?.login === owner.login && !imported.text.includes("PRIVATE KEY"),
    JSON.stringify({ wrong: [wrongPair.status, wrongPair.json?.outcome], imported: [imported.status, imported.json?.outcome, imported.json?.app] }),
  );

  // Under admin-step-up at enforce, GitHub's answer is kept as a pending
  // conversion and its attachment asks for an approval: one discarded by
  // the person who started it; another ended by the hourly sweep once its
  // hour is over.
  const C = await appOrg("sync-app-staged");
  for (const [mode, version] of [["report", 0], ["enforce", 1]]) {
    ok(await api("PATCH", `${C}/security/controls/admin-step-up`, { body: { mode, expectedVersion: version } }), `admin-step-up at ${mode}`);
  }
  const pendingOf = async (n) => {
    const r = await start(C);
    github({ op: "manifest-code", code: `code-${suffix}-${n}`, app: fakeApp(n) });
    const c = await api("POST", `${C}/github-app/registrations/complete`, { body: { state: r.state, code: `code-${suffix}-${n}` } });
    const approval = c.json?.error?.details?.approval?.id;
    if (approval) ok(await api("POST", `/v1/me/approvals/${approval}/cancel`), "cancelling the approval");
    return { status: c.status, code: c.json?.error?.code, registrationId: c.json?.error?.details?.registrationId };
  };
  const p4 = await pendingOf(4);
  const discarded = p4.registrationId ? await api("DELETE", `${C}/github-app/registrations/${p4.registrationId}`) : { status: 0 };
  const discardedAgain = p4.registrationId ? await api("DELETE", `${C}/github-app/registrations/${p4.registrationId}`) : { status: 0 };
  const attachEnded = p4.registrationId ? await api("POST", `${C}/github-app/registrations/${p4.registrationId}/attach`, { body: {} }) : { status: 0 };
  check(
    "sync.github-app-pending-discard",
    "under admin-step-up at enforce, completing a registration keeps GitHub's App pending and asks for an approval to attach it; the person who started it discards it, with where to delete the App; discarding again changes nothing, and attaching it then is refused before any approval",
    p4.status === 403 && p4.code === "STEP_UP_REQUIRED" && typeof p4.registrationId === "string" &&
      discarded.status === 200 && discarded.json?.discarded === true && discarded.json.state === "discarded" &&
      typeof discarded.json.deleteUrl === "string" && discarded.json.app?.githubAppId === fakeApp(4).id &&
      discardedAgain.status === 200 && discardedAgain.json?.discarded === false && discardedAgain.json.state === "ended" &&
      attachEnded.status === 200 && attachEnded.json?.outcome === "refused" && attachEnded.json.reason === "registration-ended",
    JSON.stringify({ pending: p4, discarded: [discarded.status, discarded.json], again: [discardedAgain.status, discardedAgain.json?.state], attach: [attachEnded.status, attachEnded.json?.outcome, attachEnded.json?.reason] }),
  );
  const p5 = await pendingOf(5);
  if (p5.registrationId) JSON.parse(targetOp("probe", ["github-app-pending-expired", p5.registrationId]));
  const swept = p5.registrationId && await waitFor(async () => {
    const items = ok(await api("GET", `${C}/audit-events?eventType=sync.github_app_registration_abandoned&limit=50`), "listing abandoned registrations").items ?? [];
    return items.find((e) => e.metadata?.registrationId === p5.registrationId) ?? null;
  }, 90_000);
  const afterSweep = p5.registrationId ? await api("DELETE", `${C}/github-app/registrations/${p5.registrationId}`) : { status: 0 };
  check(
    "sync.github-app-sweep",
    "a pending conversion not attached within its hour is ended by the registration sweep (recorded with reason expired, its key deleted); discarding it afterwards changes nothing",
    p5.status === 403 && Boolean(swept) && swept.metadata?.reason === "expired" && swept.metadata?.appId === fakeApp(5).id &&
      afterSweep.status === 200 && afterSweep.json?.discarded === false && afterSweep.json.state === "ended",
    JSON.stringify({ pending: p5, swept: swept ? { metadata: swept.metadata } : null, after: [afterSweep.status, afterSweep.json?.state] }),
  );
} catch (err) {
  error(err instanceof Error ? err.message : String(err));
}
finish();
