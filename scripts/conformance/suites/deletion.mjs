#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Deletion over the API (ADR-0051): a Project's deletion (Decision 2,
 * immediate and final), and, under admin-step-up at enforce, the approval
 * it asks for (ADR-0054 amendment B); then an Organization's deletion
 * (Decisions 4 to 8) and the audit-access tombstone (Decision 8).
 *
 * In an Organization of its own: a Project with two environments, an
 * active Contract, values (one with a second version) and a Team linking
 * it; its deletion, what it answers and what is left (nothing readable, the
 * slug free again, the Team's link gone, project.deleted with the counts).
 * Then, in a second Organization at enforce, the deletion's approval.
 *
 * Then an Organization with a machine identity and a second admin (an
 * admin invitation enrolled in a browser, services/varlatchd/scripts/
 * e2e-enroll-invitee.mjs): its deletion scheduled (the machine suspended,
 * writes refused), approved by the second admin and not by the one who
 * scheduled it, made due (the target's deletion-due probe) and run by the
 * deletion loop's next pass; its audit read and exported by its
 * readers, listed by the Installation Admin, who removes a reader. And in
 * another Organization, a scheduled deletion cancelled, which restores its
 * machine.
 *
 * What the due run tears down, in the Organization deleted: a Sync Target
 * (a GitHub repository on a token Connection, the fake platforms) paused
 * when the deletion is scheduled and revoked with its Connection when it
 * runs; a webhook suspended, then removed; its GitHub App (imported from
 * the fake GitHub) removed; and its audit export to a local S3 server,
 * which drains: the final events, organization.deleted among them, reach
 * the bucket and the drain completes. In a third Organization, an export
 * whose bucket is gone cannot drain, and is abandoned once its deadline
 * passes (the target's audit-export-drain-due probe).
 *
 *   deletion.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { listedKeys, s3Request } from "../lib/s3.mjs";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: deletion.mjs <origin> <api token>");
  process.exit(64);
}
const kit = reporter({ detailOnFailure: true });
const { check, error, finish } = kit;

async function api(method, path, { body, bearer = token } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${bearer}`,
      "User-Agent": "varlatch-conformance-deletion",
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

const suffix = randomBytes(4).toString("hex");
const ENROLL = fileURLToPath(new URL("../../../services/varlatchd/scripts/e2e-enroll-invitee.mjs", import.meta.url));

/** An invitation enrolled in a browser: the new person's short-lived API credential. */
function enroll(url, name) {
  const dir = mkdtempSync(join(tmpdir(), "deletion-enroll-"));
  try {
    const r = spawnSync(process.execPath, [ENROLL, url, name, join(dir, "credential")], { encoding: "utf8", timeout: 120_000 });
    if (r.status !== 0) throw new Error(`enrolling ${name}: ${(r.stderr || r.stdout).trim().slice(-500)}`);
    return readFileSync(join(dir, "credential"), "utf8").trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** Waits until `done()` answers a truthy value, for up to `ms`; answers the last value. */
async function waitFor(done, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    const got = await done();
    if (got || Date.now() > deadline) return got;
    await sleep(2000);
  }
}

/**
 * A bucket on the object store (Object Lock when `lock`). MinIO can answer
 * ready before it finishes initializing, refusing requests with 503
 * XMinioServerNotInitialized for a moment: that answer is retried within
 * 30 seconds.
 */
async function bucket(s3, name, lock) {
  const headers = lock ? { "x-amz-bucket-object-lock-enabled": "true" } : {};
  const deadline = Date.now() + 30_000;
  let made = await s3Request(s3, "PUT", `/${name}`, { headers });
  while (made.status === 503 && made.text.includes("XMinioServerNotInitialized") && Date.now() < deadline) {
    await sleep(500);
    made = await s3Request(s3, "PUT", `/${name}`, { headers, timeoutMs: Math.max(1000, deadline - Date.now()) });
  }
  if (made.status !== 200) throw new Error(`creating the bucket ${name}: ${made.status} ${made.text.slice(0, 300)}`);
}

/** Deletes a bucket without Object Lock and everything in it; the export may still be writing to it. */
async function removeBucket(s3, name) {
  for (let attempt = 0; attempt < 15; attempt++) {
    for (const key of listedKeys((await s3Request(s3, "GET", `/${name}`, { query: { "list-type": "2" } })).text)) {
      await s3Request(s3, "DELETE", `/${name}/${key}`);
    }
    const gone = await s3Request(s3, "DELETE", `/${name}`);
    if (gone.status === 204 || gone.status === 404) return;
    await sleep(1000);
  }
  throw new Error(`the bucket ${name} could not be removed`);
}
const item = (name, sensitive) => ({ name, required: { kind: "never" }, sensitive, type: "string" });

try {
  // ---- A Project's deletion.
  const org = ok(await api("POST", "/v1/organizations", { body: { name: `Deletion ${suffix}`, slug: `deletion-${suffix}` } }), "creating the Organization");
  const base = `/v1/organizations/${org.slug}`;
  const project = ok(await api("POST", `${base}/projects`, { body: { name: "Doomed", slug: "doomed", contractAuthority: "git" } }), "creating the Project");
  const P = `${base}/projects/doomed`;
  for (const tier of ["development", "production"]) ok(await api("POST", `${P}/environments`, { body: { name: tier, tier } }), `creating ${tier}`);
  const rev = ok(await api("POST", `${P}/contract/revisions`, { body: { contract: { schemaVersion: 1, items: [item("API_KEY", true), item("LOG_LEVEL", false)] } } }), "pushing a Contract");
  ok(await api("POST", `${P}/contract/revisions/${rev.id}/activate`), "activating the Contract");
  for (const [env, name, value] of [
    ["development", "API_KEY", "dev-1"], ["development", "API_KEY", "dev-2"], ["development", "LOG_LEVEL", "debug"], ["production", "API_KEY", "prod-1"],
  ]) {
    ok(await api("PUT", `${P}/environments/${env}/values/${name}`, { body: { value } }), `setting ${env} ${name}`);
  }
  const team = ok(await api("POST", `${base}/teams`, { body: { name: "Owners" } }), "creating a Team");
  const r0 = await api("POST", `${base}/teams/${team.id}/projects`, { body: { projectId: project.id } });
  if (r0.status !== 204) throw new Error(`linking the Team: ${r0.status} ${r0.text}`);

  const deleted = await api("DELETE", P);
  const counts = deleted.json ?? {};
  check(
    "deletion.project-deleted",
    "deleting a Project answers what it ended: its live environments, its values, the versions erased, the Team links removed",
    deleted.status === 200 && counts.projectId === project.id && counts.slug === "doomed" && counts.environments === 2 &&
      counts.values === 3 && counts.versionsErased === 4 && counts.capabilitiesRevoked === 0 && counts.targetsRevoked === 0 &&
      counts.teamLinksRemoved === 1,
    `${deleted.status} ${deleted.text}`,
  );

  const after = {
    get: (await api("GET", P)).status,
    byId: (await api("GET", `${base}/projects/${project.id}`)).status,
    environments: (await api("GET", `${P}/environments`)).status,
    values: (await api("GET", `${P}/environments/development/effective-configuration`)).status,
    again: (await api("DELETE", P)).status,
    listed: (ok(await api("GET", `${base}/projects`), "listing the Projects").items ?? []).some((p) => p.id === project.id),
    linked: (ok(await api("GET", `${base}/teams/${team.id}/projects`), "listing the Team's Projects").items ?? []).some((p) => p.projectId === project.id),
  };
  const reused = await api("POST", `${base}/projects`, { body: { name: "Doomed again", slug: "doomed", contractAuthority: "managed" } });
  check(
    "deletion.project-gone",
    "a deleted Project and its environments and values are not found, a second deletion too; it is no longer listed or linked to its Team, and its slug can be used again",
    after.get === 404 && after.byId === 404 && after.environments === 404 && after.values === 404 && after.again === 404 &&
      !after.listed && !after.linked && reused.status === 201 && reused.json?.id !== project.id,
    JSON.stringify({ ...after, reused: reused.status }),
  );

  const events = ok(await api("GET", `${base}/audit-events?eventType=project.deleted&limit=10`), "listing project.deleted").items ?? [];
  const event = events.find((e) => e.resource?.projectId === project.id);
  check(
    "deletion.project-audited",
    "the deletion is recorded as project.deleted, under project.manage, with the Project's slug and name and the counts",
    event !== undefined && event.action === "project.manage" && event.resource?.projectSlug === "doomed" && event.metadata?.name === "Doomed" &&
      event.metadata?.environments === 2 && event.metadata?.versionsErased === 4 && event.metadata?.teamLinksRemoved === 1,
    JSON.stringify(event ?? events),
  );

  // ---- Under admin-step-up at enforce: the deletion asks for an approval.
  const enf = ok(await api("POST", "/v1/organizations", { body: { name: `Deletion enforce ${suffix}`, slug: `deletion-enf-${suffix}` } }), "creating the second Organization");
  const ebase = `/v1/organizations/${enf.slug}`;
  const kept = ok(await api("POST", `${ebase}/projects`, { body: { name: "Kept", slug: "kept", contractAuthority: "managed" } }), "creating its Project");
  ok(await api("POST", `${ebase}/projects/kept/environments`, { body: { name: "development", tier: "development" } }), "creating its environment");
  for (const [mode, version] of [["report", 0], ["enforce", 1]]) {
    ok(await api("PATCH", `${ebase}/security/controls/admin-step-up`, { body: { mode, expectedVersion: version } }), `admin-step-up at ${mode}`);
  }
  const asked = await api("DELETE", `${ebase}/projects/kept`);
  const approval = asked.json?.error?.details?.approval;
  const still = await api("GET", `${ebase}/projects/kept`);
  check(
    "deletion.project-step-up",
    "under admin-step-up at enforce, deleting a Project answers STEP_UP_REQUIRED with an approval for project.delete that names the Project and its environment, and deletes nothing",
    asked.status === 403 && asked.json?.error?.code === "STEP_UP_REQUIRED" && approval?.operation === "project.delete" &&
      typeof approval?.summary?.title === "string" && approval.summary.title.includes(kept.id) && approval.summary.title.includes("1 environment") &&
      still.status === 200,
    `${asked.status} ${asked.text}; the Project: ${still.status}`,
  );
  if (approval?.id) ok(await api("POST", `/v1/me/approvals/${approval.id}/cancel`), "cancelling the approval");

  // ---- An Organization's deletion: scheduled, approved by another admin.
  const dorg = ok(await api("POST", "/v1/organizations", { body: { name: `Deleted ${suffix}`, slug: `deleted-${suffix}` } }), "creating the Organization to delete");
  const D = `/v1/organizations/${dorg.slug}`;
  const bot = ok(await api("POST", `${D}/identities`, { body: { name: "bot", kind: "service" } }), "creating its machine identity");
  const invitation = ok(await api("POST", `${D}/invitations`, { body: { role: "admin", name: "Second admin" } }), "inviting a second admin");
  const second = enroll(`${origin}/enroll#${invitation.token}`, "Second admin");

  // What its deletion tears down: a Sync Target pushed to a repository, a
  // webhook, its GitHub App, and its audit export.
  const hosts = JSON.parse(targetOp("platform-fakes", ["start"]));
  ok(await api("POST", `${D}/projects`, { body: { name: "App", slug: "app", contractAuthority: "managed" } }), "creating its Project");
  ok(await api("POST", `${D}/projects/app/environments`, { body: { name: "production", tier: "production" } }), "creating its environment");
  const drev = ok(await api("POST", `${D}/projects/app/contract/revisions`, { body: { contract: { schemaVersion: 1, items: [item("SECRET", true)] } } }), "its Contract");
  ok(await api("POST", `${D}/projects/app/contract/revisions/${drev.id}/activate`), "activating it");
  ok(await api("PUT", `${D}/projects/app/environments/production/values/SECRET`, { body: { value: `doomed-${suffix}` } }), "setting SECRET");
  const dconn = ok(await api("POST", `${D}/platform-connections`, { body: { platform: "github-actions", baseIdentity: hosts.github, name: "GitHub", credential: `conformance-deletion-${suffix}` } }), "its Connection");
  const dtarget = ok(await api("POST", `${D}/projects/app/environments/production/sync-targets`, { body: { connectionId: dconn.id, destination: { repo: `deletion-${suffix}` }, mapping: { kind: "wildcard" } } }), "its Sync Target");
  const pushedBefore = await waitFor(() => (JSON.parse(targetOp("platform-fakes", ["state"])).github[`${hosts.github}/deletion-${suffix}`] ?? []).includes("SECRET"), 90_000);
  const receiverUrl = JSON.parse(targetOp("webhook-receiver", ["url"])).url;
  ok(await api("POST", `${D}/webhooks`, { body: { url: `${receiverUrl}/${suffix}/deleted-organization` } }), "its webhook");
  const appNumber = 8000 + Number.parseInt(suffix.slice(0, 4), 16);
  const fakeApp = { id: appNumber, slug: `varlatch-deleted-${suffix}`, clientId: `Iv1.del${suffix}`, owner: { login: `acme-deleted-${suffix}`, id: 9300, type: "Organization" } };
  const { pem } = JSON.parse(targetOp("platform-fakes", ["github", JSON.stringify({ op: "app", app: fakeApp })]));
  ok(await api("POST", `${D}/github-app/import`, { body: { appId: fakeApp.id, privateKey: pem } }), "importing its GitHub App");
  const store = JSON.parse(targetOp("object-store", ["start"]));
  const s3 = { endpoint: store.hostEndpoint, region: store.region, accessKeyId: store.accessKeyId, secretAccessKey: store.secretAccessKey };
  const exportOf = async (o, name, lock) => {
    await bucket(s3, name, lock);
    return ok(await api("POST", `${o}/audit-export`, { body: {
      destination: { endpoint: store.endpoint, region: store.region, bucket: name, prefix: "varlatch", pathStyle: true },
      credential: { accessKeyId: store.accessKeyId, secretAccessKey: store.secretAccessKey },
      retention: lock ? { mode: "governance", days: 1 } : null,
    } }), `its audit export to ${name}`);
  };
  const dexport = await exportOf(D, `deleted-${suffix}`, true);

  const fakeState = () => JSON.parse(targetOp("platform-fakes", ["state"]));
  const fakeGitHub = (op) => JSON.parse(targetOp("platform-fakes", ["github", JSON.stringify(op)]));

  const botBefore = (await api("GET", "/v1/organizations", { bearer: bot.credential })).status;
  const scheduled = await api("POST", `${D}/deletion`, { body: { afterDays: 1 } });
  const request = scheduled.json ?? {};
  const shown = ok(await api("GET", `${D}/deletion`), "reading the request").deletion;
  const refused = await api("POST", `${D}/projects`, { body: { name: "Late", slug: "late", contractAuthority: "managed" } });
  const botDuring = (await api("GET", "/v1/organizations", { bearer: bot.credential })).status;
  const scheduledEvent = (ok(await api("GET", `${D}/audit-events?eventType=organization.deletion_scheduled&limit=10`), "listing deletion_scheduled").items ?? [])
    .find((e) => e.resource?.deletionId === request.id);
  const pausedTarget = await api("GET", `${D}/projects/app/environments/production/sync-targets/${dtarget.id}`);
  check(
    "deletion.teardown-suspended",
    "scheduling the deletion pauses the Organization's Sync Targets (a Target that was pushed is paused) and suspends its webhooks, and organization.deletion_scheduled counts them",
    Boolean(pushedBefore) && scheduledEvent?.metadata?.targetsPaused === 1 && scheduledEvent.metadata.webhooksSuspended === 1 &&
      pausedTarget.status === 200 && pausedTarget.json?.state === "paused",
    JSON.stringify({ pushedBefore: Boolean(pushedBefore), scheduled: scheduledEvent?.metadata ?? null, target: [pausedTarget.status, pausedTarget.json?.state] }),
  );
  check(
    "deletion.organization-scheduled",
    "scheduling an Organization's deletion answers the request (an approval required with two admins, due after the waiting period) and shows it; writes are refused with ORGANIZATION_DELETING and its machine identities are suspended",
    scheduled.status === 201 && request.approvalRequired === true && request.approvedBy === null &&
      Date.parse(request.runAfter) - Date.parse(request.scheduledAt) === 86_400_000 && shown?.id === request.id &&
      refused.status === 409 && refused.json?.error?.code === "ORGANIZATION_DELETING" && botBefore === 200 && botDuring === 401,
    JSON.stringify({ scheduled: scheduled.status, request, refused: refused.status, botBefore, botDuring }),
  );

  const selfApproval = await api("POST", `${D}/deletion/${request.id}/approve`);
  const approved = await api("POST", `${D}/deletion/${request.id}/approve`, { bearer: second });
  const approvedAgain = await api("POST", `${D}/deletion/${request.id}/approve`, { bearer: second });
  check(
    "deletion.organization-approval-by-another-admin",
    "the admin who scheduled an Organization's deletion cannot approve it; another admin can, and approving again answers the same approval",
    selfApproval.status === 403 && approved.status === 200 && typeof approved.json?.approvedBy === "string" &&
      approved.json.approvedBy !== request.requestedBy && approvedAgain.status === 200 && approvedAgain.json?.approvedAt === approved.json.approvedAt,
    JSON.stringify({ self: selfApproval.status, approved: approved.status, by: approved.json?.approvedBy, again: approvedAgain.status }),
  );

  // ---- In another Organization: a scheduled deletion cancelled.
  const corg = ok(await api("POST", "/v1/organizations", { body: { name: `Kept ${suffix}`, slug: `kept-${suffix}` } }), "creating the Organization to keep");
  const C = `/v1/organizations/${corg.slug}`;
  const keptBot = ok(await api("POST", `${C}/identities`, { body: { name: "bot", kind: "service" } }), "creating its machine identity");
  // A Sync Target with a run in flight across the scheduling: its write is
  // held at the fake GitHub while the deletion is scheduled, then answered.
  // The fence must refuse that stale run's commit, so the Target's ledger
  // never records the change: once the deletion is cancelled and the
  // Target resumed and pushed, the value is written again. Had the stale
  // run committed, the Target would already be converged and nothing would
  // be written.
  ok(await api("POST", `${C}/projects`, { body: { name: "App", slug: "app", contractAuthority: "managed" } }), "creating the kept Project");
  ok(await api("POST", `${C}/projects/app/environments`, { body: { name: "production", tier: "production" } }), "creating its environment");
  const crev = ok(await api("POST", `${C}/projects/app/contract/revisions`, { body: { contract: { schemaVersion: 1, items: [item("SECRET", true)] } } }), "its Contract");
  ok(await api("POST", `${C}/projects/app/contract/revisions/${crev.id}/activate`), "activating it");
  const CE = `${C}/projects/app/environments/production`;
  ok(await api("PUT", `${CE}/values/SECRET`, { body: { value: `kept-${suffix}` } }), "setting SECRET");
  const cconn = ok(await api("POST", `${C}/platform-connections`, { body: { platform: "github-actions", baseIdentity: hosts.github, name: "GitHub", credential: `conformance-kept-${suffix}` } }), "its Connection");
  const ctarget = ok(await api("POST", `${CE}/sync-targets`, { body: { connectionId: cconn.id, destination: { repo: `kept-${suffix}` }, mapping: { kind: "wildcard" } } }), "its Sync Target");
  const keptRepo = `${hosts.github}/kept-${suffix}`;
  const writes = () => fakeState().writes[keptRepo] ?? 0;
  const firstPush = await waitFor(async () => writes() >= 1 && (await api("GET", `${CE}/sync-targets/${ctarget.id}`)).json?.runStartedAt === null, 90_000);
  fakeGitHub({ op: "hold", repo: keptRepo });
  ok(await api("PUT", `${CE}/values/SECRET`, { body: { value: `changed-${suffix}` } }), "changing SECRET");
  ok(await api("POST", `${CE}/sync-targets/${ctarget.id}/push`, { body: {} }), "pushing the Target");
  let inFlight = null;
  for (const until = Date.now() + 90_000; Date.now() < until && !inFlight; await sleep(250)) {
    inFlight = fakeState().held.find((h) => h.repo === keptRepo) ?? null;
  }
  // The stale run's lease: its sync_runs row, by generation, which it
  // deletes when it ends. Each probe is bounded by the time left, so a
  // stuck call cannot overrun.
  const runsOf = (timeoutMs) => {
    try {
      return JSON.parse(targetOp("probe", ["sync-runs", ctarget.id], { timeoutMs: Math.max(1, Math.floor(timeoutMs)) }));
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  };
  const heldNow = () => fakeState().held.find((h) => h.repo === keptRepo) ?? null;
  // The Target as read: only a successful read of this Target, with the
  // fields compared below, counts; anything else is null.
  const readTarget = async () => {
    const r = await api("GET", `${CE}/sync-targets/${ctarget.id}`);
    const t = r.json;
    return r.status >= 200 && r.status < 300 && t?.id === ctarget.id && Number.isInteger(t.failureCount) &&
      (t.lastResult === null || typeof t.lastResult === "string") ? t : null;
  };
  // What the stale run would change were it to commit anything (its
  // success, or a failure): read while it is held, before it can.
  const targetBefore = await readTarget();
  const atHold = { held: heldNow(), rows: runsOf(30_000) };
  // The stale run: the one run in flight while its write is held.
  const staleGen = atHold.rows?.generations?.length === 1 ? atHold.rows.generations[0] : null;
  const toCancel = ok(await api("POST", `${C}/deletion`, { body: {} }), "scheduling its deletion");
  // The ordering: the deletion was scheduled while the stale run was still
  // in flight, its write still held with its client connected and its row
  // (its generation) still there. Seen after the scheduling, so it held
  // throughout it.
  const atSchedule = { held: heldNow(), rows: runsOf(30_000) };
  const { released, abandoned: abandonedWrites } = fakeGitHub({ op: "release", repo: keptRepo });
  const orderedProof = inFlight?.name === "SECRET" && staleGen !== null && atHold.held?.connected === true &&
    atSchedule.held?.connected === true && (atSchedule.rows?.generations ?? []).includes(staleGen) &&
    JSON.stringify(released) === JSON.stringify(["SECRET"]) && Array.isArray(abandonedWrites) && abandonedWrites.length === 0;
  // The released write's answer was fully written to the stale run's
  // connection, so it went on to try its commit. The limitation: neither
  // server says when a commit is fenced, and the fake cannot see whether
  // the client still read the answer (it may have given up just before).
  // The backstop below covers that case: a run that gave up records its
  // failure unless it is fenced, and a run that read the answer commits
  // its success unless it is fenced, so either way an unfenced run changes
  // the Target's failure count or last result, or leaves nothing to write
  // again.
  const delivery = orderedProof
    ? await waitFor(() => fakeState().deliveries.find((d) => d.repo === keptRepo && d.name === "SECRET" && d.delivered !== null) ?? null, 10_000)
    : null;
  const reachedAt = writes();
  // The stale run has ended once its generation's row is gone; only then is
  // the deletion cancelled, so no later run can be what fences it.
  let staleEnded = false;
  let lastRows = null;
  if (orderedProof && delivery?.delivered === true) {
    for (const deadline = Date.now() + 60_000; !staleEnded;) {
      const left = deadline - Date.now();
      if (left <= 0) break;
      lastRows = runsOf(left);
      staleEnded = Array.isArray(lastRows?.generations) && !lastRows.generations.includes(staleGen);
      if (!staleEnded) await sleep(Math.min(1000, Math.max(0, deadline - Date.now())));
    }
  }
  // A fenced run commits nothing, its failure included: the Target's
  // failure count and last result are those from before it.
  const targetAfter = staleEnded ? await readTarget() : null;
  const committedNothing = staleEnded && targetBefore !== null && targetAfter !== null &&
    targetAfter.failureCount === targetBefore.failureCount && targetAfter.lastResult === targetBefore.lastResult;
  const fenceTitle = "a Sync Target run in flight when its Organization's deletion is scheduled reaches the platform but cannot commit: once that run has ended and the deletion is cancelled and the Target resumed (it stays paused) and pushed, the change is written again, while a push with nothing changed writes nothing";
  const fenceSoFar = { firstPush: Boolean(firstPush), inFlight, staleGen, atHold, atSchedule, released, abandonedWrites, delivery, staleEnded, lastRows,
    before: targetBefore && [targetBefore.failureCount, targetBefore.lastResult], after: targetAfter && [targetAfter.failureCount, targetAfter.lastResult] };
  // Without the ordering, the delivery, the stale run's end within a
  // minute, or with anything it committed, nothing below could prove the
  // fence: the check fails now, before the cancellation, saying why.
  const fenceShown = orderedProof && delivery?.delivered === true && staleEnded && committedNothing;
  if (!fenceShown) {
    check("deletion.scheduling-fences-runs", fenceTitle, false, JSON.stringify({
      why: !orderedProof
        ? "inconclusive: the deletion was not shown scheduled while the stale run (one generation) was in flight with its write held and connected, or the release was not exactly that write"
        : delivery?.delivered !== true ? "inconclusive: delivery not provable (the released write's answer was not fully written to the stale run's connection)"
          : !staleEnded ? "the stale run had not ended (its generation's sync_runs row still there) after 60 s"
            : targetBefore === null || targetAfter === null ? "inconclusive: the Target could not be read before and after the stale run"
              : "the stale run committed something (the Target's failure count or last result changed)",
      ...fenceSoFar,
    }));
  }
  const keptBotDuring = (await api("GET", "/v1/organizations", { bearer: keptBot.credential })).status;
  const cancelled = await api("POST", `${C}/deletion/${toCancel.id}/cancel`);
  const cancelledAgain = await api("POST", `${C}/deletion/${toCancel.id}/cancel`);
  const keptBotAfter = (await api("GET", "/v1/organizations", { bearer: keptBot.credential })).status;
  const afterCancel = ok(await api("GET", `${C}/deletion`), "reading its request").deletion;
  const writable = await api("POST", `${C}/projects`, { body: { name: "Kept", slug: "kept", contractAuthority: "managed" } });
  check(
    "deletion.organization-cancelled",
    "cancelling a scheduled deletion ends the request, restores the machine identities it suspended and writes again; a second cancel is refused",
    toCancel.approvalRequired === false && keptBotDuring === 401 && cancelled.status === 200 && typeof cancelled.json?.cancelledAt === "string" &&
      cancelledAgain.status === 409 && cancelledAgain.json?.error?.code === "STATE_CHANGED" && keptBotAfter === 200 && afterCancel === null &&
      writable.status === 201,
    JSON.stringify({ during: keptBotDuring, cancelled: cancelled.status, again: cancelledAgain.status, after: keptBotAfter, writable: writable.status }),
  );
  if (fenceShown) {
    const pausedAfterCancel = (await api("GET", `${CE}/sync-targets/${ctarget.id}`)).json;
    const resumed = await api("POST", `${CE}/sync-targets/${ctarget.id}/resume`, { body: {} });
    const repushed = await api("POST", `${CE}/sync-targets/${ctarget.id}/push`, { body: {} });
    const writtenAgain = await waitFor(() => writes() > reachedAt, 90_000);
    // The control: a push with nothing changed runs and writes nothing, so
    // the write above came from the ledger lacking the change, not from the
    // push itself.
    const idle = await waitFor(async () => {
      const t = (await api("GET", `${CE}/sync-targets/${ctarget.id}`)).json;
      return t?.runStartedAt === null && t.needsSync === false && t;
    }, 90_000);
    const writesSettled = writes();
    ok(await api("POST", `${CE}/sync-targets/${ctarget.id}/push`, { body: {} }), "pushing it again");
    const ranAgain = await waitFor(async () => {
      const t = (await api("GET", `${CE}/sync-targets/${ctarget.id}`)).json;
      return idle && t?.lastAttemptAt !== idle.lastAttemptAt && t.runStartedAt === null && t;
    }, 90_000);
    check(
      "deletion.scheduling-fences-runs",
      fenceTitle,
      pausedAfterCancel?.state === "paused" && resumed.status === 200 && repushed.status === 202 && Boolean(writtenAgain) &&
        Boolean(ranAgain) && writes() === writesSettled,
      JSON.stringify({ ...fenceSoFar, pausedAfterCancel: pausedAfterCancel?.state, resumed: resumed.status, repushed: repushed.status,
        writes: writes(), reachedAt, control: { ran: Boolean(ranAgain), writesSettled } }),
    );
  }

  // ---- The due run: made due, then run by the deletion loop's next pass
  // (every minute on both servers).
  targetOp("probe", ["deletion-due", request.id]);
  let gone = 0;
  for (const deadline = Date.now() + 90_000; Date.now() < deadline; await sleep(1000)) {
    gone = (await api("GET", D)).status;
    if (gone === 404) break;
  }
  const botAfter = (await api("GET", "/v1/organizations", { bearer: bot.credential })).status;
  const T = `/v1/deleted-organizations/${dorg.id}/audit-events`;
  const page = await api("GET", `${T}?limit=500`);
  const orgDeleted = (page.json?.items ?? []).find((e) => e.eventType === "organization.deleted");
  check(
    "deletion.organization-deleted-when-due",
    "once due and approved, the deletion loop deletes the Organization: it is not found, its machine credentials are refused, and its audit records organization.deleted with what it ended",
    gone === 404 && botAfter === 401 && page.status === 200 && orgDeleted?.metadata?.members === 2 && orgDeleted.metadata.readers === 2 &&
      orgDeleted.metadata.identitiesRetired === 1 && orgDeleted.metadata.approvedBy === approved.json?.approvedBy &&
      orgDeleted.resource?.organizationSlug === dorg.slug,
    JSON.stringify({ gone, botAfter, page: page.status, deleted: orgDeleted ?? null }),
  );

  // What is stored, read beside the audit's counts (the Organization's
  // routes answer 404 now).
  const stored = JSON.parse(targetOp("probe", ["deletion-teardown", dorg.id]));
  const allRevoked = (rows) => Array.isArray(rows) && rows.length === 1 && rows.every((r) => r.revoked === true);
  check(
    "deletion.teardown-ended",
    "the due run revokes the Organization's Sync Targets and their Connections, removes its webhooks and its GitHub App (its key deleted), as stored, and organization.deleted counts them",
    orgDeleted?.metadata?.targetsRevoked === 1 && orgDeleted.metadata.connectionsRevoked === 1 && orgDeleted.metadata.webhooksRemoved === 1 &&
      orgDeleted.metadata.githubAppRemoved === true &&
      allRevoked(stored.targets) && stored.targets[0].id === dtarget.id && allRevoked(stored.connections) && stored.connections[0].id === dconn.id &&
      allRevoked(stored.webhooks) && stored.githubApps?.length === 1 && stored.githubApps[0].removed === true && stored.githubApps[0].keyKept === false,
    JSON.stringify({ audit: orgDeleted?.metadata ?? null, stored }),
  );

  // The audit export drains: its final events, organization.deleted among
  // them, reach the bucket, and the drain completes.
  const prefix = `varlatch/varlatch-audit/${dorg.id}/`;
  const drained = await waitFor(async () => {
    const events = (await api("GET", `${T}?limit=500`)).json?.items ?? [];
    return events.some((e) => e.eventType === "audit_export.completed") && events;
  }, 150_000);
  const lines = [];
  for (const key of listedKeys((await s3Request(s3, "GET", `/deleted-${suffix}`, { query: { "list-type": "2", prefix } })).text)) {
    if (!key.endsWith(".ndjson.gz")) continue;
    const got = await s3Request(s3, "GET", `/deleted-${suffix}/${key}`);
    lines.push(...gunzipSync(got.body).toString("utf8").trimEnd().split("\n").map((l) => JSON.parse(l)));
  }
  const delivered = lines.find((l) => l.eventType === "organization.deleted");
  check(
    "deletion.audit-export-drained",
    "after the deletion its audit export drains: the final events, organization.deleted among them, reach the bucket, and the drain completes (audit_export.completed in the deleted Organization's audit)",
    Boolean(drained) && delivered?.organizationId === dorg.id && delivered.resource?.deletionId === request.id &&
      !(drained || []).some((e) => e.eventType === "audit_export.abandoned"),
    JSON.stringify({ completed: Boolean(drained), export: dexport.id, delivered: delivered ? { eventType: delivered.eventType, position: delivered.position } : null, lines: lines.length }),
  );

  // ---- The tombstone's readers.
  const secondReads = (await api("GET", T, { bearer: second })).status;
  const exported = await api("GET", `${T}/export`);
  const exportedTypes = exported.text.split("\n").filter(Boolean).map((l) => JSON.parse(l).eventType);
  const listed = (ok(await api("GET", "/v1/installation/deleted-organizations"), "listing the tombstones").items ?? []).find((o) => o.id === dorg.id);
  const secondId = listed?.readers?.find((r) => r.identityId !== request.requestedBy)?.identityId;
  const removed = secondId ? await api("DELETE", `/v1/installation/deleted-organizations/${dorg.id}/readers/${secondId}`) : { status: 0 };
  const secondAfter = (await api("GET", T, { bearer: second })).status;
  const relisted = (ok(await api("GET", "/v1/installation/deleted-organizations"), "listing the tombstones again").items ?? []).find((o) => o.id === dorg.id);
  check(
    "deletion.tombstone-readers",
    "a deleted Organization's audit is read and exported by the admins fixed as its readers; the Installation Admin lists the tombstone with its readers and removes one, who then reads nothing",
    secondReads === 200 && exported.status === 200 && exportedTypes.includes("organization.deleted") && exportedTypes[0] === "organization.created" &&
      listed?.slug === dorg.slug && listed.readers.length === 2 && removed.status === 204 && secondAfter === 404 &&
      relisted?.readers?.some((r) => r.identityId === secondId && typeof r.removedAt === "string"),
    JSON.stringify({ secondReads, exported: exported.status, types: exportedTypes.slice(-3), listed: listed ?? null, removed: removed.status, secondAfter }),
  );

  // ---- An audit export that cannot drain (its bucket is gone) is
  // abandoned once its deadline passes.
  const lorg = ok(await api("POST", "/v1/organizations", { body: { name: `Lost ${suffix}`, slug: `lost-${suffix}` } }), "creating the third Organization");
  const L = `/v1/organizations/${lorg.slug}`;
  const lexport = await exportOf(L, `lost-${suffix}`, false);
  await removeBucket(s3, `lost-${suffix}`);
  const lrequest = ok(await api("POST", `${L}/deletion`, { body: {} }), "scheduling its deletion");
  targetOp("probe", ["deletion-due", lrequest.id]);
  const lgone = await waitFor(async () => (await api("GET", L)).status === 404, 90_000);
  if (lgone) targetOp("probe", ["audit-export-drain-due", lorg.id]);
  const LT = `/v1/deleted-organizations/${lorg.id}/audit-events`;
  const abandoned = lgone && await waitFor(async () => ((await api("GET", `${LT}?limit=500`)).json?.items ?? []).find((e) => e.eventType === "audit_export.abandoned") ?? null, 90_000);
  const lastEvents = (await api("GET", `${LT}?limit=500`)).json?.items ?? [];
  check(
    "deletion.audit-export-drain-deadline",
    "an audit export that cannot deliver its final events is abandoned once its drain deadline passes: audit_export.abandoned with the deadline, never completed",
    Boolean(lgone) && abandoned?.resource?.exportId === lexport.id && typeof abandoned.metadata?.drainDeadline === "string" &&
      !lastEvents.some((e) => e.eventType === "audit_export.completed"),
    JSON.stringify({ gone: Boolean(lgone), abandoned: abandoned ? { resource: abandoned.resource, metadata: abandoned.metadata } : null, types: lastEvents.map((e) => e.eventType).slice(-5) }),
  );
} catch (err) {
  error(err instanceof Error ? err.stack ?? err.message : String(err));
}
finish("deletion checks");
