#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Deletion over the API (ADR-0051): a Project's deletion (Decision 2,
 * immediate and final), and, under admin-step-up at enforce, the approval
 * it asks for (ADR-0054 amendment B). Organization deletion (scheduling,
 * approval, cancellation, the due run, deleted Organizations' audit) is
 * step 4.12b's part of this suite.
 *
 * In an Organization of its own: a Project with two environments, an
 * active Contract, values (one with a second version) and a Team linking
 * it; its deletion, what it answers and what is left (nothing readable, the
 * slug free again, the Team's link gone, project.deleted with the counts).
 * Then, in a second Organization at enforce, the deletion's approval.
 *
 *   deletion.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { randomBytes } from "node:crypto";
import { reporter } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: deletion.mjs <origin> <api token>");
  process.exit(64);
}
const kit = reporter({ detailOnFailure: true });
const { check, error, finish } = kit;

async function api(method, path, { body } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
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
} catch (err) {
  error(err instanceof Error ? err.stack ?? err.message : String(err));
}
finish("deletion checks");
