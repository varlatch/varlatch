#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Live differential check of names Coolify resolves (`platformExpands`,
// ADR-0031 amendment 2026-10-22) against a real Coolify instance: never run
// in CI. It creates one project with project, environment, server and team
// shared variables holding canary sentinels, and one Dockerfile application
// built from scripts/coolify-fixture at a pinned commit of this public
// repository. Each reference is carried by two names: one written through
// the built adapter with `platformExpands`, and a twin created through
// Coolify's API with Coolify's defaults. After one deploy, every pair must
// deliver exactly the sentinel (or the pinned commit for $SOURCE_COMMIT) at
// build time and at runtime; literal controls arrive as given or are
// refused. Then it deletes everything it created. Only canary values are
// written.
//
//   pnpm --filter @varlatch/sync build
//   COOLIFY_LIVE_URL=https://coolify.example.com COOLIFY_LIVE_TOKEN=... \
//   FIXTURE_REF=<branch> FIXTURE_SHA=<40-hex commit with scripts/coolify-fixture> \
//     node scripts/test-coolify-live-expands.mjs
//
// The token needs Read, Write, Deploy and Read sensitive, in a team with a
// server that can build. Use a lab instance: the test deploys.
import { randomBytes } from "node:crypto";
const { coolifyAdapter: A } = await import(new URL("../packages/sync/dist/index.js", import.meta.url).href);

const BASE = (process.env.COOLIFY_LIVE_URL ?? "").replace(/\/+$/, "");
const TOKEN = process.env.COOLIFY_LIVE_TOKEN;
const REF = process.env.FIXTURE_REF;
const SHA = process.env.FIXTURE_SHA ?? "";
if (!/^https:\/\//.test(BASE)) throw new Error("COOLIFY_LIVE_URL must be the https origin of a Coolify instance");
if (!TOKEN) throw new Error("COOLIFY_LIVE_TOKEN is not set");
if (!REF || !/^[0-9a-f]{40}$/.test(SHA)) throw new Error("FIXTURE_REF and FIXTURE_SHA (40 hex) are required");

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`);
};
const api = async (method, path, body) => {
  const res = await fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json", Accept: "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    redirect: "error",
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: res.status, json };
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tag = randomBytes(4).toString("hex").toUpperCase();
const sentinel = (kind) => `${kind}-sentinel-${tag.toLowerCase()}`;
const KEYS = { PROJECT: `VLT_P_${tag}`, ENVIRONMENT: `VLT_E_${tag}`, SERVER: `VLT_S_${tag}`, TEAM: `VLT_T_${tag}` };
const REFS = {
  PROJECT: `{{project.${KEYS.PROJECT}}}`,
  ENVIRONMENT: `{{environment.${KEYS.ENVIRONMENT}}}`,
  SERVER: `{{server.${KEYS.SERVER}}}`,
  TEAM: `{{team.${KEYS.TEAM}}}`,
  COMMIT: "$SOURCE_COMMIT",
};
const EXPECTED = {
  PROJECT: sentinel("project"),
  ENVIRONMENT: sentinel("environment"),
  SERVER: sentinel("server"),
  TEAM: sentinel("team"),
  COMMIT: SHA,
};

/** The fixture's BUILD: and RUN: log lines, decoded into env maps. */
function parseLog(logs) {
  const out = {};
  for (const line of String(logs).split("\n")) {
    const m = /(BUILD|RUN):([0-9a-f]*)\s*$/.exec(line.trim());
    if (!m) continue;
    const env = new Map();
    for (const l of Buffer.from(m[2], "hex").toString("utf8").split("\n")) {
      const eq = l.indexOf("=");
      if (eq > 0) env.set(l.slice(0, eq), l.slice(eq + 1));
    }
    out[m[1]] = env;
  }
  return out;
}

const created = { team: null, server: null, project: null, environment: null };
let projectUuid, appUuid, serverUuid;
try {
  const version = await api("GET", "/version");
  console.log(`instance version: ${JSON.stringify(version.json)}`);
  const servers = await api("GET", "/servers");
  const server = (servers.json ?? []).find((s) => s?.settings?.is_reachable !== false) ?? (servers.json ?? [])[0];
  if (!server) throw new Error(`no server visible to the token (HTTP ${servers.status})`);
  serverUuid = server.uuid;
  console.log(`server: ${server.name}`);

  const project = await api("POST", "/projects", { name: `varlatch-coolify-expands-test-${tag.toLowerCase()}`, description: "Temporary Varlatch adapter live test, deleted afterwards" });
  projectUuid = project.json?.uuid;
  if (!projectUuid) throw new Error(`project not created (HTTP ${project.status} ${JSON.stringify(project.json)})`);

  // Shared variables with canary sentinels, one per scope.
  const shared = async (scope, path, key, value) => {
    const r = await api("POST", path, { key, value });
    if (r.status !== 201 && r.status !== 200) throw new Error(`${scope} shared variable not created (HTTP ${r.status} ${JSON.stringify(r.json)})`);
    created[scope] = { path, id: r.json?.id ?? r.json?.uuid };
  };
  await shared("project", `/projects/${projectUuid}/envs`, KEYS.PROJECT, EXPECTED.PROJECT);
  await shared("environment", `/projects/${projectUuid}/environments/production/envs`, KEYS.ENVIRONMENT, EXPECTED.ENVIRONMENT);
  await shared("server", `/servers/${serverUuid}/envs`, KEYS.SERVER, EXPECTED.SERVER);
  await shared("team", "/team/envs", KEYS.TEAM, EXPECTED.TEAM);

  const app = await api("POST", "/applications/public", {
    project_uuid: projectUuid,
    environment_name: "production",
    server_uuid: serverUuid,
    name: "varlatch-expands-probe",
    git_repository: "https://github.com/varlatch/varlatch",
    git_branch: REF,
    git_commit_sha: SHA,
    build_pack: "dockerfile",
    base_directory: "/scripts/coolify-fixture",
    dockerfile_location: "/Dockerfile",
    ports_exposes: "80",
    health_check_enabled: false,
    include_source_commit_in_build: true,
    instant_deploy: false,
  });
  appUuid = app.json?.uuid;
  if (!appUuid) throw new Error(`application not created (HTTP ${app.status} ${JSON.stringify(app.json)})`);
  const shown = (await api("GET", `/applications/${appUuid}`)).json ?? {};
  const settings = shown.settings ?? {};
  console.log(`settings: build_pack=${shown.build_pack} use_build_secrets=${settings.use_build_secrets} include_source_commit_in_build=${settings.include_source_commit_in_build} inject_build_args_to_dockerfile=${settings.inject_build_args_to_dockerfile}`);
  check("source commit enabled for the build", settings.include_source_commit_in_build === true || settings.include_source_commit_in_build === 1);

  const listed = Object.keys(REFS).map((k) => `EXP_${k}`);
  const dest = { applicationUuid: appUuid, buildTime: "true", platformExpands: listed.join(",") };
  const req = { baseIdentity: BASE, destination: A.canonicalizeDestination(dest).destination, credential: TOKEN };

  // Twins first, through Coolify's API with its defaults: the operator's way.
  for (const [k, ref] of Object.entries(REFS)) {
    const r = await api("POST", `/applications/${appUuid}/envs`, { key: `TWIN_${k}`, value: ref });
    check(`twin TWIN_${k} created with Coolify's defaults`, r.status === 201 || r.status === 200, `HTTP ${r.status}`);
  }
  const twinRows = (await api("GET", `/applications/${appUuid}/envs`)).json ?? [];
  const twinFlags = twinRows.filter((r) => r.key?.startsWith("TWIN_")).map((r) => `${r.key}:literal=${r.is_literal},multiline=${r.is_multiline},buildtime=${r.is_buildtime},runtime=${r.is_runtime}`);
  console.log(`twin flags: ${twinFlags.join(" ")}`);

  // The adapter: listed names, then the literal controls.
  const outcomes = await A.writeValues(req, [
    ...Object.entries(REFS).map(([k, ref]) => ({ name: `EXP_${k}`, value: ref })),
    { name: "LIT_COMMIT", value: "$SOURCE_COMMIT" },
    { name: "LIT_TEAM", value: REFS.TEAM },
    { name: "EXP_VAULT", value: "{{vault.SOMETHING}}" },
  ]);
  for (const o of outcomes) {
    if (o.name === "LIT_TEAM") check("an unlisted {{team.X}} is refused and not sent", !o.ok && /shared variables/.test(o.error ?? ""), o.error ?? "");
    else if (o.name === "EXP_VAULT") check("a listed {{vault.X}} is refused and not sent", !o.ok && /secret manager/.test(o.error ?? ""), o.error ?? "");
    else check(`adapter wrote ${o.name}`, o.ok, o.error ?? "");
  }
  const rows = new Map(((await api("GET", `/applications/${appUuid}/envs`)).json ?? []).filter((r) => !r.is_preview).map((r) => [r.key, r]));
  check("refused names were never created", !rows.has("LIT_TEAM") && !rows.has("EXP_VAULT"));
  for (const k of Object.keys(REFS)) {
    const row = rows.get(`EXP_${k}`);
    check(`EXP_${k} stored as Coolify's own variable`, row?.is_literal === false && row?.is_multiline === false && row?.is_buildtime === true && row?.is_runtime === true, JSON.stringify({ literal: row?.is_literal, multiline: row?.is_multiline, buildtime: row?.is_buildtime, runtime: row?.is_runtime }));
    check(`EXP_${k} stored as given`, row?.value === REFS[k]);
  }
  check("LIT_COMMIT stored literal", rows.get("LIT_COMMIT")?.is_literal === true && rows.get("LIT_COMMIT")?.is_multiline === true);
  const remote = await A.readRemote(req);
  const rewrite = [...remote.rewrite].filter((n) => n.startsWith("EXP_") || n === "LIT_COMMIT");
  check("a repair would rewrite none of the adapter's rows", rewrite.length === 0, rewrite.join(","));

  // Deploy once, then read what the build and the container got.
  const deploy = await api("POST", `/applications/${appUuid}/start?force=true`);
  const deploymentUuid = deploy.json?.deployments?.[0]?.deployment_uuid ?? deploy.json?.deployment_uuid;
  check("deploy queued", deploy.status === 200 && Boolean(deploymentUuid), `HTTP ${deploy.status}`);
  let status = "";
  for (let i = 0; i < 120 && deploymentUuid; i++) {
    const d = await api("GET", `/deployments/${deploymentUuid}`);
    status = String(d.json?.status ?? "");
    if (["finished", "failed", "cancelled-by-user", "cancelled"].includes(status)) break;
    await sleep(5000);
  }
  check("deployment finished", status === "finished", status);
  let seen = {};
  for (let i = 0; i < 36; i++) {
    const logs = await api("GET", `/applications/${appUuid}/logs?lines=50`);
    seen = parseLog(logs.json?.logs ?? "");
    if (seen.BUILD && seen.RUN) break;
    await sleep(5000);
  }
  check("fixture printed its build and runtime record", Boolean(seen.BUILD && seen.RUN));
  for (const phase of ["BUILD", "RUN"]) {
    const env = seen[phase] ?? new Map();
    for (const k of Object.keys(REFS)) {
      const exp = env.get(`EXP_${k}`);
      const twin = env.get(`TWIN_${k}`);
      check(`${phase.toLowerCase()}: EXP_${k} is exactly the expected value`, exp === EXPECTED[k], JSON.stringify(exp));
      check(`${phase.toLowerCase()}: TWIN_${k} is exactly the expected value`, twin === EXPECTED[k], JSON.stringify(twin));
    }
    check(`${phase.toLowerCase()}: LIT_COMMIT arrives as text`, env.get("LIT_COMMIT") === "$SOURCE_COMMIT", JSON.stringify(env.get("LIT_COMMIT")));
  }
} catch (err) {
  check("run completed", false, err instanceof Error ? err.message : String(err));
} finally {
  if (appUuid) {
    const d = await api("DELETE", `/applications/${appUuid}?delete_configurations=true&delete_volumes=true&docker_cleanup=false&delete_connected_networks=true`);
    console.log(`cleanup application: HTTP ${d.status}`);
  }
  for (const scope of ["team", "server", "environment", "project"]) {
    const c = created[scope];
    if (c?.id !== undefined) {
      const r = await api("DELETE", `${c.path}/${c.id}`);
      console.log(`cleanup ${scope} shared variable: HTTP ${r.status}`);
    }
  }
  if (projectUuid) {
    for (let i = 0; i < 12; i++) {
      const p = await api("DELETE", `/projects/${projectUuid}`);
      if (p.status === 200 || p.status === 404) {
        console.log(`cleanup project: HTTP ${p.status}`);
        break;
      }
      await sleep(5000);
    }
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(`${results.length - failed}/${results.length} passed`);
  process.exit(failed === 0 ? 0 : 1);
}
