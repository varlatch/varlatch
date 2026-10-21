#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Live check of the Coolify adapter's service support (ADR-0031 amendment
// 2026-10-21) against a real Coolify instance: never run in CI. It creates
// one project and one service (three busybox containers that print their
// environment), pushes canary values through the built adapter, reads them
// back and from the containers' logs byte for byte, checks the refusals,
// the compose verdicts, the rewrite of a row stored without the literal
// flags, restart, and Coolify's re-creation of referenced names, then
// deletes the service and the project. Only canary values are written.
//
//   pnpm --filter @varlatch/sync build
//   COOLIFY_LIVE_URL=https://coolify.example.com COOLIFY_LIVE_TOKEN=... \
//     node scripts/test-coolify-live.mjs
//
// The token needs Read, Write, Deploy and Read sensitive, in a team with a
// server that can host resources. Use a lab instance: the test deploys.
// Last run: Coolify 4.4.6, 85/85.
const { coolifyAdapter: A } = await import(new URL("../packages/sync/dist/index.js", import.meta.url).href);

const BASE = (process.env.COOLIFY_LIVE_URL ?? "").replace(/\/+$/, "");
const TOKEN = process.env.COOLIFY_LIVE_TOKEN;
if (!/^https:\/\//.test(BASE)) throw new Error("COOLIFY_LIVE_URL must be the https origin of a Coolify instance");
if (!TOKEN) throw new Error("COOLIFY_LIVE_TOKEN is not set");
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
const req = (uuid, extra = {}) => ({ baseIdentity: BASE, destination: { serviceUuid: uuid }, credential: TOKEN, ...extra });

const COMPOSE = `services:
  probe:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\\\n'; echo; sleep 2147483647"]
    environment:
      SHADOWED: fixed-in-compose
      REFERENCED: \${REFERENCED}
      DEFAULTED: \${DEFAULTED:-from-compose}
      DEFAULTED_RAW: \${DEFAULTED_RAW:-from-compose}
      ESCAPED_REF: "\\u0024ESCAPED_REF"
  lister:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\\\n'; echo; sleep 2147483647"]
    environment:
      - BARE_LIST
      - LIST_SET=from-list
  other:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\\\n'; echo; sleep 2147483647"]
`;

const VALUES = {
  PLAIN: "plain-canary-1",
  DOLLARS: "pa$$word$HOME${X}",
  HASH: "abc #x",
  MULTI: "line1\nline2",
  JSON_PLAIN: '{"a":"b","n":1}',
  DQUOTE: 'say "hi"',
  BSLASH: "a\\b",
  UNICODE: "héllo ✓ ünï",
  REFERENCED: "ref-canary",
  DEFAULTED: "dflt-canary",
  SHADOWED: "pushed-canary",
  UNMENTIONED: "unmentioned-canary",
  ESCAPED_REF: "esc-canary",
  BARE_LIST: "bare-canary",
};
const REFUSED = { QUOTE: "it's", TRAIL: "x ", SHARED: "{{environment.X}}" };

async function envOf(uuid, container, want) {
  // Poll the container's log for the env hex line until `want` (if given) appears.
  for (let i = 0; i < 60; i++) {
    const r = await api("GET", `/services/${uuid}/logs?sub_service_name=${container}&lines=20`);
    if (r.status === 200 && typeof r.json?.logs === "string") {
      const lines = r.json.logs.trim().split("\n").map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l));
      const last = lines.at(-1);
      if (last) {
        const env = Buffer.from(last, "hex").toString("utf8");
        if (!want || env.includes(want)) return env;
      }
    }
    await sleep(5000);
  }
  return null;
}
async function waitRunning(uuid) {
  for (let i = 0; i < 60; i++) {
    const r = await api("GET", `/services/${uuid}`);
    const status = String(r.json?.status ?? "");
    if (status.startsWith("running")) return status;
    await sleep(5000);
  }
  return null;
}

let projectUuid, serviceUuid;
try {
  const version = await api("GET", "/version");
  console.log(`instance version: ${JSON.stringify(version.json)}`);
  const servers = await api("GET", "/servers");
  const server = (servers.json ?? []).find((s) => s?.settings?.is_reachable !== false) ?? (servers.json ?? [])[0];
  if (!server) throw new Error(`no server visible to the token (HTTP ${servers.status})`);
  console.log(`server: ${server.name}`);

  const project = await api("POST", "/projects", { name: "varlatch-coolify-services-test", description: "Temporary Varlatch adapter live test, deleted afterwards" });
  projectUuid = project.json?.uuid;
  if (!projectUuid) throw new Error(`project not created (HTTP ${project.status} ${JSON.stringify(project.json)})`);
  const created = await api("POST", "/services", {
    project_uuid: projectUuid,
    environment_name: "production",
    server_uuid: server.uuid,
    name: "varlatch-probe",
    docker_compose_raw: Buffer.from(COMPOSE).toString("base64"),
    instant_deploy: false,
  });
  serviceUuid = created.json?.uuid;
  if (!serviceUuid) throw new Error(`service not created (HTTP ${created.status} ${JSON.stringify(created.json)})`);
  console.log(`service: ${serviceUuid}`);

  // Access check and listing.
  const access = await A.checkAccess(req(serviceUuid));
  check("access check ok", access.status === "ok", access.message);
  check("access check names containers", /probe/.test(access.message) && /other/.test(access.message), "");
  const listing = await A.listDestinations(req(serviceUuid));
  check("listing has the service", listing.items.some((o) => o.destination.serviceUuid === serviceUuid), listing.check.message);

  // Usage before any value: verdicts from the compose file.
  const names = [...Object.keys(VALUES), "DEFAULTED_RAW", "PREEXIST"];
  const usage = await A.inspectUsage(req(serviceUuid), names);
  check("usage checked", usage?.checked === true, usage?.reason ?? "");
  const u = (n) => usage?.names.get(n) ?? {};
  check("SHADOWED shadowed in probe", JSON.stringify(u("SHADOWED").shadowedIn) === '["probe"]', JSON.stringify(u("SHADOWED")));
  check("REFERENCED referenced, not copied", u("REFERENCED").referenced === true && !u("REFERENCED").copiedIntoCompose, JSON.stringify(u("REFERENCED")));
  check("DEFAULTED copied into compose", u("DEFAULTED").copiedIntoCompose === true, JSON.stringify(u("DEFAULTED")));
  check("UNMENTIONED plain", JSON.stringify(u("UNMENTIONED")) === "{}", JSON.stringify(u("UNMENTIONED")));
  check("ESCAPED_REF referenced through YAML decoding", u("ESCAPED_REF").referenced === true, JSON.stringify(u("ESCAPED_REF")));
  check("BARE_LIST copied into compose (pure list)", u("BARE_LIST").copiedIntoCompose === true, JSON.stringify(u("BARE_LIST")));
  check("$ refused for a copied name", /copies this value/.test(A.valueProblem({ serviceUuid }, "BARE_LIST", "a$b", usage) ?? ""), "");
  check("$ refused while usage is unknown", /could not check/.test(A.valueProblem({ serviceUuid }, "UNMENTIONED", "a$b", { checked: false, names: new Map() }) ?? ""), "");
  check("$ allowed for a name the compose file does not copy", A.valueProblem({ serviceUuid }, "UNMENTIONED", "a$b", usage) === null, "");

  // A pre-existing row with the matching value but without the literal flags.
  const pre = await api("POST", `/services/${serviceUuid}/envs`, { key: "PREEXIST", value: "abc$HOME #x", is_literal: false, is_multiline: false });
  check("pre-existing row without flags created", pre.status === 201, `HTTP ${pre.status}`);
  const state = await A.readRemote(req(serviceUuid));
  check("read-back flags it for rewrite though its value matches", state.values.get("PREEXIST") === "abc$HOME #x" && state.rewrite.has("PREEXIST"), "");
  const pre2 = await A.writeValues(req(serviceUuid, { usage }), [{ name: "PREEXIST", value: "abc$HOME #x" }]);
  check("rewrite with the flags", pre2[0]?.ok === true, pre2[0]?.error ?? "");
  check("no rewrite needed after", !(await A.readRemote(req(serviceUuid))).rewrite.has("PREEXIST"), "");

  // Writes through the adapter.
  const items = [...Object.entries(VALUES), ...Object.entries(REFUSED)].map(([name, value]) => ({ name, value }));
  const outcomes = await A.writeValues(req(serviceUuid, { usage }), items);
  for (const o of outcomes) {
    const shouldRefuse = o.name in REFUSED;
    check(`write ${o.name} ${shouldRefuse ? "refused" : "ok"}`, o.ok === !shouldRefuse, o.error ?? "");
  }
  // The premise of the copied-$ rule: write a $ value past the adapter, raw.
  // Coolify's parse at creation already made the row (the compose file references it).
  const raw = await api("PATCH", `/services/${serviceUuid}/envs`, { key: "DEFAULTED_RAW", value: "a$HOME-b", is_literal: true, is_multiline: true });
  check("raw write for the $-expansion premise", raw.status === 200 || raw.status === 201, `HTTP ${raw.status}`);

  // Read-back is exact.
  const back = await A.readValues(req(serviceUuid));
  for (const [name, value] of Object.entries(VALUES)) check(`read back ${name}`, back.get(name) === value, JSON.stringify(back.get(name)));

  // Start, then read what the containers got.
  const start = await api("POST", `/services/${serviceUuid}/start`);
  check("start queued", start.status === 200, `HTTP ${start.status}`);
  check("service running", (await waitRunning(serviceUuid)) !== null, "");
  const env = await envOf(serviceUuid, "probe", "PLAIN=plain-canary-1");
  check("probe env read", env !== null, "");
  if (env) {
    for (const [name, value] of Object.entries(VALUES)) {
      const expected = name === "SHADOWED" ? "fixed-in-compose" : value;
      check(`probe ${name} byte for byte`, env.includes(`\n${name}=${expected}\n`) || env.startsWith(`${name}=${expected}\n`), "");
    }
    for (const name of Object.keys(REFUSED)) check(`probe has no ${name}`, !env.includes(`\n${name}=`), "");
    check("probe PREEXIST byte for byte after the rewrite", env.includes("\nPREEXIST=abc$HOME #x\n"), "");
    const home = /\nHOME=([^\n]*)\n/.exec(env)?.[1] ?? "";
    const rawGot = /\nDEFAULTED_RAW=([^\n]*)\n/.exec(env)?.[1];
    check("premise: Compose expands $ in a copied value", rawGot !== undefined && rawGot !== "a$HOME-b", `got ${JSON.stringify(rawGot)} (HOME=${JSON.stringify(home)})`);
  }
  const usageRunning = await A.inspectUsage(req(serviceUuid), names);
  check("usage after start agrees", JSON.stringify([...usageRunning.names]) === JSON.stringify([...usage.names]), JSON.stringify([...usageRunning.names]));
  const listerEnv = await envOf(serviceUuid, "lister", "BARE_LIST=");
  check("lister BARE_LIST through the copied path", listerEnv?.includes("\nBARE_LIST=bare-canary\n") === true, "");
  check("lister LIST_SET from the compose file", listerEnv?.includes("\nLIST_SET=from-list\n") === true, "");
  const otherEnv = await envOf(serviceUuid, "other", "UNMENTIONED=");
  check("other container gets every variable through .env", otherEnv?.includes("\nUNMENTIONED=unmentioned-canary\n") === true, "");

  // A change, then the adapter's restart, reaches the containers.
  const changed = await A.writeValues(req(serviceUuid, { usage }), [{ name: "PLAIN", value: "plain-canary-2" }]);
  check("change written", changed[0]?.ok === true, changed[0]?.error ?? "");
  await A.triggerRedeploy(req(serviceUuid));
  check("restart requested", true, "");
  const after = await envOf(serviceUuid, "probe", "PLAIN=plain-canary-2");
  check("restart delivers the change", after !== null, "");

  // Delete: a referenced name comes back at every parse; an unmentioned one does not.
  const del = await A.deleteNames(req(serviceUuid), ["REFERENCED", "UNMENTIONED", "ESCAPED_REF"]);
  check("deletes ok", del.every((o) => o.ok), JSON.stringify(del));
  for (const round of [1, 2]) {
    await A.triggerRedeploy(req(serviceUuid));
    await sleep(10000);
    await waitRunning(serviceUuid);
    await envOf(serviceUuid, "probe", "PLAIN=plain-canary-2");
    await sleep(15000);
    const later = await A.readValues(req(serviceUuid));
    check(`restart ${round}: Coolify re-creates the referenced name`, later.has("REFERENCED"), `REFERENCED=${JSON.stringify(later.get("REFERENCED"))}`);
    check(`restart ${round}: Coolify re-creates the YAML-escaped reference`, later.has("ESCAPED_REF"), `ESCAPED_REF=${JSON.stringify(later.get("ESCAPED_REF"))}`);
    check(`restart ${round}: an unmentioned name stays deleted`, !later.has("UNMENTIONED"), "");
  }
} catch (err) {
  check("run", false, err instanceof Error ? err.message : String(err));
} finally {
  if (serviceUuid) {
    const d = await api("DELETE", `/services/${serviceUuid}?delete_configurations=true&delete_volumes=true&docker_cleanup=true&delete_connected_networks=true`.replace("docker_cleanup=true", "docker_cleanup=false"));
    console.log(`cleanup service: HTTP ${d.status}`);
    for (let i = 0; i < 24; i++) {
      if ((await api("GET", `/services/${serviceUuid}`)).status === 404) break;
      await sleep(5000);
    }
  }
  if (projectUuid) {
    const p = await api("DELETE", `/projects/${projectUuid}`);
    console.log(`cleanup project: HTTP ${p.status}`);
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  process.exitCode = failed > 0 ? 1 : 0;
}
