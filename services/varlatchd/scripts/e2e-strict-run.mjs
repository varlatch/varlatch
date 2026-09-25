#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live E2E for `varlatch run --strict` against the clean-room stack, with the
 * bundled CLI. The child records the environment it received to a marker
 * file, so each case checks both that it started (or did not) and exactly
 * what it received.
 *
 * Usage: node scripts/e2e-strict-run.mjs <server-url> <admin-token>
 */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [server, adminToken] = process.argv.slice(2);
if (!server || !adminToken) {
  console.error("Usage: e2e-strict-run.mjs <server-url> <admin-token>");
  process.exit(1);
}
const cliPath = new URL("../../../apps/cli/dist/varlatch.cjs", import.meta.url).pathname;
const P = "/v1/organizations/acme/projects/strictrun";
const E = `${P}/environments/development`;
const DB = "postgres://strict-db.internal/app";

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
  if (res.status >= 400) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

const item = (name, fields = {}) => ({ name, required: { kind: "always" }, sensitive: false, type: "string", ...fields });
async function contract(items) {
  const revision = await api("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, semanticsVersion: 2, items } });
  await api("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
}
const setValue = (name, value) => api("PUT", `${E}/values/${name}`, { value });
const deleteValue = (name) => api("DELETE", `${E}/values/${name}`);

// --- setup ------------------------------------------------------------------
await api("POST", "/v1/organizations/acme/projects", { name: "Strict run", slug: "strictrun", contractAuthority: "managed" });
const projectId = (await api("GET", P)).id;
await api("POST", `${P}/environments`, { name: "development", tier: "development" });

async function identity(name, envActions, projectActions) {
  const svc = await api("POST", "/v1/organizations/acme/identities", { name, kind: "service" });
  await api("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: svc.id,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "development" } },
    actions: envActions,
  });
  if (projectActions.length > 0) {
    await api("POST", "/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "project", projectId },
      actions: projectActions,
    });
  }
  return svc.credential;
}
const readerToken = await identity(
  "strict reader",
  ["environment.read", "config.metadata.read", "config.value.read"],
  ["contract.read"],
);
const noContractToken = await identity(
  "no contract reader",
  ["environment.read", "config.metadata.read", "config.value.read", "secret.reveal"],
  [],
);

/** A CLI checkout logged in as one identity. */
async function workspace(token) {
  const repoDir = mkdtempSync(join(tmpdir(), "strict-e2e-repo-"));
  const configDir = mkdtempSync(join(tmpdir(), "strict-e2e-cfg-"));
  const cli = (args, extraEnv = {}) =>
    new Promise((resolve) => {
      const env = { ...process.env, VARLATCH_CONFIG_DIR: configDir, ...extraEnv };
      delete env.VARLATCH_TOKEN;
      const child = spawn("node", [cliPath, ...args], { cwd: repoDir, env });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      child.on("exit", (code) => resolve({ code, out }));
    });
  await cli(["init", "--org", "acme", "--project", "strictrun", "--server", server]);
  const login = await cli(["login", "--server", server, "--token", token]);
  if (!/Logged in/.test(login.out)) throw new Error(`login failed: ${login.out}`);
  return cli;
}

const CHILD = `require("fs").writeFileSync(process.env.STRICT_MARKER, JSON.stringify({
  DATABASE_URL: process.env.DATABASE_URL ?? null, PORT: process.env.PORT ?? null,
  LEVEL: process.env.LEVEL ?? null, NEEDED: process.env.NEEDED ?? null,
  context: process.env.VARLATCH_RUN_CONTEXT ?? null }))`;

/** Run the child under `varlatch run`; returns the exit code, output, and what the child received (or null). */
async function run(cli, flags, parentEnv = {}) {
  const marker = join(mkdtempSync(join(tmpdir(), "strict-e2e-marker-")), "env.json");
  const res = await cli(["run", "-e", "development", ...flags, "--", "node", "-e", CHILD], {
    STRICT_MARKER: marker,
    ...parentEnv,
  });
  const received = existsSync(marker) ? JSON.parse(readFileSync(marker, "utf8")) : null;
  rmSync(marker, { force: true });
  return { ...res, received };
}

const admin = await workspace(adminToken);
const reader = await workspace(readerToken);
const noContract = await workspace(noContractToken);
const base = [
  item("DATABASE_URL", { sensitive: true, type: "url", defaultValue: "postgres://default.invalid/app" }),
  item("PORT", { type: "number", defaultValue: "3000" }),
  item("LEVEL", { type: "enum", enumValues: ["debug", "info"], required: { kind: "never" } }),
];
await contract(base);
await setValue("DATABASE_URL", DB);
await setValue("LEVEL", "info");

// --- a valid configuration ------------------------------------------------------
{
  const r = await run(admin, ["--strict"], { VARLATCH_RUN_CONTEXT: '{"stale":true}' });
  check("a valid configuration starts the child", r.code === 0 && r.received !== null, r.out);
  check("the child receives the delivered Secret", r.received?.DATABASE_URL === DB);
  check("a Contract default fills an item that is not stored", r.received?.PORT === "3000");
  const context = r.received?.context ? JSON.parse(r.received.context) : null;
  check("the run context replaces an inherited one", context?.mode === "strict" && !("stale" in (context ?? {})));
  check(
    "the run context records server status and delivery separately",
    JSON.stringify(context?.items) ===
      JSON.stringify({
        DATABASE_URL: { server: "delivered", delivery: "varlatch" },
        LEVEL: { server: "delivered", delivery: "varlatch" },
        PORT: { server: "notStored", delivery: "default" },
      }),
    JSON.stringify(context?.items),
  );
  check("the run context holds names only", !r.received?.context?.includes("strict-db") && !r.received?.context?.includes("3000"));
}

// --- violations: nothing starts, every violation is named, no value printed --------
await contract([...base, item("NEEDED")]);
{
  const r = await run(admin, ["--strict"]);
  check("a missing required item stops startup with exit 78", r.code === 78 && r.received === null, `exit ${r.code}`);
  check("the violation is named", /NEEDED: missing/.test(r.out), r.out);
  check("no value is printed", !r.out.includes("strict-db"));
  const inherited = await run(admin, ["--strict"], { NEEDED: "from-parent" });
  check("a parent-only value is a violation without an allowance", inherited.code === 78 && /NEEDED: inherited/.test(inherited.out), inherited.out);
  const allowed = await run(admin, ["--strict", "--allow-inherited", "NEEDED"], { NEEDED: "from-parent" });
  check("--allow-inherited accepts the parent's value", allowed.code === 0 && allowed.received?.NEEDED === "from-parent", allowed.out);
  const typo = await run(admin, ["--strict", "--allow-inherited", "NEEDDED"], { NEEDED: "from-parent" });
  check("an --allow-inherited name outside the Contract is a usage error", typo.code !== 0 && typo.received === null && /not in the Contract/.test(typo.out), typo.out);
}
await contract(base);

await setValue("LEVEL", "loud");
{
  const r = await run(admin, ["--strict"]);
  check("an invalid delivered value stops startup", r.code === 78 && r.received === null && /LEVEL: invalid/.test(r.out), r.out);
  check("the invalid value is not printed", !r.out.includes("loud"));
}
await setValue("LEVEL", "info");

await contract([...base, item("REF", { required: { kind: "never" } })]);
await setValue("REF", "${DATABASE_URL}");
{
  const r = await run(admin, ["--strict"]);
  check("a reference left literal stops startup", r.code === 78 && r.received === null && /REF: unresolved-reference/.test(r.out), r.out);
}
await deleteValue("REF");
await contract(base);

// --- withheld Secrets and inherited allowances -------------------------------------
{
  const r = await run(reader, ["--strict"]);
  check("a withheld required Secret stops startup; its default does not replace it", r.code === 78 && r.received === null && /DATABASE_URL: withheld/.test(r.out), r.out);
  const parent = await run(reader, ["--strict"], { DATABASE_URL: "postgres://parent.internal/app" });
  check("a parent value does not replace a withheld one without an allowance", parent.code === 78 && /--allow-inherited DATABASE_URL/.test(parent.out), parent.out);
  const allowed = await run(reader, ["--strict", "--allow-inherited", "DATABASE_URL"], { DATABASE_URL: "postgres://parent.internal/app" });
  check("an allowed inherited value stands in for a withheld one", allowed.code === 0 && allowed.received?.DATABASE_URL === "postgres://parent.internal/app", allowed.out);
  const context = allowed.received?.context ? JSON.parse(allowed.received.context) : null;
  check("the run context records it as withheld and inherited", JSON.stringify(context?.items?.DATABASE_URL) === JSON.stringify({ server: "withheld", delivery: "inherited" }));
  const invalid = await run(reader, ["--strict", "--allow-inherited", "DATABASE_URL"], { DATABASE_URL: "not a url" });
  check("an allowed inherited value is validated", invalid.code === 78 && /DATABASE_URL: invalid/.test(invalid.out), invalid.out);
}

// --- Contract access -------------------------------------------------------------------
{
  const r = await run(noContract, ["--strict"]);
  check("without contract.read, strict startup does not start the child", r.code === 78 && r.received === null && /contract\.read/.test(r.out), r.out);
}

// --- default runs are unchanged, except for the run context ----------------------------
{
  const r = await run(admin, [], { VARLATCH_RUN_CONTEXT: '{"stale":true}' });
  check("a default run still starts and delivers", r.code === 0 && r.received?.DATABASE_URL === DB, r.out);
  check("a default run removes an inherited run context", r.received?.context === null);
}

if (failures > 0) {
  console.error(`${failures} strict-run check(s) failed`);
  process.exit(1);
}
console.log("strict run E2E: all checks passed");
