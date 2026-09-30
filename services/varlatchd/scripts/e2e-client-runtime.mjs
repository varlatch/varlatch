#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live E2E for the client runtime against the clean-room stack, with the
 * bundled CLI: `varlatch run --redact`, `varlatch run --export-context`,
 * `varlatch types` and the module it writes (compiled and run), and
 * `varlatch scan`, checked against the server's own state and audit log.
 *
 * Every value here is a low-entropy test value; none resembles a credential.
 *
 * Usage: node scripts/e2e-client-runtime.mjs <server-url> <admin-token> [-- <docker compose command...>]
 * With the compose command, the suite also checks that no value reached the
 * varlatchd logs.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

const sep = process.argv.indexOf("--");
const [server, adminToken] = process.argv.slice(2, sep < 0 ? undefined : sep);
const compose = sep < 0 ? [] : process.argv.slice(sep + 1);
if (!server || !adminToken) {
  console.error("Usage: e2e-client-runtime.mjs <server-url> <admin-token> [-- <docker compose command...>]");
  process.exit(1);
}
const cliPath = new URL("../../../apps/cli/dist/varlatch.cjs", import.meta.url).pathname;
const TSC = createRequire(import.meta.url).resolve("typescript/bin/tsc");
const ORG = "acme";
const PROJECT = "clientrt";
const P = `/v1/organizations/${ORG}/projects/${PROJECT}`;
const E = `${P}/environments/development`;

// Test values: at least 8 bytes (the redaction and scan minimum), except PIN.
const SECRET = "secretaaaaaaaaaaaaaa";
const PIN = "pinpin";
const PLAIN = "plainvaluebbbbbbbbbb";
const PARENT_COPY = "parentcccccccccccccc";
const INHERITED = "inheritedddddddddddd";
const BAD = { PORT: "eightyeightyeighty", DEBUG: "maybemaybemaybe", LEVEL: "loudloudloud" };
const NAMES = ["RT_SECRET", "RT_PIN", "RT_PLAIN", "RT_UNSTORED", "RT_ABSENT", "PORT", "DEBUG", "LEVEL", "RT_ADDED"];

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || !detail ? "" : `: ${detail}`}`);
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

/** JSON with sorted keys, so two objects compare regardless of key order. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const temporary = [];
function tempDir(prefix) {
  const dir = mkdtempSync(join(tmpdir(), `clientrt-e2e-${prefix}-`));
  temporary.push(dir);
  return dir;
}

/**
 * The environment every command starts from: this process's, without any
 * Varlatch setting or Contract item name, so the host cannot leak into a run.
 */
function baseEnv(extra = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith("VARLATCH_") || NAMES.includes(key)) delete env[key];
  // A coding agent's marker in the host shell would switch on assisted mode
  // (ADR-0043); these runs test the modes they name, so detection is off.
  return { ...env, VARLATCH_ASSISTED: "0", ...extra };
}

/**
 * Run a command with piped stdout and stderr (never a terminal), captured
 * separately. A bound on the run's duration turns a hang into a failure.
 */
function capture(command, args, { cwd, env, timeoutMs = 90_000 }) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ...result, stdout, stderr, out: stdout + stderr });
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      done({ code: null, timedOut: true });
    }, timeoutMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      stderr += String(err);
      done({ code: null, timedOut: false });
    });
    child.on("close", (code) => done({ code, timedOut: false }));
  });
}

function git(dir, args) {
  const r = spawnSync("git", args, { cwd: dir, encoding: "utf8", env: baseEnv() });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}

/** A checkout (optionally a Git repository) with `varlatch.toml`, logged in as one identity. */
async function workspace(token, { gitRepo = false } = {}) {
  const dir = tempDir("repo");
  const configDir = tempDir("cfg");
  if (gitRepo) git(dir, ["-c", "init.defaultBranch=main", "init", "-q"]);
  const cli = (args, extraEnv = {}, timeoutMs) =>
    capture(process.execPath, [cliPath, ...args], {
      cwd: dir,
      env: baseEnv({ VARLATCH_CONFIG_DIR: configDir, ...extraEnv }),
      timeoutMs,
    });
  const init = await cli(["init", "--org", ORG, "--project", PROJECT, "--server", server]);
  if (init.code !== 0) throw new Error(`init failed: ${init.out}`);
  const login = await cli(["login", "--server", server, "--token", token]);
  if (!/Logged in/.test(login.out)) throw new Error(`login failed: ${login.out}`);
  return { dir, cli };
}

const item = (name, fields = {}) => ({ name, required: { kind: "never" }, sensitive: false, type: "string", ...fields });
const BASE_CONTRACT = [
  item("RT_SECRET", { sensitive: true, required: { kind: "always" }, description: "The Secret this suite redacts and scans for" }),
  item("RT_PIN", { sensitive: true, description: "A Secret shorter than 8 bytes" }),
  item("RT_PLAIN", { description: "A non-sensitive value" }),
  item("RT_UNSTORED", { description: "Never stored; the parent shell may set it" }),
  item("RT_ABSENT", { description: "Never stored and never set" }),
  item("PORT", { type: "number", required: { kind: "always" } }),
  item("DEBUG", { type: "boolean" }),
  item("LEVEL", { type: "enum", enumValues: ["debug", "info", "warn"] }),
];
async function activate(items) {
  const revision = await api("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, semanticsVersion: 2, items } });
  await api("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  return api("GET", `${P}/contract`);
}
const setValue = (name, value) => api("PUT", `${E}/values/${name}`, { value });

async function auditEvents() {
  const res = await fetch(`${server}/v1/organizations/${ORG}/audit-events/export`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const ndjson = await res.text();
  if (res.status !== 200) throw new Error(`audit export: ${res.status} ${ndjson}`);
  return { ndjson, events: ndjson.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) };
}

// --- setup ------------------------------------------------------------------
await api("POST", `/v1/organizations/${ORG}/projects`, { name: "Client runtime", slug: PROJECT, contractAuthority: "managed" });
const projectId = (await api("GET", P)).id;
const environment = await api("POST", `${P}/environments`, { name: "development", tier: "development" });

async function identity(name, envActions, projectActions) {
  const svc = await api("POST", `/v1/organizations/${ORG}/identities`, { name, kind: "service" });
  await api("POST", `/v1/organizations/${ORG}/grants`, {
    subjectIdentityId: svc.id,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "development" } },
    actions: envActions,
  });
  if (projectActions.length > 0) {
    await api("POST", `/v1/organizations/${ORG}/grants`, {
      subjectIdentityId: svc.id,
      scope: { kind: "project", projectId },
      actions: projectActions,
    });
  }
  return svc;
}
// May read everything but Secrets: its Secrets are withheld.
const reader = await identity("clientrt reader", ["environment.read", "config.metadata.read", "config.value.read"], ["contract.read"]);
// May read Secrets but not the Contract.
const noContract = await identity(
  "clientrt no contract",
  ["environment.read", "config.metadata.read", "config.value.read", "secret.reveal"],
  [],
);

let active = await activate(BASE_CONTRACT);
const secretVersion = (await setValue("RT_SECRET", SECRET)).versionId;
await setValue("RT_PIN", PIN);
await setValue("RT_PLAIN", PLAIN);
await setValue("PORT", "8080");
await setValue("DEBUG", "true");
await setValue("LEVEL", "warn");

const admin = await workspace(adminToken);
const readerWs = await workspace(reader.credential);
const noContractWs = await workspace(noContract.credential);

// --- varlatch run --redact ----------------------------------------------------
// The child prints the Secret on both streams, directly, split across two
// writes with a pause between them, and base64-encoded; then a non-sensitive
// value; then exits 7.
const LOUD = `
const v = process.env.RT_SECRET;
const out = (s) => process.stdout.write(s);
const err = (s) => process.stderr.write(s);
out("start\\n");
out("direct:" + v + "\\n");
err("err-direct:" + v + "\\n");
out("split:" + v.slice(0, 6));
err("err-split:" + v.slice(0, 6));
setTimeout(() => {
  out(v.slice(6) + "\\n");
  err(v.slice(6) + "\\n");
  out("base64:" + Buffer.from(v).toString("base64") + "\\n");
  out("plain:" + process.env.RT_PLAIN + "\\n");
  out("end\\n");
  process.exitCode = 7;
}, 200);
`;
{
  const b64 = Buffer.from(SECRET).toString("base64");
  const r = await admin.cli(["run", "-e", "development", "--redact", "--", process.execPath, "-e", LOUD]);
  check("--redact: the run exits with the child's status", r.code === 7, `exit ${r.code}${r.timedOut ? " (timed out)" : ""}: ${r.out}`);
  check("--redact: the Secret never appears on stdout or stderr", !r.out.includes(SECRET) && !r.out.includes(b64.slice(0, 16)), r.out);
  const lines = r.stdout.split("\n");
  check(
    "--redact: stdout keeps its lines and order, with each Secret replaced by its marker",
    lines[0] === "start" &&
      lines[1] === "direct:[REDACTED:RT_SECRET]" &&
      lines[2] === "split:[REDACTED:RT_SECRET]" &&
      lines[3]?.startsWith("base64:[REDACTED:RT_SECRET]") &&
      lines[4] === `plain:${PLAIN}` &&
      lines[5] === "end",
    JSON.stringify(lines),
  );
  const errLines = r.stderr.split("\n");
  check(
    "--redact: stderr is masked too, including a value split across writes",
    errLines.includes("err-direct:[REDACTED:RT_SECRET]") && errLines.includes("err-split:[REDACTED:RT_SECRET]"),
    r.stderr,
  );
  check("--redact: a non-sensitive value passes through", r.stdout.includes(`plain:${PLAIN}\n`));
  check(
    "--redact: a Secret shorter than 8 bytes is named, never shown, as passing through",
    /--redact does not mask values shorter than 8 bytes; these pass through unchanged: RT_PIN/.test(r.stderr),
    r.stderr,
  );

  const plainRun = await admin.cli(["run", "-e", "development", "--", process.execPath, "-e", LOUD]);
  check(
    "without --redact the same run relays the output unchanged",
    plainRun.code === 7 && plainRun.stdout.includes(`direct:${SECRET}\n`) && !plainRun.out.includes("[REDACTED:"),
    `exit ${plainRun.code}`,
  );
}

// --- varlatch run --export-context ----------------------------------------------
const RECORD = `require("fs").writeFileSync(process.env.CLIENTRT_MARKER, JSON.stringify({
  RT_SECRET: process.env.RT_SECRET ?? null, RT_UNSTORED: process.env.RT_UNSTORED ?? null,
  RT_ABSENT: process.env.RT_ABSENT ?? null, context: process.env.VARLATCH_RUN_CONTEXT ?? null }))`;

/** Run the recording child; returns the exit code, output, and what the child received (or null). */
async function record(ws, flags, parentEnv = {}) {
  const marker = join(tempDir("marker"), "env.json");
  const r = await ws.cli(["run", "-e", "development", ...flags, "--", process.execPath, "-e", RECORD], {
    CLIENTRT_MARKER: marker,
    ...parentEnv,
  });
  const received = existsSync(marker) ? JSON.parse(readFileSync(marker, "utf8")) : null;
  return { ...r, received };
}

function expectedContext(items) {
  return {
    v: 1,
    mode: "exported",
    contractRevisionId: active.id,
    contractHash: active.contentHash,
    semanticsVersion: 2,
    environment: { rootId: environment.id, tier: "development" },
    items,
  };
}
const delivered = { server: "delivered", delivery: "varlatch" };
const noValueIn = (text) => [SECRET, PARENT_COPY, INHERITED, PLAIN].every((v) => !text.includes(v));

{
  const r = await record(admin, ["--export-context"], {
    RT_SECRET: PARENT_COPY,
    RT_UNSTORED: INHERITED,
    VARLATCH_RUN_CONTEXT: '{"stale":true}',
  });
  check("--export-context: a default run starts the child", r.code === 0 && r.received !== null, r.out);
  check("--export-context: a delivered Secret replaces the parent's copy", r.received?.RT_SECRET === SECRET);
  check("--export-context: an item that is not stored is inherited from the parent", r.received?.RT_UNSTORED === INHERITED);
  check("--export-context: no default is applied and nothing is invented", r.received?.RT_ABSENT === null);
  const context = r.received?.context ? JSON.parse(r.received.context) : null;
  const expected = expectedContext({
    RT_SECRET: delivered,
    RT_PIN: delivered,
    RT_PLAIN: delivered,
    PORT: delivered,
    DEBUG: delivered,
    LEVEL: delivered,
    RT_UNSTORED: { server: "notStored", delivery: "inherited" },
    RT_ABSENT: { server: "notStored", delivery: "absent" },
  });
  check(
    "--export-context: the context names the active revision, its hash, semantics, the environment, and each item's status",
    canonical(context) === canonical(expected),
    `${r.received?.context} expected ${canonical(expected)}`,
  );
  check("--export-context: the context holds no value", r.received?.context !== null && noValueIn(r.received.context));
}
{
  const r = await record(readerWs, ["--export-context"], { RT_SECRET: PARENT_COPY });
  check("--export-context: an identity without secret.reveal still starts the child", r.code === 0 && r.received !== null, r.out);
  check("--export-context: a withheld Secret is left to the parent's copy", r.received?.RT_SECRET === PARENT_COPY);
  const context = r.received?.context ? JSON.parse(r.received.context) : null;
  const expected = expectedContext({
    RT_SECRET: { server: "withheld", delivery: "inherited" },
    RT_PIN: { server: "withheld", delivery: "absent" },
    RT_PLAIN: delivered,
    PORT: delivered,
    DEBUG: delivered,
    LEVEL: delivered,
    RT_UNSTORED: { server: "notStored", delivery: "absent" },
    RT_ABSENT: { server: "notStored", delivery: "absent" },
  });
  check(
    "--export-context: withheld Secrets are recorded as withheld, inherited or absent",
    canonical(context) === canonical(expected),
    `${r.received?.context} expected ${canonical(expected)}`,
  );
  check("--export-context: the withheld run's context holds no value", r.received?.context !== null && noValueIn(r.received.context));
}
{
  const before = (await auditEvents()).events.filter((e) => e.actorIdentityId === noContract.id && e.eventType === "secret.disclosed");
  const r = await record(noContractWs, ["--export-context"]);
  check(
    "--export-context without contract.read starts nothing and says why",
    r.code !== 0 && r.received === null && /contract\.read/.test(r.out),
    `exit ${r.code}: ${r.out}`,
  );
  const after = (await auditEvents()).events.filter((e) => e.actorIdentityId === noContract.id && e.eventType === "secret.disclosed");
  check("--export-context: a run that cannot export its context discloses no Secret", before.length === 0 && after.length === 0, `${after.length} disclosure(s)`);
  const plain = await record(noContractWs, []);
  check("the same identity's default run, without the flag, gets no context", plain.code === 0 && plain.received?.context === null, plain.out);
}

// --- varlatch types, and the module it writes ----------------------------------------
const OUT = "src/varlatch.gen.ts";
const outPath = join(admin.dir, OUT);
const APP = `import { ConfigError, generatedFrom, loadConfig, type Config } from "./varlatch.gen.js";

declare const process: { exitCode?: number };
declare const console: { log(line: string): void };

// Types only; never called. A type error fails the compilation.
export function typeChecks(config: Readonly<Config>): void {
  const port: number = config.PORT;
  const secret: string = config.RT_SECRET;
  const debug: boolean | undefined = config.DEBUG;
  const level: "debug" | "info" | "warn" | undefined = config.LEVEL;
  // @ts-expect-error PORT is a number
  const wrong: string = config.PORT;
  // @ts-expect-error DEBUG is optional
  const always: boolean = config.DEBUG;
  // @ts-expect-error not a Contract item
  const unknown = config.NOT_AN_ITEM;
  void [port, secret, debug, level, wrong, always, unknown];
}

let report: Record<string, unknown>;
try {
  const result = loadConfig({ onWarning: () => undefined });
  const c = result.config;
  report = {
    ok: true,
    values: { PORT: c.PORT, DEBUG: c.DEBUG, LEVEL: c.LEVEL },
    types: { PORT: typeof c.PORT, DEBUG: typeof c.DEBUG, LEVEL: typeof c.LEVEL, RT_SECRET: typeof c.RT_SECRET },
    context: result.context,
    warnings: result.warnings,
    generatedFrom,
  };
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  report = { ok: false, name: err.name, issues: err.issues, message: err.message };
  process.exitCode = 3;
}
console.log(JSON.stringify(report));
`;
const TSCONFIG = {
  compilerOptions: {
    target: "ES2022",
    lib: ["ES2022"],
    types: [],
    module: "NodeNext",
    moduleResolution: "NodeNext",
    verbatimModuleSyntax: true,
    strict: true,
    noUncheckedIndexedAccess: true,
    exactOptionalPropertyTypes: true,
    noUnusedLocals: true,
    noUnusedParameters: true,
    skipLibCheck: false,
    rootDir: "src",
    outDir: "dist",
  },
  include: ["src"],
};
mkdirSync(join(admin.dir, "src"), { recursive: true });
writeFileSync(join(admin.dir, "src", "main.ts"), APP);
writeFileSync(join(admin.dir, "package.json"), JSON.stringify({ type: "module", private: true }));
writeFileSync(join(admin.dir, "tsconfig.json"), JSON.stringify(TSCONFIG, null, 2));
const appPath = join(admin.dir, "dist", "main.js");

async function compile() {
  rmSync(join(admin.dir, "dist"), { recursive: true, force: true });
  return capture(process.execPath, [TSC, "-p", admin.dir], { cwd: admin.dir, env: baseEnv(), timeoutMs: 180_000 });
}
/** Start the compiled application under `varlatch run --export-context`; returns its report. */
async function startApp(ws) {
  const r = await ws.cli(["run", "-e", "development", "--export-context", "--", process.execPath, appPath]);
  let report = null;
  try {
    report = JSON.parse(r.stdout.trim().split("\n").at(-1) ?? "");
  } catch {
    // Reported by the checks below.
  }
  return { ...r, report };
}

{
  const wrote = await admin.cli(["types", "--out", OUT]);
  check("types: the module is generated from the active revision", wrote.code === 0 && /^Wrote /.test(wrote.stdout), wrote.out);
  const source = existsSync(outPath) ? readFileSync(outPath, "utf8") : "";
  check("types: the header records the active revision and its content hash", source.includes(active.id) && source.includes(active.contentHash));
  check("types: the module holds no value", source.length > 0 && noValueIn(source) && !source.includes("8080"));
  const mtime = statSync(outPath).mtimeMs;
  const again = await admin.cli(["types", "--out", OUT]);
  check("types: regenerating an unchanged revision leaves the file untouched", again.code === 0 && /left unchanged/.test(again.stdout) && statSync(outPath).mtimeMs === mtime, again.out);
  const current = await admin.cli(["types", "--out", OUT, "--check"]);
  check("types --check passes while the module matches the active revision", current.code === 0 && /is current with/.test(current.stdout), current.out);

  const compiled = await compile();
  check("types: the module and an application using it compile under strict settings", compiled.code === 0 && compiled.out === "", compiled.out);
  const r = await startApp(admin);
  check("types: the application starts under --export-context", r.code === 0 && r.report?.ok === true, r.out);
  check(
    "types: the accessor returns typed values (number, boolean, enum)",
    canonical(r.report?.values) === canonical({ PORT: 8080, DEBUG: true, LEVEL: "warn" }) &&
      canonical(r.report?.types) === canonical({ PORT: "number", DEBUG: "boolean", LEVEL: "string", RT_SECRET: "string" }),
    JSON.stringify(r.report),
  );
  check(
    "types: the accessor reads the exported context of the same revision, without warnings",
    r.report?.context === "exported" && r.report?.warnings?.length === 0 && r.report?.generatedFrom?.revisionId === active.id,
    JSON.stringify(r.report),
  );
  check("types: the application's output holds no Secret", !r.out.includes(SECRET));
}

// A changed Contract: --check fails, and the old module reports stale types at runtime.
active = await activate([...BASE_CONTRACT, item("RT_ADDED", { description: "Added after the module was generated" })]);
{
  const stale = await admin.cli(["types", "--out", OUT, "--check"]);
  check("types --check fails once a changed Contract is active", stale.code === 1 && /is stale/.test(stale.stderr), `exit ${stale.code}: ${stale.out}`);
  const r = await startApp(admin);
  check(
    "types: the old module warns that its types are stale for this run",
    r.code === 0 && r.report?.ok === true && r.report?.warnings?.length === 1 && /types are stale/.test(r.report.warnings[0]),
    r.out,
  );
  const wrote = await admin.cli(["types", "--out", OUT]);
  const current = await admin.cli(["types", "--out", OUT, "--check"]);
  check("types: regenerating makes --check pass again", wrote.code === 0 && current.code === 0, wrote.out + current.out);
  const compiled = await compile();
  check("types: the regenerated module compiles", compiled.code === 0 && compiled.out === "", compiled.out);
  const fresh = await startApp(admin);
  check(
    "types: the regenerated module reads the run without warnings",
    fresh.code === 0 &&
      fresh.report?.ok === true &&
      fresh.report?.context === "exported" &&
      fresh.report?.warnings?.length === 0 &&
      fresh.report?.generatedFrom?.revisionId === active.id,
    fresh.out,
  );
}

// A withheld required Secret, read through the real server's run context.
{
  const r = await startApp(readerWs);
  const issues = r.report?.issues ?? [];
  check(
    "types: a required Secret withheld by the server is one ConfigError issue",
    r.code === 3 && r.report?.ok === false && issues.length === 1 && issues[0]?.name === "RT_SECRET" && /withheld/.test(issues[0]?.reason ?? ""),
    r.out,
  );
}

// Invalid values: one aggregated error, and no value in it.
await setValue("PORT", BAD.PORT);
await setValue("DEBUG", BAD.DEBUG);
await setValue("LEVEL", BAD.LEVEL);
{
  const r = await startApp(admin);
  const names = (r.report?.issues ?? []).map((i) => i.name).sort();
  check(
    "types: invalid values throw one ConfigError listing every item",
    r.code === 3 && r.report?.ok === false && r.report?.name === "ConfigError" && canonical(names) === canonical(["DEBUG", "LEVEL", "PORT"]),
    r.out,
  );
  check(
    "types: the error names items and reasons, never a value",
    /configuration is invalid \(3 problems\)/.test(r.report?.message ?? "") &&
      Object.values(BAD).every((v) => !r.out.includes(v)) &&
      !r.out.includes(SECRET),
    r.out,
  );
}
await setValue("PORT", "8080");
await setValue("DEBUG", "true");
await setValue("LEVEL", "warn");

// --- varlatch scan ------------------------------------------------------------------
const scanEvents = async () =>
  (await auditEvents()).events.filter(
    (e) => e.eventType === "secret.disclosed" && e.resource?.projectId === projectId && e.metadata?.purpose === "scan",
  );
{
  const repo = await workspace(adminToken, { gitRepo: true });
  const nothing = await repo.cli(["scan", "--staged", "-e", "development"]);
  check("scan: with nothing staged, the scan reads nothing and exits 0", nothing.code === 0 && /nothing is staged/.test(nothing.stdout), nothing.out);
  check("scan: with nothing to read, nothing is disclosed", (await scanEvents()).length === 0);

  // Staged content holds the Secret as written (line 2) and inside a base64
  // Basic credential (line 3); the working copy is then cleaned, which the
  // staged scan must not be fooled by.
  const basic = Buffer.from(`user:${SECRET}`).toString("base64");
  mkdirSync(join(repo.dir, "config"));
  writeFileSync(join(repo.dir, "config", "leak.txt"), `# settings\nconnection = ${SECRET}\nbasic = ${basic}\n`);
  git(repo.dir, ["add", "config/leak.txt"]);
  writeFileSync(join(repo.dir, "config", "leak.txt"), "# settings\n");

  const staged = await repo.cli(["scan", "--staged", "-e", "development"]);
  check("scan --staged: a staged Secret is a finding and the scan exits non-zero", staged.code === 1, `exit ${staged.code}: ${staged.out}`);
  const lines = staged.stdout.split("\n");
  check(
    "scan --staged: each finding names the path, line, column, item, and stored version",
    lines.includes(`config/leak.txt:2:14: RT_SECRET (version ${secretVersion}), as written`) &&
      lines.some((l) => new RegExp(`^config/leak\\.txt:3:\\d+: RT_SECRET \\(version ${secretVersion}\\), base64$`).test(l)),
    staged.stdout,
  );
  check("scan --staged: the output never shows the value", !staged.out.includes(SECRET) && !staged.out.includes(basic), staged.out);
  check("scan --staged: a Secret shorter than 8 bytes is named as not checked", /values shorter than 8 bytes are not checked: RT_PIN/.test(staged.stderr), staged.stderr);

  const json = await repo.cli(["scan", "--staged", "--json", "-e", "development"]);
  let report = null;
  try {
    report = JSON.parse(json.stdout);
  } catch {
    // Reported below.
  }
  check(
    "scan --staged --json: the report matches the server's stored version",
    json.code === 1 &&
      report?.exitCode === 1 &&
      report?.mode === "staged" &&
      canonical(report?.findings?.map((f) => [f.path, f.line, f.item, f.versionId, f.retiring, f.form])) ===
        canonical([
          ["config/leak.txt", 2, "RT_SECRET", secretVersion, false, "raw"],
          ["config/leak.txt", 3, "RT_SECRET", secretVersion, false, "base64"],
        ]),
    json.out,
  );
  check("scan --staged --json: the report never shows the value", !json.out.includes(SECRET) && !json.out.includes(basic));

  mkdirSync(join(repo.dir, "clean"));
  writeFileSync(join(repo.dir, "clean", "notes.txt"), `nothing to see here\n${PLAIN}\n`);
  const clean = await repo.cli(["scan", "clean", "-e", "development"]);
  check("scan <path>: a clean path exits 0 with no findings", clean.code === 0 && /1 file\(s\) checked .*: no findings\./.test(clean.stdout), clean.out);

  const events = await scanEvents();
  check(
    "scan: each scan that read files is one audited disclosure with purpose \"scan\"",
    events.length === 3 && events.every((e) => e.decision === "allow" && String(e.metadata?.items).includes(`RT_SECRET@${secretVersion}`)),
    JSON.stringify(events.map((e) => e.metadata)),
  );
}

// --- the audit log and the server's logs hold no value --------------------------------
{
  const { ndjson, events } = await auditEvents();
  const runDisclosures = events.filter((e) => e.eventType === "secret.disclosed" && e.resource?.projectId === projectId && e.metadata?.purpose === undefined);
  check("run disclosures are audited without a purpose", runDisclosures.length > 0);
  check("the audit export holds no value", noValueIn(ndjson) && Object.values(BAD).every((v) => !ndjson.includes(v)));
  if (compose.length >= 2) {
    const logs = spawnSync(compose[0], [...compose.slice(1), "logs", "varlatchd"], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
    check("varlatchd logs hold no value", logs.status === 0 && noValueIn(logs.stdout + logs.stderr), `docker compose logs exited ${logs.status}`);
  }
}

for (const dir of temporary) rmSync(dir, { recursive: true, force: true });
if (failures > 0) {
  console.error(`${failures} client runtime check(s) failed`);
  process.exit(1);
}
console.log("client runtime E2E: all checks passed");
