// SPDX-License-Identifier: Apache-2.0
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { agentsBlock } from "../src/agents/install.js";
import { contractItem, revision } from "./fixtures.js";

/**
 * ADR-0043 step 1 end to end: the CLI, bundled from this checkout's source,
 * against a local fake server, with real child processes. Assisted mode's
 * precedence, output protection (stdout, stderr, encodings, a
 * pseudo-terminal, short values, inherited values), Secret input for
 * `values set` and `values rotate`, and `varlatch import`. Each protection
 * is paired with a negative control: the same input with that protection
 * disabled.
 */

const TOKEN = "api-token-canary/9f2e+Q>>?";
const LEGACY = "legacy-inherited-canary-3c71";
const WITHHELD = "withheld-inherited-canary-8a02";
const UNKNOWN = "unknown-name-canary-66d4";
const PIN = "1234567";
const b64 = (s: string) => Buffer.from(s).toString("base64");

const dir = mkdtempSync(join(tmpdir(), "varlatch-assisted-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const bare = join(dir, "bare");
let server: http.Server;
let origin = "";

interface StoredItem {
  name: string;
  sensitive: boolean;
  value: string;
  withheld?: boolean;
}

/** Server state, reset before each test. */
let stored: StoredItem[];
let requests: { method: string; url: string; auth: string; body: unknown }[];
let denyEffective = false;
let noActiveContract = false;
let failPut: Set<string>;

const CONTRACT = [
  contractItem("API_TOKEN", { sensitive: true }),
  contractItem("LEGACY_KEY", { sensitive: true }), // in the Contract, never stored
  contractItem("PIN", { sensitive: true }),
  contractItem("PORT"),
  contractItem("WITHHELD_KEY", { sensitive: true }),
];

function defaultItems(): StoredItem[] {
  return [
    { name: "API_TOKEN", sensitive: true, value: TOKEN },
    { name: "PORT", sensitive: false, value: "8080" },
    { name: "WITHHELD_KEY", sensitive: true, value: "never-disclosed", withheld: true },
  ];
}

const ENV_PATH = "/v1/organizations/acme/projects/web/environments/development";

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as unknown) : undefined;
    requests.push({ method: req.method ?? "", url, auth: req.headers.authorization ?? "", body });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    const active = revision(CONTRACT, { id: "crv_active" });
    if (url === "/v1/meta") return json(200, { serverVersion: "0.13.0", capabilities: ["retrieval.strict"], semanticsVersions: [1, 2, 3] });
    if (url === "/v1/organizations/acme/projects/web/contract" && req.method === "GET") return json(200, active);
    if (url === `/v1/organizations/acme/projects/web/contract/revisions/${active.id}` && req.method === "GET") return json(200, active);
    if (url === "/v1/organizations/acme/projects/web/contract/revisions" && req.method === "POST") {
      return json(201, { ...active, id: "crv_imported", active: false });
    }
    const effectiveIn = /^\/v1\/organizations\/acme\/projects\/web\/environments\/([a-z]+)\/effective-configuration/.exec(url);
    if (effectiveIn) {
      if (denyEffective) return json(403, { error: { code: "PERMISSION_DENIED", message: "metadata read denied", requestId: "req_d" } });
      // "preview" is a child of development, with no values of its own: it inherits development's.
      const inEnv = effectiveIn[1] === "development" || effectiveIn[1] === "preview" ? stored : [];
      const source = effectiveIn[1] === "preview" ? "parent" : "self";
      return json(200, {
        environmentId: "env_1",
        // As the daemon: metadata only, unless include=values, which returns non-sensitive values only.
        items: inEnv.map((i) => ({ name: i.name, sensitive: i.sensitive, source, value: !i.sensitive && url.includes("include=values") ? i.value : null })),
        stateDigest: `sha256:${"0".repeat(64)}`,
        manifest: {
          manifestVersion: 1,
          projectId: "prj_1",
          environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
          contract: { revisionId: active.id, contentHash: active.contentHash, semanticsVersion: 2 },
          items: [],
        },
      });
    }
    if (url === `${ENV_PATH}/disclosures`) {
      return json(200, {
        items: stored.filter((i) => i.sensitive && !i.withheld).map((i) => ({ name: i.name, versionId: `ver_${i.name}`, value: i.value })),
        withheld: stored.filter((i) => i.withheld).map((i) => i.name),
        stateDigest: `sha256:${"0".repeat(64)}`,
      });
    }
    if (url === `${ENV_PATH}/retrievals`) {
      const items = stored.filter((i) => !i.withheld).map((i) => ({ ...i, source: "self", versionId: `ver_${i.name}` }));
      return json(200, {
        environmentId: "env_1",
        manifest: {
          manifestVersion: 1,
          projectId: "prj_1",
          environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
          contract: noActiveContract ? null : { revisionId: active.id, contentHash: active.contentHash, semanticsVersion: 2 },
          items: items.map((i) => ({ name: i.name, source: "self", valueRowId: `val_${i.name}`, versionId: i.versionId })),
        },
        stateDigest: `sha256:${"0".repeat(64)}`,
        contract: noActiveContract ? null : active.contract,
        items,
        callerView: { withheld: [], unexpanded: [], contractWithheld: false },
        validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
      });
    }
    // Any environment: a handoff for production must reach production's path.
    const put = /^\/v1\/organizations\/acme\/projects\/web\/environments\/[a-z]+\/values\/([A-Z0-9_]+)$/.exec(url);
    if (put && req.method === "PUT") {
      if (failPut.has(put[1]!)) return json(500, { error: { code: "INTERNAL", message: "injected", requestId: "req_x" } });
      // Stored, as the server would: a later request sees it (a new item is a Secret, as outside a Contract).
      if (url.startsWith(`${ENV_PATH}/`)) {
        const before = stored.find((i) => i.name === put[1]);
        stored = [...stored.filter((i) => i.name !== put[1]), { name: put[1]!, sensitive: before?.sensitive ?? true, value: (body as { value: string }).value }];
      }
      return json(200, { versionId: `ver_new_${put[1]}` });
    }
    // Any environment; development's stored values change, as the server would.
    const del = /^\/v1\/organizations\/acme\/projects\/web\/environments\/([a-z]+)\/values\/([A-Z0-9_]+)$/.exec(url);
    if (del && req.method === "DELETE") {
      if (del[1] === "development") stored = stored.filter((i) => i.name !== del[2]);
      res.writeHead(204);
      return res.end();
    }
    const rotate = new RegExp(`^${ENV_PATH}/values/([A-Z0-9_]+)/rotations$`).exec(url);
    if (rotate && req.method === "POST") {
      return json(200, { primaryVersionId: `ver_rot_${rotate[1]}`, rotationDeadline: "2026-10-01T00:00:00.000Z" });
    }
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "req_1" } });
  });
}

beforeAll(async () => {
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile: bundle,
    logLevel: "silent",
  });
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  mkdirSync(bare);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  stored = defaultItems();
  requests = [];
  failPut = new Set();
  denyEffective = false;
  noActiveContract = false;
});

/** No coding agent's marker and no VARLATCH_ASSISTED: every signal is added per test. */
function baseEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", ...extra };
}

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], opts: { env?: Record<string, string>; input?: string; cwd?: string } = {}): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], { cwd: opts.cwd ?? repo, env: baseEnv(opts.env), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(opts.input ?? "");
  });
}

/** A child that prints every value the tests follow, raw and encoded, on stdout and stderr, with pauses between writes. */
function printer(): string {
  const file = join(dir, `printer-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(
    file,
    `
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const out = (s) => new Promise((r) => process.stdout.write(s, r));
const err = (s) => new Promise((r) => process.stderr.write(s, r));
(async () => {
  const e = process.env;
  const t = e.API_TOKEN ?? "";
  await out("tty=" + Boolean(process.stdout.isTTY) + "\\n");
  await out("token=" + t.slice(0, 5)); await pause(40); await out(t.slice(5) + "\\n");
  await out("json=" + JSON.stringify({ t }).replace(/\\//g, "\\\\/") + "\\n");
  await out("pct=" + encodeURIComponent(t) + "\\n");
  await err("b64=" + Buffer.from(t).toString("base64") + "\\n");
  await out("legacy=" + e.LEGACY_KEY + " withheld=" + e.WITHHELD_KEY + "\\n");
  await err("unknown=" + e.UNKNOWN_TOKEN + " pin=" + e.PIN + " port=" + e.PORT + "\\n");
  if (e.MARKER) require("fs").writeFileSync(e.MARKER, "started");
})();`,
  );
  return file;
}

/** The inherited values the parent shell holds: two known Secret names and one unknown one. */
const INHERITED = { LEGACY_KEY: LEGACY, WITHHELD_KEY: WITHHELD, UNKNOWN_TOKEN: UNKNOWN };

function leaked(r: Result): string[] {
  const all = r.stdout + r.stderr;
  return [
    ["token", TOKEN],
    ["token-base64", b64(TOKEN)],
    ["token-percent", encodeURIComponent(TOKEN)],
    ["token-json", JSON.stringify(TOKEN).slice(1, -1).replace(/\//g, "\\/")],
    ["legacy", LEGACY],
    ["withheld", WITHHELD],
  ]
    .filter(([, v]) => all.includes(v as string))
    .map(([k]) => k as string);
}

describe("assisted run: output protection and precedence", () => {
  it.each([
    ["--assisted", ["--assisted"], {}],
    ["VARLATCH_ASSISTED=1", [], { VARLATCH_ASSISTED: "1" }],
    ["the CLAUDECODE marker", [], { CLAUDECODE: "1" }],
    ["the CODEX_THREAD_ID marker", [], { CODEX_THREAD_ID: "thread_1" }],
    ["--assisted with VARLATCH_ASSISTED=0", ["--assisted"], { VARLATCH_ASSISTED: "0", CLAUDECODE: "1" }],
  ] as const)("%s masks delivered and inherited known-name Secrets on stdout and stderr, in every printed form", async (_name, flags, env) => {
    const r = await cli([...flags, "run", "--", process.execPath, printer()], { env: { ...env, ...INHERITED } });
    expect(r.code).toBe(0);
    expect(leaked(r)).toEqual([]);
    expect(r.stdout).toContain("token=[REDACTED:API_TOKEN]\n");
    expect(r.stdout).toContain("legacy=[REDACTED:LEGACY_KEY] withheld=[REDACTED:WITHHELD_KEY]\n");
    // Base64 is matched on the characters that come only from the value (ADR-0039 Decision 17); the padding tail remains.
    expect(r.stderr).toMatch(/b64=\[REDACTED:API_TOKEN\][A-Za-z0-9+/]?=*\n/);
    // Limit check, not a control: an inherited secret under an unknown name passes, as documented.
    expect(r.stderr).toContain(`unknown=${UNKNOWN} pin=undefined port=8080`);
  });

  it.each([
    ["no option, setting, or marker", [], [], {}],
    ["a marker with VARLATCH_ASSISTED=0", [], [], { VARLATCH_ASSISTED: "0", CLAUDECODE: "1" }],
    ["--no-redact outside assisted mode", [], ["--no-redact"], {}],
  ] as const)("negative control, same input: %s leaves the output unmasked", async (_name, global, runFlags, env) => {
    const r = await cli([...global, "run", ...runFlags, "--", process.execPath, printer()], { env: { ...env, ...INHERITED } });
    expect(r.code).toBe(0);
    expect(leaked(r)).toEqual(["token", "token-base64", "token-percent", "token-json", "legacy", "withheld"]);
    expect(r.stderr).not.toMatch(/refused in assisted mode/);
  });

  it("negative control for inherited-value filtering: --redact outside assisted mode masks the delivered Secret but not the inherited ones", async () => {
    const r = await cli(["run", "--redact", "--", process.execPath, printer()], { env: INHERITED });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("token=[REDACTED:API_TOKEN]\n");
    expect(leaked(r)).toEqual(["legacy", "withheld"]);
  });

  it("works with --strict: delivered and allowed inherited Secrets are masked", async () => {
    const r = await cli(["--assisted", "run", "--strict", "--allow-inherited", "LEGACY_KEY", "--", process.execPath, printer()], { env: { LEGACY_KEY: LEGACY } });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("token=[REDACTED:API_TOKEN]\n");
    expect(r.stdout).toContain("legacy=[REDACTED:LEGACY_KEY]");
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
    expect(r.stdout + r.stderr).not.toContain(LEGACY);
  });

  it("assisted mode refuses --no-redact and --allow-unmasked before anything starts; outside it, they do not combine; with --agent-safe, both are refused", async () => {
    const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
    for (const [flag, shown] of [["--no-redact", "<NAME>"], ["--allow-unmasked", "PIN"]] as const) {
      const args = flag === "--no-redact" ? ["--no-redact"] : ["--allow-unmasked", "PIN"];
      for (const env of [{}, { CLAUDECODE: "1" }]) {
        const refused = await cli([...("CLAUDECODE" in env ? [] : ["--assisted"]), "run", ...args, "--", process.execPath, "-e", `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`], { env });
        expect(refused.code).toBe(64);
        expect(refused.stderr).toContain(`varlatch: ${flag} is refused in assisted mode: showing a Secret unmasked is the human's decision, for a named item, made in their own terminal.`);
        expect(refused.stderr).toContain(`  varlatch run -e development --allow-unmasked ${shown} -- <command>`);
        expect(existsSync(marker)).toBe(false);
      }
    }
    expect(requests.filter((r) => r.url.includes("/disclosures") || r.url.includes("/retrievals"))).toEqual([]);
    const both = await cli(["run", "--allow-unmasked", "PIN", "--no-redact", "--", "true"]);
    expect(both.code).toBe(64);
    expect(both.stderr).toMatch(/--allow-unmasked shows only the named items and keeps every other Secret masked; it cannot be combined with --no-redact/);
    const agentSafe = await cli(["--assisted", "run", "--agent-safe", "--no-redact", "--agent", "a", "--", "true"]);
    expect(agentSafe.code).toBe(64);
    expect(agentSafe.stderr).toMatch(/do not apply to --agent-safe runs/);
  });

  // A malformed unmasking option must not leave the list of names empty and
  // select a plain run, which masks nothing (review of #75: a missing name
  // printed every Secret raw).
  const malformed: [string, string[], RegExp][] = [
    ["no name before --", ["--allow-unmasked"], /--allow-unmasked needs an item's name: --allow-unmasked <NAME>/],
    ["the = spelling", ["--allow-unmasked=PIN"], /--allow-unmasked=\.\.\. is not supported; write --allow-unmasked <NAME>/],
    ["an option where the name goes", ["--allow-unmasked", "--strict"], /--allow-unmasked needs an item's name, not --strict/],
    ["a name no item can have", ["--allow-unmasked", "pin"], /--allow-unmasked needs an item's name, not pin/],
    ["--no-redact=", ["--no-redact=1"], /--no-redact=\.\.\. is not supported; write --no-redact/],
  ];
  const leaky = (marker: string) => [process.execPath, "-e", `require('fs').writeFileSync(${JSON.stringify(marker)}, ''); console.log(process.env.API_TOKEN, process.env.PIN)`];

  it.each(malformed)("a malformed unmasking option (%s) exits 64 before any request, in either mode, and the command never starts", async (_name, options, message) => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
    for (const mode of [[], ["--assisted"]]) {
      const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
      requests = [];
      const r = await cli([...mode, "run", ...options, "--", ...leaky(marker)]);
      expect(r.code, `${mode.join(" ")} ${r.stderr}`).toBe(64);
      expect(r.stderr).toMatch(message);
      expect(r.stderr).toContain("Nothing was started.");
      expect(requests).toEqual([]);
      expect(existsSync(marker)).toBe(false);
      expect(r.stdout + r.stderr).not.toContain(TOKEN);
      expect(r.stdout + r.stderr).not.toContain(PIN);
    }
  });

  it("control: the well-formed override, same child, makes its requests and starts, showing only PIN", async () => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
    const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
    const r = await cli(["run", "--allow-unmasked", "PIN", "--", ...leaky(marker)]);
    expect(r.code, r.stderr).toBe(0);
    expect(requests.length).toBeGreaterThan(0);
    expect(existsSync(marker)).toBe(true);
    expect(r.stdout).toContain(`[REDACTED:API_TOKEN] ${PIN}`);
  });

  it("the refusal's handoff keeps the run's policy: run as printed, a strict override still validates strictly", async () => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
    // Only LEGACY_KEY is inherited, and allowed: strict startup refuses any other inherited Secret.
    const refused = await cli(["--assisted", "run", "--strict", "--allow-inherited", "LEGACY_KEY", "--allow-unmasked", "PIN", "--", "true"], { env: { LEGACY_KEY: LEGACY } });
    expect(refused.code).toBe(64);
    const printed = /^ {2}(varlatch run .* -- <command>)$/m.exec(refused.stderr)?.[1];
    expect(printed).toBe("varlatch run -e development --strict --allow-inherited LEGACY_KEY --allow-unmasked PIN -- <command>");
    const human = (printed as string).split(" ").slice(1, -1);
    // With LEGACY_KEY inherited, as the agent's run had it: strict passes, PIN shown, every other Secret masked.
    const passes = await cli([...human, process.execPath, printer()], { env: { LEGACY_KEY: LEGACY } });
    expect(passes.code, passes.stderr).toBe(0);
    expect(passes.stderr).toContain(`pin=${PIN}`);
    expect(passes.stdout).toContain("legacy=[REDACTED:LEGACY_KEY]");
    expect(passes.stdout + passes.stderr).not.toContain(TOKEN);
    expect(passes.stdout + passes.stderr).not.toContain(LEGACY);
    // A strict violation (no active Contract) stops the printed command before it starts.
    noActiveContract = true;
    const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
    const stops = await cli([...human, ...leaky(marker)], { env: { LEGACY_KEY: LEGACY } });
    expect(stops.code).toBe(78);
    expect(stops.stderr).toMatch(/no active Contract/);
    expect(existsSync(marker)).toBe(false);
    // Control: the handoff with the policy dropped, as before this fix, starts the command.
    const weakened = await cli(["run", "-e", "development", "--allow-unmasked", "PIN", "--", ...leaky(marker)], { env: { LEGACY_KEY: LEGACY } });
    expect(weakened.code).toBe(0);
    expect(existsSync(marker)).toBe(true);
  });

  it("the refusal's handoff keeps --export-context, as the exit-78 remedy does", async () => {
    const refused = await cli(["--assisted", "run", "--export-context", "--no-redact", "--", "true"]);
    expect(refused.code).toBe(64);
    expect(refused.stderr).toContain("  varlatch run -e development --export-context --allow-unmasked <NAME> -- <command>");
  });
});

describe("run: a strict command line before --", () => {
  // Each exits 64 in every mode, before any request and before the command
  // starts, the nested agent-run case included (review of #75: a misspelled
  // `--allow-unmask PIN` gave a plain run that printed every Secret raw).
  const leaky = (marker: string) => [process.execPath, "-e", `require('fs').writeFileSync(${JSON.stringify(marker)}, ''); console.log(process.env.API_TOKEN, process.env.PIN)`];
  const malformed: [string, string[], RegExp][] = [
    ["the misspelled override (the review's reproduction)", ["--allow-unmask", "PIN"], /varlatch run: unknown option --allow-unmask/],
    ["an unknown option", ["--bogus"], /unknown option --bogus/],
    ["--json, which run does not take", ["--json"], /unknown option --json/],
    ["--environment=, which is not parsed", ["--environment=development"], /unknown option --environment=development/],
    ["-e without a value", ["-e"], /--environment needs a value/],
    ["--server followed by another option", ["--server", "--strict"], /--server needs a value/],
    ["-e and --environment both", ["-e", "development", "--environment", "development"], /--environment \(or -e\) given twice/],
    ["--strict twice", ["--strict", "--strict"], /--strict given twice/],
    ["--ttl twice", ["--agent-safe", "--agent", "a", "--ttl", "60", "--ttl", "60"], /--ttl given twice/],
    ["an argument before --", ["extra"], /unexpected argument extra/],
  ];
  const modes: [string, string[], Record<string, string>][] = [
    ["a human's run", [], {}],
    ["assisted", ["--assisted"], {}],
    ["a nested run inside an agent-safe run", [], { VARLATCH_AGENT_RUN: "run_0123456789abcdef" }],
  ];

  it.each(malformed)("%s: exit 64, no request, nothing started, in every mode", async (_name, options, message) => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
    for (const [mode, flags, env] of modes) {
      const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
      requests = [];
      const r = await cli([...flags, "run", ...options, "--", ...leaky(marker)], { env });
      expect(r.code, `${mode}: ${r.stderr}`).toBe(64);
      expect(r.stderr, mode).toMatch(message);
      expect(r.stderr, mode).not.toMatch(/inside agent-safe run/);
      expect(requests, mode).toEqual([]);
      expect(existsSync(marker), mode).toBe(false);
      expect(r.stdout + r.stderr).not.toContain(TOKEN);
      expect(r.stdout + r.stderr).not.toContain(PIN);
    }
  });

  it("control: the intended override, same child, starts and masks every Secret but PIN", async () => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
    const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
    const r = await cli(["run", "--allow-unmasked", "PIN", "--", ...leaky(marker)]);
    expect(r.code, r.stderr).toBe(0);
    expect(existsSync(marker)).toBe(true);
    expect(r.stdout).toContain(`[REDACTED:API_TOKEN] ${PIN}`);
  });

  it("the command's own arguments after -- reach it unchanged: a default, assisted, strict, and nested run", async () => {
    const argv = join(dir, `argv-${Math.random().toString(36).slice(2)}.cjs`);
    writeFileSync(argv, "console.log(JSON.stringify(process.argv.slice(2)));\n");
    const childArgs = ["--bogus", "--allow-unmask", "PIN", "-e", "x", "--strict", "--strict", "extra", "--", "--no-redact"];
    for (const [name, args, env] of [
      ["default", ["run", "-e", "development"], {}],
      ["assisted", ["--assisted", "run", "--environment", "development"], {}],
      ["strict", ["run", "--strict", "--allow-inherited", "LEGACY_KEY"], { LEGACY_KEY: LEGACY }],
      ["nested", ["run"], { VARLATCH_AGENT_RUN: "run_0123456789abcdef" }],
    ] as [string, string[], Record<string, string>][]) {
      const r = await cli([...args, "--", process.execPath, argv, ...childArgs], { env });
      expect(r.code, `${name}: ${r.stderr}`).toBe(0);
      expect(JSON.parse(r.stdout.trim().split("\n").at(-1) as string), name).toEqual(childArgs);
    }
  });

  it("every documented option is accepted, repeatable ones repeated", async () => {
    const r = await cli(["run", "-e", "development", "--server", origin, "--export-context", "--redact", "--", "true"]);
    expect(r.code, r.stderr).toBe(0);
    stored.push({ name: "PIN", sensitive: true, value: PIN }, { name: "PIN_TWO", sensitive: true, value: "abcdefg" });
    const two = await cli(["run", "--strict", "--allow-inherited", "LEGACY_KEY", "--allow-inherited", "PORT", "--allow-unmasked", "PIN", "--allow-unmasked", "PIN_TWO", "--", "true"], { env: { LEGACY_KEY: LEGACY } });
    expect(two.code, two.stderr).toBe(0);
    expect(two.stderr).toContain("varlatch: showing PIN, PIN_TWO unmasked in this run only");
  });
});

describe("assisted run: notices before the command starts", () => {
  const run = (flags: string[], env: Record<string, string> = {}) => cli([...flags, "run", "--", process.execPath, "-e", "console.log(process.env.API_TOKEN ? 'configured' : 'started')"], { env });

  it("no stored values is said as a fact; the command still gets what it inherits, and may be configured", async () => {
    stored = [];
    const r = await run(["--assisted"], { API_TOKEN: "inherited-token-value-31" });
    expect(r.code).toBe(0);
    // Configured from the inherited variable: the notice must not say otherwise.
    expect(r.stdout).toContain("configured");
    expect(r.stderr).toContain(`varlatch: no values are stored in Varlatch for development; ${process.execPath} gets only the variables it inherits.`);
    expect(r.stderr).not.toMatch(/without its configuration|not success/);
    stored = defaultItems();
    const withValues = await run(["--assisted"]);
    expect(withValues.stderr).not.toMatch(/no values are stored in Varlatch/);
  });

  it("a .env file is named as existing, never read, with no claim about what Varlatch has, and the value-free comparison", async () => {
    const file = join(repo, ".env");
    writeFileSync(file, "DOTENV_CANARY=dotenv-content-never-read-58\n");
    try {
      const r = await run(["--assisted"]);
      expect(r.code).toBe(0);
      expect(r.stderr).toContain(
        "varlatch: .env exists and is not read by Varlatch, which cannot tell whether its values are stored already (or older copies). To compare names, without values: varlatch --assisted import .env -e development --dry-run --json",
      );
      expect(r.stderr).not.toMatch(/not in Varlatch yet|move them in|once moved in/);
      expect(r.stdout + r.stderr).not.toContain("dotenv-content-never-read-58");
      // Not in assisted mode: no notices, the human's output is unchanged.
      stored = [];
      const plain = await run([]);
      expect(plain.stderr).not.toMatch(/is not read by Varlatch|no values are stored/);
    } finally {
      rmSync(file, { force: true });
    }
    const none = await run(["--assisted"]);
    expect(none.stderr).not.toMatch(/is not read by Varlatch/);
  });
});

describe("init in a repository that is already set up", () => {
  it("says so and names the next steps, assisted forms in assisted mode", async () => {
    const assisted = await cli(["--assisted", "init"]);
    expect(assisted.code).toBe(1);
    expect(assisted.stderr).toMatch(/varlatch\.toml already exists at .*: this repository is already set up for Varlatch, so there is nothing to initialize\./);
    expect(assisted.stderr).toContain("To compare a .env file's names with what Varlatch has, without values: varlatch --assisted import .env --dry-run --json");
    expect(assisted.stderr).toContain("To see whether an environment is ready: varlatch --assisted validate -e <environment> --json");
    const plain = await cli(["init"]);
    expect(plain.code).toBe(1);
    expect(plain.stderr).toContain("varlatch import .env --dry-run");
    expect(plain.stderr).not.toContain("--assisted");
  });
});

describe("assisted run: a value too short to mask", () => {
  beforeEach(() => {
    stored.push({ name: "PIN", sensitive: true, value: PIN });
  });

  it.each([
    ["a default run", []],
    ["a strict run", ["--strict"]],
  ])("%s exits 78 naming the item, before the command starts", async (_name, mode) => {
    const marker = join(dir, `started-${Math.random().toString(36).slice(2)}`);
    const r = await cli(["--assisted", "run", ...mode, "--", process.execPath, printer()], { env: { MARKER: marker } });
    expect(r.code).toBe(78);
    expect(r.stderr).toMatch(/shorter than 8 bytes, so its value cannot be masked in the command's output: PIN/);
    // First stop and ask; each remedy is the human's decision, for this item only.
    expect(r.stderr).toMatch(/Stop and ask the human what to do about PIN\. Approval for one item or action never covers another\./);
    // After approval, the replacement is the agent's own command, with --assisted and --replace.
    expect(r.stderr).toMatch(/Only if they approve replacing PIN with a new random value \(it overwrites the current one\):\n {6}varlatch --assisted values set PIN -e development --replace PIN --generate hex:32\n/);
    expect(r.stderr).not.toMatch(/^\s*varlatch values set PIN .*--generate/m);
    // The human's override: outside assisted mode (no --assisted), the option before `--`.
    expect(r.stderr).toMatch(new RegExp(`Showing it unmasked is the human's alone, in their own terminal .*\\n {6}varlatch run -e development ${mode.length > 0 ? "--strict " : ""}--allow-unmasked PIN -- <command>`));
    expect(r.stderr).not.toMatch(/varlatch --assisted run/);
    expect(r.stderr).toMatch(/Nothing was started\./);
    expect(existsSync(marker)).toBe(false);
    expect(r.stdout + r.stderr).not.toContain(PIN);
  });

  it("the human's override, run exactly as the refusal prints it, shows only PIN: every other known Secret, inherited ones included, stays masked", async () => {
    const refused = await cli(["--assisted", "run", "--", process.execPath, printer()]);
    const printed = /^ {6}(varlatch run -e development --allow-unmasked PIN -- <command>)$/m.exec(refused.stderr)?.[1];
    expect(printed, refused.stderr).toBeDefined();
    // The human's terminal: no --assisted, no marker.
    const args = (printed as string).split(" ").slice(1, -1).concat([process.execPath, printer()]);
    const r = await cli(args, { env: INHERITED });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain("varlatch: showing PIN unmasked in this run only, if too short to mask; every other known Secret stays masked.");
    expect(r.stderr).toContain(`pin=${PIN}`);
    expect(r.stdout).toContain("token=[REDACTED:API_TOKEN]");
    expect(r.stdout).toContain("legacy=[REDACTED:LEGACY_KEY]");
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
    expect(r.stdout + r.stderr).not.toContain(LEGACY);
  });

  it("a default run's remedy keeps --export-context: run as printed, the command gets its run context", async () => {
    const r = await cli(["--assisted", "run", "--export-context", "--", process.execPath, printer()]);
    expect(r.code, r.stderr).toBe(78);
    const printed = /^ {6}(varlatch run .* -- <command>)$/m.exec(r.stderr)?.[1];
    expect(printed).toBe("varlatch run -e development --export-context --allow-unmasked PIN -- <command>");
    const human = await cli([...(printed as string).split(" ").slice(1, -1), process.execPath, "-e", "console.log(process.env.VARLATCH_RUN_CONTEXT ? 'run context given' : 'no run context')"]);
    expect(human.code, human.stderr).toBe(0);
    expect(human.stdout).toContain("run context given");
  });

  it("the human's override names one item: another short Secret still stops the run", async () => {
    stored.push({ name: "PIN_TWO", sensitive: true, value: "abcdefg" });
    const r = await cli(["run", "--allow-unmasked", "PIN", "--", process.execPath, printer()]);
    expect(r.code).toBe(78);
    expect(r.stderr).toMatch(/shorter than 8 bytes, so its value cannot be masked in the command's output: PIN_TWO/);
    expect(r.stdout + r.stderr).not.toContain("abcdefg");
  });

  it("negative control, same input: outside assisted mode the run starts and prints the value", async () => {
    const r = await cli(["run", "--", process.execPath, printer()]);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain(`pin=${PIN}`);
  });
});

// util-linux `script` gives the command a pseudo-terminal; skipped where none can be allocated.
const hasScript = spawnSync("script", ["-qec", "true", "/dev/null"]).status === 0;
const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

function underTerminal(args: string[], extra: Record<string, string> = {}, input?: { after: string; text: string }): Promise<{ code: number | null; terminal: string }> {
  return new Promise((resolve) => {
    const command = [process.execPath, bundle, ...args].map(shellQuote).join(" ");
    const child = spawn("script", ["-qec", command, "/dev/null"], { cwd: repo, env: { ...baseEnv(extra), SHELL: "/bin/sh" }, stdio: ["pipe", "pipe", "pipe"] });
    let terminal = "";
    let typed = false;
    child.stdout.on("data", (d: Buffer) => {
      terminal += d.toString();
      if (input && !typed && terminal.includes(input.after)) {
        typed = true;
        // The prompt switched the terminal to raw mode before it was written.
        setTimeout(() => child.stdin.write(input.text), 100);
      }
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, terminal });
    });
  });
}

describe.skipIf(!hasScript)("assisted run on a pseudo-terminal", () => {
  it("the command gets pipes and its output is masked", async () => {
    const { code, terminal } = await underTerminal(["--assisted", "run", "--", process.execPath, printer()], INHERITED);
    expect(code).toBe(0);
    expect(terminal).toContain("tty=false");
    expect(terminal).toContain("token=[REDACTED:API_TOKEN]");
    expect(terminal).not.toContain(TOKEN);
    expect(terminal).not.toContain(LEGACY);
  });

  it("an explicit --redact is not refused in assisted mode on a terminal", async () => {
    const { code, terminal } = await underTerminal(["--assisted", "run", "--redact", "--", process.execPath, printer()]);
    expect(code).toBe(0);
    expect(terminal).toContain("token=[REDACTED:API_TOKEN]");
  });

  it("negative control, same input: with --no-redact the command keeps the terminal and its output is not masked", async () => {
    const { code, terminal } = await underTerminal(["run", "--no-redact", "--", process.execPath, printer()], INHERITED);
    expect(code).toBe(0);
    expect(terminal).toContain("tty=true");
    expect(terminal).toContain(TOKEN);
  });

  it("values set without a value prompts with hidden input outside assisted mode", async () => {
    const hidden = "typed-hidden-value-5521";
    const { code, terminal } = await underTerminal(["values", "set", "API_TOKEN"], {}, { after: "(input hidden): ", text: `${hidden}\r` });
    expect(code).toBe(0);
    expect(terminal).toContain("API_TOKEN set (version ver_new_API_TOKEN).");
    expect(terminal).not.toContain(hidden);
    expect(requests.find((r) => r.method === "PUT")?.body).toEqual({ value: hidden });
  });

  it("Backspace after an astral character stores the exact remaining value, and arrow keys are ignored", async () => {
    const { code, terminal } = await underTerminal(["values", "set", "API_TOKEN"], {}, { after: "(input hidden): ", text: "abcdefgh😀\u007f\u001b[Dij\r" });
    expect(code).toBe(0);
    expect(terminal).toContain("API_TOKEN set (version ver_new_API_TOKEN).");
    expect(requests.find((r) => r.method === "PUT")?.body).toEqual({ value: "abcdefghij" });
  });
});

describe("values set and values rotate: Secret input", () => {
  const puts = () => requests.filter((r) => r.method === "PUT");

  it.each([
    ["--assisted", ["--assisted"], {}],
    ["the CLAUDECODE marker", [], { CLAUDECODE: "1" }],
  ] as const)("%s refuses a Secret's value on the command line, storing nothing and never echoing it", async (_name, flags, env) => {
    for (const item of ["API_TOKEN", "UNCONTRACTED_ITEM"]) {
      // API_TOKEN exists: the replacement is named, so this checks the command-line refusal.
      const r = await cli([...flags, "values", "set", item, ...(item === "API_TOKEN" ? ["--replace", "API_TOKEN"] : []), "argv-secret-value-771"], { env });
      expect(r.code).toBe(64);
      expect(r.stderr).toMatch(new RegExp(`${item} is a Secret, and in assisted mode a Secret's value is never taken from the command line`));
      expect(r.stderr).toMatch(/--generate hex:32/);
      expect(r.stderr).toMatch(/in their own terminal/);
      expect(r.stdout + r.stderr).not.toContain("argv-secret-value-771");
    }
    expect(puts()).toEqual([]);
  });

  it("accepts a non-sensitive value on the command line in assisted mode", async () => {
    const r = await cli(["--assisted", "values", "set", "PORT", "--replace", "PORT", "9090"]);
    expect(r.code).toBe(0);
    expect(puts().map((p) => p.body)).toEqual([{ value: "9090" }]);
  });

  it.each([
    ["no option, setting, or marker", {}],
    ["a marker with VARLATCH_ASSISTED=0", { VARLATCH_ASSISTED: "0", CLAUDECODE: "1" }],
  ] as const)("negative control, same input: %s stores the command-line value", async (_name, env) => {
    const r = await cli(["values", "set", "API_TOKEN", "argv-secret-value-771"], { env });
    expect(r.code).toBe(0);
    expect(puts().map((p) => p.body)).toEqual([{ value: "argv-secret-value-771" }]);
  });

  it("--stdin, --from-file, and --generate store the value without printing it", async () => {
    const file = join(dir, "secret.txt");
    writeFileSync(file, "from-file-value-39\n");
    const viaStdin = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN", "--stdin"], { input: "from-stdin-value-18\n" });
    const viaFile = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN", "--from-file", file]);
    const viaGenerate = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN", "--generate", "hex:32"]);
    for (const r of [viaStdin, viaFile, viaGenerate]) expect(r.code).toBe(0);
    const [a, b, c] = puts().map((p) => (p.body as { value: string }).value);
    expect([a, b]).toEqual(["from-stdin-value-18", "from-file-value-39"]);
    expect(c).toMatch(/^[0-9a-f]{64}$/);
    expect(viaGenerate.stdout).toBe("API_TOKEN set (version ver_new_API_TOKEN) to a generated value (hex, 32 random bytes; not shown).\n");
    for (const r of [viaStdin, viaFile, viaGenerate]) {
      expect(r.stdout + r.stderr).not.toMatch(/from-stdin-value-18|from-file-value-39/);
      expect(r.stdout + r.stderr).not.toContain(c);
    }
  });

  it("values rotate takes the same sources", async () => {
    const r = await cli(["--assisted", "values", "rotate", "API_TOKEN", "--replace", "API_TOKEN", "--stdin", "--grace", "60"], { input: "rotated-value-202\n" });
    expect(r.code).toBe(0);
    expect(requests.find((q) => q.url.endsWith("/rotations"))?.body).toEqual({ value: "rotated-value-202", graceSeconds: 60 });
    expect(r.stdout + r.stderr).not.toContain("rotated-value-202");
    const refused = await cli(["--assisted", "values", "rotate", "API_TOKEN", "--replace", "API_TOKEN", "argv-rotated-9"]);
    expect(refused.code).toBe(64);
    expect(refused.stderr).toMatch(/values rotate API_TOKEN -e development --generate hex:32/);
  });

  it("with no value: assisted mode never prompts; otherwise a non-terminal is told how to give one", async () => {
    const assisted = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN"]);
    expect(assisted.code).toBe(64);
    expect(assisted.stderr).toMatch(/assisted mode never prompts/);
    const plain = await cli(["values", "set", "API_TOKEN"]);
    expect(plain.code).toBe(64);
    expect(plain.stderr).toMatch(/Pass --stdin, --from-file <path>, or --generate <spec>/);
    expect(puts()).toEqual([]);
  });

  /** The command the refusal hands to the human: the line after "...or to use the dashboard:". */
  const handoff = (stderr: string) => /use the dashboard:\n {4}(varlatch values .+)\n/.exec(stderr)?.[1];

  it("the handoff names the environment, with or without -e, and never adds --assisted", async () => {
    const production = await cli(["--assisted", "values", "set", "STRIPE_KEY", "-e", "production"]);
    expect(production.code).toBe(64);
    expect(handoff(production.stderr)).toBe("varlatch values set STRIPE_KEY -e production");
    const byDefault = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN"]);
    // Without -e the command still names the environment it resolved, so it works anywhere.
    expect(handoff(byDefault.stderr)).toBe("varlatch values set API_TOKEN -e development");
    expect(production.stderr).toMatch(/values set STRIPE_KEY -e production --generate hex:32/);
    expect(puts()).toEqual([]);
  });

  it("the AGENTS.md handoff, run as written in the human's terminal, prompts and stores the value in that environment", async () => {
    const written = /```text\n  (varlatch values set <NAME> -e <environment>)\n  ```/.exec(agentsBlock())?.[1];
    expect(written).toBe("varlatch values set <NAME> -e <environment>");
    const args = (written as string).replace("<NAME>", "STRIPE_KEY").replace("<environment>", "production").split(" ").slice(1);
    const { code, terminal } = await underTerminal(args, {}, { after: "(input hidden): ", text: "typed-by-human-56\r" });
    expect(code).toBe(0);
    expect(terminal).not.toContain("typed-by-human-56");
    expect(puts()).toEqual([
      expect.objectContaining({ url: "/v1/organizations/acme/projects/web/environments/production/values/STRIPE_KEY", body: { value: "typed-by-human-56" } }),
    ]);
  });

  it("the handoff, run as printed in the human's terminal, prompts and stores the value in that environment", async () => {
    const refused = await cli(["--assisted", "values", "set", "STRIPE_KEY", "-e", "production"]);
    const printed = handoff(refused.stderr);
    expect(printed).toBeDefined();
    const args = printed!.split(" ").slice(1);
    const { code, terminal } = await underTerminal(args, {}, { after: "(input hidden): ", text: "typed-by-human-55\r" });
    expect(code).toBe(0);
    expect(terminal).not.toContain("typed-by-human-55");
    expect(puts()).toEqual([
      expect.objectContaining({ url: "/v1/organizations/acme/projects/web/environments/production/values/STRIPE_KEY", body: { value: "typed-by-human-55" } }),
    ]);
    // Control: the same command with --assisted added, as agents handed it over in the evaluation, stores nothing.
    requests = [];
    const assisted = await cli(["--assisted", ...args]);
    expect(assisted.code).toBe(64);
    expect(puts()).toEqual([]);
  });

  it("refuses two sources and weak generators", async () => {
    const two = await cli(["values", "set", "API_TOKEN", "v", "--stdin"]);
    expect(two.stderr).toMatch(/one way only/);
    const weak = await cli(["values", "set", "API_TOKEN", "--generate", "hex:4"]);
    expect(weak.stderr).toMatch(/from 16 to 4096 bytes/);
    expect(puts()).toEqual([]);
  });
});

describe("values set and values rotate in assisted mode: replacing an existing value needs --replace <ITEM>", () => {
  const writes = () => requests.filter((r) => r.method === "PUT" || r.url.endsWith("/rotations"));

  it("refused (78) before any value is read, prompted for, generated, or written: from a file, from stdin, or generated", async () => {
    const missingFile = join(dir, "does-not-exist.txt");
    for (const source of [["--from-file", missingFile], ["--stdin"], ["--generate", "hex:32"]]) {
      const r = await cli(["--assisted", "values", "set", "API_TOKEN", ...source], { input: "stdin-value-never-read-66\n" });
      expect(r.code, source.join(" ")).toBe(78);
      // The file is never opened: no "cannot read" error, only the replacement refusal.
      expect(r.stderr).toContain("varlatch values set: API_TOKEN already has a value in development; setting it replaces that value. Replacing it is the human's decision, for this item only: ask them, and with their approval add --replace API_TOKEN. Nothing was stored.");
      expect(r.stderr).not.toMatch(/cannot read|never prompts/);
    }
    const rotate = await cli(["--assisted", "values", "rotate", "API_TOKEN", "--generate", "hex:32"]);
    expect(rotate.code).toBe(78);
    expect(rotate.stderr).toMatch(/varlatch values rotate: API_TOKEN already has a value in development; rotating it replaces that value\./);
    expect(writes()).toEqual([]);
  });

  it("a wrong command line is reported first (64), before the existence check: with or without a credential, existing or not", async () => {
    const forms: [string[], RegExp][] = [
      [["set", "API_TOKEN", "--stdin", "--generate", "hex:32"], /give the value one way only/],
      [["set", "API_TOKEN", "--generate", "nonsense"], /--generate expects hex:<bytes>/],
      [["set", "API_TOKEN", "--generate", "hex:4"], /from 16 to 4096 bytes/],
      [["set", "API_TOKEN", "value-and-file", "--from-file", "x"], /give the value one way only/],
      [["rotate", "API_TOKEN", "--stdin", "--from-file", "x"], /give the value one way only/],
      [["set", "BRAND_NEW_ITEM", "--generate", "alnum:5"], /from 22 to 4096 characters/],
      // No value in assisted mode: there is no prompt, whatever the server has.
      [["set", "API_TOKEN"], /assisted mode never prompts/],
    ];
    for (const [args, message] of forms) {
      for (const env of [{}, { VARLATCH_TOKEN: "" }]) {
        requests = [];
        const r = await cli(["--assisted", "values", ...args], { env, input: "stdin-value-never-read-67\n" });
        expect(r.code, `${args.join(" ")} ${JSON.stringify(env)}: ${r.stderr}`).toBe(64);
        expect(r.stderr).toMatch(message);
        expect(requests).toEqual([]);
      }
    }
    // Control: without a credential, a well-formed command gets as far as the server (77), so the forms above were refused first.
    const signedOut = await cli(["--assisted", "values", "set", "API_TOKEN", "--generate", "hex:32"], { env: { VARLATCH_TOKEN: "" } });
    expect(signedOut.code).toBe(77);
    expect(writes()).toEqual([]);
  });

  it("a value inherited from the parent environment counts as existing: overriding it in the child needs --replace", async () => {
    const refused = await cli(["--assisted", "values", "set", "API_TOKEN", "-e", "preview", "--generate", "hex:32"]);
    expect(refused.code).toBe(78);
    expect(refused.stderr).toContain(
      "varlatch values set: preview inherits a value for API_TOKEN from its parent environment; setting it here overrides that value in preview. Replacing it is the human's decision, for this item only: ask them, and with their approval add --replace API_TOKEN. Nothing was stored.",
    );
    expect(writes()).toEqual([]);
    const approved = await cli(["--assisted", "values", "set", "API_TOKEN", "-e", "preview", "--replace", "API_TOKEN", "--generate", "hex:32"]);
    expect(approved.code, approved.stderr).toBe(0);
    expect(writes().map((w) => w.url)).toEqual(["/v1/organizations/acme/projects/web/environments/preview/values/API_TOKEN"]);
    // An item the parent does not have is new in the child too: no approval needed.
    const fresh = await cli(["--assisted", "values", "set", "BRAND_NEW_ITEM", "-e", "preview", "--generate", "hex:32"]);
    expect(fresh.code, fresh.stderr).toBe(0);
  });

  it("with --replace naming the item it proceeds; --replace naming another item is a usage error; a new item needs none", async () => {
    const approved = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "API_TOKEN", "--generate", "hex:32"]);
    expect(approved.code, approved.stderr).toBe(0);
    requests = [];
    const other = await cli(["--assisted", "values", "set", "API_TOKEN", "--replace", "PORT", "--generate", "hex:32"]);
    expect(other.code).toBe(64);
    expect(other.stderr).toMatch(/--replace names PORT, but this command sets API_TOKEN; approval for one item never covers another\./);
    expect(requests).toEqual([]);
    const fresh = await cli(["--assisted", "values", "set", "BRAND_NEW_ITEM", "--generate", "hex:32"]);
    expect(fresh.code, fresh.stderr).toBe(0);
  });

  it("when the server cannot say whether the item exists, it counts as existing", async () => {
    denyEffective = true;
    const unknown = await cli(["--assisted", "values", "set", "BRAND_NEW_ITEM", "--generate", "hex:32"]);
    expect(unknown.code).toBe(78);
    expect(unknown.stderr).toMatch(/whether BRAND_NEW_ITEM already has a value in development cannot be checked \(403 PERMISSION_DENIED\), so it counts as existing\./);
    expect(writes()).toEqual([]);
    const approved = await cli(["--assisted", "values", "set", "BRAND_NEW_ITEM", "--replace", "BRAND_NEW_ITEM", "--generate", "hex:32"]);
    expect(approved.code, approved.stderr).toBe(0);
  });

  it("run 3's sequence: with approval for REDIS_PASSWORD only, regenerating LOG_LEVEL is refused and LOG_LEVEL is kept", async () => {
    stored.push({ name: "REDIS_PASSWORD", sensitive: true, value: "r3d1s7x" }, { name: "LOG_LEVEL", sensitive: true, value: "debug" });
    const redis = await cli(["--assisted", "values", "set", "REDIS_PASSWORD", "-e", "development", "--replace", "REDIS_PASSWORD", "--generate", "hex:32"]);
    expect(redis.code, redis.stderr).toBe(0);
    const log = await cli(["--assisted", "values", "set", "LOG_LEVEL", "-e", "development", "--generate", "hex:32"]);
    expect(log.code).toBe(78);
    expect(log.stderr).toMatch(/LOG_LEVEL already has a value in development/);
    expect(stored.find((i) => i.name === "LOG_LEVEL")?.value).toBe("debug");
    expect(requests.filter((r) => r.method === "PUT").map((r) => r.url.split("/").at(-1))).toEqual(["REDIS_PASSWORD"]);
  });

  it("outside assisted mode nothing changes: no check, the value is replaced", async () => {
    const r = await cli(["values", "set", "API_TOKEN", "--generate", "hex:32"]);
    expect(r.code, r.stderr).toBe(0);
    expect(requests.some((q) => q.url.includes("/effective-configuration"))).toBe(false);
    expect(writes()).toHaveLength(1);
  });
});

describe("values delete: in assisted mode, every deletion needs the item named with --confirm", () => {
  const deletes = () => requests.filter((r) => r.method === "DELETE");
  const value = (name: string) => stored.find((i) => i.name === name)?.value;

  it.each([
    ["a Secret", "API_TOKEN"],
    ["a plain value (sensitivity is not consulted)", "PORT"],
    ["an item with no value (existence is not consulted)", "NO_SUCH_ITEM"],
  ])("%s without --confirm: 78 before any request, nothing deleted, the handoff keeps the environment", async (_name, item) => {
    for (const env of [{}, { CLAUDECODE: "1" }]) {
      requests = [];
      const before = value(item);
      const r = await cli([...("CLAUDECODE" in env ? [] : ["--assisted"]), "values", "delete", item, "-e", "development"], { env });
      expect(r.code, r.stderr).toBe(78);
      expect(r.stderr).toContain(
        `varlatch values delete: deleting ${item} from development is the human's decision, for this item in this environment. Ask them, and with their approval for ${item} in development, add --confirm ${item}. Or the human runs, in their own terminal:\n  varlatch values delete ${item} -e development\nNothing was deleted.`,
      );
      expect(requests).toEqual([]);
      expect(value(item)).toBe(before);
    }
  });

  it("an unconfirmed delete-and-recreate leaves the original value intact", async () => {
    const del = await cli(["--assisted", "values", "delete", "API_TOKEN"]);
    expect(del.code).toBe(78);
    const set = await cli(["--assisted", "values", "set", "API_TOKEN", "--generate", "hex:32"]);
    expect(set.code).toBe(78);
    expect(value("API_TOKEN")).toBe(TOKEN);
    expect(requests.filter((r) => r.method !== "GET")).toEqual([]);
  });

  it("a confirmation naming another item is refused (64), before any request", async () => {
    for (const flags of [["--assisted"], []]) {
      requests = [];
      const r = await cli([...flags, "values", "delete", "API_TOKEN", "--confirm", "PORT"]);
      expect(r.code).toBe(64);
      expect(r.stderr).toMatch(/--confirm names PORT, but this command deletes API_TOKEN; approval for one item never covers another\./);
      expect(requests).toEqual([]);
      expect(value("API_TOKEN")).toBe(TOKEN);
    }
  });

  it("with the human's approval, --confirm naming the item deletes it, in that environment only", async () => {
    const r = await cli(["--assisted", "values", "delete", "API_TOKEN", "-e", "development", "--confirm", "API_TOKEN"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("API_TOKEN deleted from development.");
    expect(deletes().map((d) => d.url)).toEqual(["/v1/organizations/acme/projects/web/environments/development/values/API_TOKEN"]);
    expect(value("API_TOKEN")).toBeUndefined();
    expect(value("PORT")).toBe("8080");
  });

  it("the handoff keeps an overridden server, and run as printed in the human's terminal deletes that environment's value", async () => {
    const refused = await cli(["--assisted", "values", "delete", "PORT", "-e", "production", "--server", origin]);
    expect(refused.code).toBe(78);
    const printed = /^ {2}(varlatch values delete .*)$/m.exec(refused.stderr)?.[1];
    expect(printed).toBe(`varlatch values delete PORT -e production --server ${origin}`);
    requests = [];
    const human = await cli((printed as string).split(" ").slice(1));
    expect(human.code, human.stderr).toBe(0);
    expect(deletes().map((d) => d.url)).toEqual(["/v1/organizations/acme/projects/web/environments/production/values/PORT"]);
  });

  it("outside assisted mode a deletion needs no confirmation, as before", async () => {
    const r = await cli(["values", "delete", "API_TOKEN"]);
    expect(r.code, r.stderr).toBe(0);
    expect(value("API_TOKEN")).toBeUndefined();
  });

  it.each([
    ["an unknown option (the --env typo)", ["--env", "production"], /unknown option --env/],
    ["--environment=, which is not parsed", ["--environment=production"], /unknown option --environment=production/],
    ["--confirm=, which is not parsed", ["--confirm=API_TOKEN"], /unknown option --confirm=API_TOKEN/],
    ["--confirm without a value", ["--confirm"], /--confirm needs a value/],
    ["--confirm twice", ["--confirm", "API_TOKEN", "--confirm", "API_TOKEN"], /--confirm given twice/],
    ["-e and --environment both", ["-e", "development", "--environment", "development"], /--environment \(or -e\) given twice/],
    ["an extra argument", ["extra"], /unexpected argument extra/],
  ])("a wrong command line, %s: 64 in either mode, before any request", async (_name, extra, message) => {
    for (const flags of [["--assisted"], []]) {
      requests = [];
      const r = await cli([...flags, "values", "delete", "API_TOKEN", ...extra]);
      expect(r.code, `${flags.join(" ")} ${r.stderr}`).toBe(64);
      expect(r.stderr).toMatch(message);
      expect(requests).toEqual([]);
      expect(value("API_TOKEN")).toBe(TOKEN);
    }
  });

  it("no item is a usage error", async () => {
    const r = await cli(["values", "delete"]);
    expect(r.code).toBe(64);
    expect(requests).toEqual([]);
  });
});

describe("values set and values rotate: a strict command line", () => {
  // Each exits 64 before anything is read, prompted, or written: no request
  // reaches the server. Before, `values set STRIPE_KEY --env production` in
  // a terminal stored the literal "--env" in the default environment.
  const both: [string, string[], RegExp][] = [
    ["an unknown option", ["--env", "production"], /unknown option --env/],
    ["--environment=, which is not parsed", ["--environment=production"], /unknown option --environment=production/],
    ["--json, which these commands do not take", ["--json"], /unknown option --json/],
    ["-e without a value", ["-e"], /--environment needs a value/],
    ["--from-file without a path", ["--from-file"], /--from-file needs a value/],
    ["--generate without a spec", ["--generate"], /--generate needs a value/],
    ["--server followed by another option", ["--server", "--stdin"], /--server needs a value/],
    ["-e and --environment both", ["-e", "production", "--environment", "development"], /--environment \(or -e\) given twice/],
    ["-e twice", ["-e", "development", "-e", "development"], /--environment \(or -e\) given twice/],
    ["--from-file twice", ["--from-file", "a", "--from-file", "b"], /--from-file given twice/],
    ["an extra argument", ["value", "extra"], /unexpected argument extra/],
    ["a value that begins with a dash, before --", ["-x9-value"], /unknown option -x9-value \(a value that begins with "-" goes after --\)/],
  ];
  const cases: [string, string, string[], RegExp][] = [
    ...both.flatMap(([name, extra, message]): [string, string, string[], RegExp][] => [["set", name, extra, message], ["rotate", name, extra, message]]),
    ["rotate", "--grace without a value", ["--grace"], /--grace needs a value/],
    ["rotate", "--grace that is not a number", ["--grace", "soon"], /--grace needs a whole number of seconds, not soon/],
    ["rotate", "--grace twice", ["--grace", "60", "--grace", "60"], /--grace given twice/],
    ["set", "--grace, which only rotate takes", ["--grace", "60"], /unknown option --grace/],
  ];

  it.each(cases)("values %s, %s: assisted, exit 64 and nothing sent", async (sub, _name, extra, message) => {
    const r = await cli(["--assisted", "values", sub, "API_TOKEN", ...extra]);
    expect(r.code).toBe(64);
    expect(r.stderr).toMatch(message);
    expect(requests).toEqual([]);
  });

  describe.skipIf(!hasScript)("in the human's terminal", () => {
    it.each(cases)("values %s, %s: exit 64 without a prompt, and nothing sent", async (sub, _name, extra, message) => {
      const { code, terminal } = await underTerminal(["values", sub, "API_TOKEN", ...extra], {}, { after: "(input hidden): ", text: "typed-after-a-typo-91\r" });
      expect(code).toBe(64);
      expect(terminal).toMatch(message);
      expect(terminal).not.toContain("(input hidden)");
      expect(requests).toEqual([]);
    });
  });

  it("the documented forms still work: options on either side of the value, -- before a value that begins with a dash, rotate's --grace", async () => {
    expect((await cli(["--assisted", "values", "set", "PORT", "-e", "development", "--replace", "PORT", "9090"])).code).toBe(0);
    expect((await cli(["values", "set", "PORT", "--", "-1"])).code).toBe(0);
    expect((await cli(["--assisted", "values", "set", "API_TOKEN", "--environment", "development", "--replace", "API_TOKEN", "--stdin"], { input: "from-stdin-value-27\n" })).code).toBe(0);
    expect(requests.filter((r) => r.method === "PUT").map((r) => r.body)).toEqual([{ value: "9090" }, { value: "-1" }, { value: "from-stdin-value-27" }]);
    const rotated = await cli(["--assisted", "values", "rotate", "API_TOKEN", "--grace", "60", "--replace", "API_TOKEN", "--stdin"], { input: "rotated-value-303\n" });
    expect(rotated.code).toBe(0);
    expect(requests.find((r) => r.url.endsWith("/rotations"))?.body).toEqual({ value: "rotated-value-303", graceSeconds: 60 });
  });
});

describe("varlatch import", () => {
  const ENV_FILE = [
    "# local development",
    "API_TOKEN=import-token-canary-11",
    'DATABASE_URL="postgres://app:db-password-canary@localhost/app"',
    "PORT=3000",
    "DEBUG=true",
    "NEW_SECRET='new-secret-canary-42'",
    "",
  ].join("\n");
  const VALUES = ["import-token-canary-11", "db-password-canary", "new-secret-canary-42"];
  const noValues = (r: Result) => {
    for (const v of VALUES) expect(r.stdout + r.stderr).not.toContain(v);
  };
  function envFile(content = ENV_FILE): string {
    const file = join(dir, `.env-${Math.random().toString(36).slice(2)}`);
    writeFileSync(file, content);
    return file;
  }
  const puts = () => requests.filter((r) => r.method === "PUT");

  it("--dry-run lists names, inferred types, and sensitivity, and stores nothing", async () => {
    const r = await cli(["--assisted", "import", envFile(), "--dry-run"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Dry run: would import 5 value\(s\) \(4 secret, 1 plain\) from .* into acme\/web \(development\):/);
    expect(r.stdout).toMatch(/API_TOKEN\s+string\s+secret\s+in the Contract/);
    expect(r.stdout).toMatch(/DATABASE_URL\s+url\s+secret/);
    expect(r.stdout).toMatch(/PORT\s+string\s+plain\s+in the Contract/);
    expect(r.stdout).toMatch(/DEBUG\s+boolean\s+secret/);
    expect(r.stdout).toMatch(/Dry run: nothing was stored\./);
    expect(puts()).toEqual([]);
    noValues(r);
  });

  describe("an existing value is replaced only with the human's approval for that item", () => {
    // The fake environment already has API_TOKEN (a Secret) and PORT=8080 (plain).
    const revisions = () => requests.filter((r) => r.method === "POST" && r.url.endsWith("/contract/revisions"));

    it("the dry run marks the names the environment already has, in every mode", async () => {
      const r = await cli(["--assisted", "import", envFile(), "--dry-run", "--json"]);
      expect(r.code).toBe(0);
      const items = JSON.parse(r.stdout).items as { name: string; existing: boolean | null }[];
      expect(Object.fromEntries(items.map((i) => [i.name, i.existing]))).toEqual({ API_TOKEN: true, DATABASE_URL: false, PORT: true, DEBUG: false, NEW_SECRET: false });
      const human = await cli(["import", envFile(), "--dry-run"]);
      expect(human.stdout).toMatch(/API_TOKEN\s+string\s+secret\s+in the Contract\s+already has a value/);
      expect(human.stdout).toMatch(/development already has a value for API_TOKEN, PORT; importing replaces them\./);
      noValues(r);
    });

    it("assisted: without --replace for each existing item, nothing is stored, pushed, or deleted (78)", async () => {
      const file = envFile();
      const r = await cli(["--assisted", "import", file, "--contract", "--delete-source"]);
      expect(r.code).toBe(78);
      expect(r.stderr).toMatch(/development already has a value for API_TOKEN, PORT; the file may be an older copy\./);
      expect(r.stderr).toMatch(/Replacing a value is the human's decision, for each named item\. Ask them; with their approval for an item, add --replace <NAME> for it\./);
      expect(r.stderr).toMatch(/Nothing was imported and .* was not deleted\./);
      expect(puts()).toEqual([]);
      expect(revisions()).toEqual([]);
      expect(existsSync(file)).toBe(true);
      // Approval for one item does not cover another.
      const one = await cli(["--assisted", "import", file, "--replace", "API_TOKEN"]);
      expect(one.code).toBe(78);
      expect(one.stderr).toMatch(/already has a value for PORT;/);
      expect(puts()).toEqual([]);
      noValues(r);
    });

    it("assisted: with --replace for each existing item, the import stores every value", async () => {
      const r = await cli(["--assisted", "import", envFile(), "--replace", "API_TOKEN", "--replace", "PORT"]);
      expect(r.code, r.stderr).toBe(0);
      expect(puts().map((p) => p.url.split("/").at(-1))).toEqual(["API_TOKEN", "DATABASE_URL", "PORT", "DEBUG", "NEW_SECRET"]);
    });

    it("a plain value identical to the stored one is not a replacement; --replace must name an entry of the file", async () => {
      const same = await cli(["--assisted", "import", envFile("PORT=8080\nFRESH_ITEM=fresh-value-canary-77\n")]);
      expect(same.code, same.stderr).toBe(0);
      expect(puts().map((p) => p.url.split("/").at(-1))).toEqual(["PORT", "FRESH_ITEM"]);
      requests = [];
      const unknown = await cli(["--assisted", "import", envFile(), "--replace", "NOT_IN_FILE"]);
      expect(unknown.code).toBe(1);
      expect(unknown.stderr).toMatch(/--replace names NOT_IN_FILE, which .* does not set/);
      expect(puts()).toEqual([]);
    });

    it("after a partial import, the retry advice asks for approval again, and a value rotated meanwhile is not replaced", async () => {
      const file = envFile("FIRST_KEY=first-key-from-file-21\nSECOND_KEY=second-key-from-file-22\n");
      failPut.add("SECOND_KEY");
      const partial = await cli(["--assisted", "import", file]);
      expect(partial.code).toBe(1);
      expect(partial.stderr).toMatch(/1 of 2 value\(s\) stored\. Fix the cause and run the import again: it now finds FIRST_KEY stored, and replaces it only with the human's approval for that item \(--replace <NAME>\)\./);
      expect(partial.stderr).not.toMatch(/--replace FIRST_KEY/);
      // FIRST_KEY is rotated before the retry; the file still holds the old value.
      stored = stored.map((i) => (i.name === "FIRST_KEY" ? { ...i, value: "first-key-rotated-meanwhile-23" } : i));
      failPut.clear();
      requests = [];
      const retry = await cli(["--assisted", "import", file]);
      expect(retry.code).toBe(78);
      expect(retry.stderr).toMatch(/development already has a value for FIRST_KEY;/);
      expect(puts()).toEqual([]);
      expect(stored.find((i) => i.name === "FIRST_KEY")?.value).toBe("first-key-rotated-meanwhile-23");
      expect(partial.stdout + partial.stderr + retry.stdout + retry.stderr).not.toMatch(/first-key-from-file-21|second-key-from-file-22|first-key-rotated/);
    });

    it("outside assisted mode the import still replaces, as documented", async () => {
      const r = await cli(["import", envFile()]);
      expect(r.code, r.stderr).toBe(0);
      expect(puts().map((p) => p.url.split("/").at(-1))).toContain("API_TOKEN");
    });
  });

  it("--dry-run works without a repository, listing names and inferred types", async () => {
    const r = await cli(["import", envFile(), "--dry-run"], { cwd: bare });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Dry run: would import 5 value\(s\) from .* \(not connected: No varlatch.toml found/);
    expect(r.stdout).toMatch(/NEW_SECRET\s+string/);
    noValues(r);
  });

  it("stores every value exactly, printing names only", async () => {
    const r = await cli(["import", envFile()]);
    expect(r.code).toBe(0);
    expect(puts().map((p) => [p.url.split("/").pop(), (p.body as { value: string }).value])).toEqual([
      ["API_TOKEN", "import-token-canary-11"],
      ["DATABASE_URL", "postgres://app:db-password-canary@localhost/app"],
      ["PORT", "3000"],
      ["DEBUG", "true"],
      ["NEW_SECRET", "new-secret-canary-42"],
    ]);
    expect(r.stdout).toMatch(/Stored 5 value\(s\) in acme\/web \(development\)\./);
    noValues(r);
  });

  it("--contract adds new items as Secrets unless --plain, keeps existing definitions, and pushes before storing", async () => {
    const r = await cli(["import", envFile(), "--contract", "--plain", "DEBUG"]);
    expect(r.code).toBe(0);
    const pushIndex = requests.findIndex((q) => q.url.endsWith("/contract/revisions"));
    const firstPut = requests.findIndex((q) => q.method === "PUT");
    expect(pushIndex).toBeGreaterThanOrEqual(0);
    expect(pushIndex).toBeLessThan(firstPut);
    const pushed = requests[pushIndex]!.body as { contract: { items: { name: string; sensitive: boolean; type: string }[] }; provenance: unknown };
    const byName = Object.fromEntries(pushed.contract.items.map((i) => [i.name, i]));
    expect(byName.API_TOKEN).toMatchObject({ sensitive: true, type: "string" });
    expect(byName.PORT).toMatchObject({ sensitive: false });
    expect(byName.LEGACY_KEY).toMatchObject({ sensitive: true });
    expect(byName.DATABASE_URL).toMatchObject({ sensitive: true, type: "url" });
    expect(byName.NEW_SECRET).toMatchObject({ sensitive: true, type: "string" });
    expect(byName.DEBUG).toMatchObject({ sensitive: false, type: "boolean" });
    expect(pushed.provenance).toEqual({ adapter: "varlatch-import" });
    expect(r.stdout).toMatch(/Contract: 3 new item\(s\); 2 already in the Contract keep their definition\./);
    expect(r.stdout).toMatch(/Activate with: varlatch contract activate crv_imported/);
    noValues(r);
  });

  it("refuses --plain for an item the Contract marks sensitive, and --plain without --contract", async () => {
    const conflict = await cli(["import", envFile(), "--contract", "--plain", "API_TOKEN"]);
    expect(conflict.code).toBe(1);
    expect(conflict.stderr).toMatch(/--plain names API_TOKEN, which the Contract already marks sensitive/);
    const alone = await cli(["import", envFile(), "--plain", "DEBUG"]);
    expect(alone.code).toBe(64);
    expect(alone.stderr).toMatch(/--plain applies only with --contract/);
    expect(puts()).toEqual([]);
  });

  it("--delete-source removes the file after every value was stored", async () => {
    const file = envFile();
    const r = await cli(["import", file, "--delete-source"]);
    expect(r.code).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(r.stdout).toMatch(/Deleted .*\./);
  });

  it("negative control for --delete-source: when a write fails the file stays, and the report names items, not values", async () => {
    failPut.add("PORT");
    const file = envFile();
    const r = await cli(["import", file, "--delete-source"]);
    expect(r.code).toBe(1);
    expect(existsSync(file)).toBe(true);
    expect(r.stderr).toMatch(/stored: API_TOKEN, DATABASE_URL/);
    expect(r.stderr).toMatch(/not stored: PORT \(INTERNAL\)/);
    expect(r.stderr).toMatch(/not attempted: DEBUG, NEW_SECRET/);
    expect(r.stderr).toMatch(/2 of 5 value\(s\) stored\. .* was not deleted\./);
    noValues(r);
  });

  describe("a file that is not valid UTF-8", () => {
    // Byte 0xff can never appear in UTF-8; decoding with replacement would store U+FFFD instead.
    const invalid = Buffer.concat([Buffer.from("A=1\nTOKEN=abcdefgh"), Buffer.from([0xff]), Buffer.from("ijkl\nB=2\n")]);
    function invalidFile(): string {
      const file = join(dir, `.env-invalid-${Math.random().toString(36).slice(2)}`);
      writeFileSync(file, invalid);
      return file;
    }

    it.each([
      ["an import", []],
      ["an import with --delete-source", ["--delete-source"]],
      ["a dry run", ["--dry-run"]],
    ])("%s refuses it by line, stores nothing, and leaves the file byte for byte", async (_name, flags) => {
      const file = invalidFile();
      const r = await cli(["import", file, ...flags]);
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/line 2: not valid UTF-8 text\. Nothing was imported\./);
      expect(r.stdout + r.stderr).not.toMatch(/abcdefgh|ijkl/);
      expect(puts()).toEqual([]);
      expect(readFileSync(file).equals(invalid)).toBe(true);
    });

    it("valid non-ASCII UTF-8 is stored exactly", async () => {
      const value = "pässwörd-€-😀-ok";
      const r = await cli(["import", envFile(`PASS=${value}\n`), "--delete-source"]);
      expect(r.code).toBe(0);
      expect(puts().map((p) => p.body)).toEqual([{ value }]);
    });
  });

  it("reports a parse error by line, and every name problem at once, without values; nothing is stored", async () => {
    const parse = await cli(["import", envFile("A=1\nB=\"unterminated-canary-value\n")]);
    expect(parse.code).toBe(1);
    expect(parse.stderr).toMatch(/line 2: a quoted value is not closed\. Nothing was imported\./);
    expect(parse.stderr).not.toContain("unterminated-canary-value");
    const names = await cli(["import", envFile("lower_case=x-canary-1\nVARLATCH_TOKEN=vlt_should_not_print\nA=1\nA=2\n")]);
    expect(names.code).toBe(1);
    expect(names.stderr).toMatch(/line 1: lower_case is not a valid item name/);
    expect(names.stderr).toMatch(/line 2: VARLATCH_TOKEN is reserved for the Varlatch CLI/);
    expect(names.stderr).toMatch(/A is set more than once, on lines 3, 4/);
    expect(names.stderr + names.stdout).not.toMatch(/x-canary-1|vlt_should_not_print/);
    expect(puts()).toEqual([]);
  });
});
