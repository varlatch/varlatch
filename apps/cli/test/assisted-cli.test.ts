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
    if (url === "/v1/organizations/acme/projects/web/contract/revisions" && req.method === "POST") {
      return json(201, { ...active, id: "crv_imported", active: false });
    }
    if (url.startsWith(`${ENV_PATH}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_1",
        items: stored.map((i) => ({ name: i.name, sensitive: i.sensitive, source: "self", value: i.sensitive ? null : i.value })),
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
          contract: { revisionId: active.id, contentHash: active.contentHash, semanticsVersion: 2 },
          items: items.map((i) => ({ name: i.name, source: "self", valueRowId: `val_${i.name}`, versionId: i.versionId })),
        },
        stateDigest: `sha256:${"0".repeat(64)}`,
        contract: active.contract,
        items,
        callerView: { withheld: [], unexpanded: [], contractWithheld: false },
        validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
      });
    }
    // Any environment: a handoff for production must reach production's path.
    const put = /^\/v1\/organizations\/acme\/projects\/web\/environments\/[a-z]+\/values\/([A-Z0-9_]+)$/.exec(url);
    if (put && req.method === "PUT") {
      if (failPut.has(put[1]!)) return json(500, { error: { code: "INTERNAL", message: "injected", requestId: "req_x" } });
      return json(200, { versionId: `ver_new_${put[1]}` });
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
    ["--assisted --no-redact", ["--assisted"], ["--no-redact"], {}],
  ] as const)("negative control, same input: %s leaves the output unmasked", async (_name, global, runFlags, env) => {
    const r = await cli([...global, "run", ...runFlags, "--", process.execPath, printer()], { env: { ...env, ...INHERITED } });
    expect(r.code).toBe(0);
    expect(leaked(r)).toEqual(["token", "token-base64", "token-percent", "token-json", "legacy", "withheld"]);
    if (runFlags.length > 0) expect(r.stderr).toMatch(/--no-redact: this run's output is not masked/);
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

  it("refuses --allow-unmasked outside assisted mode, and --no-redact or --allow-unmasked with --agent-safe", async () => {
    const outside = await cli(["run", "--allow-unmasked", "PIN", "--", "true"]);
    expect(outside.code).toBe(64);
    expect(outside.stderr).toMatch(/--allow-unmasked applies only in assisted mode/);
    const agentSafe = await cli(["--assisted", "run", "--agent-safe", "--no-redact", "--agent", "a", "--", "true"]);
    expect(agentSafe.code).toBe(64);
    expect(agentSafe.stderr).toMatch(/do not apply to --agent-safe runs/);
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
    // Every remedy is the human's, for this item only; replacing overwrites.
    expect(r.stderr).toMatch(/Ask the human before changing anything\. Each choice is theirs, for PIN only:/);
    expect(r.stderr).toMatch(/overwrites the current value: varlatch --assisted values set PIN --generate hex:32/);
    expect(r.stderr).toMatch(/approval for one item does not cover another/);
    // The override is shown as a command with the option before `--`, where the CLI reads it.
    expect(r.stderr).toMatch(/varlatch --assisted run --allow-unmasked PIN -- <command>/);
    expect(r.stderr).toMatch(/Nothing was started\./);
    expect(existsSync(marker)).toBe(false);
    expect(r.stdout + r.stderr).not.toContain(PIN);
  });

  it("runs with the human's --allow-unmasked, masking everything else", async () => {
    const r = await cli(["--assisted", "run", "--allow-unmasked", "PIN", "--", process.execPath, printer()]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/allowed with --allow-unmasked, so not masked \(shorter than 8 bytes\): PIN/);
    expect(r.stderr).toContain(`pin=${PIN}`);
    expect(r.stdout).toContain("token=[REDACTED:API_TOKEN]");
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
    const { code, terminal } = await underTerminal(["--assisted", "run", "--no-redact", "--", process.execPath, printer()], INHERITED);
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
      const r = await cli([...flags, "values", "set", item, "argv-secret-value-771"], { env });
      expect(r.code).toBe(64);
      expect(r.stderr).toMatch(new RegExp(`${item} is a Secret, and in assisted mode a Secret's value is never taken from the command line`));
      expect(r.stderr).toMatch(/--generate hex:32/);
      expect(r.stderr).toMatch(/in their own terminal/);
      expect(r.stdout + r.stderr).not.toContain("argv-secret-value-771");
    }
    expect(puts()).toEqual([]);
  });

  it("accepts a non-sensitive value on the command line in assisted mode", async () => {
    const r = await cli(["--assisted", "values", "set", "PORT", "9090"]);
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
    const viaStdin = await cli(["--assisted", "values", "set", "API_TOKEN", "--stdin"], { input: "from-stdin-value-18\n" });
    const viaFile = await cli(["--assisted", "values", "set", "API_TOKEN", "--from-file", file]);
    const viaGenerate = await cli(["--assisted", "values", "set", "API_TOKEN", "--generate", "hex:32"]);
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
    const r = await cli(["--assisted", "values", "rotate", "API_TOKEN", "--stdin", "--grace", "60"], { input: "rotated-value-202\n" });
    expect(r.code).toBe(0);
    expect(requests.find((q) => q.url.endsWith("/rotations"))?.body).toEqual({ value: "rotated-value-202", graceSeconds: 60 });
    expect(r.stdout + r.stderr).not.toContain("rotated-value-202");
    const refused = await cli(["--assisted", "values", "rotate", "API_TOKEN", "argv-rotated-9"]);
    expect(refused.code).toBe(64);
    expect(refused.stderr).toMatch(/values rotate API_TOKEN -e development --generate hex:32/);
  });

  it("with no value: assisted mode never prompts; otherwise a non-terminal is told how to give one", async () => {
    const assisted = await cli(["--assisted", "values", "set", "API_TOKEN"]);
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
    const byDefault = await cli(["--assisted", "values", "set", "API_TOKEN"]);
    // Without -e the command still names the environment it resolved, so it works anywhere.
    expect(handoff(byDefault.stderr)).toBe("varlatch values set API_TOKEN -e development");
    expect(production.stderr).toMatch(/values set STRIPE_KEY -e production --generate hex:32/);
    expect(puts()).toEqual([]);
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
