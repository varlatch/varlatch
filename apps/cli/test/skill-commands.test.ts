// SPDX-License-Identifier: Apache-2.0
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeContract, contractHash } from "@varlatch/contract";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";
import { agentsBlock } from "../src/agents/install.js";
import { SKILL_FILES } from "../src/agents/skillFiles.generated.js";

/**
 * The commands the skill tells a coding agent to run, run exactly as
 * written through the bundled CLI against a fake server. Checking option
 * names alone missed that `import --dry-run <file>`, the skill's own
 * example, exited 64 (found by the ADR-0043 agent evaluation).
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-skill-commands-"));
const bundle = join(dir, "varlatch.cjs");
let server: http.Server;
let origin = "";
// `values` is development's; `production` lets a test check which environment a command reached.
let state: { values: Record<string, string>; production: Record<string, string>; revisions: Record<string, unknown>[]; active: Record<string, unknown> | null };
let n = 0;

const API_TOKEN = "skill-commands-canary-token-42";

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    // As the server: a pushed Contract keeps its own Semantics version, or the active revision's when it names none.
    const revisionOf = (items: unknown[], id: string, semantics?: number) => {
      const version = semantics ?? (state.active?.semanticsVersion as number | undefined) ?? 3;
      const contract = normalizeContract({ schemaVersion: 1, semanticsVersion: version, items: items as never });
      return { id, projectId: "prj_1", contentHash: contractHash(contract), semanticsVersion: version, active: false, contract, createdAt: "2026-10-01T00:00:00.000Z" };
    };
    if (url === "/v1/meta") return json(200, { serverVersion: "0.14.0", apiMajor: 1, capabilities: ["retrieval.strict"], semanticsVersions: [1, 2, 3] });
    if (url === "/v1/organizations/acme/projects/web/contract") return state.active ? json(200, state.active) : json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "none", requestId: "r" } });
    if (url === "/v1/organizations/acme/projects/web/contract/revisions" && req.method === "POST") {
      pushed.push(body);
      const sent = body.contract as { items?: unknown[]; semanticsVersion?: number };
      const rev = revisionOf((sent?.items ?? []) as unknown[], `crv_${state.revisions.length + 1}`, sent?.semanticsVersion);
      state.revisions.push(rev);
      return json(201, rev);
    }
    const activate = /contract\/revisions\/([^/]+)\/activate$/.exec(url);
    if (activate) {
      const rev = state.revisions.find((r) => r.id === activate[1]);
      if (!rev) return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "no revision", requestId: "r" } });
      state.active = { ...rev, active: true };
      return json(200, state.active);
    }
    const scoped = /^\/v1\/organizations\/acme\/projects\/web\/environments\/(development|production)(\/.*)$/.exec(url);
    if (!scoped) return json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
    const values = scoped[1] === "production" ? state.production : state.values;
    const rest = scoped[2] as string;
    const put = /^\/values\/([A-Z_]+)$/.exec(rest);
    if (put && req.method === "PUT") {
      values[put[1] as string] = body.value as string;
      return json(200, { versionId: `ver_${put[1]}` });
    }
    const sensitive = (name: string) => ((state.active?.contract as { items: { name: string; sensitive: boolean }[] } | undefined)?.items.find((i) => i.name === name)?.sensitive ?? true);
    const items = Object.entries(values).map(([name, value]) => ({ name, value, sensitive: sensitive(name), source: "self", versionId: `ver_${name}` }));
    const pinned = state.active ? { revisionId: state.active.id, contentHash: state.active.contentHash, semanticsVersion: 3 } : null;
    const manifest = { manifestVersion: 1, projectId: "prj_1", environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null }, contract: pinned, items: items.map((i) => ({ name: i.name, source: "self", valueRowId: `v_${i.name}`, versionId: i.versionId })) };
    if (rest === "/retrievals") {
      return json(200, { environmentId: "env_1", manifest, stateDigest: `sha256:${"0".repeat(64)}`, contract: state.active?.contract ?? null, items, callerView: { withheld: [], unexpanded: [], contractWithheld: false }, validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] } });
    }
    if (rest === "/disclosures") return json(200, { items: items.map(({ name, versionId, value }) => ({ name, versionId, value })), withheld: [] });
    if (rest.startsWith("/effective-configuration")) return json(200, { environmentId: "env_1", items: items.map((i) => ({ ...i, value: null })), manifest });
    if (rest === "/validate" && req.method === "POST") {
      // Production requires STRIPE_KEY in these tests' Contract-free fake: missing unless stored.
      const missing = scoped[1] === "production" && values.STRIPE_KEY === undefined ? ["STRIPE_KEY"] : [];
      return json(200, { valid: missing.length === 0, complete: true, missing, invalid: [], unresolved: [], notEvaluated: [] });
    }
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
  });
}

beforeAll(async () => {
  await build({ entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))], bundle: true, platform: "node", format: "cjs", target: "node22", outfile: bundle, logLevel: "silent" });
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

let pushed: Record<string, unknown>[] = [];

beforeEach(() => {
  state = { values: {}, production: {}, revisions: [], active: null };
  pushed = [];
});

/** A fresh project with a .env holding a long Secret and a short non-secret. */
function project(): string {
  const repo = join(dir, `p${n++}`);
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
  writeFileSync(join(repo, ".env"), `API_TOKEN=${API_TOKEN}\nLOG_LEVEL=debug\n`);
  return repo;
}

function cli(args: string[], cwd: string, extraEnv: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg"), VARLATCH_TOKEN: "vlt_test", ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/** Splits a documented command line into arguments, honouring quotes. */
function words(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(/'([^']*)'|"([^"]*)"|(\S+)/g)) out.push(m[1] ?? m[2] ?? (m[3] as string));
  return out;
}

/** Every `varlatch --assisted ...` command in the skill's sh blocks and inline spans whose subcommand is `sub`. */
function documented(sub: string): { file: string; line: string }[] {
  const found: { file: string; line: string }[] = [];
  for (const [file, content] of Object.entries(SKILL_FILES)) {
    for (const block of content.matchAll(/^\s*```sh\n([\s\S]*?)^\s*```$/gm)) {
      for (const line of (block[1] as string).split("\n")) {
        const at = line.indexOf("varlatch --assisted ");
        if (at >= 0) found.push({ file, line: line.slice(at).trim() });
      }
    }
    for (const span of content.matchAll(/`(varlatch --assisted [^`]+)`/g)) found.push({ file, line: (span[1] as string).replace(/\s+/g, " ") });
  }
  // Commands only: a span that just names the subcommand is prose.
  return found.filter((c) => words(c.line)[2] === sub && words(c.line).length > 3);
}

const FILLS: Record<string, string> = { "<file>": ".env" };
const fill = (line: string, extra: Record<string, string> = {}) => words(line).slice(1).map((w) => ({ ...FILLS, ...extra })[w] ?? w);

describe("documented import commands run as written", () => {
  it("every import command in the skill exits 0 on a fresh project", async () => {
    const commands = documented("import");
    expect(commands.length).toBeGreaterThanOrEqual(4);
    expect(commands.map((c) => c.line)).toContain("varlatch --assisted import <file> --dry-run");
    for (const c of commands) {
      state = { values: {}, production: {}, revisions: [], active: null };
      const repo = project();
      const r = await cli(fill(c.line), repo);
      expect(r.code, `${c.file}: ${c.line}\n${r.stderr}`).toBe(0);
      expect(r.stdout + r.stderr).not.toContain(API_TOKEN);
    }
  });

  it("options go on either side of the one filename; anything else is 64 and stores nothing", async () => {
    for (const args of [["--assisted", "import", "--dry-run", ".env"], ["--assisted", "import", ".env", "--dry-run"], ["--assisted", "import", "--json", ".env", "--dry-run"]]) {
      expect((await cli(args, project())).code, args.join(" ")).toBe(0);
    }
    for (const args of [
      ["--assisted", "import", ".env", "--dryrun"],
      ["--assisted", "import", ".env", "other.env", "--dry-run"],
      ["--assisted", "import", ".env", "--dry-run", "-e"],
      ["--assisted", "import", ".env", "--contract", "--plain"],
      ["--assisted", "import", "--dry-run"],
    ]) {
      state = { values: {}, production: {}, revisions: [], active: null };
      const repo = project();
      const r = await cli(args, repo);
      expect(r.code, args.join(" ")).toBe(EXIT.usage);
      expect(state.values, args.join(" ")).toEqual({});
      expect(existsSync(join(repo, ".env")), args.join(" ")).toBe(true);
    }
  });
});

describe("the onboarding pattern in SKILL.md", () => {
  it("with a leftover .env holding an older copy of a stored value: run as written, it stops before replacing it, and stores, pushes, and deletes nothing", async () => {
    const block = /## Moving a project's `\.env` into Varlatch\n\n```sh\n([\s\S]*?)```/.exec(SKILL_FILES["SKILL.md"] as string);
    const lines = (block?.[1] as string).trim().split("\n");
    const repo = project();
    // The current, rotated value is stored; the project's .env still holds the old one.
    state.values = { API_TOKEN: "current-rotated-token-value-90" };
    const dry = await cli(fill(lines[0] as string), repo);
    expect(dry.code, dry.stderr).toBe(0);
    const items = (JSON.parse(dry.stdout) as { items: { name: string; existing: boolean }[] }).items;
    expect(items.find((i) => i.name === "API_TOKEN")?.existing).toBe(true);
    expect(items.find((i) => i.name === "LOG_LEVEL")?.existing).toBe(false);
    const imp = await cli(fill(lines[1] as string), repo);
    expect(imp.code, imp.stderr).toBe(78);
    expect(imp.stderr).toMatch(/development already has a value for API_TOKEN; the file may be an older copy\./);
    expect(state.values).toEqual({ API_TOKEN: "current-rotated-token-value-90" });
    expect(state.revisions).toEqual([]);
    expect(existsSync(join(repo, ".env"))).toBe(true);
    // Once the human approves replacing API_TOKEN by name, the same step proceeds.
    const approved = await cli(fill(lines[1] as string).concat(["--replace", "API_TOKEN"]), repo);
    expect(approved.code, approved.stderr).toBe(0);
    expect(state.values).toEqual({ API_TOKEN, LOG_LEVEL: "debug" });
  });

  it("runs as written, in order: dry run, import with the Contract, activate, start", async () => {
    const block = /## Moving a project's `\.env` into Varlatch\n\n```sh\n([\s\S]*?)```/.exec(SKILL_FILES["SKILL.md"] as string);
    expect(block, "the onboarding block is in the main skill").not.toBeNull();
    const lines = (block?.[1] as string).trim().split("\n");
    expect(lines).toHaveLength(4);
    const repo = project();
    let revision = "";
    for (const line of lines) {
      const r = await cli(fill(line, { "<revision>": revision, "<command>": "node" }).concat(line.endsWith("<command>") ? ["-e", "console.log('app started')"] : []), repo);
      expect(r.code, `${line}\n${r.stdout}\n${r.stderr}`).toBe(0);
      if (line.includes("--contract")) revision = (JSON.parse(r.stdout) as { contract: { revision: { id: string } } }).contract.revision.id;
      if (line.endsWith("<command>")) expect(r.stdout).toContain("app started");
    }
    expect(state.values).toEqual({ API_TOKEN, LOG_LEVEL: "debug" });
    expect(existsSync(join(repo, ".env"))).toBe(false);
    const items = (state.active?.contract as { items: { name: string; sensitive: boolean }[] }).items;
    expect(items.find((i) => i.name === "API_TOKEN")?.sensitive).toBe(true);
    expect(items.find((i) => i.name === "LOG_LEVEL")?.sensitive).toBe(false);
  });
});

describe("the override the exit-78 message prints", () => {
  it("is a command that runs as printed once the human approves it", async () => {
    const repo = project();
    state.values = { PIN: "1234567" };
    const refused = await cli(["--assisted", "run", "--", "node", "-e", "console.log('ok')"], repo);
    expect(refused.code, refused.stderr).toBe(78);
    const printed = /(varlatch run -e development --allow-unmasked PIN -- <command>)/.exec(refused.stderr)?.[1];
    expect(printed, refused.stderr).toBeDefined();
    const r = await cli(fill(printed as string, { "<command>": "node" }).concat(["-e", "console.log('ran')"]), repo);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("ran");
  });
});

describe("the exit-78 remedies keep the run's environment", () => {
  const DEV_PIN = "development-pin-long-enough";

  /** A production run refused on a short PIN, development's PIN long; returns the two printed remedies. */
  async function refusedInProduction(repo: string, extra: string[] = [], env: Record<string, string> = {}) {
    state.values = { PIN: DEV_PIN };
    state.production = { PIN: "1234567" };
    const r = await cli(["--assisted", "run", "-e", "production", ...extra, "--", "node", "-e", "console.log('ok')"], repo, env);
    expect(r.code, r.stderr).toBe(78);
    return {
      replace: /^ {6}(varlatch --assisted values set PIN .*--generate hex:32)$/m.exec(r.stderr)?.[1],
      unmask: /^ {6}(varlatch run .*--allow-unmasked PIN -- <command>)$/m.exec(r.stderr)?.[1],
      stderr: r.stderr,
    };
  }

  it.each([
    ["a default run", []],
    ["a strict run", ["--strict"]],
  ] as const)("%s: the printed override shows production's value and changes nothing", async (_name, extra) => {
    const repo = project();
    // Strict startup needs an active Contract.
    const contract = normalizeContract({ schemaVersion: 1, semanticsVersion: 3, items: [{ name: "PIN", type: "string", sensitive: true, required: { kind: "always" } }] as never });
    state.active = { id: "crv_pin", projectId: "prj_1", contentHash: contractHash(contract), semanticsVersion: 3, active: true, contract, createdAt: "2026-10-01T00:00:00.000Z" };
    const { unmask } = await refusedInProduction(repo, [...extra]);
    expect(unmask).toBe(`varlatch run -e production ${extra.length > 0 ? "--strict " : ""}--allow-unmasked PIN -- <command>`);
    const r = await cli(fill(unmask as string, { "<command>": "node" }).concat(["-e", "console.log('PIN=' + process.env.PIN)"]), repo);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("PIN=1234567");
    expect(state.values.PIN).toBe(DEV_PIN);
  });

  it("after approval, the printed assisted replacement replaces production's value, leaves development's, and the refused run then starts", async () => {
    const repo = project();
    const { replace, stderr } = await refusedInProduction(repo);
    expect(stderr).toMatch(/Only if they approve replacing PIN with a new random value/);
    expect(replace).toBe("varlatch --assisted values set PIN -e production --replace PIN --generate hex:32");
    // Control: without --replace, as the remedy was printed before, assisted mode refuses to replace (78).
    const unapproved = await cli(fill((replace as string).replace(" --replace PIN", "")), repo);
    expect(unapproved.code).toBe(78);
    expect(state.production.PIN).toBe("1234567");
    const r = await cli(fill(replace as string), repo);
    expect(r.code, r.stderr).toBe(0);
    expect(state.production.PIN).toMatch(/^[0-9a-f]{64}$/);
    expect(state.values.PIN).toBe(DEV_PIN);
    const again = await cli(["--assisted", "run", "-e", "production", "--", "node", "-e", "console.log('ran')"], repo);
    expect(again.code, again.stderr).toBe(0);
    expect(again.stdout).toContain("ran");
  });

  it("an overridden server, by flag or VARLATCH_SERVER, is kept in every suggested command; otherwise none is added", async () => {
    const repo = project();
    for (const [extra, env] of [[["--server", origin], {}], [[], { VARLATCH_SERVER: origin }]] as const) {
      const { replace, unmask } = await refusedInProduction(repo, [...extra], env);
      expect(replace).toBe(`varlatch --assisted values set PIN -e production --server ${origin} --replace PIN --generate hex:32`);
      expect(unmask).toBe(`varlatch run -e production --server ${origin} --allow-unmasked PIN -- <command>`);
    }
    const handoff = await cli(["--assisted", "values", "set", "STRIPE_KEY", "-e", "production", "--server", origin], repo);
    expect(handoff.code).toBe(64);
    expect(handoff.stderr).toContain(`    varlatch values set STRIPE_KEY -e production --server ${origin}\n`);
    const plain = await refusedInProduction(repo);
    expect(`${plain.replace} ${plain.unmask}`).not.toContain("--server");
  });
});

describe("correcting an item's sensitivity: references/contract.md, run as written", () => {
  // The Contract an import made with LOG_LEVEL as a Secret (no --plain), on Semantics version 2.
  function withSecretLogLevel(repo: string): void {
    const contract = normalizeContract({
      schemaVersion: 1,
      semanticsVersion: 2,
      items: [
        { name: "API_TOKEN", type: "string", sensitive: true, required: { kind: "always" } },
        { name: "LOG_LEVEL", type: "string", sensitive: true, required: { kind: "never" } },
        { name: "PORT", type: "number", sensitive: false, required: { kind: "never" }, defaultValue: "8080" },
      ] as never,
    });
    state.active = { id: "crv_import", projectId: "prj_1", contentHash: contractHash(contract), semanticsVersion: 2, active: true, contract, createdAt: "2026-10-01T00:00:00.000Z" };
    state.revisions.push(state.active);
    state.values = { API_TOKEN, LOG_LEVEL: "debug" };
    rmSync(join(repo, ".env"), { force: true });
  }
  const guide = SKILL_FILES["references/contract.md"] as string;
  const steps = (/^```sh\n([\s\S]*?)^```$/m.exec(guide)?.[1] ?? "").trim().split("\n");
  const hasJq = spawnSync("jq", ["--version"]).status === 0;
  const items = () => (state.active?.contract as { items: { name: string; sensitive: boolean }[] }).items;

  it("the guide's steps are show, extract, push --file --json, activate: no invented command", () => {
    expect(steps).toEqual([
      "varlatch --assisted contract show > revision.json",
      "jq '.contract' revision.json > contract.json",
      "varlatch --assisted contract push --file contract.json --json",
      "varlatch --assisted contract activate <revision>",
    ]);
    expect(guide).toMatch(/applies to the item in every environment of the project/);
    expect(guide).toMatch(/change only `"sensitive"` on the approved item/);
  });

  it("changes only the approved item's sensitivity, keeps every other definition and the Semantics version, and the run then starts", async () => {
    const repo = project();
    withSecretLogLevel(repo);
    const before = await cli(["--assisted", "run", "--", "node", "-e", "console.log('started')"], repo);
    expect(before.code).toBe(78);
    expect(before.stderr).toMatch(/cannot be masked in the command's output: LOG_LEVEL/);
    expect(before.stderr).toMatch(/marking LOG_LEVEL as not secret \(a Contract change, for the whole project\): varlatch --assisted agents guide contract/);
    const activeBefore = JSON.parse(JSON.stringify(state.active)) as { contract: { items: { name: string; sensitive: boolean }[] } };

    // 1. show, written to revision.json as the redirect would.
    const shown = await cli((steps[0] as string).split(" > ")[0]!.split(" ").slice(1), repo);
    expect(shown.code, shown.stderr).toBe(0);
    writeFileSync(join(repo, "revision.json"), shown.stdout);
    // 2. the `contract` field, unchanged, in its own file.
    if (hasJq) {
      const extracted = spawnSync("sh", ["-c", steps[1] as string], { cwd: repo, encoding: "utf8" });
      expect(extracted.status, extracted.stderr).toBe(0);
    } else {
      writeFileSync(join(repo, "contract.json"), JSON.stringify((JSON.parse(shown.stdout) as { contract: unknown }).contract, null, 2));
    }
    const extracted = JSON.parse(readFileSync(join(repo, "contract.json"), "utf8")) as { items: { name: string; sensitive: boolean }[]; semanticsVersion?: number };
    expect(extracted).toEqual(activeBefore.contract);
    // 3. only the approved item's "sensitive".
    for (const item of extracted.items) if (item.name === "LOG_LEVEL") item.sensitive = false;
    writeFileSync(join(repo, "contract.json"), JSON.stringify(extracted, null, 2));
    // 4. push, then activate the returned revision.
    const pushedRev = await cli((steps[2] as string).split(" ").slice(1), repo);
    expect(pushedRev.code, pushedRev.stderr).toBe(0);
    const id = (JSON.parse(pushedRev.stdout) as { revision: { id: string } }).revision.id;
    expect(state.active?.id).toBe("crv_import");
    const activated = await cli(fill(steps[3] as string, { "<revision>": id }), repo);
    expect(activated.code, activated.stderr).toBe(0);

    expect(state.active?.id).toBe(id);
    expect(state.active?.semanticsVersion).toBe(2);
    const changed = items().filter((i) => i.sensitive !== activeBefore.contract.items.find((b) => b.name === i.name)?.sensitive).map((i) => i.name);
    expect(changed).toEqual(["LOG_LEVEL"]);
    expect({ ...(state.active?.contract as object), items: undefined }).toEqual({ ...activeBefore.contract, items: undefined });
    expect(items().map((i) => ({ ...i, sensitive: undefined }))).toEqual(activeBefore.contract.items.map((i) => ({ ...i, sensitive: undefined })));
    expect(state.values).toEqual({ API_TOKEN, LOG_LEVEL: "debug" });
    const after = await cli(["--assisted", "run", "--", "node", "-e", "console.log('started')"], repo);
    expect(after.code, after.stderr).toBe(0);
    expect(after.stdout).toContain("started");
  });

  it("negative controls: an invented contract update, and re-importing with --plain, change nothing", async () => {
    const repo = project();
    withSecretLogLevel(repo);
    const invented = await cli(["--assisted", "contract", "update", "--correct-sensitivity", "LOG_LEVEL"], repo);
    expect(invented.code).toBe(64);
    writeFileSync(join(repo, ".env"), "LOG_LEVEL=debug\n");
    await cli(["--assisted", "import", ".env", "--contract", "--plain", "LOG_LEVEL", "--replace", "LOG_LEVEL", "--json"], repo);
    expect(items().find((i) => i.name === "LOG_LEVEL")?.sensitive).toBe(true);
    expect(state.active?.id).toBe("crv_import");
    expect(pushed).toEqual([]);
  });
});

describe("completion gaps from the second agent evaluation", () => {
  it("the AGENTS.md block: no init, the full onboarding, readiness is validate, the human-terminal handoff, named replacement, no agent-added unmasking, listed Placeholders only", () => {
    const block = agentsBlock();
    const skill = SKILL_FILES["SKILL.md"] as string;
    expect(block).toMatch(/never run `varlatch init`/);
    expect(block).toMatch(/1\. Compare names with the target environment: `varlatch --assisted import \.env -e <environment> --dry-run --json`/);
    expect(block).toMatch(/Ask the human about each; the import replaces one\s+only with `--replace <NAME>` for it/);
    expect(block).toMatch(/2\. Import: `varlatch --assisted import \.env -e <environment> --contract --plain <NAME> --delete-source --json`/);
    expect(block).toMatch(/`--plain` only for items the human confirmed are not secret; the file is deleted only after every value was stored/);
    expect(block).toMatch(/3\. If the import created a Contract revision, activate it: `varlatch --assisted contract activate <revision>`/);
    expect(block).toMatch(/`varlatch --assisted validate -e <environment> --json`; listing values does not check the Contract/);
    expect(block).toMatch(/no `--assisted`; add `--server <url>` when the server was overridden\), or point them to the dashboard:\n\n  ```text\n  varlatch values set <NAME> -e <environment>\n  ```/);
    expect(block).toMatch(/in assisted mode `values set`, `values rotate`, and `import` refuse to replace one without `--replace <NAME>`/);
    expect(block).toMatch(/When a Secret is too short to mask \(exit 78\), stop and ask the human\. Only after they approve a remedy for that\s+item and environment may you carry it out, with `--assisted`; for a new random value:\s+`varlatch --assisted values set <NAME> -e <environment> --replace <NAME> --generate hex:32` \(keep `--server <url>`\s+when it was overridden\)\. A credential a provider issued is the human's to enter\./);
    expect(block).toMatch(/Marking an item as not secret\s+changes the Contract for the whole project: `varlatch --assisted agents guide contract`\./);
    expect(block).toMatch(/Showing a Secret unmasked\s+is the human's alone: never add `--allow-unmasked` or `--no-redact` \(assisted mode refuses both\)\./);
    expect(block).toMatch(/When the human asks for a new random value, generate it \(`--generate hex:32`\); a credential issued elsewhere is\s+theirs to enter\. Never run a command printed for the human's own terminal yourself\./);
    expect(block).toMatch(/\(double quotes: in single quotes the literal `\$STRIPE_KEY` is sent, and nothing is substituted\)/);
    expect(block).not.toMatch(/every remedy is the human's, run in their own terminal/);
    expect(block).toMatch(/`varlatch --assisted context --json` under `agentRun\.placeholders`/);
    // The skill says the same.
    expect(skill).toMatch(/never add\s+`--allow-unmasked` or `--no-redact` \(assisted mode refuses both\)/);
    expect(skill).toMatch(/After they approve one, you may carry it out yourself, with\s+`--assisted`/);
    expect(skill).toMatch(/`varlatch --assisted values set\s+<NAME> -e <environment> --replace <NAME> --generate hex:32`/);
    expect(skill).toMatch(/A command printed for the human's own terminal\s+\(without `--assisted`\) is theirs: never run it yourself\./);
    expect(skill).not.toMatch(/Every\s+remedy is the human's, run in their own terminal/);
    expect(skill).toMatch(/```text\n   varlatch run -e <environment> --allow-unmasked <NAME> -- <command>\n   ```/);
    expect(skill).toMatch(/applies to the whole project: approval to change it\s+covers that item, in every environment, and nothing else/);
    expect(skill).toMatch(/refuse \(78\) to replace an existing value\s+unless that item is named with `--replace <NAME>`/);
    expect(skill).toMatch(/add\s+`--server <url>` when the server was overridden/);
    expect(skill).toMatch(/If the import created a revision, activate it/);
    expect(skill).toMatch(/for items the human confirmed are not secret/);
  });

  it("the AGENTS.md onboarding, run as written: a fresh project is imported, its revision activated, the file deleted", async () => {
    const block = agentsBlock();
    const step = (n: number) => new RegExp(`${n}\\. [^\\n]*?\`(varlatch --assisted [^\`]+)\``).exec(block)?.[1] as string;
    const repo = project();
    const fills = { "<environment>": "development", "<NAME>": "LOG_LEVEL" };
    const dry = await cli(fill(step(1), fills), repo);
    expect(dry.code, dry.stderr).toBe(0);
    const imported = await cli(fill(step(2), fills), repo);
    expect(imported.code, imported.stderr).toBe(0);
    const revision = (JSON.parse(imported.stdout) as { contract: { revision: { id: string } } }).contract.revision.id;
    const activated = await cli(fill(step(3), { "<revision>": revision }), repo);
    expect(activated.code, activated.stderr).toBe(0);
    expect(state.values).toEqual({ API_TOKEN, LOG_LEVEL: "debug" });
    expect(existsSync(join(repo, ".env"))).toBe(false);
    const items = (state.active?.contract as { items: { name: string; sensitive: boolean }[] }).items;
    expect(items.find((i) => i.name === "LOG_LEVEL")?.sensitive).toBe(false);
    expect(items.find((i) => i.name === "API_TOKEN")?.sensitive).toBe(true);
  });

  it("the AGENTS.md onboarding, run as written over a stale .env: step 2 stops (78) before replacing the stored value", async () => {
    const block = agentsBlock();
    const step2 = /2\. [^\n]*?`(varlatch --assisted [^`]+)`/.exec(block)?.[1] as string;
    const repo = project();
    state.values = { API_TOKEN: "current-rotated-token-value-91" };
    const r = await cli(fill(step2, { "<environment>": "development", "<NAME>": "LOG_LEVEL" }), repo);
    expect(r.code).toBe(78);
    expect(state.values).toEqual({ API_TOKEN: "current-rotated-token-value-91" });
    expect(existsSync(join(repo, ".env"))).toBe(true);
  });

  it("the readiness command runs as written and reports the missing item", async () => {
    const line = /`(varlatch --assisted validate -e <environment> --json)`/.exec(agentsBlock())?.[1] as string;
    const r = await cli(fill(line, { "<environment>": "production" }), project());
    expect(r.stderr).not.toMatch(/unknown option|needs a value|unexpected argument/);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stdout)).toMatchObject({ environment: "production", result: "invalid", missing: ["STRIPE_KEY"] });
  });

  it("the Placeholder check runs as written; outside an agent-safe run, assisted mode still masks the value", async () => {
    const repo = project();
    state.values = { API_TOKEN };
    const line = /`(varlatch --assisted run -- printenv <NAME>)`/.exec(agentsBlock())?.[1] as string;
    const r = await cli(fill(line, { "<NAME>": "API_TOKEN" }), repo);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("[REDACTED:API_TOKEN]");
    expect(r.stdout + r.stderr).not.toContain(API_TOKEN);
  });
});

describe("the .env notice's comparison command", () => {
  it("keeps the run's environment and server: run from a fresh shell, it compares against the store the run used", async () => {
    // The project's own server is unreachable; this run reaches the fake one through VARLATCH_SERVER, in production.
    const repo = join(dir, `p${n++}`);
    mkdirSync(repo);
    writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "http://127.0.0.1:9"\ndefault_environment = "development"\n`);
    writeFileSync(join(repo, ".env"), "STRIPE_KEY=stale-stripe-copy-44\n");
    state.production = { STRIPE_KEY: "current-production-stripe-45" };
    const run = await cli(["--assisted", "run", "-e", "production", "--", "node", "-e", "console.log('ok')"], repo, { VARLATCH_SERVER: origin });
    expect(run.code, run.stderr).toBe(0);
    const hint = /To compare names, without values: (varlatch --assisted import \.env [^\n]+--dry-run --json)/.exec(run.stderr)?.[1];
    expect(hint).toBe(`varlatch --assisted import .env -e production --server ${origin} --dry-run --json`);
    // A fresh shell: no VARLATCH_SERVER.
    const compared = await cli(words(hint as string).slice(1), repo);
    expect(compared.code, compared.stderr).toBe(0);
    const doc = JSON.parse(compared.stdout) as { target: { environment: string }; items: { name: string; existing: boolean }[] };
    expect(doc.target.environment).toBe("production");
    expect(doc.items).toEqual([expect.objectContaining({ name: "STRIPE_KEY", existing: true })]);
    expect(run.stderr + compared.stdout + compared.stderr).not.toMatch(/stale-stripe-copy|current-production-stripe/);
  });
});

describe("Placeholders in an agent-safe run", () => {
  it("the AGENTS.md block and the skill both permit them in request targets, with a concrete example, and keep real values forbidden", () => {
    const block = agentsBlock();
    expect(block).toMatch(/agent-safe run, the run's Secrets are Placeholders, not secrets/);
    expect(block).toMatch(/`varlatch --assisted request -H "Authorization: Bearer \$STRIPE_KEY" https:\/\/[^`]+`/);
    expect(block).toMatch(/never put a secret value in a command/);
    const skill = SKILL_FILES["SKILL.md"] as string;
    expect(skill).toMatch(/Putting a Placeholder in\s+a `varlatch --assisted request` header or body target is how you use a\s+secret there; a real secret value stays forbidden/);
    expect(skill).toMatch(/`varlatch --assisted request -X POST -H "Authorization: Bearer \$STRIPE_KEY" --json '\{"amount": 500\}' https:\/\/[^`]+`/);
  });
});

describe("the agent-safe request example", () => {
  it("parses as written, in SKILL.md and in the AGENTS.md block; outside an agent-safe run it is refused, not misread", async () => {
    const examples = [...documented("request").map((c) => c.line), ...[...agentsBlock().matchAll(/`(varlatch --assisted request [^`]+)`/g)].map((m) => m[1] as string)];
    expect(examples.length).toBeGreaterThanOrEqual(2);
    for (const line of examples) {
      const r = await cli(words(line).slice(1).map((w) => w.replace("$STRIPE_KEY", "vlch_ph_v1_example")), project());
      expect(r.stderr, line).not.toMatch(/unknown option|needs a value|unexpected argument/);
      expect(r.stderr, line).toMatch(/agent-safe run/);
    }
  });
});
