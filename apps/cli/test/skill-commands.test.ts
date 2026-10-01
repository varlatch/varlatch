// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
let state: { values: Record<string, string>; revisions: Record<string, unknown>[]; active: Record<string, unknown> | null };
let n = 0;

const ENV = "/v1/organizations/acme/projects/web/environments/development";
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
    const revisionOf = (items: unknown[], id: string) => {
      const contract = normalizeContract({ schemaVersion: 1, semanticsVersion: 3, items: items as never });
      return { id, projectId: "prj_1", contentHash: contractHash(contract), semanticsVersion: 3, active: false, contract, createdAt: "2026-10-01T00:00:00.000Z" };
    };
    if (url === "/v1/meta") return json(200, { serverVersion: "0.14.0", apiMajor: 1, capabilities: ["retrieval.strict"], semanticsVersions: [1, 2, 3] });
    if (url === "/v1/organizations/acme/projects/web/contract") return state.active ? json(200, state.active) : json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "none", requestId: "r" } });
    if (url === "/v1/organizations/acme/projects/web/contract/revisions" && req.method === "POST") {
      const rev = revisionOf(((body.contract as { items?: unknown[] })?.items ?? []) as unknown[], `crv_${state.revisions.length + 1}`);
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
    const put = new RegExp(`^${ENV}/values/([A-Z_]+)$`).exec(url);
    if (put && req.method === "PUT") {
      state.values[put[1] as string] = body.value as string;
      return json(200, { versionId: `ver_${put[1]}` });
    }
    const sensitive = (name: string) => ((state.active?.contract as { items: { name: string; sensitive: boolean }[] } | undefined)?.items.find((i) => i.name === name)?.sensitive ?? true);
    const items = Object.entries(state.values).map(([name, value]) => ({ name, value, sensitive: sensitive(name), source: "self", versionId: `ver_${name}` }));
    const manifest = { manifestVersion: 1, projectId: "prj_1", environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null }, contract: null, items: items.map((i) => ({ name: i.name, source: "self", valueRowId: `v_${i.name}`, versionId: i.versionId })) };
    if (url === `${ENV}/retrievals`) {
      return json(200, { environmentId: "env_1", manifest, stateDigest: `sha256:${"0".repeat(64)}`, contract: state.active?.contract ?? null, items, callerView: { withheld: [], unexpanded: [], contractWithheld: false }, validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] } });
    }
    if (url === `${ENV}/disclosures`) return json(200, { items: items.map(({ name, versionId, value }) => ({ name, versionId, value })), withheld: [] });
    if (url.startsWith(`${ENV}/effective-configuration`)) return json(200, { environmentId: "env_1", items: items.map((i) => ({ ...i, value: null })), manifest });
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

beforeEach(() => {
  state = { values: {}, revisions: [], active: null };
});

/** A fresh project with a .env holding a long Secret and a short non-secret. */
function project(): string {
  const repo = join(dir, `p${n++}`);
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
  writeFileSync(join(repo, ".env"), `API_TOKEN=${API_TOKEN}\nLOG_LEVEL=debug\n`);
  return repo;
}

function cli(args: string[], cwd: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg"), VARLATCH_TOKEN: "vlt_test" },
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
      state = { values: {}, revisions: [], active: null };
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
      state = { values: {}, revisions: [], active: null };
      const repo = project();
      const r = await cli(args, repo);
      expect(r.code, args.join(" ")).toBe(EXIT.usage);
      expect(state.values, args.join(" ")).toEqual({});
      expect(existsSync(join(repo, ".env")), args.join(" ")).toBe(true);
    }
  });
});

describe("the onboarding pattern in SKILL.md", () => {
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
    const printed = /(varlatch --assisted run --allow-unmasked PIN -- <command>)/.exec(refused.stderr)?.[1];
    expect(printed, refused.stderr).toBeDefined();
    const r = await cli(fill(printed as string, { "<command>": "node" }).concat(["-e", "console.log('ran')"]), repo);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("ran");
  });
});

describe("Placeholders in an agent-safe run", () => {
  it("the AGENTS.md block and the skill both permit them in request targets, with a concrete example, and keep real values forbidden", () => {
    const block = agentsBlock();
    expect(block).toMatch(/agent-safe run, variables hold Placeholders, not secrets/);
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
