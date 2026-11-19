// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { VarlatchApiError } from "@varlatch/sdk";
import { guidedInit, type GuidedApi } from "../src/guidedInit.js";
import { PassThrough } from "node:stream";
import { terminalPrompter, type Prompter } from "../src/prompt.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's guided `init` (internal docs/design/go-cli.md,
 * slice 5.8a): every case of guided-init.test.ts, and more, run through
 * guidedInit.ts in this process with that test's fake API and a scripted
 * prompter. Each records the exit status, what was printed (out, err, the
 * questions, the options shown, the lines said), the configuration written,
 * every API call, the fake's state afterwards, and the files left. The Go
 * test (internal/cli's TestGuidedInitVectors) runs Go's guided init with a
 * port of the same fake and compares. Regenerate after a change to
 * guidedInit.ts:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-guided-init.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/guided-init.json", import.meta.url));

const CANARY_DEV = "dev-canary-5d1f3a9e7b";
const CANARY_PROD = "prod-canary-0c4e8b2a61";
const CANARY_OLD = "old-canary-77aa31";
const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);

interface FakeInit {
  orgs?: { slug: string; name: string }[];
  projects?: { slug: string; name: string; contractAuthority: "git" | "managed" }[];
  envs?: { name: string; tier: string; kind: string }[];
  values?: Record<string, Record<string, string>>;
  sensitive?: string[];
  unreadable?: string[];
  failOn?: string;
  contractForbidden?: boolean;
  failing?: ("push" | "activate" | "read")[];
  failCode?: string;
  /** The push answers that the revision is active already. */
  pushActive?: boolean;
}

interface Answer {
  /** A regular expression the question must match (JavaScript and Go read it alike). */
  q: string;
  a: number | boolean | string;
  /** Files written when this question is asked (the run sees them changed). */
  write?: Record<string, string>;
}

interface Case {
  id: string;
  files: Record<string, string>;
  fake?: FakeInit;
  answers: Answer[];
  extra?: { organization?: string; project?: string; defaultEnvironment?: string };
  /** The server already resolved; null to ask for it. */
  server?: string | null;
  /** How a typed address is checked: as it is, or refused with a path or query. */
  validate?: "identity" | "no-query";
  expect?: unknown;
}

function fake(init: FakeInit) {
  const f = {
    orgs: structuredClone(init.orgs ?? [{ slug: "acme", name: "Acme" }]),
    projects: structuredClone(init.projects ?? [{ slug: "api", name: "API", contractAuthority: "git" as const }]),
    envs: structuredClone(
      init.envs ?? [
        { name: "development", tier: "development", kind: "shared" },
        { name: "production", tier: "production", kind: "shared" },
      ],
    ),
    values: new Map(Object.entries(init.values ?? {}).map(([env, v]) => [env, new Map(Object.entries(v))])),
    sensitive: new Set(init.sensitive ?? []),
    revisions: [{ id: "rev_0", items: [{ name: "PORT", type: "integer", sensitive: false }] as unknown[], active: true }],
    unreadable: new Set(init.unreadable ?? []),
    failing: new Set(init.failing ?? []),
    failCode: init.failCode ?? "VALIDATION_FAILED",
    calls: [] as unknown[][],
  };
  const page = <T>(items: T[]) => ({ items, nextCursor: null });
  const echo = (status: number, code: string) => new VarlatchApiError(status, { code, message: `rejected ${CANARY_DEV} ${CANARY_PROD}`, requestId: "r" } as never);
  const denied = (status: number, code: string) => new VarlatchApiError(status, { code, message: "no", requestId: "r" } as never);
  const api = {
    listOrganizations: async () => page(f.orgs),
    createOrganization: async (input: { slug: string; name: string }) => (f.orgs.push(input), input),
    listProjects: async () => page(f.projects),
    createProject: async (_o: string, input: { slug: string; name: string; contractAuthority: "git" | "managed" }) => (f.projects.push(input), input),
    listEnvironments: async () => page(f.envs),
    createEnvironment: async (_o: string, _p: string, input: { name: string; tier: string }) => {
      const env = { ...input, kind: "shared" };
      f.envs.push(env);
      return env;
    },
    getActiveContract: async () => {
      if (init.contractForbidden) throw denied(403, "FORBIDDEN");
      const active = f.revisions.find((r) => r.active);
      if (!active) throw denied(404, "RESOURCE_NOT_FOUND");
      return {
        id: active.id,
        contract: { schemaVersion: 1, semanticsVersion: 3, items: active.items.map((i) => ({ ...(i as object), required: { kind: "never" } })) },
      };
    },
    pushContractRevision: async (_o: string, _p: string, input: { contract: { items: unknown[] } }) => {
      if (f.failing.has("push")) throw echo(422, f.failCode);
      const revision = { id: `rev_${f.revisions.length}`, items: input.contract.items, active: init.pushActive === true };
      if (revision.active) for (const r of f.revisions) r.active = false;
      f.revisions.push(revision);
      return { id: revision.id, contentHash: "h", active: revision.active };
    },
    activateContractRevision: async (_o: string, _p: string, id: string) => {
      if (f.failing.has("activate")) throw echo(409, f.failCode);
      for (const r of f.revisions) r.active = r.id === id;
      return {};
    },
    effectiveConfiguration: async (_o: string, _p: string, env: string) => {
      if (f.unreadable.has(env)) throw denied(403, "FORBIDDEN");
      if (f.failing.has("read")) throw echo(500, f.failCode);
      const stored = f.values.get(env) ?? new Map();
      return {
        items: [...stored].map(([name, value]) => ({
          name,
          sensitive: f.sensitive.has(name),
          value: f.sensitive.has(name) ? null : value,
          rawValue: f.sensitive.has(name) ? null : value,
        })),
      };
    },
    setValue: async (_o: string, _p: string, env: string, name: string, input: { value: string }) => {
      if (init.failOn === name) throw new VarlatchApiError(500, { code: f.failCode === "VALIDATION_FAILED" ? "INTERNAL" : f.failCode, message: "boom", requestId: "r" } as never);
      const stored = f.values.get(env) ?? new Map<string, string>();
      stored.set(name, input.value);
      f.values.set(env, stored);
      return {};
    },
  };
  // Every call, with its arguments, as the Go fake logs it.
  const logged = Object.fromEntries(
    Object.entries(api).map(([name, fn]) => [name, async (...args: unknown[]) => (f.calls.push([name, ...structuredClone(args)]), (fn as (...a: unknown[]) => unknown)(...args))]),
  ) as unknown as GuidedApi;
  return { f, api: logged };
}

const cases: Case[] = [];
const add = (c: Case) => cases.push(c);
const pick = [
  { q: "^Organization:", a: 0 },
  { q: "^Project:", a: 0 },
  { q: "^Default environment", a: 0 },
];
const into = (file: string, a: number) => ({ q: `^Import ${file.replace(/\./g, "\\.")} into:`, a });

// ---- guided-init.test.ts --------------------------------------------------------
add({
  id: "two-files",
  files: { ".env": `API_KEY=${CANARY_DEV}\nTIMEOUT=30\nPORT=3000\n`, ".env.production": `API_KEY=${CANARY_PROD}\nTIMEOUT=fast\nSENTRY_DSN=https://x.example\n` },
  answers: [
    ...pick,
    into(".env", 0),
    into(".env.production", 1),
    { q: "^TIMEOUT: the files suggest different types", a: 0 },
    { q: "^Items that are not secret", a: "TIMEOUT" },
    { q: "^Activate it\\?", a: true },
    { q: "^Delete \\.env\\?", a: true },
    { q: "^Delete \\.env\\.production\\?", a: true },
  ],
});
add({ id: "flags-org", files: {}, answers: [{ q: "^Project:", a: 0 }, { q: "^Default environment", a: 0 }], extra: { organization: "acme" } });
add({
  id: "create-everything",
  files: {},
  fake: { orgs: [], projects: [], envs: [] },
  answers: [
    { q: "^New organization's slug", a: "acme" },
    { q: "^Its name", a: "Acme" },
    { q: "^Create organization acme \\(Acme\\)\\?", a: true },
    { q: "^New project's slug", a: "api" },
    { q: "^Its name", a: "API" },
    { q: "^Create project api in acme\\?", a: true },
    { q: "^The project has no environments", a: true },
    { q: "^Default environment", a: 0 },
  ],
});
add({
  id: "declined-replacement",
  files: { ".env": `API_KEY=${CANARY_DEV}\nNEW_ONE=hello\n` },
  fake: { values: { development: { API_KEY: CANARY_OLD } }, sensitive: ["API_KEY"] },
  answers: [...pick, into(".env", 0), { q: "^Replace it with the values in \\.env\\?", a: false }, { q: "^Items that are not secret", a: "" }, { q: "^Activate it\\?", a: true }],
});
add({
  id: "production-not-typed",
  files: { ".env.production": `API_KEY=${CANARY_PROD}\n` },
  fake: { values: { production: { API_KEY: CANARY_OLD } }, sensitive: ["API_KEY"] },
  answers: [...pick, into(".env.production", 1), { q: "^Replace it with the values in \\.env\\.production\\?", a: true }, { q: "^This is a production environment\\. Type production", a: "prod" }],
});
add({
  id: "production-typed",
  files: { ".env.production": `API_KEY=${CANARY_PROD}\n` },
  fake: { values: { production: { API_KEY: CANARY_OLD } }, sensitive: ["API_KEY"] },
  answers: [
    ...pick,
    into(".env.production", 1),
    { q: "^Replace it with the values in \\.env\\.production\\?", a: true },
    { q: "^This is a production environment\\. Type production", a: "production" },
    { q: "^Items that are not secret", a: "" },
    { q: "^Activate it\\?", a: true },
    { q: "^Delete \\.env\\.production\\?", a: false },
  ],
});
add({ id: "unreadable-environment", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { unreadable: ["development"] }, answers: [...pick, into(".env", 0)] });
add({
  id: "declined-activation",
  files: { ".env": `API_KEY=${CANARY_DEV}\n` },
  answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }, { q: "^Activate it\\?", a: false }],
});
add({ id: "managed-new-items", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] }, answers: [...pick, into(".env", 0)] });
add({
  id: "changed-after-read",
  files: { ".env": "PORT=3000\n" },
  answers: [...pick, into(".env", 0), { q: "^Delete \\.env\\?", a: true, write: { ".env": "PORT=4000\n" } }],
});
add({
  id: "interrupted-import",
  files: { ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\nC_ITEM=y\n`, ".env.production": `API_KEY=${CANARY_PROD}\n` },
  fake: { failOn: "B_ITEM" },
  answers: [...pick, into(".env", 0), into(".env.production", 1), { q: "^Items that are not secret", a: "" }],
});
add({ id: "contract-forbidden", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { contractForbidden: true }, answers: [...pick, into(".env", 0)] });
add({ id: "fails.push", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { failing: ["push"] }, answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }] });
add({
  id: "fails.activate",
  files: { ".env": `API_KEY=${CANARY_DEV}\n` },
  fake: { failing: ["activate"] },
  answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }, { q: "^Activate it\\?", a: true }],
});
add({ id: "fails.read", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { failing: ["read"] }, answers: [...pick, into(".env", 0)] });
add({ id: "managed-all-in-contract", files: { ".env": "PORT=3000\n" }, fake: { projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] }, answers: [...pick, into(".env", 0), { q: "^Delete \\.env\\?", a: true }] });
add({ id: "managed-missing", files: { ".env": `PORT=3000\nAPI_KEY=${CANARY_DEV}\n` }, fake: { projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] }, answers: [...pick, into(".env", 0)] });
add({
  id: "failed-write-later-files",
  files: { ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\n`, ".env.production": `API_KEY=${CANARY_PROD}\nZ_ITEM=z\n` },
  fake: { failOn: "B_ITEM" },
  answers: [...pick, into(".env", 0), into(".env.production", 1), { q: "^Items that are not secret", a: "" }],
});
add({
  id: "address.rejected-then-accepted",
  files: {},
  server: null,
  validate: "no-query",
  answers: [{ q: "^Your Varlatch installation's address", a: "https://vault.example.com/?token=URL_CANARY_7723" }, { q: "^Your Varlatch installation's address", a: "https://vault.example.com" }, ...pick],
});
add({ id: "address.credentialed-given", files: {}, server: "https://user:pw9secret@vault.example.com", answers: [] });
add({ id: "address.credentialed-typed", files: {}, server: null, answers: [{ q: "address", a: "https://user:pw9secret@vault.example.com" }] });
add({ id: "code.unrecognized-push", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { failing: ["push"], failCode: CANARY_DEV }, answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }] });
add({
  id: "code.unrecognized-write",
  files: { ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\n` },
  fake: { failOn: "B_ITEM", failCode: CANARY_PROD },
  answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }],
});
add({
  id: "hostile-names",
  files: { ".env": "PORT=3000\n" },
  fake: {
    orgs: [{ slug: "acme", name: `Acme\n  [2] Evil${ESC}]52;c;ZXZpbA==${BEL}${ESC}[31m` }],
    envs: [
      { name: "development", tier: "development", kind: "shared" },
      { name: `production${ESC}[2J`, tier: "production", kind: "shared" },
    ],
  },
  answers: [...pick, into(".env", 0), { q: "^Delete \\.env\\?", a: false }],
});

// ---- More paths -----------------------------------------------------------------
add({ id: "stop.organization", files: {}, fake: { orgs: [] }, answers: [{ q: "^New organization's slug", a: "acme" }, { q: "^Its name", a: "" }, { q: "^Create organization", a: false }] });
add({ id: "stop.project", files: {}, fake: { projects: [] }, answers: [{ q: "^Organization:", a: 0 }, { q: "^New project's slug", a: "web" }, { q: "^Its name", a: "Web" }, { q: "^Create project web in acme\\?", a: false }] });
add({
  id: "slug.asked-again",
  files: {},
  fake: { orgs: [{ slug: "acme", name: "Acme" }] },
  answers: [
    { q: "^Organization:", a: 1 },
    { q: "^New organization's slug", a: "Bad Slug" },
    { q: "^New organization's slug", a: "-x" },
    { q: "^New organization's slug", a: "good-one" },
    { q: "^Its name", a: "Good One" },
    { q: "^Create organization good-one \\(Good One\\)\\?", a: true },
    { q: "^Project:", a: 0 },
    { q: "^Default environment", a: 1 },
  ],
});
add({
  id: "one-file-per-environment",
  files: { ".env": `A_ITEM=1\n`, ".env.local": `B_ITEM=2\n` },
  answers: [...pick, into(".env", 0), into(".env.local", 0), into(".env.local", 2), { q: "^Items that are not secret", a: "" }, { q: "^Activate it\\?", a: true }, { q: "^Delete \\.env\\?", a: false }],
});
add({ id: "skip-file", files: { ".env": `A_ITEM=1\n` }, answers: [...pick, into(".env", 2)] });
add({ id: "empty-file", files: { ".env": "# nothing\n" }, answers: [...pick, into(".env", 0)] });
add({ id: "file-problems", files: { ".env": "A_ITEM=1\nA_ITEM=2\n" }, answers: [...pick, into(".env", 0)] });
add({
  id: "not-a-new-item",
  files: { ".env": `API_KEY=${CANARY_DEV}\nLOG_LEVEL=debug\n` },
  answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: " LOG_LEVEL , NOPE,PORT,, " }, { q: "^Activate it\\?", a: true }, { q: "^Delete \\.env\\?", a: true }],
});
add({ id: "no-environments-declined", files: { ".env": `A_ITEM=1\n` }, fake: { envs: [] }, answers: [{ q: "^Organization:", a: 0 }, { q: "^Project:", a: 0 }, { q: "^The project has no environments", a: false }] });
add({ id: "default-environment-production", files: {}, answers: [{ q: "^Organization:", a: 0 }, { q: "^Project:", a: 0 }, { q: "^Default environment", a: 1 }] });
add({ id: "flags-project", files: {}, answers: [{ q: "^Organization:", a: 0 }, { q: "^Default environment", a: 0 }], extra: { project: "api" } });
add({ id: "flags-default-environment", files: { ".env": "PORT=3000\n" }, answers: [{ q: "^Organization:", a: 0 }, { q: "^Project:", a: 0 }, into(".env", 1), { q: "^Delete \\.env\\?", a: false }], extra: { defaultEnvironment: "staging" } });
add({
  id: "type-conflict-picks-integer",
  files: { ".env": `TIMEOUT=30\n`, ".env.production": `TIMEOUT=fast\n` },
  answers: [...pick, into(".env", 0), into(".env.production", 1), { q: "^TIMEOUT: the files suggest different types", a: 1 }, { q: "^Items that are not secret", a: "" }, { q: "^Activate it\\?", a: true }, { q: "^Delete \\.env\\?", a: false }, { q: "^Delete \\.env\\.production\\?", a: false }],
});
add({ id: "push-answers-active", files: { ".env": `API_KEY=${CANARY_DEV}\n` }, fake: { pushActive: true }, answers: [...pick, into(".env", 0), { q: "^Items that are not secret", a: "" }, { q: "^Delete \\.env\\?", a: false }] });
add({
  id: "file-order",
  files: { ".env.production": "B=1\n", ".env.b": "B=1\n", ".env.A": "A=1\n", ".env": "Z=1\n", ".env.example": "Z=\n", ".env.schema": "Z=\n", ".envrc": "Z=1\n" },
  answers: [...pick, into(".env", 2), into(".env.A", 2), into(".env.b", 2), into(".env.production", 2)],
});
add({ id: "single-shared-environment", files: {}, fake: { envs: [{ name: "main", tier: "production", kind: "shared" }, { name: "pr-1", tier: "development", kind: "preview" }] }, answers: [{ q: "^Organization:", a: 0 }, { q: "^Project:", a: 0 }] });

// ---- The terminal prompter ------------------------------------------------------

type Op = { select: string; options: string[]; preselected?: number } | { confirm: string; defaultYes: boolean } | { text: string; defaultValue?: string } | { say: string };
interface PromptCase {
  id: string;
  /** What is typed, all of it given before the first question (lines typed ahead wait). */
  input: string;
  ops: Op[];
  expect?: unknown;
}
const promptCases: PromptCase[] = [
  { id: "select.number", input: "2\n", ops: [{ select: "Organization:", options: ["acme (Acme)", "Create a new organization"], preselected: 0 }] },
  { id: "select.enter", input: "\n", ops: [{ select: "Project:", options: ["a", "b", "c"], preselected: 1 }] },
  { id: "select.retry", input: "0\n4\nx\n1.5\n 3 \n", ops: [{ select: "Pick:", options: ["a", "b", "c"] }] },
  { id: "select.number-forms", input: "0x2\n", ops: [{ select: "Pick:", options: ["a", "b", "c"] }] },
  { id: "select.plus-and-exponent", input: "+1\n1e0\n", ops: [{ select: "Pick:", options: ["a", "b"] }, { select: "Pick:", options: ["a", "b"] }] },
  { id: "confirm.default-yes", input: "\n", ops: [{ confirm: "Activate it?", defaultYes: true }] },
  { id: "confirm.default-no", input: "\n", ops: [{ confirm: "Delete .env?", defaultYes: false }] },
  { id: "confirm.words", input: "YES\nmaybe\nNo\n", ops: [{ confirm: "Sure?", defaultYes: false }, { confirm: "Sure?", defaultYes: true }] },
  { id: "text.default", input: "\n", ops: [{ text: "Its name", defaultValue: "acme" }] },
  { id: "text.typed", input: "  Acme Inc  \n", ops: [{ text: "Its name", defaultValue: "acme" }] },
  { id: "text.no-default", input: "\n", ops: [{ text: "Your address" }] },
  { id: "lines.cr-and-crlf", input: "a\rb\r\nc\n", ops: [{ text: "One" }, { text: "Two" }, { text: "Three" }] },
  { id: "lines.last-without-newline", input: "last", ops: [{ text: "Only" }] },
  { id: "say", input: "", ops: [{ say: "A line between questions." }] },
  { id: "input-ends", input: "1\n", ops: [{ select: "Pick:", options: ["a"] }, { text: "Next" }] },
];

async function recordPrompts(c: PromptCase): Promise<unknown> {
  const input = new PassThrough();
  const output = new PassThrough();
  let written = "";
  output.on("data", (d: Buffer) => (written += d.toString()));
  const prompt = terminalPrompter(input, output);
  input.end(c.input);
  const results: unknown[] = [];
  let error: string | null = null;
  try {
    for (const op of c.ops) {
      if ("select" in op) results.push(await prompt.select(op.select, op.options, op.preselected));
      else if ("confirm" in op) results.push(await prompt.confirm(op.confirm, op.defaultYes));
      else if ("text" in op) results.push(await prompt.text(op.text, op.defaultValue));
      else results.push((prompt.say(op.say), null));
    }
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
  }
  prompt.close();
  await new Promise((resolve) => setImmediate(resolve));
  return { results, error, written };
}

// ---- Recording ------------------------------------------------------------------

const scratch = mkdtempSync(join(tmpdir(), "varlatch-go-vectors-guided-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function scripted(answers: Answer[], dir: string): Prompter & { asked: string[]; said: string[]; shown: string[] } {
  const asked: string[] = [];
  const shown: string[] = [];
  const said: string[] = [];
  const queue = [...answers];
  const problems: string[] = [];
  const next = (question: string) => {
    asked.push(question);
    const answer = queue.shift();
    if (!answer) problems.push(`unexpected question: ${question}`);
    else if (!new RegExp(answer.q).test(question)) problems.push(`expected a question matching ${answer.q}, got: ${question}`);
    if (!answer || problems.length > 0) throw new Error(problems.at(-1));
    for (const [name, text] of Object.entries(answer.write ?? {})) writeFileSync(join(dir, name), text);
    return answer.a;
  };
  return {
    asked,
    said,
    shown,
    select: async (q, options) => {
      shown.push(...options);
      return next(q) as number;
    },
    confirm: async (q) => next(q) as boolean,
    text: async (q) => next(q) as string,
    say: (line) => void said.push(line),
    pause: () => {},
    resume: () => {},
    close: () => {},
    get left() {
      return queue.length;
    },
    problems,
  } as never;
}

async function record(c: Case): Promise<unknown> {
  const dir = mkdtempSync(join(scratch, `${c.id}-`));
  for (const [name, text] of Object.entries(c.files)) writeFileSync(join(dir, name), text);
  const { f, api } = fake(c.fake ?? {});
  const prompt = scripted(c.answers, dir);
  const out: string[] = [];
  const err: string[] = [];
  const written: unknown[] = [];
  const code = await guidedInit({
    cwd: dir,
    prompt,
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    server: c.server === null ? undefined : (c.server ?? "https://vault.example.com"),
    validateServer: (raw) => {
      if (c.validate === "no-query" && raw.includes("?")) throw new Error(`Use an origin without path or query: ${raw}`);
      return raw;
    },
    signIn: async () => api,
    writeRepository: async (config) => void written.push(config),
    ...(c.extra ?? {}),
  });
  const left = (prompt as unknown as { left: number }).left;
  const problems = (prompt as unknown as { problems: string[] }).problems;
  if (problems.length > 0) throw new Error(`${c.id}: ${problems.join("; ")}`);
  if (left > 0) throw new Error(`${c.id}: ${left} answer(s) never asked for; asked ${JSON.stringify(prompt.asked)}; out ${JSON.stringify(out)} err ${JSON.stringify(err)}`);
  const text = [...out, ...err, ...prompt.said].join("\n");
  for (const canary of [CANARY_DEV, CANARY_PROD, CANARY_OLD, "pw9secret", "URL_CANARY_7723"]) {
    if (text.includes(canary)) throw new Error(`${c.id}: ${canary} reached the output`);
  }
  const remaining = Object.fromEntries(
    readdirSync(dir)
      .sort()
      .map((name) => [name, readFileSync(join(dir, name), "utf8")]),
  );
  return {
    code,
    out,
    err,
    asked: prompt.asked,
    shown: prompt.shown,
    said: prompt.said,
    written,
    calls: f.calls,
    state: {
      orgs: f.orgs,
      projects: f.projects,
      envs: f.envs,
      values: Object.fromEntries([...f.values].map(([env, v]) => [env, Object.fromEntries(v)])),
      revisions: f.revisions,
    },
    files: remaining,
    deleted: Object.keys(c.files).filter((name) => !existsSync(join(dir, name))),
  };
}

describe("Go CLI guided init vectors", () => {
  it("are recorded from guidedInit.ts as it is", async () => {
    const ids = new Set<string>();
    const recorded: Case[] = [];
    for (const c of cases) {
      if (ids.has(c.id)) throw new Error(`case ${c.id} twice`);
      ids.add(c.id);
      recorded.push({ ...c, expect: await record(c) });
    }
    const prompts: PromptCase[] = [];
    for (const c of promptCases) prompts.push({ ...c, expect: await recordPrompts(c) });
    const text = `{\n"schema": 1,\n"comment": ${JSON.stringify("Recorded from apps/cli/src/guidedInit.ts and prompt.ts by apps/cli/test/go-vectors-guided-init.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.")},\n"cases": [\n${recorded.map((c) => JSON.stringify(c)).join(",\n")}\n],\n"prompter": [\n${prompts.map((c) => JSON.stringify(c)).join(",\n")}\n]\n}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "guided-init.json is stale: regenerate it (see this file's comment)").toBe(true);
    const all = JSON.stringify(recorded);
    for (const marker of ["Deleted .env.", "changed or disappeared", "not attempted in", "UNRECOGNIZED_ERROR", "No organization was created.", "is not a new item; ignored.", "one file per environment", "Not typed"]) {
      expect(all, marker).toContain(marker);
    }
  }, 120_000);
});
