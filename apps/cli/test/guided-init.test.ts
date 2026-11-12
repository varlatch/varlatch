// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { VarlatchApiError } from "@varlatch/sdk";
import { findEnvFiles, guidedInit, guidedSignIn, type GuidedApi } from "../src/guidedInit.js";
import type { Prompter } from "../src/prompt.js";

/**
 * Guided `varlatch init` (ADR-0058 Decision 2, Acceptance): planning every
 * .env file before writing, declined replacements left out, one Contract
 * revision for all files, activation asked on its own, deletion only when
 * nothing is left behind, and never a value in what it prints.
 */

const CANARY_DEV = "dev-canary-5d1f3a9e7b";
const CANARY_PROD = "prod-canary-0c4e8b2a61";
const CANARY_OLD = "old-canary-77aa31";

type Answer = { q: RegExp; a: number | boolean | string };

function scripted(answers: Answer[]): Prompter & { asked: string[]; said: string[]; shown: string[] } {
  const asked: string[] = [];
  const shown: string[] = [];
  const said: string[] = [];
  const next = (question: string) => {
    asked.push(question);
    const answer = answers.shift();
    if (!answer) throw new Error(`unexpected question: ${question}`);
    if (!answer.q.test(question)) throw new Error(`expected a question matching ${answer.q}, got: ${question}`);
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
  };
}

interface Fake {
  api: GuidedApi;
  orgs: { slug: string; name: string }[];
  projects: { slug: string; name: string; contractAuthority: "git" | "managed" }[];
  envs: { name: string; tier: string; kind: string }[];
  values: Map<string, Map<string, string>>;
  sensitive: Set<string>;
  revisions: { id: string; items: { name: string; type: string; sensitive: boolean }[]; active: boolean }[];
  unreadable: Set<string>;
  failOn: string | null;
  contractForbidden: boolean;
  /** Calls that fail with a server message carrying a value (it must never be printed). */
  failing: Set<"push" | "activate" | "read">;
  /** The code a failing call answers with: a server can put anything there. */
  failCode: string;
}

function fake(init: Partial<Pick<Fake, "orgs" | "projects" | "envs">> = {}): Fake {
  const f: Fake = {
    orgs: init.orgs ?? [{ slug: "acme", name: "Acme" }],
    projects: init.projects ?? [{ slug: "api", name: "API", contractAuthority: "git" }],
    envs: init.envs ?? [
      { name: "development", tier: "development", kind: "shared" },
      { name: "production", tier: "production", kind: "shared" },
    ],
    values: new Map(),
    sensitive: new Set(),
    revisions: [{ id: "rev_0", items: [{ name: "PORT", type: "integer", sensitive: false }], active: true }],
    unreadable: new Set(),
    failOn: null,
    contractForbidden: false,
    failing: new Set(),
    failCode: "VALIDATION_FAILED",
    api: undefined as unknown as GuidedApi,
  };
  const page = <T>(items: T[]) => ({ items, nextCursor: null });
  f.api = {
    listOrganizations: async () => page(f.orgs),
    createOrganization: async (input: { slug: string; name: string }) => (f.orgs.push(input), input),
    listProjects: async () => page(f.projects),
    createProject: async (_org: string, input: { slug: string; name: string; contractAuthority: "git" | "managed" }) => (f.projects.push(input), input),
    listEnvironments: async () => page(f.envs),
    createEnvironment: async (_o: string, _p: string, input: { name: string; tier: string }) => {
      const env = { ...input, kind: "shared" };
      f.envs.push(env);
      return env;
    },
    getActiveContract: async () => {
      if (f.contractForbidden) throw new VarlatchApiError(403, { code: "FORBIDDEN", message: "no", requestId: "r" } as never);
      const active = f.revisions.find((r) => r.active);
      if (!active) throw new VarlatchApiError(404, { code: "RESOURCE_NOT_FOUND", message: "none", requestId: "r" } as never);
      return { id: active.id, contract: { schemaVersion: 1, semanticsVersion: 3, items: active.items.map((i) => ({ ...i, required: { kind: "never" } })) } };
    },
    pushContractRevision: async (_o: string, _p: string, input: { contract: { items: { name: string; type: string; sensitive: boolean }[] } }) => {
      if (f.failing.has("push")) throw echo(422, f.failCode);
      const revision = { id: `rev_${f.revisions.length}`, items: input.contract.items, active: false };
      f.revisions.push(revision);
      return { id: revision.id, contentHash: "h", active: false };
    },
    activateContractRevision: async (_o: string, _p: string, id: string) => {
      if (f.failing.has("activate")) throw echo(409, f.failCode);
      for (const r of f.revisions) r.active = r.id === id;
      return {};
    },
    effectiveConfiguration: async (_o: string, _p: string, env: string) => {
      if (f.unreadable.has(env)) throw new VarlatchApiError(403, { code: "FORBIDDEN", message: "no", requestId: "r" } as never);
      if (f.failing.has("read")) throw echo(500, f.failCode);
      const stored = f.values.get(env) ?? new Map();
      return { items: [...stored].map(([name, value]) => ({ name, sensitive: f.sensitive.has(name), value: f.sensitive.has(name) ? null : value, rawValue: f.sensitive.has(name) ? null : value })) };
    },
    setValue: async (_o: string, _p: string, env: string, name: string, input: { value: string }) => {
      if (f.failOn === name) throw new VarlatchApiError(500, { code: f.failCode === "VALIDATION_FAILED" ? "INTERNAL" : f.failCode, message: "boom", requestId: "r" } as never);
      const stored = f.values.get(env) ?? new Map<string, string>();
      stored.set(name, input.value);
      f.values.set(env, stored);
      return {};
    },
  } as unknown as GuidedApi;
  return f;
}

/** A server error whose message echoes what was sent: it must never reach the output. */
function echo(status: number, code = "VALIDATION_FAILED") {
  return new VarlatchApiError(status, { code, message: `rejected ${CANARY_DEV} ${CANARY_PROD}`, requestId: "r" } as never);
}

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-guided-"));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return dir;
}

async function run(cwd: string, f: Fake, answers: Answer[], extra: { organization?: string; project?: string } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const written: unknown[] = [];
  const prompt = scripted(answers);
  const code = await guidedInit({
    cwd,
    prompt,
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    server: "https://vault.example.com",
    validateServer: (raw) => raw,
    signIn: async () => f.api,
    writeRepository: async (config) => void written.push(config),
    ...extra,
  });
  const text = [...out, ...err].join("\n");
  for (const canary of [CANARY_DEV, CANARY_PROD, CANARY_OLD]) expect(text, "a value reached the output").not.toContain(canary);
  expect(answers, "every scripted answer was asked for").toEqual([]);
  return { code, out: out.join("\n"), err: err.join("\n"), written, asked: prompt.asked, shown: prompt.shown };
}

const pickExisting: Answer[] = [
  { q: /^Organization:/, a: 0 },
  { q: /^Project:/, a: 0 },
  { q: /^Default environment/, a: 0 },
];

describe("guided init", () => {
  it("finds .env files and leaves examples and schemas out", () => {
    const dir = repo({ ".env": "A=1\n", ".env.production": "A=2\n", ".env.example": "A=\n", ".env.schema": "A=\n" });
    expect(findEnvFiles(dir)).toEqual([".env", ".env.production"]);
  });

  it("two files: one revision with both files' new items, a type conflict the person resolves, activation, then deletion", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\nTIMEOUT=30\nPORT=3000\n`, ".env.production": `API_KEY=${CANARY_PROD}\nTIMEOUT=fast\nSENTRY_DSN=https://x.example\n` });
    const f = fake();
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env into:/, a: 0 },
      { q: /^Import \.env\.production into:/, a: 1 },
      { q: /^TIMEOUT: the files suggest different types/, a: 0 },
      { q: /^Items that are not secret/, a: "TIMEOUT" },
      { q: /^Activate it\?/, a: true },
      { q: /^Delete \.env\?/, a: true },
      { q: /^Delete \.env\.production\?/, a: true },
    ]);
    expect(r.code).toBe(0);
    expect(r.written).toEqual([{ server: "https://vault.example.com", organization: "acme", project: "api", defaultEnvironment: "development" }]);
    // One revision: PORT kept as it was, every new item from both files.
    expect(f.revisions).toHaveLength(2);
    const rev = f.revisions[1]!;
    expect(rev.active).toBe(true);
    expect(rev.items.map((i) => i.name).sort()).toEqual(["API_KEY", "PORT", "SENTRY_DSN", "TIMEOUT"]);
    expect(rev.items.find((i) => i.name === "PORT")).toMatchObject({ type: "integer", sensitive: false });
    expect(rev.items.find((i) => i.name === "TIMEOUT")).toMatchObject({ type: "string", sensitive: false });
    expect(rev.items.find((i) => i.name === "API_KEY")).toMatchObject({ sensitive: true });
    expect(f.values.get("development")?.get("API_KEY")).toBe(CANARY_DEV);
    expect(f.values.get("production")?.get("API_KEY")).toBe(CANARY_PROD);
    expect(existsSync(join(dir, ".env")) || existsSync(join(dir, ".env.production"))).toBe(false);
    expect(r.out).toContain("$ varlatch contract activate rev_1");
  });

  it("asks only for what the flags leave out", async () => {
    const dir = repo({});
    const f = fake();
    const r = await run(dir, f, [{ q: /^Project:/, a: 0 }, { q: /^Default environment/, a: 0 }], { organization: "acme" });
    expect(r.code).toBe(0);
    expect(r.asked.some((q) => q.startsWith("Organization"))).toBe(false);
  });

  it("creates the organization, project and environments only after asking", async () => {
    const dir = repo({});
    const f = fake({ orgs: [], projects: [], envs: [] });
    const r = await run(dir, f, [
      { q: /^New organization's slug/, a: "acme" },
      { q: /^Its name/, a: "Acme" },
      { q: /^Create organization acme \(Acme\)\?/, a: true },
      { q: /^New project's slug/, a: "api" },
      { q: /^Its name/, a: "API" },
      { q: /^Create project api in acme\?/, a: true },
      { q: /^The project has no environments/, a: true },
      { q: /^Default environment/, a: 0 },
    ]);
    expect(r.code).toBe(0);
    expect(f.envs.map((e) => e.name)).toEqual(["development", "production"]);
    expect(r.out).toContain("$ varlatch env-create production --tier production");
  });

  it("a declined replacement stores the file's new names, leaves the declined one, and keeps the file", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\nNEW_ONE=hello\n` });
    const f = fake();
    f.values.set("development", new Map([["API_KEY", CANARY_OLD]]));
    f.sensitive.add("API_KEY");
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env into:/, a: 0 },
      { q: /^Replace it with the values in \.env\?/, a: false },
      { q: /^Items that are not secret/, a: "" },
      { q: /^Activate it\?/, a: true },
    ]);
    expect(r.code).toBe(0);
    expect(f.values.get("development")?.get("API_KEY")).toBe(CANARY_OLD);
    expect(f.values.get("development")?.get("NEW_ONE")).toBe("hello");
    expect(f.revisions[1]!.items.map((i) => i.name)).not.toContain("API_KEY");
    expect(existsSync(join(dir, ".env"))).toBe(true);
    expect(r.out).toContain(".env is kept: it holds values you chose not to store.");
  });

  it("replacing in production needs the environment's name typed", async () => {
    const dir = repo({ ".env.production": `API_KEY=${CANARY_PROD}\n` });
    const f = fake();
    f.values.set("production", new Map([["API_KEY", CANARY_OLD]]));
    f.sensitive.add("API_KEY");
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env\.production into:/, a: 1 },
      { q: /^Replace it with the values in \.env\.production\?/, a: true },
      { q: /^This is a production environment\. Type production/, a: "prod" },
    ]);
    expect(r.code).toBe(0);
    expect(f.values.get("production")?.get("API_KEY")).toBe(CANARY_OLD);
    expect(r.out).toContain("Not typed: they are left as they are.");
    expect(existsSync(join(dir, ".env.production"))).toBe(true);
  });

  it("skips and keeps a file whose environment's values cannot be read", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
    const f = fake();
    f.unreadable.add("development");
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }]);
    expect(r.code).toBe(0);
    expect(f.values.size).toBe(0);
    expect(f.revisions).toHaveLength(1);
    expect(existsSync(join(dir, ".env"))).toBe(true);
    expect(r.out).toMatch(/cannot be read \(403\).*kept/);
  });

  it("a declined activation leaves the revision inactive and keeps the file that added items", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
    const f = fake();
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env into:/, a: 0 },
      { q: /^Items that are not secret/, a: "" },
      { q: /^Activate it\?/, a: false },
    ]);
    expect(r.code).toBe(0);
    expect(f.revisions[1]!.active).toBe(false);
    expect(f.revisions[0]!.active).toBe(true);
    expect(existsSync(join(dir, ".env"))).toBe(true);
    expect(r.out).toContain("To activate it later: varlatch contract activate rev_1");
    expect(r.out).toContain(".env is kept: its new items are not in the active Contract.");
  });

  it("a managed Contract gets values only, and the file with new items is kept", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
    const f = fake({ projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] });
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }]);
    expect(r.code).toBe(0);
    expect(f.revisions).toHaveLength(1);
    expect(f.values.get("development")?.get("API_KEY")).toBe(CANARY_DEV);
    expect(existsSync(join(dir, ".env"))).toBe(true);
    expect(r.out).toContain("managed in the dashboard");
    expect(r.out).toContain(".env is kept: API_KEY still need adding to the Contract in the dashboard.");
  });

  it("keeps a file that changed after it was read", async () => {
    const dir = repo({ ".env": "PORT=3000\n" });
    const f = fake();
    const prompt = [...pickExisting, { q: /^Import \.env into:/, a: 0 }];
    const r = await run(dir, f, [
      ...prompt,
      {
        q: /^Delete \.env\?/,
        // The file changes between the plan and the deletion.
        get a() {
          writeFileSync(join(dir, ".env"), "PORT=4000\n");
          return true;
        },
      },
    ]);
    expect(r.code).toBe(0);
    expect(readFileSync(join(dir, ".env"), "utf8")).toBe("PORT=4000\n");
    expect(r.out).toContain(".env changed or disappeared since it was read; it was not deleted.");
  });

  it("an interrupted import stops, names what was and was not stored, and keeps every file", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\nC_ITEM=y\n`, ".env.production": `API_KEY=${CANARY_PROD}\n` });
    const f = fake();
    f.failOn = "B_ITEM";
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env into:/, a: 0 },
      { q: /^Import \.env\.production into:/, a: 1 },
      { q: /^Items that are not secret/, a: "" },
    ]);
    expect(r.code).not.toBe(0);
    expect(r.err).toContain("not stored in acme / api / development (.env): B_ITEM (INTERNAL)");
    expect(r.err).toContain("not attempted in acme / api / development (.env): C_ITEM");
    expect(f.revisions[1]!.active).toBe(false);
    expect(existsSync(join(dir, ".env")) && existsSync(join(dir, ".env.production"))).toBe(true);
  });

  it("keeps every file when the Contract cannot be read, even after a full import", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
    const f = fake();
    f.contractForbidden = true;
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }]);
    expect(r.code).toBe(0);
    expect(f.values.get("development")?.get("API_KEY")).toBe(CANARY_DEV);
    expect(r.asked.some((q) => q.startsWith("Delete"))).toBe(false);
    expect(existsSync(join(dir, ".env"))).toBe(true);
    expect(r.out).toContain(".env is kept: whether its items are in the Contract cannot be read.");
  });

  for (const [call, step, answers] of [
    ["push", "pushing the Contract revision", [{ q: /^Items that are not secret/, a: "" }]],
    ["activate", "activating Contract revision rev_1", [{ q: /^Items that are not secret/, a: "" }, { q: /^Activate it\?/, a: true }]],
    ["read", "reading what development already has", []],
  ] as const) {
    it(`a server error while ${step} prints the step and its code, never the server's text`, async () => {
      const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
      const f = fake();
      f.failing.add(call);
      const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }, ...answers]);
      expect(r.code).not.toBe(0);
      expect(r.err).toMatch(new RegExp(`varlatch init: ${step} failed \\(VALIDATION_FAILED, HTTP \\d+\\)\\.`));
      expect(r.err).toContain("every .env file is kept");
      expect(existsSync(join(dir, ".env"))).toBe(true);
    });
  }

  it("a managed Contract keeps its definitions, and a file whose items are all in it may go", async () => {
    const dir = repo({ ".env": "PORT=3000\n" });
    const f = fake({ projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] });
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }, { q: /^Delete \.env\?/, a: true }]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/PORT\s+integer\s+plain\s+in the Contract/);
    expect(f.revisions).toHaveLength(1);
    expect(existsSync(join(dir, ".env"))).toBe(false);
  });

  it("a managed Contract names what is missing from it, and keeps that file", async () => {
    const dir = repo({ ".env": `PORT=3000\nAPI_KEY=${CANARY_DEV}\n` });
    const f = fake({ projects: [{ slug: "api", name: "API", contractAuthority: "managed" }] });
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }]);
    expect(r.code).toBe(0);
    expect(r.out).toContain(".env is kept: API_KEY still need adding to the Contract in the dashboard.");
  });

  it("a failed write names, per destination, what was stored and what was never attempted, later files included", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\n`, ".env.production": `API_KEY=${CANARY_PROD}\nZ_ITEM=z\n` });
    const f = fake();
    f.failOn = "B_ITEM";
    const r = await run(dir, f, [
      ...pickExisting,
      { q: /^Import \.env into:/, a: 0 },
      { q: /^Import \.env\.production into:/, a: 1 },
      { q: /^Items that are not secret/, a: "" },
    ]);
    expect(r.code).not.toBe(0);
    expect(r.err).toContain("stored in acme / api / development (.env): API_KEY");
    expect(r.err).toContain("not stored in acme / api / development (.env): B_ITEM (INTERNAL)");
    expect(r.err).toContain("not attempted in acme / api / production (.env.production): API_KEY, Z_ITEM");
    expect(r.err).toContain("Contract revision rev_1 was not activated.");
  });

  it("never echoes a rejected address, which may hold a credential", async () => {
    const dir = repo({});
    const f = fake();
    const prompt = scripted([
      { q: /^Your Varlatch installation's address/, a: "https://vault.example.com/?token=URL_CANARY_7723" },
      { q: /^Your Varlatch installation's address/, a: "https://vault.example.com" },
      { q: /^Organization:/, a: 0 },
      { q: /^Project:/, a: 0 },
      { q: /^Default environment/, a: 0 },
    ]);
    const out: string[] = [];
    const code = await guidedInit({
      cwd: dir,
      prompt,
      out: (l) => out.push(l),
      err: (l) => out.push(l),
      server: undefined,
      validateServer: (raw) => {
        if (raw.includes("?")) throw new Error(`Use an origin without path or query: ${raw}`);
        return raw;
      },
      signIn: async () => f.api,
      writeRepository: async () => {},
    });
    expect(code).toBe(0);
    expect([...out, ...prompt.said].join("\n")).not.toContain("URL_CANARY_7723");
    expect(prompt.said[0]).toMatch(/^That is not an installation's address/);
  });

  it("the guided sign-in prints nothing a server sent, even when its answers echo the bearers", async () => {
    const handoff = "HANDOFF_CANARY_4410";
    const cli = "CLI_CANARY_9902";
    const out: string[] = [];
    const saved: unknown[] = [];
    const api = await guidedSignIn("https://vault.example.com", {
      browserLogin: async (server) => {
        out.push(`Complete passkey sign-in in your browser:\n  ${server}/enroll?callback=...`);
        return handoff;
      },
      client: (token) => ({
        // A hostile server echoing what it was sent in every field it controls.
        exchangeCliCredential: async () => ({ token: cli, id: `crd ${token}`, expiresAt: `expires ${token}` }) as never,
        listOrganizations: async () => ({ items: [{ slug: `org ${token}`, name: token }], nextCursor: null }) as never,
      }),
      save: (credential) => void saved.push(credential),
      out: (line) => out.push(line),
    });
    expect(api).toBeDefined();
    expect(saved).toHaveLength(1);
    const printed = out.join("\n");
    expect(printed).not.toContain(handoff);
    expect(printed).not.toContain(cli);
    expect(printed).toContain("Signed in to https://vault.example.com.");
  });

  it("prints an error code only when the protocol defines it: a server can echo a value there", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\n` });
    const f = fake();
    f.failing.add("push");
    f.failCode = CANARY_DEV;
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }, { q: /^Items that are not secret/, a: "" }]);
    expect(r.code).not.toBe(0);
    expect(r.err).toContain("pushing the Contract revision failed (UNRECOGNIZED_ERROR, HTTP 422).");
  });

  it("the same for a failed write's reason", async () => {
    const dir = repo({ ".env": `API_KEY=${CANARY_DEV}\nB_ITEM=x\n` });
    const f = fake();
    f.failOn = "B_ITEM";
    f.failCode = CANARY_PROD;
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }, { q: /^Items that are not secret/, a: "" }]);
    expect(r.code).not.toBe(0);
    expect(r.err).toContain("not stored in acme / api / development (.env): B_ITEM (UNRECOGNIZED_ERROR)");
  });

  it("shows server-provided names with control characters escaped, and uses the real ones for API calls", async () => {
    const hostile = "Acme\n  [2] Evil\u001b]52;c;ZXZpbA==\u0007\u001b[31m";
    const dir = repo({ ".env": "PORT=3000\n" });
    const f = fake({
      orgs: [{ slug: "acme", name: hostile }],
      envs: [{ name: "development", tier: "development", kind: "shared" }, { name: "production\u001b[2J", tier: "production", kind: "shared" }],
    });
    const r = await run(dir, f, [...pickExisting, { q: /^Import \.env into:/, a: 0 }, { q: /^Delete \.env\?/, a: false }]);
    expect(r.code).toBe(0);
    const everything = [r.out, r.err, ...r.asked, ...r.shown].join("\n");
    expect(everything).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
    expect(r.shown).toContain("acme (Acme\\u000a  [2] Evil\\u001b]52;c;ZXZpbA==\\u0007\\u001b[31m)");
    expect(r.written).toEqual([{ server: "https://vault.example.com", organization: "acme", project: "api", defaultEnvironment: "development" }]);
  });
});
