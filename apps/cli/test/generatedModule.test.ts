// SPDX-License-Identifier: Apache-2.0
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { StrictRetrieval } from "@varlatch/protocol";
import { exportedRunContext } from "../src/exportContext.js";
import { RUN_CONTEXT } from "../src/inject.js";
import { planStrictRun } from "../src/strictRun.js";
import { generateTypesModule } from "../src/typegen.js";
import { ITEMS, revision } from "./fixtures.js";

/**
 * The generated module is all an application needs: it is compiled here by
 * the TypeScript compiler under strict consumer settings (ES modules and
 * CommonJS, with no Node or DOM type definitions), and run in a child Node
 * process with a crafted environment and run context.
 */

const REVISION = revision(ITEMS, { id: "crv_generated" });
const TSC = createRequire(import.meta.url).resolve("typescript/bin/tsc");

const MAIN = `import { ConfigError, config, generatedFrom, loadConfig, type Config, type PublicConfig } from "./varlatch.gen.js";

declare const process: { env: Record<string, string | undefined>; argv: string[] };
declare const console: { log(line: string): void };

// Types only; never called. A compile error fails the test.
export function typeChecks(): void {
  const port: number = config.PORT;
  const key: string = config.API_KEY;
  const level: "debug" | "info" | "warn" | undefined = config.LOG_LEVEL;
  const debug: boolean | undefined = config.DEBUG;
  // @ts-expect-error PORT is a number
  const wrong: string = config.PORT;
  // @ts-expect-error an item required only in some environments may be absent
  const dsn: string = config.SENTRY_DSN;
  // @ts-expect-error the configuration is read-only
  config.PORT = 1;
  // @ts-expect-error PublicConfig holds no Secrets
  const secret: PublicConfig["API_KEY"] = "x";
  // @ts-expect-error not a Contract item
  const unknown = config.NOT_AN_ITEM;
  const publicPort: PublicConfig["PORT"] = 1;
  const minimal: Config = { API_KEY: "k", DATABASE_URL: "u", PORT: 1 };
  const defaulted: readonly (keyof Config)[] = loadConfig({ applyDefaults: true, staleTypes: "throw" }).defaulted;
  const version: 2 = generatedFrom.semanticsVersion;
  void [port, key, level, debug, wrong, dsn, secret, unknown, publicPort, minimal, defaulted, version];
}

const envBefore = JSON.stringify(process.env);
const options = JSON.parse(process.argv[2] ?? "{}");
let report: Record<string, unknown>;
try {
  const result = loadConfig(options);
  let writeThrew = false;
  try {
    (result.config as unknown as Record<string, unknown>)["PORT"] = 2;
  } catch (err) {
    writeThrew = err instanceof TypeError;
  }
  report = {
    ok: true,
    config: result.config,
    keys: Object.keys(result.config),
    typeofPort: typeof result.config.PORT,
    defaulted: result.defaulted,
    notEvaluated: result.notEvaluated,
    context: result.context,
    warnings: result.warnings,
    writeThrew,
    generatedFrom,
  };
} catch (err) {
  const e = err as ConfigError;
  report = { ok: false, isConfigError: err instanceof ConfigError, name: e.name, issues: e.issues, message: e.message };
}
try {
  report["lazy"] = { ...config };
} catch (err) {
  report["lazyError"] = err instanceof ConfigError;
}
report["envUnchanged"] = JSON.stringify(process.env) === envBefore;
report["envPort"] = process.env["PORT"] ?? null;
console.log(JSON.stringify(report));
`;

const STRICT_FLAGS = {
  target: "ES2022",
  lib: ["ES2022"],
  types: [],
  strict: true,
  noUncheckedIndexedAccess: true,
  exactOptionalPropertyTypes: true,
  noImplicitOverride: true,
  noImplicitReturns: true,
  noUnusedLocals: true,
  noUnusedParameters: true,
  noPropertyAccessFromIndexSignature: true,
  isolatedModules: true,
  declaration: true,
  skipLibCheck: false,
  rootDir: "src",
  outDir: "dist",
};

const VARIANTS = {
  esm: {
    packageType: "module",
    compilerOptions: { ...STRICT_FLAGS, module: "NodeNext", moduleResolution: "NodeNext", verbatimModuleSyntax: true, isolatedDeclarations: true },
  },
  commonjs: { packageType: "commonjs", compilerOptions: { ...STRICT_FLAGS, module: "CommonJS", moduleResolution: "Node10" } },
} as const;

let root: string;

function run(file: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [file, ...args], { env }, (error, stdout, stderr) =>
      resolve({ code: error ? Number(error.code ?? 1) : 0, stdout, stderr }),
    );
  });
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "varlatch-generated-"));
  const generated = generateTypesModule(REVISION, { generatorVersion: "0.11.0-test" });
  for (const [name, variant] of Object.entries(VARIANTS)) {
    const dir = join(root, name);
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "varlatch.gen.ts"), generated);
    writeFileSync(join(dir, "src", "main.ts"), MAIN);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ type: variant.packageType }));
    writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: variant.compilerOptions, include: ["src"] }));
  }
}, 30_000);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** Runs the compiled application with exactly this environment. */
async function start(variant: keyof typeof VARIANTS, env: Record<string, string>, options: Record<string, unknown> = {}) {
  const result = await run(join(root, variant, "dist", "main.js"), [JSON.stringify(options)], env);
  expect(result.code, result.stderr).toBe(0);
  return { ...(JSON.parse(result.stdout) as Record<string, unknown>), stderr: result.stderr };
}

/** A strict retrieval for the generated Contract, in production. */
function strictRetrieval(items: { name: string; value: string | null; sensitive?: boolean }[], withheld: string[]): StrictRetrieval {
  return {
    mode: "strict",
    environmentId: "env_prod",
    manifest: {
      manifestVersion: 1,
      projectId: "prj_1",
      environment: { id: "env_prod", rootId: "env_prod", parentId: null, tier: "production", expiresAt: null },
      contract: { revisionId: REVISION.id, contentHash: REVISION.contentHash, semanticsVersion: 2 },
      items: items.map((i) => ({ name: i.name, source: "self", valueRowId: `val_${i.name}`, versionId: `ver_${i.name}` })),
    },
    stateDigest: `sha256:${"0".repeat(64)}`,
    stateDigests: {} as never,
    contract: REVISION.contract,
    items: items.map((i) => ({ name: i.name, sensitive: i.sensitive ?? false, source: "self", versionId: `ver_${i.name}`, value: i.value })),
    callerView: {
      withheld: withheld.map((name) => ({ name, reason: "permission", requires: "secret.reveal" })),
      unexpanded: [],
    },
    validation: { environmentId: "env_prod", valid: true, complete: true, missing: [], invalid: [], notEvaluated: [], unresolved: [] },
  } as StrictRetrieval;
}

const DELIVERED = [
  { name: "DATABASE_URL", value: "postgres://db.internal/app", sensitive: true },
  { name: "FEATURE_X", value: "1" },
  { name: "PORT", value: "8080" },
  { name: "SENTRY_DSN", value: "https://sentry.example.com/1" },
];

describe.each(Object.keys(VARIANTS).map((v) => [v as keyof typeof VARIANTS]))("the generated module (%s)", (variant) => {
  beforeAll(async () => {
    const compiled = await run(TSC, ["-p", join(root, variant)], { PATH: process.env.PATH });
    expect(compiled.stdout + compiled.stderr).toBe("");
    expect(compiled.code).toBe(0);
  }, 60_000);

  it("compiles under strict settings, and the accessor returns a withheld value supplied through --allow-inherited", async () => {
    // Strict startup: API_KEY is withheld by the server and inherited, as allowed.
    const plan = planStrictRun(
      strictRetrieval([...DELIVERED, { name: "API_KEY", value: null, sensitive: true }], ["API_KEY"]),
      { API_KEY: "key-from-the-shell-7f3a" },
      new Set(["API_KEY"]),
    );
    expect(plan.violations).toEqual([]);
    expect(JSON.parse(plan.env[RUN_CONTEXT] as string).items.API_KEY).toEqual({ server: "withheld", delivery: "inherited" });

    const report = await start(variant, plan.env as Record<string, string>);
    expect(report).toMatchObject({
      ok: true,
      context: "strict",
      typeofPort: "number",
      defaulted: [],
      notEvaluated: [],
      warnings: [],
      writeThrew: true,
      envUnchanged: true,
      envPort: "8080",
      generatedFrom: { revisionId: "crv_generated", contentHash: REVISION.contentHash, semanticsVersion: 2 },
    });
    expect(report.config).toEqual({
      API_KEY: "key-from-the-shell-7f3a",
      DATABASE_URL: "postgres://db.internal/app",
      FEATURE_X: true,
      // Strict startup injected the default; the accessor only converted it.
      LOG_LEVEL: "info",
      PORT: 8080,
      SENTRY_DSN: "https://sentry.example.com/1",
    });
    expect(report.lazy).toEqual(report.config);
  });

  it("an invalid configuration throws one ConfigError naming items and reasons, never values", async () => {
    const report = await start(variant, { API_KEY: "key-1", DATABASE_URL: "no url here", PORT: "80abc" });
    expect(report).toMatchObject({ ok: false, isConfigError: true, name: "ConfigError", lazyError: true, envUnchanged: true });
    expect(report.issues).toEqual([
      { name: "DATABASE_URL", reason: "must be a valid URL" },
      { name: "PORT", reason: "must be a number" },
    ]);
    const error = JSON.stringify({ issues: report.issues, message: report.message, stderr: report.stderr });
    for (const value of ["no url here", "80abc", "key-1"]) expect(error).not.toContain(value);
    // The accessor left the delivered string as it was.
    expect(report.envPort).toBe("80abc");
  });

  it("without a context: defaults only with applyDefaults, and conditional items not evaluated", async () => {
    const env = { API_KEY: "key-1", DATABASE_URL: "postgres://db/app", PORT: "3000" };
    const plain = await start(variant, env);
    expect(plain).toMatchObject({ ok: true, context: null, defaulted: [], notEvaluated: ["FEATURE_X", "SENTRY_DSN"] });
    expect(plain.config).not.toHaveProperty("LOG_LEVEL");

    const defaulted = await start(variant, env, { applyDefaults: true });
    expect(defaulted).toMatchObject({ ok: true, defaulted: ["LOG_LEVEL"] });
    expect((defaulted.config as Record<string, unknown>).LOG_LEVEL).toBe("info");

    const required = await start(variant, env, { requireContext: true });
    expect(required).toMatchObject({ ok: false, isConfigError: true });
  });

  it("under an exported context: defaults fill items not stored, never a withheld one, and stale types warn", async () => {
    const manifest = strictRetrieval(DELIVERED, []).manifest;
    const exported = (logLevel: string | null, inherited: Record<string, string> = {}) => {
      const effective = {
        environmentId: "env_prod",
        items: [
          ...DELIVERED.map((i) => ({ name: i.name, sensitive: i.sensitive ?? false, source: "self" as const, value: i.value })),
          { name: "API_KEY", sensitive: true, source: "self" as const, value: "key-delivered" },
          ...(logLevel === null ? [] : [{ name: "LOG_LEVEL", sensitive: false, source: "self" as const, value: null }]),
        ],
      };
      return exportedRunContext(manifest.contract!, manifest.environment, REVISION.contract as never, effective, inherited);
    };
    const base = { API_KEY: "key-delivered", ...Object.fromEntries(DELIVERED.map((i) => [i.name, i.value as string])) };

    // Not stored: applyDefaults fills it and reports it.
    const notStored = exported(null);
    expect(notStored.items.LOG_LEVEL).toEqual({ server: "notStored", delivery: "absent" });
    const filled = await start(variant, { ...base, [RUN_CONTEXT]: JSON.stringify(notStored) }, { applyDefaults: true });
    expect(filled).toMatchObject({ ok: true, context: "exported", defaulted: ["LOG_LEVEL"], warnings: [] });
    expect((filled.config as Record<string, unknown>).LOG_LEVEL).toBe("info");

    // Withheld by the server: no default stands in, and LOG_LEVEL is required here.
    const withheld = exported("withheld");
    expect(withheld.items.LOG_LEVEL).toEqual({ server: "withheld", delivery: "absent" });
    const refused = await start(variant, { ...base, [RUN_CONTEXT]: JSON.stringify(withheld) }, { applyDefaults: true });
    expect(refused).toMatchObject({ ok: false, isConfigError: true });
    expect(refused.issues).toEqual([{ name: "LOG_LEVEL", reason: "required in this environment, withheld by the server, and absent" }]);

    // A different content hash: stale types warn by default, and throw on request.
    const staleContext = JSON.stringify({ ...notStored, contractHash: `sha256:${"e".repeat(64)}` });
    const stale = await start(variant, { ...base, LOG_LEVEL: "warn", [RUN_CONTEXT]: staleContext });
    expect(stale).toMatchObject({ ok: true });
    expect(String((stale.warnings as string[])[0])).toContain("the types are stale");
    expect(stale.stderr).toContain("VarlatchWarning: the types are stale");
    const thrown = await start(variant, { ...base, LOG_LEVEL: "warn", [RUN_CONTEXT]: staleContext }, { staleTypes: "throw" });
    expect(thrown).toMatchObject({ ok: false, isConfigError: true });
  });
});
