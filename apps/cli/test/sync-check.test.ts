// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { checkExitCode, compareKeys, type CheckedKey } from "../src/syncCheck.js";
import { contractItem, revision } from "./fixtures.js";

/**
 * `varlatch sync check` (ADR-0044): the CLI, bundled from this checkout's
 * source, against a fake Varlatch API and fake Coolify and Convex APIs over
 * real HTTPS. Every value in the fixture, Varlatch's and the platforms',
 * short ones included, is checked against everything the command prints.
 */

describe("compareKeys", () => {
  const pairs = (...names: string[]) => names.map((name) => ({ name, destination: name }));

  it("gives each key one status, from presence and exact equality", () => {
    const varlatch = new Map<string, string | null>([
      ["SAME", "v1"],
      ["CHANGED", "new"],
      ["SPACES", "token"],
      ["ONLY_HERE", "x"],
      ["HIDDEN", null],
      ["HIDDEN_MISSING", null],
    ]);
    const platform = new Map([
      ["SAME", "v1"],
      ["CHANGED", "old"],
      ["SPACES", "token\n"],
      ["ONLY_THERE", "y"],
      ["HIDDEN", "z"],
    ]);
    const keys = compareKeys(pairs("SAME", "CHANGED", "SPACES", "ONLY_HERE", "ONLY_THERE", "HIDDEN", "HIDDEN_MISSING", "NOWHERE"), varlatch, platform);
    expect(keys.map((k) => [k.name, k.status, k.reason ?? null])).toEqual([
      ["SAME", "match", null],
      ["CHANGED", "differs", null],
      // No normalization: whitespace in a credential matters.
      ["SPACES", "differs", null],
      ["ONLY_HERE", "missing-on-platform", null],
      ["ONLY_THERE", "extra-on-platform", null],
      ["HIDDEN", "unreadable", "withheld"],
      // Presence needs no value: a withheld item the platform lacks is still missing there.
      ["HIDDEN_MISSING", "missing-on-platform", null],
      ["NOWHERE", "absent", null],
    ]);
  });

  it("compares a mapped item against its platform name", () => {
    const keys = compareKeys([{ name: "API_TOKEN", destination: "APP_API_TOKEN" }], new Map([["API_TOKEN", "t"]]), new Map([["APP_API_TOKEN", "t"], ["API_TOKEN", "other"]]));
    expect(keys).toEqual([{ name: "API_TOKEN", destination: "APP_API_TOKEN", status: "match" }]);
  });

  it("a write-only platform leaves every key unreadable, and a name the platform cannot store is never compared", () => {
    expect(compareKeys(pairs("A", "B"), new Map([["A", "1"]]), null).map((k) => k.reason)).toEqual(["platform-write-only", "platform-write-only"]);
    expect(compareKeys([{ name: "a-b", destination: "a-b", invalid: true }], new Map([["a-b", "1"]]), new Map()).map((k) => k.reason)).toEqual(["invalid-name"]);
  });

  it("exit status: 0 all match (absent keys are no drift), 1 any drift, else 2 when something was not compared", () => {
    const k = (status: CheckedKey["status"]): CheckedKey => ({ name: "X", destination: "X", status });
    expect(checkExitCode([k("match"), k("absent")])).toBe(0);
    expect(checkExitCode([])).toBe(0);
    for (const drift of ["differs", "missing-on-platform", "extra-on-platform"] as const) expect(checkExitCode([k("match"), k(drift), k("unreadable")])).toBe(1);
    expect(checkExitCode([k("match"), k("unreadable")])).toBe(2);
  });
});

// Every value below must never appear in the command's output, in any mode.
const V = {
  API_TOKEN: "api-token-canary-7f3a9c1e",
  SENTRY_AUTH_TOKEN: "sentry-canary-b62d1f0a",
  DATABASE_URL: "postgres://app:db-canary-5c2e@db.internal/app",
  PIN: "q7Zx2Kw", // 7 bytes: too short to mask
  LOG_LEVEL: "info-canary-level",
  STRAY_SECRET: "stray-canary-91d0",
};
const PLATFORM = {
  SENTRY_OLD: "sentry-old-canary-44e1",
  PREVIEW_DB: "postgres://app:preview-canary-0d3f@db.internal/app",
  OLD_FLAG: "old-flag-canary-77",
  FQDN: "https://fqdn-canary.example",
  LOG_LEVEL: "debug-canary-level",
};
const ALL_VALUES = [...Object.values(V), ...Object.values(PLATFORM)];

const COOLIFY_TOKEN = "coolify-token-canary-3e8b";
const CONVEX_CREDENTIAL = "convex-credential-canary";
const APP = "app-uuid-0001";

const dir = mkdtempSync(join(tmpdir(), "varlatch-sync-check-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
let api: http.Server;
let platformServer: https.Server;
let origin = "";
let platformOrigin = "";

interface Stored {
  name: string;
  sensitive: boolean;
  value: string;
}

/** Fixture state, reset before each test. */
let stored: Stored[];
let contract: Record<string, unknown>[] | null;
let denyDisclosure: boolean;
let coolifyRows: Record<string, unknown>[];
let coolifyMode: "ok" | "garbage" | "unauthorized";
let convexVars: { name: string; value: string }[];
let requests: { url: string; body: unknown; seq: number }[];
let platformRequests: { method: string; url: string; auth: string; seq: number }[];
/** One order across both fake servers (they run in this process). */
let seq = 0;

const CONTRACT_ITEMS = [
  contractItem("API_TOKEN", { sensitive: true }),
  contractItem("DATABASE_URL", { sensitive: true }),
  contractItem("LOG_LEVEL"),
  contractItem("OLD_FLAG"),
  contractItem("OPTIONAL_X"),
  contractItem("PIN", { sensitive: true }),
  contractItem("SENTRY_AUTH_TOKEN", { sensitive: true }),
];

function defaults(): void {
  stored = [
    { name: "API_TOKEN", sensitive: true, value: V.API_TOKEN },
    { name: "SENTRY_AUTH_TOKEN", sensitive: true, value: V.SENTRY_AUTH_TOKEN },
    { name: "DATABASE_URL", sensitive: true, value: V.DATABASE_URL },
    { name: "PIN", sensitive: true, value: V.PIN },
    { name: "LOG_LEVEL", sensitive: false, value: V.LOG_LEVEL },
    // Stored, but not in the Contract: not compared.
    { name: "STRAY_SECRET", sensitive: true, value: V.STRAY_SECRET },
  ];
  contract = CONTRACT_ITEMS;
  denyDisclosure = false;
  coolifyMode = "ok";
  coolifyRows = [
    { uuid: "e1", key: "API_TOKEN", value: V.API_TOKEN, is_preview: false },
    { uuid: "e2", key: "SENTRY_AUTH_TOKEN", value: PLATFORM.SENTRY_OLD, is_preview: false },
    // The preview copy holds the right value: it must not stand in for the production row.
    { uuid: "e3", key: "SENTRY_AUTH_TOKEN", value: V.SENTRY_AUTH_TOKEN, is_preview: true },
    // Only a preview row: the production app does not have it.
    { uuid: "e4", key: "DATABASE_URL", value: PLATFORM.PREVIEW_DB, is_preview: true },
    { uuid: "e5", key: "PIN", value: V.PIN, is_preview: false },
    { uuid: "e6", key: "LOG_LEVEL", value: PLATFORM.LOG_LEVEL, is_preview: false },
    // In the Contract, not stored in Varlatch.
    { uuid: "e7", key: "OLD_FLAG", value: PLATFORM.OLD_FLAG, is_preview: false },
    // The platform's own, outside the Contract: never compared.
    { uuid: "e8", key: "COOLIFY_FQDN", value: PLATFORM.FQDN, is_preview: false },
  ];
  convexVars = [
    { name: "API_TOKEN", value: V.API_TOKEN },
    { name: "SENTRY_AUTH_TOKEN", value: PLATFORM.SENTRY_OLD },
    { name: "PIN", value: V.PIN },
    { name: "LOG_LEVEL", value: V.LOG_LEVEL },
    { name: "OLD_FLAG", value: PLATFORM.OLD_FLAG },
    { name: "CONVEX_SITE_EXTRA", value: PLATFORM.FQDN },
  ];
  requests = [];
  platformRequests = [];
}

/** Every key in the Contract present on the platform with Varlatch's value, nothing extra. */
function inSync(): void {
  coolifyRows = stored
    .filter((s) => CONTRACT_ITEMS.some((c) => c.name === s.name))
    .map((s, i) => ({ uuid: `s${i}`, key: s.name, value: s.value, is_preview: false }))
    .concat([{ uuid: "x", key: "COOLIFY_FQDN", value: PLATFORM.FQDN, is_preview: false }]);
  convexVars = stored.filter((s) => CONTRACT_ITEMS.some((c) => c.name === s.name)).map((s) => ({ name: s.name, value: s.value }));
}

const ENV_PATH = "/v1/organizations/acme/projects/web/environments/production";

function answerApi(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as unknown) : undefined;
    requests.push({ url, body, seq: ++seq });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    const active = contract ? revision(contract, { id: "crv_active" }) : null;
    if (url === "/v1/meta") return json(200, { serverVersion: "0.14.1", capabilities: ["retrieval.strict"], semanticsVersions: [1, 2, 3] });
    if (url === "/v1/organizations/acme/projects/web/contract") return active ? json(200, active) : json(404, { error: { code: "NOT_FOUND", message: "no contract", requestId: "r" } });
    if (url.startsWith(`${ENV_PATH}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_prod",
        // As the daemon: non-sensitive values with include=values, never a Secret's.
        items: stored.map((s) => ({ name: s.name, sensitive: s.sensitive, source: "self", value: s.sensitive ? null : s.value })),
        stateDigest: `sha256:${"0".repeat(64)}`,
        manifest: {
          manifestVersion: 1,
          projectId: "prj_1",
          environment: { id: "env_prod", rootId: "env_prod", parentId: null, tier: "production", expiresAt: null },
          contract: active ? { revisionId: active.id, contentHash: active.contentHash, semanticsVersion: 2 } : null,
          items: [],
        },
      });
    }
    if (url === `${ENV_PATH}/disclosures`) {
      if (denyDisclosure) return json(403, { error: { code: "PERMISSION_DENIED", message: "secret.reveal needed", requestId: "r" } });
      // As the server: a request that names its items gets only those.
      const asked = (body as { items?: string[] }).items;
      const secrets = stored.filter((s) => s.sensitive && (!asked || asked.includes(s.name)));
      return json(200, { items: secrets.map((s) => ({ name: s.name, versionId: `ver_${s.name}`, value: s.value })), withheld: [] });
    }
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
  });
}

function answerPlatform(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    const auth = req.headers.authorization ?? "";
    platformRequests.push({ method: req.method ?? "", url, auth, seq: ++seq });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (url === `/api/v1/applications/${APP}/envs` && req.method === "GET") {
      if (coolifyMode === "unauthorized" || auth !== `Bearer ${COOLIFY_TOKEN}`) return json(401, { message: "Unauthenticated." });
      if (coolifyMode === "garbage") {
        // Not JSON, and quoting values: a parse error would repeat this text.
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(`<html>${V.API_TOKEN} ${V.PIN} ${PLATFORM.SENTRY_OLD}</html>`);
      }
      return json(200, coolifyRows);
    }
    if (url === "/api/query" && req.method === "POST") {
      if (auth !== `Convex ${CONVEX_CREDENTIAL}`) return json(401, { code: "Unauthenticated" });
      return json(200, { status: "success", value: convexVars });
    }
    json(404, { message: "not found" });
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
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
    { stdio: "ignore" },
  );
  platformServer = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) }, answerPlatform);
  await new Promise<void>((resolve) => platformServer.listen(0, "127.0.0.1", resolve));
  platformOrigin = `https://127.0.0.1:${(platformServer.address() as AddressInfo).port}`;
  api = http.createServer(answerApi);
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => api.close(resolve));
  await new Promise((resolve) => platformServer.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(defaults);

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], extra: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve) => {
    const env = {
      PATH: process.env.PATH,
      HOME: dir,
      VARLATCH_CONFIG_DIR: join(dir, "config"),
      VARLATCH_TOKEN: "vlt_test",
      NODE_EXTRA_CA_CERTS: join(dir, "cert.pem"),
      COOLIFY_TOKEN,
      CONVEX_KEY: CONVEX_CREDENTIAL,
      ...extra,
    };
    const child = spawn(process.execPath, [bundle, ...args], { cwd: repo, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const coolify = (...extra: string[]) => ["sync", "check", "--platform", "coolify", "--base", platformOrigin, "--app", APP, "-e", "production", "--token-env", "COOLIFY_TOKEN", ...extra];
const convex = (...extra: string[]) => ["sync", "check", "--platform", "convex", "--base", platformOrigin, "-e", "production", "--token-env", "CONVEX_KEY", ...extra];

/** Every fixture value found in the output, and the platform tokens: must be none. */
function leaked(r: Result): string[] {
  const all = r.stdout + r.stderr;
  return [...ALL_VALUES, COOLIFY_TOKEN, CONVEX_CREDENTIAL].filter((v) => all.includes(v));
}

const statuses = (r: Result) => Object.fromEntries((JSON.parse(r.stdout) as { keys: CheckedKey[] }).keys.map((k) => [k.name, k.reason ? `${k.status}:${k.reason}` : k.status]));
const disclosures = () => requests.filter((q) => q.url === `${ENV_PATH}/disclosures`).map((q) => q.body);

describe("sync check against Coolify", () => {
  it("reports each Contract key's status: match, differs, missing, extra, absent; preview rows ignored; exit 1 on drift", async () => {
    const r = await cli(coolify("--json"));
    expect(r.code, r.stderr).toBe(1);
    expect(statuses(r)).toEqual({
      API_TOKEN: "match",
      // Production row differs; the preview row's matching value does not count.
      SENTRY_AUTH_TOKEN: "differs",
      // Only a preview row holds it.
      DATABASE_URL: "missing-on-platform",
      PIN: "match",
      LOG_LEVEL: "differs",
      OLD_FLAG: "extra-on-platform",
      OPTIONAL_X: "absent",
    });
    const doc = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(doc).toMatchObject({ version: 1, result: "drift", platform: "coolify", base: platformOrigin, destination: { applicationUuid: APP }, environment: "production", keySet: "contract", exitCode: 1 });
    expect(doc.counts).toEqual({ match: 2, differs: 2, "missing-on-platform": 1, "extra-on-platform": 1, unreadable: 0, absent: 1 });
    // Contract keys only: neither a stored item outside the Contract nor the platform's own keys.
    expect(r.stdout + r.stderr).not.toMatch(/STRAY_SECRET|COOLIFY_FQDN/);
    expect(leaked(r)).toEqual([]);
  });

  it("the human form names keys and statuses only", async () => {
    const r = await cli(coolify());
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(`coolify ${platformOrigin} ${APP} against production:`);
    expect(r.stdout).toMatch(/^ {2}differs\s+SENTRY_AUTH_TOKEN$/m);
    expect(r.stdout).toMatch(/^ {2}missing on the platform\s+DATABASE_URL$/m);
    expect(r.stdout).toMatch(/^ {2}extra on the platform\s+OLD_FLAG$/m);
    expect(r.stdout).toMatch(/^ {2}match\s+PIN$/m);
    expect(r.stdout).toContain("DRIFT: 2 match, 2 differ, 1 missing on the platform, 1 extra on the platform, 0 not compared");
    expect(leaked(r)).toEqual([]);
  });

  it("all in sync: exit 0", async () => {
    inSync();
    const r = await cli(coolify());
    expect(r.code, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toContain("in sync: 5 match, 0 differ, 0 missing on the platform, 0 extra on the platform, 0 not compared");
    expect(leaked(r)).toEqual([]);
  });

  it("reads the platform first, then discloses only the Secrets the platform also holds, by name", async () => {
    await cli(coolify());
    // Not DATABASE_URL (missing on the platform: presence decides), not STRAY_SECRET (outside the Contract).
    expect(disclosures()).toEqual([{ items: ["API_TOKEN", "PIN", "SENTRY_AUTH_TOKEN"] }]);
    expect(platformRequests.map((p) => `${p.method} ${p.url}`)).toEqual([`GET /api/v1/applications/${APP}/envs`]);
    const disclosedAt = requests.find((q) => q.url === `${ENV_PATH}/disclosures`)?.seq as number;
    expect(platformRequests[0]!.seq).toBeLessThan(disclosedAt);
  });

  it("--map compares an item against a renamed platform key; --exclude skips names", async () => {
    coolifyRows.push({ uuid: "m1", key: "APP_API_TOKEN", value: V.API_TOKEN, is_preview: false });
    const mapped = await cli(coolify("--json", "--map", "API_TOKEN=APP_API_TOKEN", "--map", "LOG_LEVEL"));
    expect(mapped.code).toBe(1);
    expect(JSON.parse(mapped.stdout).keys).toEqual([
      { name: "API_TOKEN", destination: "APP_API_TOKEN", status: "match" },
      { name: "LOG_LEVEL", destination: "LOG_LEVEL", status: "differs" },
    ]);
    expect(JSON.parse(mapped.stdout).keySet).toBe("map");
    const excluded = await cli(coolify("--json", "--exclude", "SENTRY_*", "--exclude", "LOG_LEVEL", "--exclude", "OLD_FLAG", "--exclude", "DATABASE_URL"));
    expect(excluded.code).toBe(0);
    expect(Object.keys(statuses(excluded)).sort()).toEqual(["API_TOKEN", "OPTIONAL_X", "PIN"]);
    expect(leaked(mapped)).toEqual([]);
  });

  it("without an active Contract, compares the stored items and says that extras are not reported", async () => {
    contract = null;
    const r = await cli(coolify("--json"));
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("no active Contract: comparing the stored items, and extra-on-platform is not reported");
    expect(JSON.parse(r.stdout).keySet).toBe("stored");
    expect(statuses(r)).toMatchObject({ STRAY_SECRET: "missing-on-platform", API_TOKEN: "match" });
    expect(statuses(r)).not.toHaveProperty("OLD_FLAG");
    expect(leaked(r)).toEqual([]);
  });
});

describe("sync check: could not check (exit 2), and nothing disclosed", () => {
  it("no platform credential in the named variable", async () => {
    const r = await cli(coolify("--json"), { COOLIFY_TOKEN: "" });
    expect(r.code).toBe(2);
    expect(JSON.parse(r.stdout)).toMatchObject({ result: "unchecked", unchecked: "no platform credential in $COOLIFY_TOKEN (choose the variable with --token-env)", keys: [] });
    expect(platformRequests).toEqual([]);
    expect(disclosures()).toEqual([]);
  });

  it("the platform refuses the credential: its status only", async () => {
    coolifyMode = "unauthorized";
    const r = await cli(coolify());
    expect(r.code).toBe(2);
    expect(r.stderr).toContain(`varlatch: could not check coolify ${platformOrigin} ${APP} against production: Coolify env list failed (401)`);
    expect(disclosures()).toEqual([]);
    expect(leaked(r)).toEqual([]);
  });

  it("a response that is not JSON, quoting values: never repeated", async () => {
    coolifyMode = "garbage";
    for (const flags of [[], ["--json"]]) {
      const r = await cli(coolify(...flags));
      expect(r.code).toBe(2);
      expect(r.stdout + r.stderr).toContain("the platform's response could not be read (SyntaxError)");
      expect(leaked(r)).toEqual([]);
    }
    expect(disclosures()).toEqual([]);
  });

  it("Secrets this identity may not read: not compared (exit 2 when nothing drifted); presence still checked", async () => {
    inSync();
    denyDisclosure = true;
    const r = await cli(coolify("--json"));
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("varlatch: secrets not disclosed (PERMISSION_DENIED): Secrets the platform holds cannot be compared");
    expect(statuses(r)).toMatchObject({ API_TOKEN: "unreadable:withheld", PIN: "unreadable:withheld", LOG_LEVEL: "match" });
    // Drift found without values still wins: a Secret missing on the platform needs no value.
    coolifyRows = coolifyRows.filter((row) => row.key !== "DATABASE_URL");
    const drift = await cli(coolify("--json"));
    expect(drift.code).toBe(1);
    expect(statuses(drift)).toMatchObject({ DATABASE_URL: "missing-on-platform" });
  });

  it("GitHub Actions secrets are write-only: every key unreadable, no platform request, no disclosure, no credential needed", async () => {
    const r = await cli(["sync", "check", "--platform", "github-actions", "--base", "acme", "--repo", "web", "-e", "production", "--json"]);
    expect(r.code).toBe(2);
    expect(JSON.parse(r.stdout).result).toBe("incomplete");
    expect(new Set(Object.values(statuses(r)))).toEqual(new Set(["unreadable:platform-write-only"]));
    expect(r.stderr).toContain("github-actions values cannot be read back (write-only)");
    expect(platformRequests).toEqual([]);
    expect(disclosures()).toEqual([]);
  });
});

describe("sync check against Convex", () => {
  it("match, differs, missing, extra, absent; the deployment's own keys ignored; exit 1, then 0 in sync", async () => {
    const r = await cli(convex("--json"));
    expect(r.code, r.stderr).toBe(1);
    expect(statuses(r)).toEqual({
      API_TOKEN: "match",
      SENTRY_AUTH_TOKEN: "differs",
      DATABASE_URL: "missing-on-platform",
      PIN: "match",
      LOG_LEVEL: "match",
      OLD_FLAG: "extra-on-platform",
      OPTIONAL_X: "absent",
    });
    expect(r.stdout).not.toContain("CONVEX_SITE_EXTRA");
    expect(platformRequests.map((p) => `${p.method} ${p.url}`)).toEqual(["POST /api/query"]);
    expect(leaked(r)).toEqual([]);
    inSync();
    const ok = await cli(convex());
    expect(ok.code).toBe(0);
    expect(leaked(ok)).toEqual([]);
  });
});

describe("sync check in assisted mode, with a Secret too short to mask", () => {
  it.each([
    ["--assisted", ["--assisted"], {}],
    ["a coding agent's marker", [], { CLAUDECODE: "1" }],
  ] as const)("%s: the check runs and prints no value, where run refuses (the control)", async (_name, global, env) => {
    // Control, same Environment: PIN cannot be masked, so an assisted run refuses to start.
    const run = await cli([...global, "run", "-e", "production", "--", process.execPath, "-e", "console.log('started')"], env);
    expect(run.code).toBe(78);
    expect(run.stderr).toMatch(/cannot be masked in the command's output: PIN/);
    for (const flags of [[], ["--json"]]) {
      const r = await cli([...global, ...coolify(...flags)], env);
      expect(r.code, r.stderr).toBe(1);
      expect(r.stdout).toMatch(/PIN/);
      expect(leaked(r)).toEqual([]);
    }
    inSync();
    const ok = await cli([...global, ...coolify()], env);
    expect(ok.code).toBe(0);
    expect(leaked(ok)).toEqual([]);
  });
});

describe("sync check: a strict command line", () => {
  it.each([
    ["an unknown option", ["--jsn"], /unknown option --jsn/],
    ["a push-only option", ["--build-time", "true"], /unknown option --build-time/],
    ["--map with --exclude", ["--map", "API_TOKEN", "--exclude", "PIN"], /--exclude only applies without --map/],
    ["a --map name that is neither stored nor in the Contract", ["--map", "API_TOKN"], /--map must name items stored in this environment or in its Contract; not found: API_TOKN/],
    ["two items mapped to one platform name", ["--map", "API_TOKEN=X", "--map", "PIN=X"], /API_TOKEN and PIN both map to the platform name X/],
  ])("%s: exit 64, nothing read from the platform, nothing disclosed", async (_name, extra, message) => {
    const r = await cli(coolify(...extra));
    expect(r.code).toBe(64);
    expect(r.stderr).toMatch(message);
    expect(platformRequests).toEqual([]);
    expect(disclosures()).toEqual([]);
  });

  it("required options and a valid destination", async () => {
    expect((await cli(["sync", "check", "--base", platformOrigin])).code).toBe(64);
    const http = await cli(["sync", "check", "--platform", "coolify", "--base", "http://insecure.example", "--app", APP]);
    expect(http.code).toBe(64);
    expect(http.stderr).toMatch(/Coolify instance URL must be https/);
    expect((await cli(["sync", "check", "--platform", "nosuch", "--base", "x"])).stderr).toMatch(/unknown platform "nosuch"/);
  });
});
