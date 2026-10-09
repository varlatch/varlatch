// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { contractItem, revision } from "./fixtures.js";
import { EXIT } from "../src/exitCodes.js";
import { commandHelp } from "../src/usage.js";

/**
 * The CLI's machine interface (ADR-0043 Decision 10) end to end: help on
 * stdout with status 0, sysexits statuses for usage (64), an unreachable
 * server (69), and authentication or permission (77), the frozen statuses,
 * and the JSON document of every read command that gained --json.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-machine-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
let server: http.Server;
let origin = "";
let requests: { method: string; url: string }[] = [];

const ORG = "/v1/organizations/acme";
const PROJECT = `${ORG}/projects/web`;
const ENV = (name: string) => `${PROJECT}/environments/${name}`;

const REPORTS: Record<string, unknown> = {
  development: { valid: true, complete: true, missing: [], invalid: [], unresolved: [], notEvaluated: [] },
  staging: { valid: false, complete: true, missing: ["API_TOKEN"], invalid: [{ name: "PORT", reason: "must be a whole number" }], unresolved: [], notEvaluated: [] },
  production: {
    valid: false,
    complete: false,
    missing: [],
    invalid: [],
    unresolved: [],
    notEvaluated: [{ name: "API_TOKEN", reason: "authority", requires: "secret.reveal" }],
  },
};

const WHOAMI = {
  identity: { id: "idn_1", name: "runner-macmini", kind: "service", email: null },
  organization: { id: "org_1", slug: "acme", name: "Acme", createdAt: "2026-09-01T00:00:00.000Z" },
  credential: { id: "crd_1", name: "desktop-runner", kind: "service", expiresAt: null },
  listener: "tailnet",
  tailnet: { recognized: true, tailnet: "example.ts.net", nodeId: "nRunner", nodeName: "macmini", tags: ["tag:desktop-runner"] },
};

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    requests.push({ method: req.method ?? "", url });
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const error = (status: number, code: string) => json(status, { error: { code, message: code.toLowerCase(), requestId: "req_1" } });
    const auth = req.headers.authorization ?? "";
    if (auth === "Bearer vlt_bad") return error(401, "UNAUTHENTICATED");
    if (auth === "Bearer vlt_denied") return error(403, "PERMISSION_DENIED");
    if (auth === "Bearer vlt_overloaded") return error(503, "UNAVAILABLE");
    if (auth === "Bearer vlt_broken") return error(500, "INTERNAL");
    // A reverse proxy's error page, and a captive portal: not Varlatch API responses.
    if (auth === "Bearer vlt_html502") {
      res.writeHead(502, { "Content-Type": "text/html" });
      return res.end("<html><body>Bad Gateway from proxy-page-marker</body></html>");
    }
    if (auth === "Bearer vlt_html200") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body>portal-page-marker</body></html>");
    }
    // vlt_old: a server from before GET /v1/me (no identity.whoami).
    if (url === "/v1/meta") {
      return json(200, {
        apiMajor: 1,
        serverVersion: auth === "Bearer vlt_old" ? "0.16.0" : "0.17.0",
        semanticsVersions: [1, 2, 3],
        capabilities: auth === "Bearer vlt_old" ? ["identity.lifecycle"] : ["identity.lifecycle", "identity.whoami"],
      });
    }
    if (url === "/v1/me") return json(200, WHOAMI);
    if (url === "/v1/me/credentials") {
      return json(200, {
        items: [{ id: "crd_1", kind: "service", name: "desktop-runner", createdAt: "2026-09-01T00:00:00.000Z", expiresAt: null, current: true }],
        nextCursor: null,
      });
    }
    if (url === "/v1/organizations") return json(200, { items: [{ id: "org_1", slug: "acme", name: "Acme" }] });
    if (url === `${ORG}/projects`) return json(200, { items: [{ slug: "web", name: "Web", contractAuthority: "git", id: "prj_1" }] });
    if (url === `${ORG}/identities`) {
      return json(200, {
        items: [
          { id: "idn_1", name: "ci", kind: "service", disabled: false, lastSeenAt: "2026-09-30T10:00:00.000Z" },
          { id: "idn_2", name: "old", kind: "service", disabled: true },
        ],
      });
    }
    if (url === `${ORG}/identities/idn_1/credentials`) {
      return json(200, { items: [{ id: "crd_1", kind: "service", name: "deploy", createdAt: "2026-09-01T00:00:00.000Z", lastUsedAt: null }] });
    }
    if (url.startsWith(`${ORG}/audit-events`)) {
      return json(200, { items: [{ id: "evt_1", occurredAt: "2026-09-30T10:00:00.000Z", decision: "allow", eventType: "value.set", actorIdentityId: "idn_1" }] });
    }
    if (url === `${ORG}/requirements`) return json(200, { items: [{ id: "req_t1", target: { kind: "tier", tier: "production" }, selector: { tailnet: "x.ts.net" } }] });
    const validate = /environments\/([a-z]+)\/validate$/.exec(url);
    if (validate) return json(200, REPORTS[validate[1] as string]);
    if (url.startsWith(`${ENV("development")}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_1",
        items: [
          { name: "API_TOKEN", sensitive: true, source: "self", value: null },
          { name: "PORT", sensitive: false, source: "self", value: "8080" },
        ],
      });
    }
    if (url === `${ENV("development")}/disclosures`) return json(200, { items: [{ name: "API_TOKEN", versionId: "v", value: "json-canary-value-81" }], withheld: [] });
    const active = revision([contractItem("API_TOKEN", { sensitive: true })], { id: "crv_active" });
    if (url === `${PROJECT}/contract` && req.method === "GET") return json(200, active);
    if (url === `${PROJECT}/contract/revisions` && req.method === "POST") return json(201, { ...active, id: "crv_new", active: false });
    if (/\/values\/[A-Z_]+$/.test(url) && req.method === "PUT") return json(200, { versionId: "ver_1" });
    error(404, "NOT_FOUND");
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
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
  writeFileSync(join(repo, "contract.json"), JSON.stringify({ schemaVersion: 1, items: [contractItem("API_TOKEN", { sensitive: true })] }));
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("help", () => {
  it.each([[["--help"]], [["-h"]], [["help"]], [[]]])("%j prints the usage on stdout with status 0", async (args) => {
    const r = await cli(args);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^Usage:/m);
    expect(r.stdout).toMatch(/Exit status: 0 success/);
    expect(r.stderr).toBe("");
  });

  it("`<command> --help` and `help <command>` print that command's entries only, and contact no server", async () => {
    for (const args of [["run", "--help"], ["help", "run"], ["run", "-e", "prod", "-h"]]) {
      const r = await cli(args);
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/^Usage:\n {2}varlatch run /);
      expect(r.stdout).not.toMatch(/varlatch values/);
    }
    expect(requests).toEqual([]);
  });

  it("a --help after `--` belongs to the command run starts", async () => {
    const script = join(dir, "argv.cjs");
    writeFileSync(script, "console.log('ran ' + process.argv.slice(2).join(' '))");
    const r = await cli(["run", "--", process.execPath, script, "--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("ran --help\n");
  });

  it("every command has help entries", () => {
    const commands = ["login", "logout", "status", "whoami", "init", "context", "env", "run", "validate", "values", "import", "contract", "types", "sync", "admin", "setup", "adopt", "doctor", "scan", "invite", "tailnet", "audit", "org", "project", "env-create", "env-delete", "identity", "credential", "self-update", "upgrade", "request", "mcp", "agents"];
    for (const command of commands) expect(commandHelp(command), command).not.toBeNull();
    expect(commandHelp("nosuch")).toBeNull();
  });

  it("an unknown command, or help for one, is a usage error (64) with the usage on stderr", async () => {
    for (const args of [["nosuch"], ["help", "nosuch"]]) {
      const r = await cli(args);
      expect(r.code).toBe(EXIT.usage);
      expect(r.stdout).toBe("");
      expect(r.stderr).toMatch(/Usage:/);
    }
  });
});

describe("exit statuses", () => {
  const malformed: [string, string[]][] = [
    ["values set without an item", ["values", "set"]],
    ["run without --", ["run", "true"]],
    ["import without a file", ["import"]],
    ["contract push without a source", ["contract", "push"]],
    ["conflicting run flags", ["run", "--redact", "--no-redact", "--", "true"]],
    ["two value sources", ["values", "set", "API_TOKEN", "v", "--stdin"]],
    ["an unknown values subcommand", ["values", "bogus"]],
    ["an unknown contract subcommand", ["contract", "bogus"]],
    ["an unknown identity subcommand", ["identity", "bogus"]],
    ["an unknown credential subcommand", ["credential", "bogus"]],
    ["an unknown audit subcommand", ["audit", "bogus"]],
    ["an unknown tailnet subcommand", ["tailnet", "bogus"]],
    ["an unknown org subcommand", ["org", "bogus"]],
    ["org create without a slug", ["org", "create"]],
    ["credential list without an identity", ["credential", "list"]],
    ["an unknown whoami option", ["whoami", "--jsno"]],
    ["whoami with an argument", ["whoami", "me"]],
  ];

  it.each(malformed)("%s: 64 (usage) with a credential, before any request", async (_name, args) => {
    const r = await cli(args);
    expect(r.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
  });

  it.each(malformed)("%s: 64 (usage) without any credential too, never a request to sign in", async (_name, args) => {
    const r = await cli(args, { VARLATCH_TOKEN: "" });
    expect(r.code).toBe(EXIT.usage);
    expect(r.stderr).not.toMatch(/Not authenticated|varlatch login/);
    expect(requests).toEqual([]);
  });

  it("not signed in: 77", async () => {
    const r = await cli(["values", "list"], { VARLATCH_TOKEN: "" });
    expect(r.code).toBe(EXIT.denied);
    expect(r.stderr).toMatch(/Not authenticated to/);
  });

  it.each([
    ["an unauthenticated credential (401)", "vlt_bad", EXIT.denied],
    ["a denied request (403)", "vlt_denied", EXIT.denied],
    ["an overloaded server (503)", "vlt_overloaded", EXIT.unavailable],
    ["a server error (500)", "vlt_broken", EXIT.failure],
  ])("%s: %i", async (_name, token, code) => {
    const r = await cli(["values", "list"], { VARLATCH_TOKEN: token });
    expect(r.code).toBe(code);
    expect(r.stderr).toMatch(/^Error [A-Z_]+: .* \(request req_1\)/);
  });

  async function closedPort(): Promise<number> {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise((resolve) => closed.close(resolve));
    return port;
  }

  it.each([
    ["values list", ["values", "list"]],
    ["an agent-safe run", ["run", "--agent-safe", "--agent", "coder", "--allow-host", "api.example.com", "--", "true"]],
    ["an agent-safe strict run", ["run", "--agent-safe", "--strict", "--agent", "coder", "--allow-host", "api.example.com", "--", "true"]],
  ])("a server that cannot be reached: 69 for %s, naming the cause, without a stack trace", async (_name, args) => {
    const port = await closedPort();
    const sep = args.indexOf("--");
    const withServer = sep < 0 ? [...args, "--server", `http://127.0.0.1:${port}`] : [...args.slice(0, sep), "--server", `http://127.0.0.1:${port}`, ...args.slice(sep)];
    const r = await cli(withServer, { VARLATCH_BROKER_CREDENTIAL: "vlt_brk_test" });
    expect(r.code).toBe(EXIT.unavailable);
    expect(r.stderr).toMatch(/Cannot reach the Varlatch server \(ECONNREFUSED\)/);
    expect(r.stderr).not.toMatch(/at .*\.cjs:\d+|fetch failed/);
  });

  it.each([
    ["a gateway's HTML 502", "vlt_html502", EXIT.unavailable, /^Error INTERNAL: HTTP 502; the response is not a Varlatch API error \(text\/html\)/],
    ["a portal's HTML 200", "vlt_html200", EXIT.failure, /^Error INTERNAL: HTTP 200; the response is not JSON \(text\/html\)/],
  ])("%s: %i, one line, the page never echoed and no stack trace", async (_name, token, code, message) => {
    const r = await cli(["values", "list", "--json"], { VARLATCH_TOKEN: token });
    expect(r.code).toBe(code);
    expect(r.stderr).toMatch(message);
    expect(r.stderr.trim().split("\n")).toHaveLength(1);
    expect(r.stdout + r.stderr).not.toMatch(/page-marker|SyntaxError|at .*\.cjs:\d+/);
  });

  it.each([
    ["development", 0, "valid"],
    ["staging", 1, "invalid"],
    ["production", 2, "incomplete"],
  ] as const)("validate keeps its statuses (%s: %i), with and without --json", async (env, code, result) => {
    const human = await cli(["validate", "-e", env]);
    expect(human.code).toBe(code);
    const machine = await cli(["validate", "-e", env, "--json"]);
    expect(machine.code).toBe(code);
    const doc = JSON.parse(machine.stdout);
    expect(doc).toMatchObject({ version: 1, environment: env, result, exitCode: code });
    if (env === "staging") expect(doc).toMatchObject({ missing: ["API_TOKEN"], invalid: [{ name: "PORT", reason: "must be a whole number" }] });
    if (env === "production") expect(doc).toMatchObject({ complete: false, notEvaluated: [{ name: "API_TOKEN" }] });
  });

  it("scan keeps 1 for every failure, as documented: usage and authentication included", async () => {
    expect((await cli(["scan", "--bogus"])).code).toBe(EXIT.failure);
    expect((await cli(["scan", "."], { VARLATCH_TOKEN: "" })).code).toBe(EXIT.failure);
    expect((await cli(["scan", "."], { VARLATCH_TOKEN: "vlt_denied" })).code).toBe(EXIT.failure);
  });
});

describe("--json documents", () => {
  const doc = async (args: string[]) => {
    const r = await cli([...args, "--json"]);
    expect(r.code, r.stderr).toBe(0);
    return JSON.parse(r.stdout) as Record<string, unknown>;
  };

  it("values list: names and classification, never a value", async () => {
    const d = await doc(["values", "list"]);
    expect(d).toEqual({
      version: 1,
      environment: "development",
      items: [
        { name: "API_TOKEN", sensitive: true, source: "self" },
        { name: "PORT", sensitive: false, source: "self" },
      ],
    });
    expect(requests.some((r) => r.url.includes("include=values") || r.url.endsWith("/disclosures"))).toBe(false);
  });

  it("org, project, identity, and credential lists", async () => {
    expect(await doc(["org", "list"])).toEqual({ version: 1, organizations: [{ id: "org_1", slug: "acme", name: "Acme" }] });
    expect(await doc(["project", "list"])).toEqual({ version: 1, organization: "acme", projects: [{ slug: "web", name: "Web", contractAuthority: "git" }] });
    expect(await doc(["identity", "list"])).toEqual({
      version: 1,
      organization: "acme",
      identities: [
        { id: "idn_1", name: "ci", kind: "service", retired: false, lastSeenAt: "2026-09-30T10:00:00.000Z" },
        { id: "idn_2", name: "old", kind: "service", retired: true, lastSeenAt: null },
      ],
    });
    expect(await doc(["credential", "list", "idn_1"])).toEqual({
      version: 1,
      identity: "idn_1",
      credentials: [{ id: "crd_1", kind: "service", name: "deploy", createdAt: "2026-09-01T00:00:00.000Z", expiresAt: null, revokedAt: null, lastUsedAt: null }],
    });
  });

  it("whoami: the caller as the server answers, never a token", async () => {
    expect(await doc(["whoami"])).toEqual({ version: 1, server: origin, ...WHOAMI });
    expect(requests.map((r) => r.url)).toEqual(["/v1/meta", "/v1/me"]);
  });

  it("audit list and tailnet requirements carry the server's records", async () => {
    expect(await doc(["audit", "list"])).toMatchObject({ version: 1, organization: "acme", events: [{ id: "evt_1", eventType: "value.set" }] });
    expect(await doc(["tailnet", "requirements"])).toMatchObject({ version: 1, organization: "acme", requirements: [{ id: "req_t1" }] });
  });

  it("contract push: the new revision", async () => {
    expect(await doc(["contract", "push", "--file", join(repo, "contract.json")])).toMatchObject({
      version: 1,
      revision: { id: "crv_new", active: false, semanticsVersion: 2 },
    });
  });

  it("import: the plan as a dry run, and what was stored, never a value", async () => {
    const file = join(dir, ".env-json");
    writeFileSync(file, "API_TOKEN=import-json-canary-17\nPORT=3000\n");
    const plan = await cli(["import", file, "--dry-run", "--json"]);
    expect(plan.code).toBe(0);
    expect(JSON.parse(plan.stdout)).toMatchObject({
      version: 1,
      dryRun: true,
      target: { organization: "acme", project: "web", environment: "development" },
      items: [
        { name: "API_TOKEN", type: "string", sensitive: true, inContract: true, line: 1 },
        // The active Contract is at semantics version 2, which has no integer type.
        { name: "PORT", type: "number", sensitive: true, inContract: false, line: 2 },
      ],
      contract: null,
      stored: [],
      deleted: false,
    });
    const done = await cli(["import", file, "--contract", "--plain", "PORT", "--json"]);
    expect(done.code).toBe(0);
    expect(JSON.parse(done.stdout)).toMatchObject({
      dryRun: false,
      contract: { newItems: ["PORT"], revision: { id: "crv_new", active: false } },
      stored: ["API_TOKEN", "PORT"],
      deleted: false,
    });
    for (const r of [plan, done]) expect(r.stdout + r.stderr).not.toContain("import-json-canary-17");
  });
});

describe("whoami", () => {
  it("prints the identity, organization, credential, listener, and device", async () => {
    const r = await cli(["whoami"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe(
      [
        "Identity      runner-macmini (service, idn_1)",
        "Organization  acme (Acme, org_1)",
        "Credential    desktop-runner (service, crd_1), no expiry",
        `Server        ${origin} (tailnet listener)`,
        "Device        macmini (nRunner), tags tag:desktop-runner, on example.ts.net",
        "",
      ].join("\n"),
    );
    expect(r.stdout + r.stderr).not.toContain("vlt_test");
  });

  it("asks the server --server names, outside any repository too", async () => {
    const elsewhere = mkdtempSync(join(tmpdir(), "varlatch-whoami-"));
    try {
      const r = await new Promise<Result>((resolve) => {
        const child = spawn(process.execPath, [bundle, "whoami", "--server", `${origin}/`, "--json"], {
          cwd: elsewhere,
          env: { PATH: process.env.PATH, HOME: elsewhere, VARLATCH_CONFIG_DIR: join(elsewhere, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0" },
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
        child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        child.on("close", (code) => resolve({ code, stdout, stderr }));
      });
      expect(r.code, r.stderr).toBe(0);
      expect(JSON.parse(r.stdout)).toMatchObject({ version: 1, server: origin, identity: { name: "runner-macmini" } });
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it("against a server without identity.whoami: 1, saying so, and never asks /v1/me", async () => {
    const r = await cli(["whoami"], { VARLATCH_TOKEN: "vlt_old" });
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toMatch(/this server \(0\.16\.0\) cannot say which identity a credential belongs to \(it lacks the identity\.whoami capability\)/);
    expect(requests.map((r) => r.url)).toEqual(["/v1/meta"]);
  });

  it("status --probe --json adds what the stored credential resolves to; its human format does not change", async () => {
    const config = join(dir, "probe-config");
    mkdirSync(config, { recursive: true });
    writeFileSync(join(config, "credentials.json"), JSON.stringify({ servers: { [origin]: { token: "vlt_test" } } }));
    const env = { VARLATCH_CONFIG_DIR: config, VARLATCH_TOKEN: "" };
    const machine = await cli(["status", "--probe", "--json"], env);
    expect(machine.code, machine.stderr).toBe(0);
    expect(JSON.parse(machine.stdout).servers).toMatchObject([
      {
        server: origin,
        probe: {
          state: "valid",
          detail: null,
          identity: { id: "idn_1", name: "runner-macmini", kind: "service" },
          organization: { id: "org_1", slug: "acme", name: "Acme" },
        },
      },
    ]);
    const human = await cli(["status", "--probe"], env);
    expect(human.code).toBe(0);
    expect(human.stdout.split("\n")[0]).toBe(`${origin}  (no expiry recorded, desktop-runner, probe: valid)`);
    expect(human.stdout).not.toContain("runner-macmini");
    // A server without identity.whoami: valid, and no identity.
    writeFileSync(join(config, "credentials.json"), JSON.stringify({ servers: { [origin]: { token: "vlt_old" } } }));
    const old = JSON.parse((await cli(["status", "--probe", "--json"], env)).stdout).servers[0].probe;
    expect(old).toEqual({ state: "valid", detail: null });
  });

  it("a refused credential: 77; no credential at all: 77 before any request", async () => {
    expect((await cli(["whoami"], { VARLATCH_TOKEN: "vlt_bad" })).code).toBe(EXIT.denied);
    requests = [];
    const none = await cli(["whoami"], { VARLATCH_TOKEN: "" });
    expect(none.code).toBe(EXIT.denied);
    expect(none.stderr).toMatch(/Not authenticated to/);
    expect(requests).toEqual([]);
  });
});
