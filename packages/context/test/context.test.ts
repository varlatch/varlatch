// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ContextError,
  agentRunOf,
  defaultServer,
  deleteCredential,
  findRepoRoot,
  listCredentials,
  loadCredential,
  loadToken,
  rememberServerIfUnset,
  resolveContext,
  resolveServer,
  saveCredential,
  saveLocalState,
  saveToken,
  setDefaultServer,
  settingsPath,
} from "../src/index.js";

function repo(config: string): string {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-ctx-"));
  writeFileSync(join(dir, "varlatch.toml"), config);
  return dir;
}

const BASE = `
server = "https://varlatch.example.com"
organization = "acme"
project = "api"
default_environment = "development"
`;

describe("resolveContext precedence (ADR-0017 §7)", () => {
  it("committed default is the floor", () => {
    const dir = repo(BASE);
    const ctx = resolveContext({ cwd: dir, env: {} });
    expect(ctx).toMatchObject({
      server: "https://varlatch.example.com",
      organization: "acme",
      project: "api",
      environment: "development",
      environmentSource: "committed-default",
    });
  });

  it("local selection beats committed default", () => {
    const dir = repo(BASE);
    saveLocalState(dir, { selectedEnvironment: "development/jeremy" });
    const ctx = resolveContext({ cwd: dir, env: {} });
    expect(ctx.environment).toBe("development/jeremy");
    expect(ctx.environmentSource).toBe("local-selection");
    // The state directory ignores itself.
    expect(readFileSync(join(dir, ".varlatch", ".gitignore"), "utf8")).toBe("*\n");
  });

  it("VARLATCH_ENV beats local selection; flag beats everything", () => {
    const dir = repo(BASE);
    saveLocalState(dir, { selectedEnvironment: "development/jeremy" });
    const viaEnv = resolveContext({ cwd: dir, env: { VARLATCH_ENV: "staging" } });
    expect(viaEnv).toMatchObject({ environment: "staging", environmentSource: "env-var" });
    const viaFlag = resolveContext({
      cwd: dir,
      env: { VARLATCH_ENV: "staging" },
      environment: "production",
    });
    expect(viaFlag).toMatchObject({ environment: "production", environmentSource: "flag" });
  });

  it("resolves from a nested working directory", () => {
    const dir = repo(BASE);
    const nested = join(dir, "src", "deep");
    mkdirSync(nested, { recursive: true });
    expect(findRepoRoot(nested)).toBe(dir);
    expect(resolveContext({ cwd: nested, env: {} }).repoRoot).toBe(dir);
  });

  it("fails precisely when context is incomplete (no prompting, ADR-0017 §9)", () => {
    const noEnv = repo(`organization = "acme"\nproject = "api"\nserver = "https://x"\n`);
    expect(() => resolveContext({ cwd: noEnv, env: {} })).toThrow(ContextError);
    expect(() => resolveContext({ cwd: noEnv, env: {} })).toThrow(/No environment selected/);

    const noServer = repo(`organization = "acme"\nproject = "api"\ndefault_environment = "dev"\n`);
    expect(() => resolveContext({ cwd: noServer, env: {} })).toThrow(/No server configured/);
    // Server override chain works.
    const ctx = resolveContext({ cwd: noServer, env: { VARLATCH_SERVER: "https://alt" } });
    expect(ctx.server).toBe("https://alt");

    const outside = mkdtempSync(join(tmpdir(), "varlatch-none-"));
    expect(() => resolveContext({ cwd: outside, env: {} })).toThrow(/No varlatch.toml/);
  });

  it("rejects a config missing organization/project", () => {
    const dir = repo(`server = "https://x"\n`);
    expect(() => resolveContext({ cwd: dir, env: {} })).toThrow(/organization/);
  });
});

describe("credential store", () => {
  it("stores per-server tokens outside the repo; VARLATCH_TOKEN wins", () => {
    const home = mkdtempSync(join(tmpdir(), "varlatch-home-"));
    const env = { VARLATCH_CONFIG_DIR: home };
    expect(loadToken("https://a.example", env)).toBeNull();
    saveToken("https://a.example/", "vlt_cli_abc", env);
    expect(loadToken("https://a.example", env)).toBe("vlt_cli_abc");
    expect(loadToken("https://a.example", { ...env, VARLATCH_TOKEN: "vlt_svc_ci" })).toBe(
      "vlt_svc_ci",
    );
  });

  it("round-trips issuance metadata and coexists with metadata-free entries (ADR-0032)", () => {
    const home = mkdtempSync(join(tmpdir(), "varlatch-home-"));
    const env = { VARLATCH_CONFIG_DIR: home };
    saveToken("https://old.example", "vlt_cli_old", env);
    saveCredential(
      "https://new.example/",
      {
        token: "vlt_cli_new",
        issuedAt: "2026-09-22T08:00:00.000Z",
        expiresAt: "2026-09-22T20:00:00.000Z",
        credentialId: "cred_123",
      },
      env,
    );
    // Pre-ADR-0032 entry: token loads, metadata is absent, nothing throws.
    expect(loadCredential("https://old.example", env)).toEqual({ token: "vlt_cli_old" });
    expect(loadCredential("https://new.example", env)).toMatchObject({
      token: "vlt_cli_new",
      expiresAt: "2026-09-22T20:00:00.000Z",
      credentialId: "cred_123",
    });
    expect(loadToken("https://new.example", env)).toBe("vlt_cli_new");
    expect(listCredentials(env).map((e) => e.server).sort()).toEqual([
      "https://new.example",
      "https://old.example",
    ]);
    // loadCredential is store-only: VARLATCH_TOKEN never masquerades as an entry.
    expect(loadCredential("https://absent.example", { ...env, VARLATCH_TOKEN: "vlt_svc_ci" })).toBeNull();
  });

  describe("inside an agent-safe run (ADR-0043 Decision 5)", () => {
    const server = "https://a.example";
    function operatorStore() {
      // The default location, as XDG_CONFIG_HOME makes it, holding the operator's credential.
      const xdg = mkdtempSync(join(tmpdir(), "varlatch-xdg-"));
      saveToken(server, "vlt_cli_operator", { XDG_CONFIG_HOME: xdg });
      return { xdg, defaultDir: join(xdg, "varlatch") };
    }

    it("never reads the operator's default store; the same lookup outside a run does (negative control)", () => {
      const { xdg, defaultDir } = operatorStore();
      expect(loadToken(server, { XDG_CONFIG_HOME: xdg })).toBe("vlt_cli_operator");
      const inRun = { XDG_CONFIG_HOME: xdg, VARLATCH_AGENT_RUN: "run_1" };
      expect(agentRunOf(inRun)).toBe("run_1");
      expect(loadToken(server, inRun)).toBeNull();
      expect(loadCredential(server, inRun)).toBeNull();
      expect(listCredentials(inRun)).toEqual([]);
      // Pointing VARLATCH_CONFIG_DIR back at the default location does not reopen it.
      expect(loadToken(server, { ...inRun, VARLATCH_CONFIG_DIR: defaultDir })).toBeNull();
      expect(loadToken(server, { ...inRun, VARLATCH_CONFIG_DIR: `${defaultDir}/` })).toBeNull();
    });

    it("uses the run's own directory and an explicit VARLATCH_TOKEN (the agent-run credential)", () => {
      const { xdg } = operatorStore();
      const runDir = mkdtempSync(join(tmpdir(), "varlatch-run-"));
      const inRun = { XDG_CONFIG_HOME: xdg, VARLATCH_AGENT_RUN: "run_1", VARLATCH_CONFIG_DIR: runDir };
      expect(loadToken(server, inRun)).toBeNull();
      saveToken(server, "vlt_cli_inside", inRun);
      expect(loadToken(server, inRun)).toBe("vlt_cli_inside");
      expect(loadToken(server, { XDG_CONFIG_HOME: xdg })).toBe("vlt_cli_operator");
      expect(loadToken(server, { XDG_CONFIG_HOME: xdg, VARLATCH_AGENT_RUN: "run_1", VARLATCH_TOKEN: "vlt_agr_1" })).toBe("vlt_agr_1");
    });

    it("refuses to write the operator's default store", () => {
      const { xdg } = operatorStore();
      expect(() => saveToken(server, "vlt_cli_new", { XDG_CONFIG_HOME: xdg, VARLATCH_AGENT_RUN: "run_1" })).toThrow(ContextError);
      expect(deleteCredential(server, { XDG_CONFIG_HOME: xdg, VARLATCH_AGENT_RUN: "run_1" })).toBe(false);
      expect(loadToken(server, { XDG_CONFIG_HOME: xdg })).toBe("vlt_cli_operator");
    });
  });

  it("deleteCredential removes one server and reports absence", () => {
    const home = mkdtempSync(join(tmpdir(), "varlatch-home-"));
    const env = { VARLATCH_CONFIG_DIR: home };
    expect(deleteCredential("https://a.example", env)).toBe(false);
    saveToken("https://a.example", "vlt_a", env);
    saveToken("https://b.example", "vlt_b", env);
    expect(deleteCredential("https://a.example/", env)).toBe(true);
    expect(loadToken("https://a.example", env)).toBeNull();
    expect(loadToken("https://b.example", env)).toBe("vlt_b");
  });
});

describe("the remembered default server (ADR-0058 Decision 1)", () => {
  const config = () => ({ VARLATCH_CONFIG_DIR: mkdtempSync(join(tmpdir(), "varlatch-settings-")) });
  const outside = () => mkdtempSync(join(tmpdir(), "varlatch-outside-"));

  it("outside a repository: flag, variable, default, then the only stored credential", () => {
    const env = config();
    const cwd = outside();
    expect(resolveServer({ cwd, env })).toBeNull();
    saveToken("https://only.example", "t", env);
    expect(resolveServer({ cwd, env })).toEqual({ server: "https://only.example", source: "only-credential" });
    saveToken("https://other.example", "t", env);
    expect(resolveServer({ cwd, env })).toBeNull();
    setDefaultServer("https://other.example/", env);
    expect(defaultServer(env)).toBe("https://other.example");
    expect(resolveServer({ cwd, env })).toEqual({ server: "https://other.example", source: "default" });
    expect(resolveServer({ cwd, env: { ...env, VARLATCH_SERVER: "https://var.example" } })).toEqual({ server: "https://var.example", source: "env-var" });
    expect(resolveServer({ cwd, env: { ...env, VARLATCH_SERVER: "https://var.example" }, server: "https://flag.example" })).toEqual({
      server: "https://flag.example",
      source: "flag",
    });
  });

  it("a repository never uses the default: a varlatch.toml without a server keeps failing", () => {
    const env = config();
    setDefaultServer("https://default.example", env);
    saveToken("https://default.example", "t", env);
    const serverless = repo('organization = "acme"\nproject = "api"\ndefault_environment = "development"\n');
    expect(resolveServer({ cwd: serverless, env })).toBeNull();
    expect(() => resolveContext({ cwd: serverless, env })).toThrow(/No server configured.*server = "https:\/\/default\.example"/);
    const named = repo(BASE);
    expect(resolveServer({ cwd: named, env })).toEqual({ server: "https://varlatch.example.com", source: "repository" });
    expect(resolveContext({ cwd: named, env }).serverSource).toBe("repository");
    saveLocalState(named, { serverOverride: "https://override.example" });
    expect(resolveContext({ cwd: named, env }).serverSource).toBe("local-override");
    expect(resolveContext({ cwd: named, env: { ...env, VARLATCH_SERVER: "https://var.example" } }).serverSource).toBe("env-var");
    expect(resolveContext({ cwd: named, env, server: "https://flag.example" }).serverSource).toBe("flag");
  });

  it("a sign-in sets the default only when none is set, and signing out of it forgets it", () => {
    const env = config();
    expect(rememberServerIfUnset("https://a.example", env)).toBe(true);
    expect(rememberServerIfUnset("https://b.example", env)).toBe(false);
    expect(defaultServer(env)).toBe("https://a.example");
    saveToken("https://a.example", "t", env);
    saveToken("https://b.example", "t", env);
    expect(deleteCredential("https://b.example", env)).toBe(true);
    expect(defaultServer(env)).toBe("https://a.example");
    expect(deleteCredential("https://a.example/", env)).toBe(true);
    expect(defaultServer(env)).toBeNull();
  });

  it("keeps settings it does not know, and writes the file for its owner only", () => {
    const env = config();
    writeFileSync(join(env.VARLATCH_CONFIG_DIR, "settings.json"), JSON.stringify({ future: { kept: true } }));
    setDefaultServer("https://a.example", env);
    expect(JSON.parse(readFileSync(settingsPath(env), "utf8"))).toEqual({ future: { kept: true }, defaultServer: "https://a.example" });
    if (process.platform !== "win32") expect(statSync(settingsPath(env)).mode & 0o777).toBe(0o600);
    setDefaultServer(null, env);
    expect(JSON.parse(readFileSync(settingsPath(env), "utf8"))).toEqual({ future: { kept: true } });
  });

  it("an unreadable settings file means no default", () => {
    const env = config();
    writeFileSync(join(env.VARLATCH_CONFIG_DIR, "settings.json"), "{not json");
    expect(defaultServer(env)).toBeNull();
  });

  it("inside an agent-safe run the operator's settings are never read or written", () => {
    const operator = config();
    setDefaultServer("https://operator.example", operator);
    // The run points VARLATCH_CONFIG_DIR at its own directory: that one counts, the operator's does not.
    const run = { ...config(), VARLATCH_AGENT_RUN: "run_1" };
    expect(defaultServer(run)).toBeNull();
    // Without its own directory, the default location is blocked.
    const blocked = { XDG_CONFIG_HOME: join(operator.VARLATCH_CONFIG_DIR, ".."), VARLATCH_AGENT_RUN: "run_1" };
    expect(defaultServer(blocked)).toBeNull();
    expect(rememberServerIfUnset("https://agent.example", blocked)).toBe(false);
    expect(() => setDefaultServer("https://agent.example", blocked)).toThrow(ContextError);
  });
});
