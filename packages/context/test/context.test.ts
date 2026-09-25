// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ContextError,
  deleteCredential,
  findRepoRoot,
  listCredentials,
  loadCredential,
  loadToken,
  resolveContext,
  saveCredential,
  saveLocalState,
  saveToken,
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
