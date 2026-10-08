// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { saveToken } from "@varlatch/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { McpStartError, mcpUserAgent, parseMcpArgs, prepareMcpServer } from "./run.js";

/**
 * Starting the MCP server (ADR-0043 Decision 9): the shared path of
 * `varlatch mcp` and the old `varlatch-mcp` entry point.
 */

function startError(fn: () => unknown): McpStartError {
  try {
    fn();
  } catch (err) {
    if (err instanceof McpStartError) return err;
    throw err;
  }
  throw new Error("expected McpStartError");
}

describe("parseMcpArgs", () => {
  it("reads the flags and VARLATCH_MCP_ALLOW_WRITES", () => {
    expect(parseMcpArgs(["--server", "https://v.example", "--org", "acme", "--project", "api", "-e", "dev"], {})).toEqual({
      server: "https://v.example",
      organization: "acme",
      project: "api",
      environment: "dev",
      allowWrites: false,
      help: false,
    });
    expect(parseMcpArgs(["--allow-writes"], {}).allowWrites).toBe(true);
    expect(parseMcpArgs([], { VARLATCH_MCP_ALLOW_WRITES: "1" }).allowWrites).toBe(true);
  });

  it("refuses --allow-disclose and VARLATCH_MCP_ALLOW_DISCLOSE with 64, never ignoring them", () => {
    for (const [argv, env] of [
      [["--allow-disclose"], {}],
      [["--allow-writes", "--allow-disclose"], {}],
      [[], { VARLATCH_MCP_ALLOW_DISCLOSE: "1" }],
      [[], { VARLATCH_MCP_ALLOW_DISCLOSE: "true" }],
    ] as [string[], NodeJS.ProcessEnv][]) {
      const err = startError(() => parseMcpArgs(argv, env));
      expect(err.exitCode).toBe(64);
      expect(err.message).toMatch(/secret disclosure through MCP has been removed/);
    }
    // Unset, empty, and 0 mean off.
    expect(() => parseMcpArgs([], { VARLATCH_MCP_ALLOW_DISCLOSE: "0" })).not.toThrow();
    expect(() => parseMcpArgs([], { VARLATCH_MCP_ALLOW_DISCLOSE: "" })).not.toThrow();
  });

  it("refuses unknown options and missing values with 64", () => {
    expect(startError(() => parseMcpArgs(["--bogus"], {})).exitCode).toBe(64);
    expect(startError(() => parseMcpArgs(["--server"], {})).exitCode).toBe(64);
  });
});

describe("prepareMcpServer: the credential", () => {
  const server = "https://varlatch.example";
  const cwd = mkdtempSync(join(tmpdir(), "varlatch-mcp-cwd-"));
  const base = { server, organization: "acme", project: "api", environment: "dev", allowWrites: false, help: false };
  function operatorStore(): NodeJS.ProcessEnv {
    // The operator's credential in the default location (XDG_CONFIG_HOME), with no VARLATCH_CONFIG_DIR.
    const xdg = mkdtempSync(join(tmpdir(), "varlatch-mcp-xdg-"));
    saveToken(server, "vlt_cli_operator", { XDG_CONFIG_HOME: xdg });
    return { XDG_CONFIG_HOME: xdg };
  }

  it("inside an agent-safe run, never the operator's stored credential, even with VARLATCH_CONFIG_DIR unset: 77", () => {
    const env = { ...operatorStore(), VARLATCH_AGENT_RUN: "run_0123456789abcdef" };
    const err = startError(() => prepareMcpServer(base, env, cwd));
    expect(err.exitCode).toBe(77);
    expect(err.message).toMatch(/inside agent-safe run run_0123456789abcdef, which gives the Agent no Varlatch credential/);
    expect(err.message).toMatch(/--agent-metadata/);
  });

  it("inside an agent-safe run, VARLATCH_CONFIG_DIR pointed back at the default location does not reopen it", () => {
    const store = operatorStore();
    const env = { ...store, VARLATCH_AGENT_RUN: "run_1", VARLATCH_CONFIG_DIR: join(store.XDG_CONFIG_HOME as string, "varlatch") };
    expect(startError(() => prepareMcpServer(base, env, cwd)).exitCode).toBe(77);
  });

  it("negative control, same store: outside an agent-safe run the stored credential is used", () => {
    const prepared = prepareMcpServer(base, operatorStore(), cwd);
    expect(prepared.client.server).toBe(server);
  });

  it("inside an agent-safe run, the agent-run credential from --agent-metadata is used", () => {
    const env = { ...operatorStore(), VARLATCH_AGENT_RUN: "run_1", VARLATCH_TOKEN: "vlt_agr_1" };
    expect(prepareMcpServer(base, env, cwd).client.server).toBe(server);
  });

  it("inside an agent-safe run, --allow-writes is refused: the only credential is read-only", () => {
    const env = { VARLATCH_AGENT_RUN: "run_1", VARLATCH_TOKEN: "vlt_agr_1" };
    const err = startError(() => prepareMcpServer({ ...base, allowWrites: true }, env, cwd));
    expect(err.exitCode).toBe(64);
    expect(err.message).toMatch(/--allow-writes does not apply here/);
  });

  it("without any credential outside a run: 77 with the login instruction", () => {
    const err = startError(() => prepareMcpServer(base, { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "x-")) }, cwd));
    expect(err.exitCode).toBe(77);
    expect(err.message).toMatch(/varlatch login/);
  });
});

describe("prepareMcpServer: the User-Agent", () => {
  const cwd = mkdtempSync(join(tmpdir(), "varlatch-mcp-ua-"));
  const base = { server: "https://varlatch.example", organization: "acme", allowWrites: false, help: false };
  afterEach(() => vi.unstubAllGlobals());

  async function sent(version?: string): Promise<string | null> {
    let userAgent: string | null = null;
    vi.stubGlobal("fetch", async (_url: unknown, init?: RequestInit) => {
      userAgent = new Headers(init?.headers).get("User-Agent");
      return Response.json({ apiMajor: 1, serverVersion: "0.16.0", capabilities: [] });
    });
    await prepareMcpServer(base, { VARLATCH_TOKEN: "vlt_cli_test" }, cwd, version).client.meta();
    return userAgent;
  }

  it("is varlatch-mcp/<version> (<platform>; <arch>), which varlatchd records as the client of each audit event", async () => {
    expect(mcpUserAgent("0.16.0", "linux", "x64")).toBe("varlatch-mcp/0.16.0 (linux; x64)");
    expect(await sent("0.16.0")).toBe(`varlatch-mcp/0.16.0 (${process.platform}; ${process.arch})`);
  });

  it("is not sent without a version to name", async () => {
    expect(await sent()).toBeNull();
  });
});
