// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CONTROL_VERSION, controlMcpServer } from "./controlCli.js";
import { McpStdio } from "./mcpStdio.js";

/**
 * `varlatch mcp` (ADR-0043 Decision 9), end to end through a real MCP
 * client over stdio, against a fake Varlatch server:
 *
 * - the release asset itself (apps/cli/dist/varlatch.cjs, which the release
 *   ships as varlatch-cli-<version>.cjs) serves MCP under the CLI's version;
 * - no disclosure tool is listed or dispatched, and --allow-disclose (or
 *   VARLATCH_MCP_ALLOW_DISCLOSE) is refused;
 * - a Secret's value is never written, whatever the write path;
 * - inside an agent-safe run the operator's stored credential is never used,
 *   with VARLATCH_CONFIG_DIR unset;
 * - the old varlatch-mcp entry point runs the same code.
 *
 * Negative control: the same probes against the 0.13 @varlatch/mcp-server
 * (built from the v0.13.0 release commit) find the disclosure tool, a
 * disclosed Secret, a written Secret, and the operator's credential in use.
 */

const CANARY = "mcp-disclosed-canary-4e91";
const cliDir = fileURLToPath(new URL("..", import.meta.url));
const RELEASE_BUNDLE = join(cliDir, "dist", "varlatch.cjs");
const OLD_ENTRY = join(cliDir, "..", "..", "packages", "mcp-server", "dist", "main.js");

const dir = mkdtempSync(join(tmpdir(), "varlatch-mcp-e2e-"));
const repo = join(dir, "repo");
let control = "";
let server: http.Server;
let origin = "";
let requests: { method: string; url: string; auth: string; userAgent: string }[] = [];
/** Names dev has (source "self") or inherits (source "parent"); a status instead makes the metadata read fail. */
let devItems: { name: string; source: "self" | "parent" }[] | number = [];

const PROJECT = "/v1/organizations/acme/projects/api";

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    requests.push({
      method: req.method ?? "",
      url,
      auth: (req.headers.authorization ?? "").replace(/^Bearer /, ""),
      userAgent: req.headers["user-agent"] ?? "",
    });
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url === "/v1/meta") return json(200, { serverVersion: "0.14.0", capabilities: [], apiMajor: 1 });
    if (url === "/v1/organizations") return json(200, { items: [{ id: "org_1", slug: "acme", name: "Acme" }], nextCursor: null });
    if (url === `${PROJECT}/contract`) {
      return json(200, {
        id: "crv_1",
        contract: {
          schemaVersion: 1,
          items: [
            { name: "API_KEY", sensitive: true, type: "string", required: { kind: "never" } },
            { name: "LOG_LEVEL", sensitive: false, type: "string", required: { kind: "never" } },
          ],
        },
      });
    }
    if (url.startsWith(`${PROJECT}/environments/dev/effective-configuration`)) {
      if (typeof devItems === "number") return json(devItems, { error: { code: "PERMISSION_DENIED", message: "denied", requestId: "r" } });
      return json(200, { environmentId: "env_dev", items: devItems.map((i) => ({ ...i, sensitive: false })) });
    }
    if (url === `${PROJECT}/environments/dev/disclosures`) {
      return json(200, { items: [{ name: "API_KEY", versionId: "ver_1", value: CANARY }], withheld: [] });
    }
    if (/\/values\/[A-Z_]+$/.test(url) && req.method === "PUT") return json(200, { versionId: "ver_new" });
    if (/\/values\/[A-Z_]+$/.test(url) && req.method === "DELETE") {
      res.writeHead(204);
      return res.end();
    }
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
  });
}

beforeAll(async () => {
  if (!existsSync(RELEASE_BUNDLE) || !existsSync(OLD_ENTRY)) {
    throw new Error("the CLI bundle and the MCP package are not built: run pnpm --filter @varlatch/cli... build");
  }
  control = await controlMcpServer(dir);
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "api"\nserver = "${origin}"\ndefault_environment = "dev"\n`);
}, 120_000);

afterAll(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  devItems = [];
});

/** A HOME whose default store holds the operator's credential, and no VARLATCH_CONFIG_DIR. */
function operatorHome(): Record<string, string> {
  const home = mkdtempSync(join(dir, "home-"));
  mkdirSync(join(home, ".config", "varlatch"), { recursive: true });
  writeFileSync(join(home, ".config", "varlatch", "credentials.json"), JSON.stringify({ servers: { [origin]: { token: "vlt_cli_operator" } } }));
  return { PATH: process.env.PATH ?? "", HOME: home, VARLATCH_ASSISTED: "0" };
}

type Entry = { name: string; command: string[] };
const RELEASE: Entry = { name: "varlatch mcp (release bundle)", command: [RELEASE_BUNDLE, "mcp"] };
const OLD: Entry = { name: "varlatch-mcp (old entry point)", command: [OLD_ENTRY] };

function connect(entry: Entry, extra: string[], env: Record<string, string>): Promise<McpStdio> {
  return McpStdio.start(process.execPath, [...entry.command, ...extra], env, repo);
}
const READ_TOOLS = [
  "varlatch_effective_configuration",
  "varlatch_get_active_contract",
  "varlatch_list_audit_events",
  "varlatch_list_environments",
  "varlatch_list_organizations",
  "varlatch_list_projects",
  "varlatch_validate_environment",
  "varlatch_whoami",
];

describe.each([RELEASE, OLD])("$name", (entry) => {
  const env = () => ({ ...operatorHome(), VARLATCH_TOKEN: "vlt_cli_test" });

  it("lists the read tools, the write tools only with --allow-writes, and never a disclosure tool", async () => {
    const plain = await connect(entry, [], env());
    expect(await plain.listTools()).toEqual(READ_TOOLS);
    await plain.close();
    const writes = await connect(entry, ["--allow-writes"], env());
    expect(await writes.listTools()).toEqual([...READ_TOOLS, "varlatch_delete_value", "varlatch_set_value"].sort());
    // Not dispatched either: calling it by name finds no tool.
    const called = await writes.callTool("varlatch_disclose_secrets", { items: ["API_KEY"] });
    expect(called.isError).toBe(true);
    expect(`${called.protocolError ?? ""} ${called.text}`).toMatch(/not found/i);
    expect(JSON.stringify(called)).not.toContain(CANARY);
    await writes.close();
    expect(requests.filter((r) => r.url.endsWith("/disclosures"))).toEqual([]);
  });

  it("refuses to write a Secret's value, contracted or not, and writes a non-secret one", async () => {
    const client = await connect(entry, ["--allow-writes"], env());
    for (const item of ["API_KEY", "UNLISTED"]) {
      const result = await client.callTool("varlatch_set_value", { item, value: "mcp-written-secret-7" });
      expect(result.isError).toBe(true);
      expect(result.text).toMatch(new RegExp(`${item} is a Secret, and its value is never written through MCP`));
    }
    expect(requests.filter((r) => r.method === "PUT")).toEqual([]);
    const plain = await client.callTool("varlatch_set_value", { item: "LOG_LEVEL", value: "debug" });
    expect(plain.isError).toBeFalsy();
    expect(requests.filter((r) => r.method === "PUT").map((r) => r.url)).toEqual([`${PROJECT}/environments/dev/values/LOG_LEVEL`]);
    await client.close();
  });

  it("replaces an existing plain value only with the item's name as replace: own, inherited, or unknown existence", async () => {
    const client = await connect(entry, ["--allow-writes"], env());
    const puts = () => requests.filter((r) => r.method === "PUT");
    for (const [existing, message] of [
      [[{ name: "LOG_LEVEL", source: "self" }], /LOG_LEVEL already has a value in dev/],
      [[{ name: "LOG_LEVEL", source: "parent" }], /dev inherits a value for LOG_LEVEL from its parent environment/],
      [403, /cannot be checked \(403 PERMISSION_DENIED\), so it counts as existing/],
    ] as [typeof devItems, RegExp][]) {
      devItems = existing;
      const refused = await client.callTool("varlatch_set_value", { item: "LOG_LEVEL", value: "debug" });
      expect(refused.isError).toBe(true);
      expect(refused.text).toMatch(message);
      expect(refused.text).toMatch(/pass replace: "LOG_LEVEL"\. Nothing was stored\./);
      const other = await client.callTool("varlatch_set_value", { item: "LOG_LEVEL", value: "debug", replace: "OTHER" });
      expect(other.isError).toBe(true);
      expect(puts()).toEqual([]);
      const approved = await client.callTool("varlatch_set_value", { item: "LOG_LEVEL", value: "debug", replace: "LOG_LEVEL" });
      expect(approved.isError).toBeFalsy();
      expect(puts()).toHaveLength(1);
      requests = [];
    }
    // A Secret stays unwritable, replace or not.
    const secret = await client.callTool("varlatch_set_value", { item: "API_KEY", value: "mcp-written-secret-7", replace: "API_KEY" });
    expect(secret.isError).toBe(true);
    expect(secret.text).toMatch(/API_KEY is a Secret, and its value is never written through MCP/);
    expect(puts()).toEqual([]);
    await client.close();
  });

  it("deletes only with the item's name as confirm: --allow-writes alone records no intent", async () => {
    const client = await connect(entry, ["--allow-writes"], env());
    for (const args of [{ item: "LOG_LEVEL" }, { item: "LOG_LEVEL", confirm: "API_KEY" }]) {
      const refused = await client.callTool("varlatch_delete_value", args);
      expect(refused.isError).toBe(true);
      expect(refused.text).toMatch(/Nothing was deleted\./);
    }
    expect(requests.filter((r) => r.method === "DELETE")).toEqual([]);
    const done = await client.callTool("varlatch_delete_value", { item: "LOG_LEVEL", confirm: "LOG_LEVEL" });
    expect(done.isError).toBeFalsy();
    expect(requests.filter((r) => r.method === "DELETE").map((r) => r.url)).toEqual([`${PROJECT}/environments/dev/values/LOG_LEVEL`]);
    await client.close();
  });

  it("refuses --allow-disclose and VARLATCH_MCP_ALLOW_DISCLOSE with 64, before any request", () => {
    for (const [extra, more] of [
      [["--allow-disclose"], {}],
      [["--allow-writes", "--allow-disclose"], {}],
      [[], { VARLATCH_MCP_ALLOW_DISCLOSE: "1" }],
    ] as [string[], Record<string, string>][]) {
      const r = spawnSync(process.execPath, [...entry.command, ...extra], { env: { ...env(), ...more }, cwd: repo, encoding: "utf8", timeout: 20_000 });
      expect(r.status).toBe(64);
      expect(r.stderr).toMatch(/secret disclosure through MCP has been removed/);
    }
    expect(requests).toEqual([]);
  });

  it("inside an agent-safe run with VARLATCH_CONFIG_DIR unset, never uses the operator's stored credential (77)", () => {
    const r = spawnSync(process.execPath, entry.command, {
      env: { ...operatorHome(), VARLATCH_AGENT_RUN: "run_0123456789abcdef" },
      cwd: repo,
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(r.status).toBe(77);
    expect(r.stderr).toMatch(/inside agent-safe run run_0123456789abcdef, which gives the Agent no Varlatch credential/);
    expect(requests).toEqual([]);
  });

  it("identifies itself to varlatchd as the MCP server, which the audit log records as its client", async () => {
    const client = await connect(entry, [], env());
    await client.callTool("varlatch_list_organizations", {});
    await client.close();
    expect(requests.length).toBeGreaterThan(0);
    const ua = new RegExp(`^varlatch-mcp/\\d+\\.\\d+\\.\\d+(?:-\\S+)? \\(${process.platform}; ${process.arch}\\)$`);
    for (const r of requests) expect(r.userAgent).toMatch(ua);
  });

  it("negative control, same store: outside an agent-safe run the stored credential is used; inside, the agent-run one", async () => {
    const outside = await connect(entry, [], operatorHome());
    await outside.callTool("varlatch_list_organizations", {});
    await outside.close();
    const inside = await connect(entry, [], { ...operatorHome(), VARLATCH_AGENT_RUN: "run_1", VARLATCH_TOKEN: "vlt_agr_1" });
    await inside.callTool("varlatch_list_organizations", {});
    await inside.close();
    expect(requests.map((r) => r.auth)).toEqual(["vlt_cli_operator", "vlt_agr_1"]);
  });
});

describe("the release bundle", () => {
  it("reports the CLI's own version to MCP hosts", async () => {
    const version = spawnSync(process.execPath, [RELEASE_BUNDLE, "--version"], { encoding: "utf8" }).stdout.split(" ")[1];
    const client = await connect(RELEASE, [], { ...operatorHome(), VARLATCH_TOKEN: "vlt_cli_test" });
    expect(client.serverInfo).toMatchObject({ name: "varlatch", version });
    // The same version in its User-Agent to varlatchd.
    await client.callTool("varlatch_list_organizations", {});
    await client.close();
    expect(requests.map((r) => r.userAgent)).toContain(`varlatch-mcp/${version} (${process.platform}; ${process.arch})`);
  });

  it("the old entry point says it is deprecated and names varlatch mcp", () => {
    const r = spawnSync(process.execPath, [OLD_ENTRY, "--allow-disclose"], { env: operatorHome(), cwd: repo, encoding: "utf8", timeout: 20_000 });
    expect(r.stderr).toMatch(/this entry point is deprecated; configure your MCP host with `varlatch mcp` instead/);
  });
});

describe(`negative control: the ${CONTROL_VERSION} @varlatch/mcp-server, same probes`, () => {
  const entry = (): Entry => ({ name: "0.13", command: [control] });

  it("lists and dispatches the disclosure tool, returning the Secret, and writes a Secret's value", async () => {
    const client = await connect(entry(), ["--allow-disclose", "--allow-writes"], { ...operatorHome(), VARLATCH_TOKEN: "vlt_cli_test" });
    expect(await client.listTools()).toContain("varlatch_disclose_secrets");
    expect((await client.callTool("varlatch_disclose_secrets", { items: ["API_KEY"] })).text).toContain(CANARY);
    const written = await client.callTool("varlatch_set_value", { item: "API_KEY", value: "mcp-written-secret-7" });
    expect(written.isError).toBeFalsy();
    expect(requests.filter((r) => r.method === "PUT").map((r) => r.url)).toEqual([`${PROJECT}/environments/dev/values/API_KEY`]);
    await client.close();
  });

  it("inside an agent-safe run with VARLATCH_CONFIG_DIR unset, uses the operator's stored credential", async () => {
    const client = await connect(entry(), [], { ...operatorHome(), VARLATCH_AGENT_RUN: "run_0123456789abcdef" });
    await client.callTool("varlatch_list_organizations", {});
    await client.close();
    expect(requests.map((r) => r.auth)).toEqual(["vlt_cli_operator"]);
  });
});
