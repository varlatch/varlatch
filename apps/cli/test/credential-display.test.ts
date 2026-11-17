// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { saveCredential, setDefaultServer } from "@varlatch/context";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";

/**
 * Diagnostics never print credential values: a stored token the server
 * would refuse is never quoted, and a server URL's user name and password
 * are shown as [redacted], wherever the CLI names a server. A server URL
 * without them is printed exactly as before.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-credential-display-"));
const bundle = join(dir, "varlatch.cjs");
const SECRET = "hunter2pw9secret";
const MASKED = "http://[redacted]@127.0.0.1:9";
let n = 0;

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
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd: string, config: string): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), VARLATCH_CONFIG_DIR: config },
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

/** A configuration directory and an empty working directory. */
function setup(): { config: string; cwd: string } {
  const base = join(dir, `t${n++}`);
  const config = join(base, "config");
  const cwd = join(base, "cwd");
  mkdirSync(config, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  return { config, cwd };
}

function shows(r: Result, what: string): void {
  expect(`${r.stdout}\n${r.stderr}`, what).not.toContain(SECRET);
}

describe("a server URL with a user name and password", () => {
  const server = `http://user:${SECRET}@127.0.0.1:9`;

  it("status, status --json, server and server --json show it masked", async () => {
    const { config, cwd } = setup();
    saveCredential(server, { token: "vlt_cli_x", expiresAt: "2000-01-01T00:00:00Z", issuedAt: "1999-01-01T00:00:00Z" }, { VARLATCH_CONFIG_DIR: config });
    setDefaultServer(server, { VARLATCH_CONFIG_DIR: config });
    const status = await cli(["status"], cwd, config);
    shows(status, "status");
    expect(status.stdout).toContain(`${MASKED}  (EXPIRED`);
    const json = await cli(["status", "--json"], cwd, config);
    shows(json, "status --json");
    expect(JSON.parse(json.stdout).servers[0].server).toBe(MASKED);
    const shown = await cli(["server"], cwd, config);
    shows(shown, "server");
    expect(shown.stdout).toContain(`Default server: ${MASKED}`);
    expect(shown.stdout).toContain(`Signed in to: ${MASKED}`);
    const shownJson = await cli(["server", "--json"], cwd, config);
    shows(shownJson, "server --json");
    expect(JSON.parse(shownJson.stdout)).toMatchObject({ server: MASKED, defaultServer: MASKED, signedIn: [MASKED] });
    const use = await cli(["server", "use", `http://other:${SECRET}@127.0.0.1:10`], cwd, config);
    shows(use, "server use");
    expect(use.code).toBe(EXIT.usage);
  });

  it("logout and whoami with several stored servers list them masked", async () => {
    const { config, cwd } = setup();
    saveCredential(server, { token: "vlt_cli_x" }, { VARLATCH_CONFIG_DIR: config });
    saveCredential("http://127.0.0.1:10", { token: "vlt_cli_y" }, { VARLATCH_CONFIG_DIR: config });
    const logout = await cli(["logout"], cwd, config);
    shows(logout, "logout");
    expect(logout.code).toBe(EXIT.usage);
    expect(logout.stderr).toContain(`Multiple servers stored (${MASKED}, http://127.0.0.1:10)`);
    const whoami = await cli(["whoami"], cwd, config);
    shows(whoami, "whoami");
    expect(whoami.code).toBe(EXIT.usage);
    expect(whoami.stderr).toContain(`credentials are stored for ${MASKED}, http://127.0.0.1:10;`);
  });

  it("logout of it says what happened with the URL masked, the failure reason included", async () => {
    const { config, cwd } = setup();
    saveCredential(server, { token: "vlt_cli_x", credentialId: "crd_1" }, { VARLATCH_CONFIG_DIR: config });
    const r = await cli(["logout", "--server", server], cwd, config);
    shows(r, "logout --server");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`${MASKED}: removed locally; server revocation failed (Request cannot be constructed from a URL that includes credentials: ${MASKED}/v1/me/credentials/crd_1)`);
  });

  it("context, context --json and a command that needs a credential show the repository's server masked", async () => {
    const { config, cwd } = setup();
    writeFileSync(join(cwd, "varlatch.toml"), `server = "${server}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n`);
    const context = await cli(["context"], cwd, config);
    shows(context, "context");
    expect(context.stdout).toContain(`Server        ${MASKED}`);
    const json = await cli(["context", "--json"], cwd, config);
    shows(json, "context --json");
    expect(JSON.parse(json.stdout).server).toBe(MASKED);
    const status = await cli(["status", "--json"], cwd, config);
    shows(status, "status --json in a repository");
    expect(JSON.parse(status.stdout).repo.server).toBe(MASKED);
    const env = await cli(["env", "list"], cwd, config);
    shows(env, "env list");
    expect(env.code).toBe(EXIT.denied);
    expect(env.stderr).toContain(`Not authenticated to ${MASKED}.`);
  });

  it("a varlatch.toml that does not parse is quoted with the URL masked", async () => {
    const { config, cwd } = setup();
    writeFileSync(join(cwd, "varlatch.toml"), `server = "${server}" oops\n`);
    const r = await cli(["context"], cwd, config);
    shows(r, "context with a broken varlatch.toml");
    expect(r.stderr).toContain("Invalid varlatch.toml");
  });

  it("a server URL without one is printed exactly as before", async () => {
    const { config, cwd } = setup();
    saveCredential("http://127.0.0.1:9", { token: "vlt_cli_x" }, { VARLATCH_CONFIG_DIR: config });
    const status = await cli(["status", "--json"], cwd, config);
    expect(JSON.parse(status.stdout).servers[0].server).toBe("http://127.0.0.1:9");
    const shown = await cli(["server"], cwd, config);
    expect(shown.stdout).toContain("Signed in to: http://127.0.0.1:9");
  });
});

describe("a stored token the server would refuse", () => {
  const token = `vlt_cli_${SECRET}\r\nmore`;

  it("logout's failure reason names the credential without quoting it", async () => {
    const { config, cwd } = setup();
    saveCredential("http://127.0.0.1:9", { token, credentialId: "crd_1" }, { VARLATCH_CONFIG_DIR: config });
    const r = await cli(["logout", "--server", "http://127.0.0.1:9"], cwd, config);
    shows(r, "logout");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(
      "http://127.0.0.1:9: removed locally; server revocation failed (the credential contains a character that is not allowed in an HTTP header)",
    );
  });

  it("status --probe's detail names the credential without quoting it", async () => {
    const { config, cwd } = setup();
    saveCredential("http://127.0.0.1:9", { token }, { VARLATCH_CONFIG_DIR: config });
    const r = await cli(["status", "--probe", "--json"], cwd, config);
    shows(r, "status --probe");
    expect(JSON.parse(r.stdout).servers[0].probe.detail).toBe("the credential contains a character that is not allowed in an HTTP header");
  });

  it("a command that uses it exits 1, as before, without quoting it", async () => {
    const { config, cwd } = setup();
    saveCredential("http://127.0.0.1:9", { token }, { VARLATCH_CONFIG_DIR: config });
    const r = await cli(["whoami", "--server", "http://127.0.0.1:9"], cwd, config);
    shows(r, "whoami");
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("the credential contains a character that is not allowed in an HTTP header");
  });
});
