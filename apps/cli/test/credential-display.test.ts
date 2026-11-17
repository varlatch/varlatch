// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { saveCredential, savePendingSignIn, setDefaultServer } from "@varlatch/context";
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

/** Runs the CLI; with `until`, stops it once its output satisfies `until` (a command that would wait). */
function cli(args: string[], cwd: string, config: string, env: Record<string, string> = {}, until?: (out: string) => boolean): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), VARLATCH_CONFIG_DIR: config, VARLATCH_NO_BROWSER: "1", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const check = () => {
      if (until?.(`${stdout}\n${stderr}`)) child.kill();
    };
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
      check();
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
      check();
    });
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

describe("signing in to a server URL with a user name and password", () => {
  const server = `http://user:${SECRET}@127.0.0.1:9`;

  it("the browser sign-in shows the address to open with them masked", async () => {
    const { config, cwd } = setup();
    const r = await cli(["login", "--server", server], cwd, config, {}, (out) => out.includes("/enroll?callback="));
    shows(r, "login");
    expect(r.stdout).toContain("Complete passkey sign-in in your browser:");
    expect(r.stdout).toContain(`  ${MASKED}/enroll?callback=`);
  });

  it("device sign-in's refusals and messages mask them, for a scheme-less address too", async () => {
    const { config, cwd } = setup();
    const http = await cli(["login", "--server", `http://user:${SECRET}@varlatch.example`, "--start"], cwd, config);
    shows(http, "login --start over http");
    expect(http.stderr).toContain("http://[redacted]@varlatch.example: device sign-in sends a code");
    const bare = await cli(["login", "--server", `user:${SECRET}@varlatch.example`, "--start"], cwd, config);
    shows(bare, "login --start without a scheme");
    expect(bare.stderr).toContain("[redacted]@varlatch.example: device sign-in sends a code");
    const start = await cli(["login", "--server", server, "--start"], cwd, config);
    shows(start, "login --start to loopback");
    expect(start.code).not.toBe(0);
    const wait = await cli(["login", "--server", server, "--wait", "--timeout", "1"], cwd, config);
    shows(wait, "login --wait without a pending sign-in");
    expect(wait.stderr).toContain(`no sign-in was started from this CLI for ${MASKED}. Start one: varlatch login --server ${MASKED} --start`);
  });

  it("device sign-in's wait for a pending sign-in masks them", async () => {
    const { config, cwd } = setup();
    savePendingSignIn(
      {
        server,
        deviceCode: "dc_x",
        userCode: "ABCD-EFGH",
        verificationUri: "https://varlatch.example/device",
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
        interval: 1,
        startedAt: new Date().toISOString(),
      },
      { VARLATCH_CONFIG_DIR: config },
    );
    const r = await cli(["login", "--server", server, "--wait", "--timeout", "1"], cwd, config);
    shows(r, "login --wait");
    expect(r.code).not.toBe(0);
  });

  it("init refuses to write them into varlatch.toml (64), and writes nothing", async () => {
    const { config, cwd } = setup();
    const r = await cli(["init", "--org", "acme", "--project", "web", "--server", server], cwd, config);
    shows(r, "init");
    expect(r.code).toBe(EXIT.usage);
    expect(r.stderr).toContain("varlatch init: a server URL with a user name or password can't be written to varlatch.toml");
    expect(readdirSync(cwd)).toEqual([]);
  });

  it("project create never prints them, signed in or not", async () => {
    const { config, cwd } = setup();
    const signedOut = await cli(["project", "create", "web", "--org", "acme", "--server", server], cwd, config);
    shows(signedOut, "project create, not signed in");
    expect(signedOut.stderr).toContain(`Not authenticated to ${MASKED}`);
    saveCredential(server, { token: "vlt_cli_x" }, { VARLATCH_CONFIG_DIR: config });
    const signedIn = await cli(["project", "create", "web", "--org", "acme", "--server", server], cwd, config);
    shows(signedIn, "project create");
    expect(signedIn.code).toBe(1);
  });

  it("varlatch mcp says it is not authenticated with them masked", async () => {
    const { config, cwd } = setup();
    const r = await cli(["mcp", "--server", server], cwd, config);
    shows(r, "mcp");
    expect(r.stderr).toContain(`not authenticated to ${MASKED}`);
  });
});

describe("login --oidc from GitHub Actions", () => {
  const login = ["login", "--server", "http://127.0.0.1:9", "--oidc", "--org", "acme"];

  it("a request token with a line break inside is refused without quoting it (exit 1, as before)", async () => {
    const { config, cwd } = setup();
    const r = await cli(login, cwd, config, { ACTIONS_ID_TOKEN_REQUEST_URL: "http://127.0.0.1:9/token", ACTIONS_ID_TOKEN_REQUEST_TOKEN: `tok_${SECRET}\r\nx` });
    shows(r, "login --oidc");
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("ACTIONS_ID_TOKEN_REQUEST_TOKEN contains a character that is not allowed in an HTTP header");
  });

  it("a request URL with a user name and password, or one that does not parse, is shown masked", async () => {
    const { config, cwd } = setup();
    const withCredentials = await cli(login, cwd, config, { ACTIONS_ID_TOKEN_REQUEST_URL: `http://user:${SECRET}@127.0.0.1:9/token`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: "tok_x" });
    shows(withCredentials, "login --oidc, URL with credentials");
    expect(withCredentials.stderr).toContain("Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:9/token");
    const broken = await cli(login, cwd, config, { ACTIONS_ID_TOKEN_REQUEST_URL: `http://user:${SECRET}@[::1/token`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: "tok_x" });
    shows(broken, "login --oidc, URL that does not parse");
    expect(broken.stderr).toContain("Failed to parse URL from http://[redacted]@[::1/token");
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
