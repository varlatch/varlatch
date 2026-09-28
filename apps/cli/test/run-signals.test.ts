// SPDX-License-Identifier: Apache-2.0
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The exit status of `varlatch run` when a signal ends its command, end to
 * end: the CLI, bundled from this checkout's source, runs against a local
 * fake server and starts a real child. Every mode reports 128 plus the
 * signal's number, as a shell does, whether the signal reached the command
 * directly or was forwarded by `varlatch run` itself (Ctrl-C).
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-run-signals-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const child = join(dir, "child.cjs");
const reloading = join(dir, "reloading.cjs");
let server: http.Server;

const stored = "valueaaaaaaaaaaaaa";
const manifest = (secrets: boolean) => ({
  manifestVersion: 1,
  projectId: "prj_1",
  environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
  contract: secrets ? { revisionId: "rev_1", contentHash: "sha256:abc", semanticsVersion: 2 } : null,
  items: [
    ...(secrets ? [{ name: "API_TOKEN", source: "self", valueRowId: "val_1", versionId: "ver_1" }] : []),
    { name: "PORT", source: "self", valueRowId: "val_2", versionId: "ver_2" },
  ],
});
const digest = `sha256:${"0".repeat(64)}`;

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = req.url ?? "";
  const json = (body: unknown): void => {
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(body));
  };
  req.resume();
  if (url === "/v1/meta") {
    return json({ serverVersion: "0.11.0", capabilities: ["retrieval.strict", "capabilities.targets"] });
  }
  if (url === "/v1/organizations/acme/identities") {
    return json({ items: [{ id: "idn_agent", name: "coding-agent", kind: "agent" }] });
  }
  // The "agents" environment stores no Secret, so an agent-safe run needs no Broker.
  if (url.endsWith("/environments/agents/effective-configuration?include=values")) {
    return json({
      environmentId: "env_1",
      items: [{ name: "PORT", sensitive: false, source: "self", versionId: "ver_2", value: "8080" }],
      manifest: manifest(false),
      stateDigest: digest,
    });
  }
  if (url.endsWith("/environments/development/effective-configuration?include=values")) {
    return json({
      environmentId: "env_1",
      items: [
        { name: "API_TOKEN", sensitive: true, source: "self", versionId: "ver_1", value: null },
        { name: "PORT", sensitive: false, source: "self", versionId: "ver_2", value: "8080" },
      ],
    });
  }
  if (url.endsWith("/environments/development/disclosures")) {
    return json({ items: [{ name: "API_TOKEN", versionId: "ver_1", value: stored }], withheld: [] });
  }
  if (url.endsWith("/environments/development/retrievals")) {
    return json({
      environmentId: "env_1",
      manifest: manifest(true),
      stateDigest: digest,
      contract: {
        schemaVersion: 1,
        semanticsVersion: 2,
        items: [
          { name: "API_TOKEN", required: { kind: "never" }, sensitive: true, type: "string" },
          { name: "PORT", required: { kind: "never" }, sensitive: false, type: "string" },
        ],
      },
      items: [
        { name: "API_TOKEN", sensitive: true, source: "self", versionId: "ver_1", value: stored },
        { name: "PORT", sensitive: false, source: "self", versionId: "ver_2", value: "8080" },
      ],
      callerView: { withheld: [], unexpanded: [], contractWithheld: false },
      validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
    });
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: { code: "NOT_FOUND", message: url, requestId: "req_1" } }));
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
  const { port } = server.address() as AddressInfo;
  mkdirSync(repo);
  writeFileSync(
    join(repo, "varlatch.toml"),
    `organization = "acme"\nproject = "web"\nserver = "http://127.0.0.1:${port}"\ndefault_environment = "development"\n`,
  );
  // The command reports that it started, with its PID, and then waits to be signalled.
  writeFileSync(child, `process.stderr.write("ready " + process.pid + "\\n"); setInterval(() => {}, 1000);`);
  // A service that treats SIGHUP, SIGUSR1, and SIGUSR2 as "reload" or "rotate" and keeps running.
  writeFileSync(
    reloading,
    `for (const s of ["SIGHUP", "SIGUSR1", "SIGUSR2"]) process.on(s, () => process.stderr.write("got " + s + "\\n"));
process.stderr.write("ready " + process.pid + "\\n"); setInterval(() => {}, 1000);`,
  );
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

interface Run {
  cli: ChildProcess;
  stderr: () => string;
  done: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

function start(flags: string[], command = child): Run {
  const cli = spawn(process.execPath, [bundle, "run", ...flags, "--", process.execPath, command], {
    cwd: repo,
    env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let err = "";
  cli.stdout!.resume();
  cli.stderr!.on("data", (d: Buffer) => (err += d.toString()));
  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    cli.on("close", (code, signal) => resolve({ code, signal })),
  );
  return { cli, stderr: () => err, done };
}

/** The command's PID, once it has started. */
async function started(run: Run): Promise<number> {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const match = /ready (\d+)\n/.exec(run.stderr());
    if (match) return Number(match[1]);
    if (Date.now() > deadline) throw new Error(`the command did not start; stderr: ${run.stderr()}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Waits until the run's stderr contains `text`. */
async function saw(run: Run, text: string): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!run.stderr().includes(text)) {
    if (Date.now() > deadline) throw new Error(`never saw ${JSON.stringify(text)}; stderr: ${run.stderr()}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const MODES: [string, string[]][] = [
  ["a default run", []],
  ["a --strict run", ["--strict"]],
  ["a --redact run", ["--redact"]],
  ["a --strict --redact run", ["--strict", "--redact"]],
  ["an agent-safe run", ["--agent-safe", "--agent", "coding-agent", "--environment", "agents"]],
];
const SIGNALS: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];

describe("varlatch run exits with 128 plus the number of the signal that ended its command", () => {
  it("the numbers are the conventional ones", () => {
    expect(SIGNALS.map((s) => 128 + constants.signals[s])).toEqual([130, 143, 129]);
  });

  describe.each(MODES)("%s", (_mode, flags) => {
    it.each(SIGNALS)("a command killed by %s", async (signal) => {
      const run = start(flags);
      process.kill(await started(run), signal);
      const { code, signal: own } = await run.done;
      expect(own).toBeNull();
      expect(code).toBe(128 + constants.signals[signal]);
      expect(run.stderr()).not.toContain(stored);
    });

    // Ctrl-C, a stop, a hangup, and Ctrl-\ sent to `varlatch run` alone are forwarded.
    it.each(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const)("%s sent to varlatch run is forwarded, and the command's death by it is reported", async (signal) => {
      const run = start(flags);
      await started(run);
      run.cli.kill(signal);
      const { code, signal: own } = await run.done;
      expect(own).toBeNull();
      expect(code).toBe(128 + constants.signals[signal]);
    });

    // A service manager's reload or a log rotation signals only `varlatch run`:
    // the command must get it, and the run must go on until the command ends.
    it.each(["SIGHUP", "SIGUSR1", "SIGUSR2"] as const)("%s sent to varlatch run reaches a command that handles it, and the run goes on", async (signal) => {
      const run = start(flags, reloading);
      await started(run);
      run.cli.kill(signal);
      await saw(run, `got ${signal}`);
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(run.cli.exitCode).toBeNull();
      expect(run.cli.signalCode).toBeNull();
      run.cli.kill("SIGTERM");
      const { code, signal: own } = await run.done;
      expect(own).toBeNull();
      expect(code).toBe(143);
    });
  });
});
