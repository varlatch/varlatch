// SPDX-License-Identifier: Apache-2.0
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * `varlatch run --redact` end to end: the CLI, bundled from this checkout's
 * source, runs against a local fake server and starts real child processes
 * whose stdout and stderr are pipes. Covers the piped output, stdin, the exit
 * code, forwarded signals, and interruption.
 */

const value = "tokenvalue-aaaaaaaa";
const multiByte = "pässword-XYZ-123";
const binary = [0x1f, 0x8b, 0x08, 0xff, 0x00, 0x80, 0xc3];

const dir = mkdtempSync(join(tmpdir(), "varlatch-redact-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
let server: http.Server;
let requests = 0;

/** The environment's items as the server stores them. */
const items = [
  { name: "API_TOKEN", sensitive: true, value },
  { name: "DB_PASS", sensitive: true, value: multiByte },
  { name: "PIN", sensitive: true, value: "1234567" },
  // A stored value with an unpaired surrogate: JSON carries it as "\ud83d", UTF-8 cannot.
  { name: "SURROGATE", sensitive: true, value: "surrogate-\uD83D-value" },
  { name: "PORT", sensitive: false, value: "8080" },
];

function contractItem(name: string, sensitive: boolean) {
  return { name, required: { kind: "never" }, sensitive, type: "string" };
}

function strictRetrieval() {
  const stored = items.map((i) => ({ ...i, source: "self", versionId: `ver_${i.name}` }));
  return {
    environmentId: "env_1",
    manifest: {
      manifestVersion: 1,
      projectId: "prj_1",
      environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
      contract: { revisionId: "rev_1", contentHash: "sha256:abc", semanticsVersion: 2 },
      items: stored.map((i) => ({ name: i.name, source: i.source, valueRowId: `val_${i.name}`, versionId: i.versionId })),
    },
    stateDigest: `sha256:${"0".repeat(64)}`,
    contract: { schemaVersion: 1, semanticsVersion: 2, items: items.map((i) => contractItem(i.name, i.sensitive)) },
    items: stored,
    callerView: { withheld: [], unexpanded: [], contractWithheld: false },
    validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
  };
}

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  requests++;
  const url = req.url ?? "";
  const json = (body: unknown) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  req.resume();
  if (url === "/v1/meta") return json({ serverVersion: "0.11.0", capabilities: ["retrieval.strict"] });
  if (url.endsWith("/effective-configuration?include=values")) {
    // Secrets need the explicit disclosure; the effective configuration holds none.
    return json({
      environmentId: "env_1",
      items: items.map((i) => ({ name: i.name, sensitive: i.sensitive, source: "self", value: i.sensitive ? null : i.value })),
    });
  }
  if (url.endsWith("/disclosures")) {
    return json({
      items: items.filter((i) => i.sensitive).map((i) => ({ name: i.name, versionId: `ver_${i.name}`, value: i.value })),
      withheld: [],
    });
  }
  if (url.endsWith("/retrievals")) return json(strictRetrieval());
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
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

interface Run {
  child: ChildProcess;
  stdout: () => Buffer;
  stderr: () => string;
  done: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/** Start `varlatch run <flags> -- node <script>` with piped stdio. */
function start(flags: string[], script: string): Run {
  const file = join(dir, `child-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(file, script);
  const child = spawn(process.execPath, [bundle, "run", ...flags, "--", process.execPath, file], {
    cwd: repo,
    env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", MARKER: join(dir, "started") },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const out: Buffer[] = [];
  let err = "";
  child.stdout!.on("data", (d: Buffer) => out.push(d));
  child.stderr!.on("data", (d: Buffer) => (err += d.toString()));
  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    child.on("close", (code, signal) => resolve({ code, signal })),
  );
  return { child, stdout: () => Buffer.concat(out), stderr: () => err, done };
}

async function until(check: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

// Child scripts write with explicit pauses so every write is its own read.
const PRELUDE = `
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const out = (chunk) => new Promise((resolve) => process.stdout.write(chunk, resolve));
const err = (chunk) => new Promise((resolve) => process.stderr.write(chunk, resolve));
`;

describe("varlatch run --redact", () => {
  it("masks delivered Secrets split across writes with pauses of seconds, keeps binary and other output byte-exact, and passes the exit code", async () => {
    const run = start(
      ["--redact"],
      `${PRELUDE}
(async () => {
  const v = process.env.API_TOKEN;
  await out(Buffer.from(${JSON.stringify(binary)}));
  await out("token=" + v.slice(0, 3)); await pause(150);
  await out(v.slice(3, 11)); await pause(1500);
  await out(v.slice(11) + "\\n");
  const b = Buffer.from(process.env.DB_PASS);
  const inside = b.indexOf(0xc3) + 1;
  await out(Buffer.concat([Buffer.from("db="), b.subarray(0, inside)])); await pause(100);
  await out(Buffer.concat([b.subarray(inside), Buffer.from("\\n")]));
  await out("port=" + process.env.PORT + " pin=" + process.env.PIN + "\\n");
  await err("warn " + v + "\\n");
  process.exitCode = 7;
})();`,
    );
    const { code } = await run.done;
    expect(code).toBe(7);
    expect(run.stdout()).toEqual(
      Buffer.concat([
        Buffer.from(binary),
        Buffer.from("token=[REDACTED:API_TOKEN]\ndb=[REDACTED:DB_PASS]\nport=8080 pin=1234567\n"),
      ]),
    );
    expect(run.stderr()).toContain("warn [REDACTED:API_TOKEN]\n");
    // The short value is named, never shown, before the child starts.
    expect(run.stderr()).toMatch(/--redact does not mask values shorter than 8 bytes; these pass through unchanged: PIN\n/);
    expect(run.stderr().indexOf("PIN")).toBeLessThan(run.stderr().indexOf("warn"));
    expect(run.stderr()).not.toContain(value);
    expect(run.stdout().includes(Buffer.from(value))).toBe(false);
    expect(run.stdout().includes(Buffer.from(multiByte))).toBe(false);
  }, 20_000);

  it("passes stdin through unchanged", async () => {
    const run = start(
      ["--redact"],
      `${PRELUDE}
let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", async () => { await out("got " + input); });`,
    );
    run.child.stdin!.end(`hello ${value}\n`);
    const { code } = await run.done;
    expect(code).toBe(0);
    // The child received the exact bytes; what it echoes is masked.
    expect(run.stdout().toString()).toBe("got hello [REDACTED:API_TOKEN]\n");
  });

  it("releases a trailing prefix unchanged when the stream ends cleanly", async () => {
    const run = start(["--redact"], `${PRELUDE}(async () => { await out("clean line\\n" + process.env.API_TOKEN.slice(0, -1)); })();`);
    const { code } = await run.done;
    expect(code).toBe(0);
    expect(run.stdout().toString()).toBe(`clean line\n${value.slice(0, -1)}`);
  });

  it("an interrupted run discards held bytes: the signal is forwarded and the prefix is never written", async () => {
    const run = start(
      ["--redact"],
      `${PRELUDE}
(async () => {
  await out("clean line\\n" + process.env.API_TOKEN.slice(0, -1));
  await err("ready\\n");
  setInterval(() => {}, 1000);
})();`,
    );
    await until(() => run.stderr().includes("ready\n") && run.stdout().toString() === "clean line\n", "the child to write");
    run.child.kill("SIGTERM");
    const { code } = await run.done;
    // The child died of the forwarded SIGTERM; the exit code is the one a run without --redact gives.
    expect(code).toBe(143);
    expect(run.stdout().toString()).toBe("clean line\n");
  });

  it("a child that handles the forwarded signal keeps writing, masked, and its exit code passes through", async () => {
    const run = start(
      ["--redact"],
      `${PRELUDE}
process.on("SIGTERM", async () => { await out("stopping " + process.env.API_TOKEN + "\\n"); process.exit(5); });
(async () => { await err("ready\\n"); setInterval(() => {}, 1000); })();`,
    );
    await until(() => run.stderr().includes("ready\n"), "the child to start");
    run.child.kill("SIGTERM");
    const { code } = await run.done;
    expect(code).toBe(5);
    expect(run.stdout().toString()).toBe("stopping [REDACTED:API_TOKEN]\n");
  });

  it("when the reader of stdout goes away, the command's next write fails as on a closed pipe, and the run ends", async () => {
    const run = start(
      ["--redact"],
      `${PRELUDE}
process.stdout.on("error", (e) => { require("fs").writeSync(2, "child saw " + e.code + "\\n"); process.exit(3); });
(async () => { for (;;) { await out("line " + process.env.API_TOKEN.slice(0, 4) + "\\n"); await pause(10); } })();`,
    );
    await until(() => run.stdout().toString().includes("line "), "the first line");
    run.child.stdout!.destroy();
    const { code } = await run.done;
    expect(run.stderr()).toContain("child saw EPIPE");
    expect(code).toBe(3);
  });

  it("works with --strict: the Secrets delivered by the strict retrieval are masked", async () => {
    const run = start(["--strict", "--redact"], `${PRELUDE}(async () => { await out("t=" + process.env.API_TOKEN + " port=" + process.env.PORT + "\\n"); })();`);
    const { code } = await run.done;
    expect(code).toBe(0);
    expect(run.stdout().toString()).toBe("t=[REDACTED:API_TOKEN] port=8080\n");
  });

  it("without --redact nothing is masked (a default run is unchanged)", async () => {
    const run = start([], `${PRELUDE}(async () => { await out("t=" + process.env.API_TOKEN + "\\n"); })();`);
    const { code } = await run.done;
    expect(code).toBe(0);
    expect(run.stdout().toString()).toBe(`t=${value}\n`);
  });

  it("masks a delivered value that holds an unpaired surrogate, as the command receives it, instead of failing", async () => {
    const script = `${PRELUDE}(async () => { await out("s=" + process.env.SURROGATE + "\\n"); })();`;
    const masked = start(["--redact"], script);
    expect((await masked.done).code).toBe(0);
    expect(masked.stdout().toString()).toBe("s=[REDACTED:SURROGATE]\n");
    // Negative control, same input: without --redact the command prints it, the surrogate replaced by U+FFFD.
    const plain = start([], script);
    expect((await plain.done).code).toBe(0);
    expect(plain.stdout().toString()).toBe("s=surrogate-\uFFFD-value\n");
  });

  it("refuses --agent-safe before fetching anything, and starts nothing", async () => {
    const before = requests;
    const run = start(
      ["--redact", "--agent-safe", "--agent", "coding agent", "--allow-host", "api.example.com"],
      `require("fs").writeFileSync(process.env.MARKER, "started");`,
    );
    const { code } = await run.done;
    expect(code).toBe(64);
    expect(run.stderr()).toMatch(/--redact does not apply to --agent-safe runs/);
    expect(run.stderr()).toMatch(/Nothing was started\./);
    expect(existsSync(join(dir, "started"))).toBe(false);
    expect(requests).toBe(before);
  });
});

// util-linux `script` gives the command a pseudo-terminal; skipped where none can be allocated.
const hasScript = spawnSync("script", ["-qec", "true", "/dev/null"]).status === 0;

// A-R8 end to end: under a pseudo-terminal, `--redact` refuses before it
// fetches anything whenever stdout or stderr is the terminal.
describe.skipIf(!hasScript)("varlatch run --redact on a terminal", () => {
  const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

  function underTerminal(redirect: string) {
    const child = join(dir, "tty-child.cjs");
    writeFileSync(child, `require("fs").writeFileSync(process.env.MARKER, "started");`);
    const command = [process.execPath, bundle, "run", "--redact", "--", process.execPath, child].map(shellQuote).join(" ");
    const result = spawnSync("script", ["-qec", `${command} ${redirect}`, "/dev/null"], {
      cwd: repo,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", MARKER: join(dir, "started"), SHELL: "/bin/sh" },
      encoding: "utf8",
      timeout: 20_000,
    });
    return { code: result.status, terminal: result.stdout };
  }

  it.each([
    ["stdout and stderr are the terminal", "", /stdout and stderr are terminals/],
    ["stdout is the terminal", `2>${join(dir, "stderr.txt")}`, /stdout is a terminal/],
    ["stderr is the terminal", `>${join(dir, "stdout.txt")}`, /stderr is a terminal/],
  ])("%s: refused, nothing fetched or started", (_name, redirect, message) => {
    rmSync(join(dir, "stderr.txt"), { force: true });
    const before = requests;
    const { code, terminal } = underTerminal(redirect);
    const diagnostic = redirect.startsWith("2>") ? readFileSync(join(dir, "stderr.txt"), "utf8") : terminal;
    expect(code).toBe(64);
    expect(diagnostic).toMatch(message);
    expect(diagnostic).toMatch(/Nothing was started\./);
    expect(existsSync(join(dir, "started"))).toBe(false);
    expect(requests).toBe(before);
  });
});
