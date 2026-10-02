// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";

/**
 * Device-authorization sign-in in the CLI (design notes "Device-authorization
 * sign-in"): `login --start` and `login --wait` against a fake server that
 * records every request, so "before any request" and "the device code
 * reaches no other server" are checked directly. The real server's side is
 * tested in services/varlatchd/test/device-sign-in*.test.ts.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-device-login-"));
const bundle = join(dir, "varlatch.cjs");
const DEVICE_CODE = "dc_canary_" + "x".repeat(33);
const USER_CODE = "WDJB-MJHT";
const ISSUED = { id: "crd_issued", token: "vlt_cli_issued-canary", expiresAt: "2030-01-01T00:00:00.000Z" };
const OLD = { token: "vlt_cli_old-canary", credentialId: "crd_old" };

type Answer = { status: number; body?: unknown; headers?: Record<string, string>; stall?: boolean };
interface Seen { method: string; path: string; body: string; at: number; authorization: string }

/** A fake Varlatch server: scripted answers for the device endpoints, a credential check, and a request log. */
function fakeServer(host = "127.0.0.1") {
  const seen: Seen[] = [];
  const state = {
    start: { status: 201, body: null as unknown } as Answer,
    polls: [] as Answer[],
    acceptedTokens: new Set([ISSUED.token, OLD.token]),
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d: Buffer) => (body += d.toString()));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", body, at: Date.now(), authorization: req.headers.authorization ?? "" });
      const send = (answer: Answer) => {
        if (answer.stall) return; // never answers
        res.writeHead(answer.status, { "Content-Type": "application/json", ...answer.headers });
        res.end(answer.body === undefined ? "" : JSON.stringify(answer.body));
      };
      if (req.method === "POST" && req.url === "/v1/auth/device") {
        return send(state.start.body === null
          ? { status: 201, body: { deviceCode: DEVICE_CODE, userCode: USER_CODE, verificationUri: `${origin}/device`, expiresIn: 600, interval: 1 } }
          : state.start);
      }
      if (req.method === "POST" && req.url === "/v1/auth/device/token") return send(state.polls.shift() ?? pending(1));
      const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "");
      if (!state.acceptedTokens.has(bearer)) return send(apiError(401, "INVALID_CREDENTIAL"));
      if (req.url === "/v1/meta") return send({ status: 200, body: { serverVersion: "0.14.0", apiMajor: 1, capabilities: ["auth.device"] } });
      if (req.url === "/v1/organizations") return send({ status: 200, body: { items: [], nextCursor: null } });
      if (req.method === "DELETE" && req.url?.startsWith("/v1/me/credentials/")) return send({ status: 204 });
      send(apiError(404, "RESOURCE_NOT_FOUND"));
    });
  });
  let origin = "";
  return {
    seen,
    state,
    get origin() { return origin; },
    async listen() {
      await new Promise<void>((resolve) => server.listen(0, host, resolve));
      origin = `http://${host}:${(server.address() as AddressInfo).port}`;
      return this;
    },
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

function apiError(status: number, code: string, details?: Record<string, unknown>): Answer {
  return { status, body: { error: { code, message: code.toLowerCase(), requestId: "req_test", ...(details ? { details } : {}) } } };
}
const pending = (interval: number) => apiError(428, "AUTHORIZATION_PENDING", { interval });
const issued: Answer = { status: 201, body: ISSUED };

let fake: ReturnType<typeof fakeServer>;
const servers: ReturnType<typeof fakeServer>[] = [];

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
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function serve(host?: string) {
  const s = await fakeServer(host).listen();
  servers.push(s);
  return s;
}

interface Result { code: number | null; stdout: string; stderr: string; ms: number }

let n = 0;
/** A fresh configuration home: credentials and pending state live under <home>/varlatch. */
function home(): string {
  const h = join(dir, `config-${n++}`);
  mkdirSync(h, { recursive: true });
  return h;
}

function cli(args: string[], config: string, options: { env?: Record<string, string>; stdin?: string } = {}): Promise<Result> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: config, ...options.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr, ms: Date.now() - started }));
    child.stdin.end(options.stdin ?? "");
  });
}

const pendingPath = (config: string) => join(config, "varlatch", "pending-sign-ins.json");
const pendingFile = (config: string) =>
  existsSync(pendingPath(config)) ? (JSON.parse(readFileSync(pendingPath(config), "utf8")) as { servers: Record<string, any> }) : null;
const credentials = (config: string) =>
  existsSync(join(config, "varlatch", "credentials.json"))
    ? (JSON.parse(readFileSync(join(config, "varlatch", "credentials.json"), "utf8")) as { servers: Record<string, any> }).servers
    : {};
const devicePosts = (s: ReturnType<typeof fakeServer>) => s.seen.filter((r) => r.path.startsWith("/v1/auth/device"));
const mode = (path: string) => statSync(path).mode & 0o777;

function expectNoSecrets(r: Result) {
  for (const secret of [DEVICE_CODE, ISSUED.token]) {
    expect(r.stdout).not.toContain(secret);
    expect(r.stderr).not.toContain(secret);
  }
}

describe("login --start", () => {
  it("prints the address and, separately, the code; keeps the device code only in a 0600 file in a 0700 directory", async () => {
    fake = await serve();
    const config = home();
    mkdirSync(join(config, "varlatch"), { mode: 0o755 });
    chmodSync(join(config, "varlatch"), 0o755);
    const r = await cli(["login", "--server", fake.origin, "--start", "--ttl", "3600"], config);
    expect(r.code).toBe(EXIT.ok);
    const lines = r.stdout.split("\n").map((l) => l.trim());
    expect(lines).toContain(`${fake.origin}/device`);
    expect(lines).toContain(USER_CODE);
    expect(lines.find((l) => l.includes("/device"))).not.toContain(USER_CODE);
    expect(r.stdout).toContain(`varlatch login --server ${fake.origin} --wait`);
    expectNoSecrets(r);
    expect(JSON.parse(devicePosts(fake)[0]!.body)).toEqual({ ttlSeconds: 3600 });
    const file = pendingFile(config)!;
    expect(file.servers[fake.origin]).toMatchObject({ server: fake.origin, deviceCode: DEVICE_CODE, userCode: USER_CODE, interval: 1 });
    expect(mode(pendingPath(config))).toBe(0o600);
    expect(mode(join(config, "varlatch"))).toBe(0o700);
    expect(readdirSync(join(config, "varlatch")).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("prints only the documented JSON fields, never the device code", async () => {
    fake = await serve();
    const r = await cli(["login", "--server", fake.origin, "--start", "--json"], home());
    expect(r.code).toBe(EXIT.ok);
    const doc = JSON.parse(r.stdout);
    expect(Object.keys(doc).sort()).toEqual(["expiresAt", "userCode", "verificationUri", "version"]);
    expect(doc).toMatchObject({ version: 1, userCode: USER_CODE, verificationUri: `${fake.origin}/device` });
    expectNoSecrets(r);
  });

  it("a second --start for the same server replaces the entry atomically and says the earlier code no longer completes", async () => {
    fake = await serve();
    const config = home();
    await cli(["login", "--server", fake.origin, "--start"], config);
    const before = statSync(pendingPath(config)).ino;
    fake.state.start = { status: 201, body: { deviceCode: "dc_second_" + "y".repeat(33), userCode: "BCDF-GHJK", verificationUri: `${fake.origin}/device`, expiresIn: 600, interval: 1 } };
    // Keyed by the normalized server URL: a trailing slash names the same server.
    const r = await cli(["login", "--server", `${fake.origin}/`, "--start"], config);
    expect(r.code).toBe(EXIT.ok);
    expect(r.stderr).toMatch(new RegExp(`code ${USER_CODE}\\) no longer completes here`));
    const file = pendingFile(config)!;
    expect(Object.keys(file.servers)).toEqual([fake.origin]);
    expect(file.servers[fake.origin].userCode).toBe("BCDF-GHJK");
    expect(statSync(pendingPath(config)).ino).not.toBe(before); // replaced by rename, not rewritten in place
    expect(mode(pendingPath(config))).toBe(0o600);
  });

  it("explains an older server without device sign-in, and stores nothing", async () => {
    fake = await serve();
    fake.state.start = apiError(404, "RESOURCE_NOT_FOUND");
    const config = home();
    const r = await cli(["login", "--server", fake.origin, "--start"], config);
    expect(r.code).toBe(EXIT.unavailable);
    expect(r.stderr).toMatch(/does not offer device sign-in \(capability auth\.device/);
    expect(pendingFile(config)).toBeNull();
  });

  it("refuses a verification address that is not HTTPS", async () => {
    fake = await serve();
    fake.state.start = { status: 201, body: { deviceCode: DEVICE_CODE, userCode: USER_CODE, verificationUri: "http://phish.example/device", expiresIn: 600, interval: 1 } };
    const config = home();
    const r = await cli(["login", "--server", fake.origin, "--start"], config);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stdout).not.toContain("phish.example");
    expect(pendingFile(config)).toBeNull();
  });
});

describe("login --wait", () => {
  async function started(config = home()) {
    fake = await serve();
    expect((await cli(["login", "--server", fake.origin, "--start"], config)).code).toBe(EXIT.ok);
    return config;
  }

  it("polls until approved, verifies and stores the credential, removes the pending entry, exits 0", async () => {
    const config = await started();
    fake.state.polls = [pending(1), issued];
    const r = await cli(["login", "--server", fake.origin, "--wait"], config);
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/Logged in to/);
    expectNoSecrets(r);
    expect(credentials(config)[fake.origin]).toMatchObject({ token: ISSUED.token, credentialId: ISSUED.id, expiresAt: ISSUED.expiresAt });
    expect(pendingFile(config)).toBeNull();
    const polls = fake.seen.filter((s) => s.path === "/v1/auth/device/token");
    expect(polls.map((p) => JSON.parse(p.body))).toEqual([{ deviceCode: DEVICE_CODE }, { deviceCode: DEVICE_CODE }]);
    expect(polls[1]!.at - polls[0]!.at).toBeGreaterThanOrEqual(950); // the server's interval
    // Verified with the new credential before it was stored.
    expect(fake.seen.some((s) => s.path === "/v1/organizations" && s.authorization === `Bearer ${ISSUED.token}`)).toBe(true);
  });

  it("keeps the existing credential until the new one is verified and saved; revokes it only after (control)", async () => {
    const config = home();
    mkdirSync(join(config, "varlatch"), { recursive: true });
    const seed = () => writeFileSync(join(config, "varlatch", "credentials.json"), JSON.stringify({ servers: { [fake.origin]: OLD } }));
    await started(config);
    seed();
    fake.state.acceptedTokens.delete(ISSUED.token); // the collected credential fails verification
    fake.state.polls = [issued];
    const failed = await cli(["login", "--server", fake.origin, "--wait"], config);
    expect(failed.code).toBe(EXIT.denied);
    expect(failed.stderr).toMatch(/could not be verified .* Revoke credential crd_issued/);
    expect(credentials(config)[fake.origin]).toEqual(OLD);
    expect(fake.seen.some((s) => s.method === "DELETE")).toBe(false);
    expectNoSecrets(failed);
    // Control: a credential that verifies replaces the old one, which is then revoked.
    await cli(["login", "--server", fake.origin, "--start"], config);
    fake.state.acceptedTokens.add(ISSUED.token);
    fake.state.polls = [issued];
    const ok = await cli(["login", "--server", fake.origin, "--wait"], config);
    expect(ok.code).toBe(EXIT.ok);
    expect(credentials(config)[fake.origin].token).toBe(ISSUED.token);
    const deletes = fake.seen.filter((s) => s.method === "DELETE");
    expect(deletes.map((d) => [d.path, d.authorization])).toEqual([[`/v1/me/credentials/${OLD.credentialId}`, `Bearer ${OLD.token}`]]);
  });

  it("exits 75 at the deadline with the entry kept, and says to run --wait again; --json reports the pending state", async () => {
    const config = await started();
    const r = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "3"], config);
    expect(r.code).toBe(75);
    expect(r.ms).toBeLessThan(3_800);
    expect(r.stderr).toMatch(new RegExp(`still waiting .* Run again: varlatch login --server ${fake.origin.replace(/[.]/g, "\\.")} --wait`));
    expect(pendingFile(config)!.servers[fake.origin].deviceCode).toBe(DEVICE_CODE);
    const json = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "2", "--json"], config);
    expect(json.code).toBe(75);
    expect(JSON.parse(json.stdout)).toEqual({ version: 1, state: "pending" });
    expectNoSecrets(json);
  });

  it("honours SLOW_DOWN: the next poll waits the grown interval", async () => {
    const config = await started();
    fake.state.polls = [apiError(429, "SLOW_DOWN", { interval: 3 }), issued];
    const r = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "10"], config);
    expect(r.code).toBe(EXIT.ok);
    const polls = fake.seen.filter((s) => s.path === "/v1/auth/device/token");
    expect(polls[1]!.at - polls[0]!.at).toBeGreaterThanOrEqual(2_950);
  });

  it("handles denial, expiry, and a lost collection (CONSUMED): exit 77, nothing stored, existing credential kept", async () => {
    for (const [answer, message, state] of [
      [apiError(403, "ACCESS_DENIED"), /denied in the browser/, { state: "denied" }],
      [apiError(410, "EXPIRED"), /expired before it was approved/, { state: "expired" }],
      [apiError(410, "CONSUMED", { credentialId: "crd_lost" }), /Revoke credential crd_lost/, { state: "consumed", credentialId: "crd_lost" }],
    ] as const) {
      const config = home();
      mkdirSync(join(config, "varlatch"), { recursive: true });
      await started(config);
      writeFileSync(join(config, "varlatch", "credentials.json"), JSON.stringify({ servers: { [fake.origin]: OLD } }));
      fake.state.polls = [answer];
      const r = await cli(["login", "--server", fake.origin, "--wait", "--json"], config);
      expect(r.code).toBe(EXIT.denied);
      expect(r.stderr).toMatch(message);
      expect(r.stderr).toMatch(/[Ss]tart again: varlatch login --server .* --start/);
      expect(JSON.parse(r.stdout)).toEqual({ version: 1, ...state });
      expect(credentials(config)[fake.origin]).toEqual(OLD);
      expect(pendingFile(config)).toBeNull();
      await fake.close();
    }
  });

  it("keeps the pending entry on a transport failure: unreachable, maintenance, a 5xx (exit 69)", async () => {
    for (const answer of [apiError(503, "MAINTENANCE"), apiError(502, "INTERNAL"), null]) {
      const config = await started();
      if (answer) fake.state.polls = [answer];
      else await fake.close();
      const r = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "5"], config);
      expect(r.code, JSON.stringify(answer)).toBe(EXIT.unavailable);
      expect(r.stderr).toMatch(/The pending sign-in is kept/);
      expect(pendingFile(config)!.servers[fake.origin].deviceCode).toBe(DEVICE_CODE);
    }
  });

  it("bounds a stalled poll by the deadline: 75 once the sign-in was seen pending", async () => {
    const config = await started();
    fake.state.polls = [pending(1), { status: 0, stall: true }];
    const r = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "4"], config);
    expect(r.code).toBe(75);
    expect(r.ms).toBeLessThan(4_800);
    expect(pendingFile(config)!.servers[fake.origin]).toBeTruthy();
  });

  it("the default deadline (60 seconds) holds against a server that stalls its first answer", { timeout: 75_000 }, async () => {
    const config = await started();
    fake.state.polls = [{ status: 0, stall: true }];
    const r = await cli(["login", "--server", fake.origin, "--wait"], config);
    expect(r.stderr).toMatch(/Waiting up to 60 seconds/);
    expect(r.code).toBe(EXIT.unavailable);
    expect(r.ms).toBeGreaterThanOrEqual(54_000);
    expect(r.ms).toBeLessThan(61_500);
    expect(r.stderr).toMatch(/did not answer before the deadline\. The pending sign-in is kept/);
    expect(pendingFile(config)!.servers[fake.origin]).toBeTruthy();
  });

  it("refuses --wait with no sign-in started from this CLI", async () => {
    fake = await serve();
    const r = await cli(["login", "--server", fake.origin, "--wait"], home());
    expect(r.code).toBe(EXIT.usage);
    expect(r.stderr).toMatch(/no sign-in was started from this CLI/);
    expect(devicePosts(fake)).toEqual([]);
  });
});

describe("transport", () => {
  const lan = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal)?.address;

  it.skipIf(!lan)("refuses http:// to a non-loopback server before any request (the server records none)", async () => {
    const remote = await serve(lan);
    const config = home();
    for (const args of [["--start"], ["--wait"]]) {
      const r = await cli(["login", "--server", remote.origin, ...args], config);
      expect(r.code, args[0]).toBe(EXIT.usage);
      expect(r.stderr).toMatch(/runs only over https:\/\//);
    }
    expect(remote.seen).toEqual([]);
    expect(pendingFile(config)).toBeNull();
  });

  it("allows http:// to loopback, the local-development exception (control)", async () => {
    fake = await serve();
    expect((await cli(["login", "--server", fake.origin, "--start"], home())).code).toBe(EXIT.ok);
  });

  it("does not follow a 307 or 308 from the token endpoint, to another origin or to http://: the device code reaches no second server", async () => {
    for (const status of [307, 308]) {
      const config = home();
      fake = await serve();
      const elsewhere = await serve();
      await cli(["login", "--server", fake.origin, "--start"], config);
      fake.state.polls = [{ status, headers: { Location: `${elsewhere.origin}/v1/auth/device/token` } }];
      const r = await cli(["login", "--server", fake.origin, "--wait", "--timeout", "5"], config);
      expect(r.code).toBe(EXIT.failure);
      expect(r.stderr).toContain(`redirect to ${elsewhere.origin}/v1/auth/device/token`);
      expect(r.stderr).toMatch(/follows no redirect, so its code was not sent there\. The pending sign-in is kept/);
      expect(elsewhere.seen).toEqual([]);
      expect(pendingFile(config)!.servers[fake.origin].deviceCode).toBe(DEVICE_CODE);
      // Control: the same exchange without the redirect completes.
      fake.state.polls = [issued];
      expect((await cli(["login", "--server", fake.origin, "--wait", "--timeout", "5"], config)).code).toBe(EXIT.ok);
    }
  });

  it("does not follow a redirect from the start endpoint either", async () => {
    fake = await serve();
    const elsewhere = await serve();
    fake.state.start = { status: 308, headers: { Location: `${elsewhere.origin}/v1/auth/device` } };
    const config = home();
    const r = await cli(["login", "--server", fake.origin, "--start"], config);
    expect(r.code).toBe(EXIT.failure);
    expect(elsewhere.seen).toEqual([]);
    expect(pendingFile(config)).toBeNull();
  });
});

describe("assisted mode", () => {
  it("starts a device sign-in when no method is given, and hands the address and code to the human", async () => {
    fake = await serve();
    const config = home();
    const r = await cli(["--assisted", "login", "--server", fake.origin], config);
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/Give the person this address and code/);
    expect(r.stdout).toContain(USER_CODE);
    expect(r.stdout).toMatch(new RegExp(`wait until they say they approved it; only then run:\\n  varlatch --assisted login --server ${fake.origin.replace(/[.]/g, "\\.")} --wait`));
    expect(pendingFile(config)!.servers[fake.origin]).toBeTruthy();
    expectNoSecrets(r);
  });

  it("keeps --token-stdin's behaviour (control)", async () => {
    fake = await serve();
    const config = home();
    const r = await cli(["--assisted", "login", "--server", fake.origin, "--token-stdin"], config, { stdin: OLD.token });
    expect(r.code).toBe(EXIT.ok);
    expect(credentials(config)[fake.origin].token).toBe(OLD.token);
    expect(devicePosts(fake)).toEqual([]);
  });
});

describe("inside an agent-safe run", () => {
  const methods: [string, string[], string?][] = [
    ["--start", ["--start"]],
    ["--wait", ["--wait"]],
    ["assisted implicit --start", []],
    ["browser", []],
    ["--token", ["--token", OLD.token]],
    ["--token-stdin", ["--token-stdin"], OLD.token],
    ["--oidc", ["--oidc", "--org", "acme", "--oidc-token", "eyJ.e30.sig"]],
  ];

  it("refuses every sign-in method with 64 before any request, without reading or writing the pending state, whatever VARLATCH_CONFIG_DIR says", async () => {
    fake = await serve();
    const config = home();
    // Pending state the refusal must not touch: unreadable, so reading it would fail differently.
    mkdirSync(join(config, "varlatch"), { recursive: true });
    writeFileSync(pendingPath(config), "{}", { mode: 0o000 });
    const other = home();
    for (const configDir of [undefined, join(config, "varlatch"), join(other, "varlatch")]) {
      for (const [name, extra, stdin] of methods) {
        const assistedPrefix = name === "assisted implicit --start" ? ["--assisted"] : [];
        const env: Record<string, string> = { VARLATCH_AGENT_RUN: "run_test", ...(configDir ? { VARLATCH_CONFIG_DIR: configDir } : {}) };
        const r = await cli([...assistedPrefix, "login", "--server", fake.origin, ...extra], config, { env, ...(stdin ? { stdin } : {}) });
        expect(r.code, `${name} ${configDir}`).toBe(EXIT.usage);
        expect(r.stderr).toMatch(/inside agent-safe run run_test, which has no human sign-in/);
        expect(r.stderr).toMatch(/--agent-metadata/);
      }
    }
    expect(fake.seen).toEqual([]);
    expect(mode(pendingPath(config))).toBe(0o000);
    expect(existsSync(pendingPath(other))).toBe(false);
    expect(credentials(other)).toEqual({});
    chmodSync(pendingPath(config), 0o600);
  });
});

describe("the command line", () => {
  it("is parsed strictly before anything is sent", async () => {
    fake = await serve();
    const cases: [string[], RegExp][] = [
      [["--start", "--wait"], /not more than one/],
      [["--start", "--token-stdin"], /not more than one/],
      [["--strat"], /unknown option --strat/],
      [["--start", "--timeout", "30"], /--timeout applies to --wait/],
      [["--wait", "--ttl", "3600"], /--ttl applies to --start/],
      [["--start", "--ttl", "30"], /--ttl takes whole seconds from 60 to 86400/],
      [["--wait", "--timeout", "601"], /--timeout takes whole seconds from 1 to 600/],
      [["--wait", "--timeout", "1.5"], /--timeout takes whole seconds/],
      [["--json"], /--json applies to --start and --wait/],
      [["--start", "--org", "acme"], /--org applies to --oidc/],
    ];
    for (const [extra, message] of cases) {
      const config = home();
      const r = await cli(["login", "--server", fake.origin, ...extra], config);
      expect(r.code, extra.join(" ")).toBe(EXIT.usage);
      expect(r.stderr, extra.join(" ")).toMatch(message);
      expect(pendingFile(config)).toBeNull();
    }
    expect(fake.seen).toEqual([]);
  });

  it("documents exit 75 and the device sign-in forms in --help", async () => {
    const r = await cli(["login", "--help"], home());
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/login --server <url> --start/);
    expect(r.stdout).toMatch(/login --server <url> --wait \[--timeout <s>\]/);
    expect(r.stdout).toMatch(/exit 75 when it is still pending/);
    expect((await cli(["--help"], home())).stdout).toMatch(/75 login --wait reached its deadline with the sign-in still pending/);
  });
});
