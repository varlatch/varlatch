// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalTargets } from "@varlatch/protocol";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CONTROL_VERSION, controlCli } from "./controlCli.js";

/**
 * Credential isolation in agent-safe runs (ADR-0043 Decision 5), end to
 * end: a real `varlatch run --agent-safe` (Broker, Capability, and, with
 * --agent-metadata, a minted agent-run credential) against a local fake
 * server, starting an "agent" that runs nested varlatch commands while the
 * operator's credential store is populated. The negative control is the
 * same run and the same probes with the 0.13 CLI, which has no isolation.
 */

const CANARY = "stripe-key-canary-operator-only-7c1d";
const OPERATOR = "vlt_cli_operator";
const BROKER = "vlt_brk_test";
const AGENT_TOKEN = "vlt_agr_test";

const dir = mkdtempSync(join(tmpdir(), "varlatch-isolation-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
let control = "";
let server: http.Server;
let origin = "";
let requests: { at: number; method: string; url: string; auth: string }[] = [];

const ENV_PATH = "/v1/organizations/acme/projects/web/environments/development";

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    // Behind the Broker's pass-through, an absolute URI arrives as the path.
    const url = (req.url ?? "").replace(/^https?:\/\/[^/]+/, "");
    const auth = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    requests.push({ at: Date.now(), method: req.method ?? "", url, auth });
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(body === undefined ? "" : JSON.stringify(body));
    };
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    if (![OPERATOR, BROKER, AGENT_TOKEN].includes(auth) && url !== "/v1/meta") {
      return json(401, { error: { code: "UNAUTHENTICATED", message: "no credential", requestId: "r" } });
    }
    // The real server refuses every non-read method for agent-run credentials (ADR-0023 Decision 4).
    if (auth === AGENT_TOKEN && req.method !== "GET") {
      return json(403, { error: { code: "PERMISSION_DENIED", message: "agent-run credentials are read-only", requestId: "r" } });
    }
    if (url === "/v1/meta") return json(200, { serverVersion: "0.13.0", capabilities: ["capabilities.targets", "retrieval.strict"] });
    if (url.startsWith(`${ENV_PATH}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_1",
        items: [
          { name: "STRIPE_KEY", sensitive: true, source: "self", value: null },
          { name: "PORT", sensitive: false, source: "self", value: "8080" },
        ],
        manifest: {
          manifestVersion: 1,
          projectId: "prj_1",
          environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null },
          contract: null,
          items: [],
        },
      });
    }
    if (url === `${ENV_PATH}/disclosures`) {
      // Reached only with the operator's credential: the leak the isolation prevents.
      return json(200, { items: [{ name: "STRIPE_KEY", versionId: "ver_1", value: CANARY }], withheld: [] });
    }
    if (url === "/v1/organizations/acme/identities") return json(200, { items: [{ id: "idn_agent", kind: "agent", name: "coder" }] });
    if (url === `${ENV_PATH}/capabilities` && req.method === "POST") {
      const items = body.items as string[];
      return json(201, {
        id: "cap_1",
        secret: "capsecret",
        agentIdentityId: "idn_agent",
        environmentId: "env_1",
        items,
        destinations: body.destinations,
        targets: canonicalTargets(items, body.targets as Record<string, string[]>),
        runId: body.runId,
        expiresAt: "2026-10-01T00:00:00.000Z",
        preflight: "ok",
      });
    }
    if (url === "/v1/organizations/acme/identities/idn_agent/credentials" && req.method === "POST") {
      return json(201, { id: "crd_agr_1", token: AGENT_TOKEN, expiresAt: "2026-10-01T00:00:00.000Z" });
    }
    if (req.method === "DELETE") return json(204, undefined);
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
  });
}

/**
 * The "coding agent": records what isolation it was given, then runs four
 * nested probes, each also with VARLATCH_TOKEN removed (a script or tool
 * that drops it, so the only way to a credential is the store).
 */
const AGENT = `
const { spawnSync } = require("child_process");
const fs = require("fs");
const e = process.env;
const record = {
  startedAt: Date.now(),
  agentRun: e.VARLATCH_AGENT_RUN ?? null,
  configDir: e.VARLATCH_CONFIG_DIR ?? null,
  configDirExists: e.VARLATCH_CONFIG_DIR ? fs.existsSync(e.VARLATCH_CONFIG_DIR) : false,
  hasToken: Boolean(e.VARLATCH_TOKEN),
  placeholder: /^vlch_ph_v1_/.test(e.STRIPE_KEY ?? ""),
  probes: {},
};
const print = [process.execPath, "-e", "process.stdout.write('nested=' + process.env.STRIPE_KEY + '\\\\n')"];
function probe(name, args, env) {
  const r = spawnSync(process.execPath, [e.CLI_BUNDLE, ...args], { cwd: e.REPO, env, encoding: "utf8", timeout: 20000 });
  record.probes[name] = { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
}
const withoutToken = { ...e };
delete withoutToken.VARLATCH_TOKEN;
probe("run", ["run", "--", ...print], e);
probe("values", ["values", "list"], e);
probe("runWithoutToken", ["run", "--", ...print], withoutToken);
probe("valuesWithoutToken", ["values", "list"], withoutToken);
fs.writeFileSync(e.OUT, JSON.stringify(record));
`;

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
  control = await controlCli(dir);
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
  writeFileSync(join(dir, "agent.cjs"), AGENT);
}, 120_000);

afterAll(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

interface Record {
  startedAt: number;
  agentRun: string | null;
  configDir: string | null;
  configDirExists: boolean;
  hasToken: boolean;
  placeholder: boolean;
  probes: { [name: string]: { code: number | null; out: string } };
}

/** One agent-safe run by `cli`, with the operator's credential in the default store (HOME), and the agent's record. */
async function agentSafeRun(cli: string, metadata: boolean): Promise<{ code: number | null; output: string; record: Record }> {
  requests = [];
  const home = mkdtempSync(join(dir, "home-"));
  mkdirSync(join(home, ".config", "varlatch"), { recursive: true });
  writeFileSync(join(home, ".config", "varlatch", "credentials.json"), JSON.stringify({ servers: { [origin]: { token: OPERATOR } } }));
  const out = join(home, "record.json");
  const args = [
    cli,
    "run",
    "--agent-safe",
    "--agent",
    "coder",
    "--allow-host",
    "api.example.com",
    "--target",
    "STRIPE_KEY=header:authorization",
    ...(metadata ? ["--agent-metadata"] : []),
    "--",
    process.execPath,
    join(dir, "agent.cjs"),
  ];
  const env = { PATH: process.env.PATH, HOME: home, VARLATCH_BROKER_CREDENTIAL: BROKER, CLI_BUNDLE: cli, REPO: repo, OUT: out };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: repo, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (d: Buffer) => (output += d.toString()));
    child.stderr.on("data", (d: Buffer) => (output += d.toString()));
    child.on("close", (code) => {
      const record = existsSync(out) ? (JSON.parse(readFileSync(out, "utf8")) as Record) : ({ probes: {} } as Record);
      resolve({ code, output, record });
    });
  });
}

const operatorRequestsAfter = (at: number) => requests.filter((r) => r.auth === OPERATOR && r.at >= at);

describe.each([
  ["without --agent-metadata", false],
  ["with --agent-metadata", true],
])("agent-safe run %s", (_mode, metadata) => {
  it("gives the Agent its own configuration directory and run id, and removes the directory at exit", async () => {
    const { code, output, record } = await agentSafeRun(bundle, metadata);
    expect(code, output).toBe(0);
    expect(record.agentRun).toMatch(/^run_[0-9a-f]{16}$/);
    expect(record.configDir).toMatch(/varlatch-agent-run-/);
    expect(record.configDirExists).toBe(true);
    expect(existsSync(record.configDir!)).toBe(false);
    expect(record.placeholder).toBe(true);
    expect(record.hasToken).toBe(metadata);
  });

  it("nested varlatch commands never disclose and never use the operator's stored credential", async () => {
    const { code, output, record } = await agentSafeRun(bundle, metadata);
    expect(code, output).toBe(0);
    const { run, values, runWithoutToken, valuesWithoutToken } = record.probes;
    for (const probe of [run, values, runWithoutToken, valuesWithoutToken]) expect(probe!.out).not.toContain(CANARY);
    expect(output).not.toContain(CANARY);
    // A nested run starts its command with the run's environment: the Placeholder, never a disclosure.
    for (const probe of [run, runWithoutToken]) {
      expect(probe!.code).toBe(0);
      expect(probe!.out).toMatch(/nested=vlch_ph_v1_[0-9a-f]+/);
      expect(probe!.out).toMatch(/inside agent-safe run run_[0-9a-f]{16}, Secrets are Placeholders and are never disclosed/);
    }
    // Reading metadata works only with the agent-run credential.
    if (metadata) {
      expect(values!.code).toBe(0);
      expect(values!.out).toContain("STRIPE_KEY  (secret, self)");
    } else {
      expect(values!.code).toBe(1);
      expect(values!.out).toMatch(/gives the Agent no Varlatch credential and never uses the operator's/);
    }
    expect(valuesWithoutToken!.code).toBe(1);
    expect(valuesWithoutToken!.out).toMatch(/relaunches the run with --agent-metadata/);
    expect(operatorRequestsAfter(record.startedAt)).toEqual([]);
    expect(requests.filter((r) => r.url.endsWith("/disclosures"))).toEqual([]);
  });

  it(`negative control: the same run and probes with the ${CONTROL_VERSION} CLI reach the operator's credential and leak`, async () => {
    const { code, output, record } = await agentSafeRun(control, metadata);
    expect(code, output).toBe(0);
    expect(record.agentRun).toBeNull();
    // Without the metadata credential the plain nested run falls back to the store; with it,
    // VARLATCH_TOKEN takes precedence, so the probe that drops it is the one that falls back.
    const leaking = metadata ? record.probes.runWithoutToken : record.probes.run;
    expect(leaking!.out).toContain(`nested=${CANARY}`);
    expect(operatorRequestsAfter(record.startedAt).some((r) => r.url.endsWith("/disclosures"))).toBe(true);
  });
});
