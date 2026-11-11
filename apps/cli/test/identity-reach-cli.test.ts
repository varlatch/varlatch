// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { EXIT } from "../src/exitCodes.js";

/**
 * `varlatch identity reach` end to end against a local server (ADR-0054
 * Decision 8): read-only, the result on stdout, conditions in words.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-reach-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const ORG = "/v1/organizations/acme";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let requests: { method: string; url: string }[] = [];

const IDENTITIES = [
  { id: "idn_ada", name: "Ada", kind: "human", disabled: false, orgRole: "admin", removedAt: null, lastSeenAt: null },
  { id: "idn_svc", name: "deployer", kind: "service", disabled: false, orgRole: null, lastSeenAt: null },
  { id: "idn_dup1", name: "twin", kind: "service", disabled: false, orgRole: null, lastSeenAt: null },
  { id: "idn_dup2", name: "twin", kind: "workload", disabled: false, orgRole: null, lastSeenAt: null },
];

const REACH = {
  identity: { id: "idn_svc", name: "deployer", kind: "service", state: "live", disabledReason: null, liveCredentials: 1 },
  organizationActions: [{ action: "audit.read", grants: [{ grantId: "grt_3", viaGroupId: null, roleId: null }], conditions: [] }],
  projects: [
    {
      id: "prj_1",
      slug: "api",
      name: "API",
      actions: [{ action: "contract.read", grants: [{ grantId: "grt_4", viaGroupId: null, roleId: null }], conditions: [] }],
      environments: [
        {
          id: "env_dev",
          name: "development",
          tier: "development",
          kind: "shared",
          parentEnvironmentId: null,
          actions: [{ action: "config.value.read", grants: [{ grantId: "grt_2", viaGroupId: "grp_1", roleId: null }], conditions: [] }],
        },
        {
          id: "env_prod",
          name: "production",
          tier: "production",
          kind: "shared",
          parentEnvironmentId: null,
          actions: [
            { action: "config.metadata.read", grants: [{ grantId: "grt_1", viaGroupId: null, roleId: null }], conditions: [] },
            { action: "secret.use", grants: [{ grantId: "grt_1", viaGroupId: null, roleId: null }], conditions: ["req_1", "req_2"] },
          ],
        },
      ],
    },
  ],
  requirements: [
    { id: "req_1", version: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] }, condition: "needs tailnet example.ts.net: tag:prod" },
    { id: "req_2", version: 1, target: { kind: "environments", environmentIds: ["env_prod"] }, selector: { tailnet: "example.ts.net", nodes: ["nAbc"] }, condition: "needs tailnet example.ts.net: node:nAbc" },
  ],
  notes: [],
};

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  req.resume();
  req.on("end", () => {
    const url = req.url ?? "";
    requests.push({ method: req.method ?? "", url });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.20.1", capabilities });
    if (url === `${ORG}/identities`) return json(200, { items: IDENTITIES, nextCursor: null });
    const id = /^\/v1\/organizations\/acme\/identities\/([a-z_0-9]+)\/reach$/.exec(url)?.[1];
    if (id === "idn_ada") {
      return json(422, { error: { code: "VALIDATION_FAILED", message: "This identity is a person. Reach is for machine identities; for a member, see their exposure report.", requestId: "req_h", details: { reason: "human-identity" } } });
    }
    if (id === "idn_svc") return json(200, REACH);
    if (id === "idn_old") {
      return json(200, {
        ...REACH,
        identity: { ...REACH.identity, id: "idn_old", name: "old", kind: "broker", state: "retired", liveCredentials: 0 },
        organizationActions: [],
        projects: [],
        requirements: [],
        notes: ["This identity is retired: it cannot sign in."],
      });
    }
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Not found", requestId: "req_1" } });
  });
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
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["identity.reach"];
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

// Each run sets its mode explicitly (VARLATCH_ASSISTED), whatever the
// environment the tests run in.
function cli(args: string[], env: Record<string, string> = {}): Promise<Result> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: repo,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("varlatch identity reach", () => {
  it("prints the reach by project and environment, with conditions in words, on stdout", async () => {
    const r = await cli(["identity", "reach", "idn_svc"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Reach of deployer (idn_svc, service, live, 1 live credential).");
    expect(r.stdout).toContain("Organization-wide: audit.read");
    expect(r.stdout).toContain("api (API):\n  project: contract.read\n  development: config.value.read\n");
    expect(r.stdout).toContain(
      "  production: config.metadata.read, secret.use (needs tailnet example.ts.net: tag:prod and needs tailnet example.ts.net: node:nAbc)",
    );
    expect(r.stdout).toContain("They are listed, not checked against any device.");
    expect(r.stdout).not.toMatch(/denied/i);
    // An ID goes straight to the server: no identity listing.
    expect(requests.map((q) => q.url)).toEqual(["/v1/meta", `${ORG}/identities/idn_svc/reach`]);
  });

  it("writes the document with --json", async () => {
    const r = await cli(["identity", "reach", "idn_svc", "--json"]);
    expect(r.code, r.stderr).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc).toMatchObject({ version: expect.any(Number), organization: "acme", identity: { id: "idn_svc", state: "live" } });
    expect(doc.projects[0].environments[1].actions[1]).toEqual(REACH.projects[0]!.environments[1]!.actions[1]);
    expect(doc.requirements).toEqual(REACH.requirements);
  });

  it("resolves a machine by name, and refuses an ambiguous or unknown one", async () => {
    const byName = await cli(["identity", "reach", "deployer"]);
    expect(byName.code, byName.stderr).toBe(0);
    expect(requests.some((q) => q.url === `${ORG}/identities/idn_svc/reach`)).toBe(true);
    const twin = await cli(["identity", "reach", "twin"]);
    expect(twin.code).toBe(EXIT.failure);
    expect(twin.stderr).toContain("Several machines are named twin; name one by its identity ID: idn_dup1, idn_dup2.");
    // A person's name never matches: reach is for machines.
    const person = await cli(["identity", "reach", "Ada"]);
    expect(person.code).toBe(EXIT.failure);
    expect(person.stderr).toContain("Ada is not a machine identity of this organization");
  });

  it("passes on the server's refusal of a person's ID", async () => {
    const r = await cli(["identity", "reach", "idn_ada"]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("Reach is for machine identities");
  });

  it("says when a machine is retired and has no project reach, with the server's notes", async () => {
    const r = await cli(["identity", "reach", "idn_old"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Reach of old (idn_old, broker, retired, 0 live credentials).");
    expect(r.stdout).toContain("No Grant allows it anything in a project.");
    expect(r.stdout).toContain("This identity is retired: it cannot sign in.");
  });

  it("works the same in assisted mode: it shows no value", async () => {
    const r = await cli(["identity", "reach", "idn_svc"], { VARLATCH_ASSISTED: "1" });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Reach of deployer");
  });

  it("refuses on a server without the capability", async () => {
    capabilities = [];
    const r = await cli(["identity", "reach", "idn_svc"]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("needs Varlatch 0.21.0 or later");
    expect(requests.map((q) => q.url)).toEqual(["/v1/meta"]);
  });

  it("checks the command line strictly, before any request", async () => {
    for (const args of [
      ["identity", "reach"],
      ["identity", "reach", "idn_svc", "extra"],
      ["identity", "reach", "idn_svc", "--jsn"],
      ["identity", "reach", "idn_svc", "--confirm", "x"],
    ]) {
      expect((await cli(args)).code, args.join(" ")).toBe(EXIT.usage);
    }
    expect(requests).toEqual([]);
  });
});
