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
 * `varlatch member` end to end against a local server (ADR-0052): removal
 * and leaving name their target again with --confirm, checked before any
 * request; in assisted mode the refusal gives the human's command.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-member-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
const ORG = "/v1/organizations/acme";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
/** When set, the identity listing is refused, as for a caller without identity.read. */
let denyIdentities = false;
/** When set, the project listing is refused, as for a caller without project.read. */
let denyProjects = false;
let requests: { method: string; url: string; body: unknown }[] = [];

const IDENTITIES = [
  { id: "idn_ada", name: "Ada", kind: "human", disabled: false, orgRole: "admin", removedAt: null, lastSeenAt: null },
  { id: "idn_bob", name: "Bob", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: "idn_old", name: "Old", kind: "human", disabled: false, orgRole: null, removedAt: "2026-10-01T10:00:00.000Z", lastSeenAt: null },
  { id: "idn_dup1", name: "Sam", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: "idn_dup2", name: "Sam", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: "idn_svc", name: "deployer", kind: "service", disabled: false, orgRole: null, lastSeenAt: null },
  // A live member whose name is another identity's ID: that ID still names the other identity.
  { id: "idn_tricky", name: "idn_old", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: "idn_ada2", name: "Ada Lovelace", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
];

const REVIEW = {
  syncTargets: [{ id: "snt_1", projectId: "prj_1", environmentId: "env_1", platform: "coolify", state: "active", changes: ["created", "destination_changed"] }],
  connections: [{ id: "pcn_1", name: "shared", platform: "coolify", credentialKind: "token", revoked: false, changes: ["credential_replaced"] }],
  webhooks: [{ id: "whk_1", host: "sink.example", revoked: false }],
  oidcBindings: [],
  credentials: [{ id: "crd_1", name: "deploy", identityId: "idn_svc", identityName: "deployer", state: "valid" }],
  personalEnvironments: [{ id: "env_2", name: "development/bob", projectId: "prj_1" }],
};

const EXPOSURE = {
  member: { identityId: "idn_old", name: "Old", role: null, removedAt: "2026-10-01T10:00:00.000Z" },
  coverage: { complete: false, from: "2026-01-01T00:00:00.000Z", to: "2026-10-30T00:00:00.000Z" },
  received: [
    {
      itemName: "TOKEN",
      versionId: "ver_1",
      owningEnvironmentId: "env_1",
      projectId: "prj_1",
      state: "served",
      servedAs: "current",
      retiringUntil: null,
      notServedBecause: null,
      served: true,
      confirmation: null,
      rotationHint: "Issue a new token in the provider console.",
      receipts: [
        { environmentId: "env_1", way: "revealed", firstAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-02T10:00:00.000Z" },
        { environmentId: "env_2", way: "delivered", firstAt: "2026-09-03T10:00:00.000Z", lastAt: "2026-09-03T10:00:00.000Z" },
      ],
    },
    {
      itemName: "OLD_KEY",
      versionId: "ver_2",
      owningEnvironmentId: "env_1",
      projectId: "prj_1",
      state: "not-served",
      servedAs: null,
      retiringUntil: null,
      notServedBecause: "replaced",
      served: false,
      confirmation: null,
      rotationHint: null,
      receipts: [{ environmentId: "env_1", way: "export", firstAt: "2026-08-01T10:00:00.000Z", lastAt: "2026-08-01T10:00:00.000Z" }],
    },
  ],
  authorityAtRemoval: {
    removalId: "mrm_1",
    removedAt: "2026-10-01T10:00:00.000Z",
    role: "member",
    left: false,
    environments: [
      { environmentId: "env_1", actions: [{ action: "secret.reveal", sources: [] }, { action: "config.metadata.read", sources: [] }], conditionalOn: ["req_1"] },
    ],
    requirements: [{ requirementId: "req_1", requirementVersion: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } }],
  },
  indirect: { syncTargets: [], connections: [], webhooks: [{ id: "whk_1", host: "sink.example", revoked: false }], oidcBindings: [], credentials: [], personalEnvironments: [] },
};

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    requests.push({ method: req.method ?? "", url, body });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.20.0", capabilities });
    if (url === `${ORG}/identities`) {
      if (denyIdentities) return json(403, { error: { code: "PERMISSION_DENIED", message: "Not authorized for this action", requestId: "req_d" } });
      return json(200, { items: IDENTITIES, nextCursor: null });
    }
    if (url === `${ORG}/projects`) {
      if (denyProjects) return json(403, { error: { code: "PERMISSION_DENIED", message: "Not authorized for this action", requestId: "req_p" } });
      return json(200, { items: [{ id: "prj_1", slug: "api", name: "API" }], nextCursor: null });
    }
    if (url === `${ORG}/projects/api/environments`) {
      return json(200, { items: [{ id: "env_1", name: "production" }, { id: "env_2", name: "development/bob" }], nextCursor: null });
    }
    const exposed = /^\/v1\/organizations\/acme\/members\/([a-z_0-9]+)\/exposure$/.exec(url)?.[1];
    if (exposed && req.method === "GET") {
      // As the server: a machine, or someone never a member, is not found.
      if (exposed === "idn_svc") return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Member not found", requestId: "req_n" } });
      return json(200, { ...EXPOSURE, member: { ...EXPOSURE.member, identityId: exposed } });
    }
    const member = /^\/v1\/organizations\/acme\/members\/([a-z_0-9]+)$/.exec(url)?.[1];
    if (member && req.method === "DELETE") {
      return json(200, {
        removalId: "mrm_1",
        identityId: member === "me" ? "idn_ada" : member,
        role: "member",
        left: member === "me",
        removedAt: "2026-10-30T12:00:00.000Z",
        grantsRevoked: 2,
        groupsLeft: 1,
        invitationsRevoked: 0,
        review: member === "me" ? { ...REVIEW, syncTargets: [], connections: [], webhooks: [], credentials: [], personalEnvironments: [] } : REVIEW,
      });
    }
    if (member && req.method === "PATCH") {
      return json(200, { identityId: member, role: body?.role, previousRole: member === "idn_ada" ? "admin" : "member" });
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
  capabilities = ["members.lifecycle"];
  denyIdentities = false;
  denyProjects = false;
});

interface Result {
  code: number | null;
  stdout: string;
  stderr: string;
}

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

const changes = () => requests.filter((r) => r.method === "DELETE" || r.method === "PATCH");

describe("varlatch member list", () => {
  it("lists people, former members marked, machines left out", async () => {
    const r = await cli(["member", "list"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("idn_ada  Ada  (admin, last seen never)");
    expect(r.stdout).toContain("idn_old  Old  (former member, left 2026-10-01T10:00:00.000Z, last seen never)");
    expect(r.stdout).not.toContain("deployer");
    const json = JSON.parse((await cli(["member", "list", "--json"])).stdout);
    expect(json.members).toContainEqual({ id: "idn_old", name: "Old", role: null, removedAt: "2026-10-01T10:00:00.000Z", lastSeenAt: null });
    expect(json.members).toContainEqual(expect.objectContaining({ id: "idn_bob", role: "member", removedAt: null }));
  });
});

describe("varlatch member remove", () => {
  it("removes a member named by name with --confirm, and says what to review", async () => {
    const r = await cli(["member", "remove", "Bob", "--confirm", "Bob"]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "DELETE", url: `${ORG}/members/idn_bob`, body: undefined }]);
    expect(r.stdout).toContain("Removed Bob from acme.");
    expect(r.stdout).toContain("Revoked 2 Grants, left 1 group or team, revoked 0 pending invitations.");
    expect(r.stdout).toContain("snt_1  coolify, active, environment env_1  (created, destination changed)");
    expect(r.stdout).toContain("pcn_1  shared (coolify, token)  (credential replaced)");
    expect(r.stdout).toContain("whk_1  sink.example");
    expect(r.stdout).toContain("crd_1  deploy for deployer: valid");
    expect(r.stdout).toContain("env_2  development/bob");
  });

  it("refuses without --confirm, before any request; in assisted mode it gives the human's command", async () => {
    const plain = await cli(["member", "remove", "Bob"]);
    expect(plain.code).toBe(EXIT.usage);
    expect(plain.stderr).toContain("varlatch member remove Bob --confirm Bob");
    const assisted = await cli(["member", "remove", "idn_bob"], { VARLATCH_ASSISTED: "1" });
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain("that is the human's decision");
    expect(assisted.stderr).toContain("  varlatch member remove idn_bob --confirm idn_bob\nNothing was changed.");
    expect(requests).toEqual([]);
  });

  it("refuses a --confirm naming someone else, and an unknown or ambiguous member", async () => {
    const other = await cli(["member", "remove", "Bob", "--confirm", "Ada"]);
    expect(other.code).toBe(EXIT.usage);
    expect(other.stderr).toContain("--confirm names Ada, but this command removes Bob");
    expect(requests).toEqual([]);
    const former = await cli(["member", "remove", "Old", "--confirm", "Old"]);
    expect(former.code).toBe(EXIT.failure);
    expect(former.stderr).toContain("Old is not a member of this organization");
    const ambiguous = await cli(["member", "remove", "Sam", "--confirm", "Sam"]);
    expect(ambiguous.stderr).toContain("Several members are named Sam; name one by its identity ID: idn_dup1, idn_dup2");
    expect(changes()).toEqual([]);
  });

  it("reads an ID as that identity first: a former member's or a machine's ID never falls back to a name", async () => {
    const former = await cli(["member", "remove", "idn_old", "--confirm", "idn_old"]);
    expect(former.code).toBe(EXIT.failure);
    expect(former.stderr).toContain("idn_old (Old) is a former member, not a member of this organization");
    const machine = await cli(["member", "role", "idn_svc", "admin"]);
    expect(machine.code).toBe(EXIT.failure);
    expect(machine.stderr).toContain("idn_svc (deployer) is a service identity");
    expect(changes()).toEqual([]);
  });

  it("quotes the human's command so it can be pasted as it is", async () => {
    const r = await cli(["member", "remove", "Ada Lovelace"], { VARLATCH_ASSISTED: "1" });
    expect(r.code).toBe(EXIT.config);
    expect(r.stderr).toContain("  varlatch member remove 'Ada Lovelace' --confirm 'Ada Lovelace'\nNothing was changed.");
    const odd = await cli(["member", "remove", "it's $(x)"]);
    expect(odd.stderr).toContain(`varlatch member remove 'it'\\''s $(x)' --confirm 'it'\\''s $(x)'`);
    const named = await cli(["member", "remove", "Ada Lovelace", "--confirm", "Ada Lovelace"]);
    expect(named.code, named.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "DELETE", url: `${ORG}/members/idn_ada2`, body: undefined }]);
  });

  it("refuses on a server without the capability, changing nothing", async () => {
    capabilities = [];
    const r = await cli(["member", "remove", "Bob", "--confirm", "Bob"]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("needs Varlatch 0.20.0 or later");
    expect(changes()).toEqual([]);
  });

  it("checks the command line strictly", async () => {
    for (const args of [
      ["member", "remove"],
      ["member", "remove", "Bob", "--confirm", "Bob", "extra"],
      ["member", "remove", "Bob", "--confim", "Bob"],
      ["member", "remove", "Bob", "--confirm", "Bob", "--json"],
      ["member", "kick", "Bob"],
    ]) {
      expect((await cli(args)).code, args.join(" ")).toBe(EXIT.usage);
    }
    expect(requests).toEqual([]);
  });
});

describe("varlatch member leave", () => {
  it("leaves with the organization named again", async () => {
    const r = await cli(["member", "leave", "--confirm", "acme"]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{ method: "DELETE", url: `${ORG}/members/me`, body: undefined }]);
    expect(r.stdout).toContain("You left acme.");
    expect(r.stdout).toContain("Nothing they set up here needs review.");
  });

  it("refuses without the organization named, or naming another", async () => {
    const missing = await cli(["member", "leave"], { VARLATCH_ASSISTED: "1" });
    expect(missing.code).toBe(EXIT.config);
    expect(missing.stderr).toContain("  varlatch member leave --confirm acme\nNothing was changed.");
    const wrong = await cli(["member", "leave", "--confirm", "other"]);
    expect(wrong.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
  });
});

describe("varlatch member exposure", () => {
  it("reads a former member's report by name, with environment names and every kind of fact apart", async () => {
    const r = await cli(["member", "exposure", "Old"]);
    expect(r.code, r.stderr).toBe(0);
    expect(requests.find((q) => q.url.endsWith("/exposure"))?.url).toBe(`${ORG}/members/idn_old/exposure`);
    expect(r.stdout).toContain("Exposure report for Old (former member, removed 2026-10-01T10:00:00.000Z).");
    expect(r.stdout).toContain("events from 2026-01-01T00:00:00.000Z to 2026-10-30T00:00:00.000Z are not covered yet");
    expect(r.stdout).toContain("TOKEN  ver_1  in api / production: still served (current)");
    expect(r.stdout).toContain("delivered to a process through api / development/bob, 2026-09-03T10:00:00.000Z");
    expect(r.stdout).toContain("to rotate: Issue a new token in the provider console.");
    expect(r.stdout).toContain("OLD_KEY  ver_2  in api / production: no longer served (replaced)");
    expect(r.stdout).toContain("No longer served is not safe");
    expect(r.stdout).toContain("api / production: secret.reveal, config.metadata.read (reading values conditional on Tailnet Requirement req_1)");
    expect(r.stdout).toContain("req_1: on the production tier, a device in example.ts.net with tags tag:prod");
    expect(r.stdout).toContain("whk_1  sink.example");
    expect(changes()).toEqual([]);
  });

  it("writes NDJSON with --json: the member and coverage first, one record per line", async () => {
    const r = await cli(["member", "exposure", "idn_old", "--json"]);
    expect(r.code, r.stderr).toBe(0);
    const records = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
    expect(records[0]).toMatchObject({ kind: "member", organization: "acme", identityId: "idn_old", coverage: { complete: false } });
    expect(records[0].version).toEqual(expect.any(Number));
    expect(records.map((x) => x.kind)).toEqual(["member", "received", "received", "authority", "requirement", "indirect"]);
    expect(records[1]).toMatchObject({ itemName: "TOKEN", versionId: "ver_1", state: "served" });
  });

  it("reads an ID with audit.read alone: only a name needs the identity listing", async () => {
    denyIdentities = true;
    const byId = await cli(["member", "exposure", "idn_old", "--json"]);
    expect(byId.code, byId.stderr).toBe(0);
    expect(requests.some((q) => q.url.endsWith("/identities"))).toBe(false);
    const byName = await cli(["member", "exposure", "Old"]);
    expect(byName.code).not.toBe(0);
  });

  it("prints the report with environment IDs when the caller may not list projects", async () => {
    denyIdentities = true;
    denyProjects = true;
    const r = await cli(["member", "exposure", "idn_old"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("TOKEN  ver_1  in env_1: still served (current)");
    expect(r.stdout).toContain("delivered to a process through env_2");
  });

  it("is read-only: no --confirm, no machines, and a server without the report is refused", async () => {
    expect((await cli(["member", "exposure", "Bob", "--confirm", "Bob"])).code).toBe(EXIT.usage);
    // An ID goes to the server, which refuses a machine; a name never matches one.
    const machine = await cli(["member", "exposure", "idn_svc"]);
    expect(machine.code).not.toBe(0);
    expect(machine.stderr).toContain("Member not found");
    const named = await cli(["member", "exposure", "deployer"]);
    expect(named.stderr).toContain("deployer is not a current or former member");
    capabilities = [];
    const old = await cli(["member", "exposure", "Old"]);
    expect(old.code).toBe(EXIT.failure);
    expect(old.stderr).toContain("needs Varlatch 0.20.0 or later");
    expect(changes()).toEqual([]);
  });
});

describe("varlatch member role", () => {
  it("promotes and demotes without --confirm, and says what stays", async () => {
    const up = await cli(["member", "role", "Bob", "admin"]);
    expect(up.code, up.stderr).toBe(0);
    expect(up.stdout).toContain("Bob is now an admin of acme.");
    const down = await cli(["member", "role", "Ada", "member"]);
    expect(down.stdout).toContain("Grants given to them directly or through groups stay");
    expect(changes()).toEqual([
      { method: "PATCH", url: `${ORG}/members/idn_bob`, body: { role: "admin" } },
      { method: "PATCH", url: `${ORG}/members/idn_ada`, body: { role: "member" } },
    ]);
  });

  it("refuses an unknown role, before any request", async () => {
    expect((await cli(["member", "role", "Bob", "owner"])).code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
  });
});
