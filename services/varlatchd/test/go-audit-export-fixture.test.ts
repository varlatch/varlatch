// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.11a's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 9), on the parity kit (go-fixture-kit.ts): the audit export's
 * configuration, built through this server's own /v1 API, and a table of
 * requests with this server's answers: getAuditExport, createAuditExport,
 * checkAuditExport, changeAuditExport, replaceAuditExportCredential and
 * removeAuditExport. go/server/auditexport's parity test replays it
 * against varlatchd.
 *
 * The destination is a local S3 server (FakeS3 here, s3fake in Go: the
 * same behaviour by access key and bucket), reached under one fixed
 * endpoint, http://s3.fixture.test: both servers' outbound policies allow
 * the name and connect it to the local server. Each request's exchange
 * with it (method, retention read or not, access key, status) is kept in
 * the file and must be the same: the access key the probe sends is the
 * one sealed in the export's credential, so a check or a change with the
 * stored key opens the envelope this code sealed (G3 at the database
 * level for audit export credentials).
 *
 * The database: alice (the bootstrap Installation Admin) and her second
 * CLI credential (alice2, whose approval intents bind exact requests of
 * the table); Organizations acme (an export with governance retention),
 * beta and gamma (none), frozen (an export, then an incident freeze) and
 * deleting (an export, then a deletion scheduled); bob (a member of acme),
 * carol (in none). The keys the exports were made with are in the file
 * (`credentials`), so the envelopes can be sealed again.
 *
 * Two files: audit-export-v0.22.0.json, sealed by this code; and, with
 * VARLATCH_GO_SEALED_AUDIT_EXPORT=<file>, a file the Go tests wrote (go
 * test ./server/auditexport -run TestGoSealedFixture -args
 * -write-go-sealed=<file>) whose Organization KEKs and export credentials
 * Go sealed, which this server must give the same answers and exchanges
 * on (go.yml). v0.21.0 sealed no audit export credential (the class came
 * in v0.22.0).
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-audit-export-fixture.test.ts
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it, vi } from "vitest";
import type { BucketDestination, StorageClient, StorageCredentials } from "@varlatch/backup/s3";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { OutboundPolicy, type OutboundPurpose, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RawAnswer, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/audit-export-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
export const PUBLIC_URL = "http://127.0.0.1:8686";
/** The destination's fixed endpoint, and the allow list and resolver that open it. */
export const ENDPOINT = "http://s3.fixture.test";
export const ALLOW = "s3.fixture.test,127.0.0.1/32:*";
const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = { "s3.fixture.test": [{ address: "10.9.9.9", family: 4 }] };
const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};

// The fake's keys and buckets (go/server/auditexport/s3fake).
export const KEY_GOOD = "AKIAFIXTUREGOOD";
export const KEY_NO_READ = "AKIAFIXTURENOREAD";
const BUCKET = "export-bucket";

/**
 * A local S3 server with Object Lock, path style: the requests the probe
 * makes, answered by access key and bucket as s3fake answers them. It
 * records each request.
 */
class FakeS3 {
  readonly objects = new Map<string, { sha256: string; mode: string; until: string }>();
  readonly requests: string[] = [];
  private server: Server | null = null;
  url = "";

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => this.serve(req, res));
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", r));
    this.url = `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  private fail(req: IncomingMessage, res: ServerResponse, status: number, code: string): number {
    if (req.method === "HEAD") {
      res.writeHead(status).end();
      return status;
    }
    res.writeHead(status, { "content-type": "application/xml" });
    res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>${code}</Code><Message>${code}</Message></Error>`);
    return status;
  }

  private serve(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? "/", "http://fake");
    const [bucket = "", ...rest] = url.pathname.slice(1).split("/");
    const key = decodeURIComponent(rest.join("/"));
    const access = /Credential=([^/]+)\//.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const retention = url.searchParams.has("retention");
    const status = this.answer(req, res, bucket, key, access, retention);
    this.requests.push(`${req.method}${retention ? " retention" : ""} ${access} ${status}`);
  }

  private answer(req: IncomingMessage, res: ServerResponse, bucket: string, key: string, access: string, retention: boolean): number {
    if (![KEY_GOOD, KEY_NO_READ, "AKIAFIXTURENORETENTION"].includes(access)) return this.fail(req, res, 403, "InvalidAccessKeyId");
    if (!["export-bucket", "overwrite-bucket", "nometa-bucket", "nolock-bucket", "weak-bucket"].includes(bucket)) return this.fail(req, res, 404, "NoSuchBucket");
    const name = `${bucket}/${key}`;
    const h = (n: string) => (req.headers[n] as string | undefined) ?? "";
    if (req.method === "PUT") {
      if (this.objects.has(name) && h("if-none-match") === "*" && bucket !== "overwrite-bucket") return this.fail(req, res, 412, "PreconditionFailed");
      const o = { sha256: h("x-amz-meta-sha256"), mode: h("x-amz-object-lock-mode"), until: h("x-amz-object-lock-retain-until-date") };
      if (bucket === "nometa-bucket") o.sha256 = "";
      if (bucket === "nolock-bucket") [o.mode, o.until] = ["", ""];
      if (bucket === "weak-bucket" && o.mode) o.mode = "GOVERNANCE";
      this.objects.set(name, o);
      res.writeHead(200, { etag: '"fixture"' }).end();
      return 200;
    }
    if (req.method === "HEAD") {
      if (access === KEY_NO_READ) return this.fail(req, res, 403, "AccessDenied");
      const o = this.objects.get(name);
      if (!o) return this.fail(req, res, 404, "NotFound");
      res.writeHead(200, { ...(o.sha256 ? { "x-amz-meta-sha256": o.sha256 } : {}), "content-length": "0", "last-modified": new Date(0).toUTCString() }).end();
      return 200;
    }
    if (req.method === "GET" && retention) {
      if (access === KEY_NO_READ || access === "AKIAFIXTURENORETENTION") return this.fail(req, res, 403, "AccessDenied");
      const o = this.objects.get(name);
      if (!o) return this.fail(req, res, 404, "NoSuchKey");
      if (!o.mode) return this.fail(req, res, 404, "NoSuchObjectLockConfiguration");
      res.writeHead(200, { "content-type": "application/xml" });
      res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>${o.mode}</Mode><RetainUntilDate>${o.until}</RetainUntilDate></Retention>`);
      return 200;
    }
    return this.fail(req, res, 405, "MethodNotAllowed");
  }
}

/** The outbound policy with the fixed endpoint connected to the fake. */
class FixturePolicy extends OutboundPolicy {
  constructor(private readonly fake: FakeS3) {
    super(ALLOW, { resolve, log: () => {} });
  }
  override storageClient(purpose: OutboundPurpose, destination: BucketDestination, credentials: StorageCredentials, requestTimeoutMs: number): StorageClient {
    const endpoint = destination.endpoint === ENDPOINT ? this.fake.url : destination.endpoint;
    return super.storageClient(purpose, { ...destination, endpoint }, credentials, requestTimeoutMs);
  }
}

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "audit_exports", orderBy: "id", random: ["credential_envelope"] },
  // A manifest names its stream and its planning time; its checksums follow.
  { name: "audit_export_plans", orderBy: "id", random: ["body", "sha256", "md5"] },
];

const SIDE: SideTable[] = [
  {
    name: "audit_exports", key: ["id"], sortBy: ["organization_id", "state"],
    volatile: ["credential_envelope", "stream_started_at", "conditional_checked_at", "created_at", "updated_at", "removed_at"],
  },
  {
    name: "audit_export_plans", key: ["id"], sortBy: ["export_id", "kind"],
    // The manifest names its planning time; its checksums follow it.
    volatile: ["body", "sha256", "md5", "planned_at", "retain_until"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { change: aprId("change"), replace: aprId("replace"), remove: aprId("remove") } as const;

const destination = (extra: Record<string, unknown> = {}) => ({ endpoint: ENDPOINT, region: "us-east-1", bucket: BUCKET, prefix: "logs", pathStyle: true, ...extra });
const good = { accessKeyId: KEY_GOOD, secretAccessKey: "fixture-secret" };
const rotated = { accessKeyId: KEY_GOOD, secretAccessKey: "rotated-secret" };

/** The table of requests. */
function requestTable(): RequestCase[] {
  const approval = (id: string) => ({ credential: "alice2", headers: { "Varlatch-Approval": id } });
  const get = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${org}/audit-export`, credential });
  const create = (name: string, org: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/audit-export`, credential, body });
  const createRaw = (name: string, org: string, rawBody: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/audit-export`, credential: "alice", rawBody });
  const check = (name: string, org: string, body: unknown): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/audit-export/check`, credential: "alice", body });
  const change = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ORG}/${org}/audit-export`, credential: "alice", body, ...extra });
  const replace = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "PUT", path: `${ORG}/${org}/audit-export/credential`, credential: "alice", body, ...extra });
  const remove = (name: string, org: string, query: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/audit-export${query}`, credential: "alice", ...extra });
  const compliance = { mode: "compliance", days: 1 };
  return withIds([
    // getAuditExport: organization.manage, existence hidden; inspection while frozen.
    get("get", "acme"),
    get("get by id", "{acmeId}"),
    get("get, none yet", "beta"),
    get("get as a member", "acme", "bob"),
    get("get as an outsider", "acme", "carol"),
    get("get a frozen Organization's", "frozen"),
    get("get an Organization's being deleted", "deleting"),
    get("get in an unknown Organization", "nope"),

    // createAuditExport in beta: zod, the validation, the policy, the probe.
    createRaw("create, an empty body", "beta", ""),
    createRaw("create, a body that is not JSON", "beta", "{nope"),
    create("create, an extra member", "beta", { destination: destination(), credential: good, extra: 1 }),
    create("create, no destination", "beta", { credential: good }),
    create("create, an extra destination member", "beta", { destination: destination({ extra: true }), credential: good }),
    create("create, a retention of 0 days", "beta", { destination: destination(), credential: good, retention: { mode: "compliance", days: 0 } }),
    create("create, from somewhere else", "beta", { destination: destination(), credential: good, from: "yesterday" }),
    create("create, an endpoint with a path", "beta", { destination: destination({ endpoint: `${ENDPOINT}/s3` }), credential: good }),
    create("create, a bucket in capitals", "beta", { destination: destination({ bucket: "Export-Bucket" }), credential: good }),
    create("create, a key with a space", "beta", { destination: destination(), credential: { accessKeyId: "AKIA X", secretAccessKey: "s" } }),
    create("create to a private address", "beta", { destination: destination({ endpoint: "https://10.0.0.7" }), credential: good }),
    create("create, a destination that overwrites", "beta", { destination: destination({ bucket: "overwrite-bucket" }), credential: good }),
    create("create, a wrong key", "beta", { destination: destination(), credential: { accessKeyId: "AKIAWRONG", secretAccessKey: "s" } }),
    create("create, no such bucket", "beta", { destination: destination({ bucket: "missing-bucket" }), credential: good }),
    create("create as a member", "beta", { destination: destination(), credential: good }, "bob"),
    create("create", "beta", { destination: destination({ prefix: "" }), credential: good, retention: compliance, from: "now" }),
    create("create again", "beta", { destination: destination(), credential: good }),
    create("create in a frozen Organization", "frozen", { destination: destination(), credential: good }),
    create("create in an Organization being deleted", "deleting", { destination: destination(), credential: good }),

    // checkAuditExport in gamma (no export) and acme (the stored key).
    check("check, a bucket without Object Lock", "gamma", { destination: destination({ bucket: "nolock-bucket" }), credential: good, retention: compliance }),
    check("check, a weaker retention", "gamma", { destination: destination({ bucket: "weak-bucket" }), credential: good, retention: compliance }),
    check("check, a key that cannot read", "gamma", { destination: destination(), credential: { accessKeyId: KEY_NO_READ, secretAccessKey: "s" }, retention: compliance }),
    check("check, a private address", "gamma", { destination: destination({ endpoint: "https://10.0.0.8" }), credential: good }),
    check("check, the stored key and no export", "gamma", { destination: destination() }),
    check("check, the stored key", "acme", { destination: destination() }),
    check("check, the stored key elsewhere", "acme", { destination: destination({ prefix: "elsewhere" }) }),

    // changeAuditExport in acme (version 1, governance 7 days, prefix logs/).
    change("change, tighten the retention", "acme", { expectedVersion: 1, retention: { mode: "compliance", days: 30 } }),
    change("change, nothing", "acme", { expectedVersion: 2, retention: { mode: "compliance", days: 30 } }),
    change("change, remove the retention", "acme", { expectedVersion: 2, retention: null }),
    change("change the destination", "acme", { expectedVersion: 2, destination: { prefix: "moved" } }),
    change("change the destination, its approval", "acme", { expectedVersion: 2, destination: { prefix: "moved" } }, approval(APPROVALS.change)),
    change("change, a stale version", "acme", { expectedVersion: 2, retention: { mode: "compliance", days: 60 } }),
    change("change, an extra member", "acme", { expectedVersion: 3, extra: 1 }),
    change("change to a private address", "acme", { expectedVersion: 3, destination: { endpoint: "https://10.0.0.9" } }),
    change("change in an Organization without one", "gamma", { expectedVersion: 1, retention: null }),
    change("change in a frozen Organization", "frozen", { expectedVersion: 1, retention: null }),
    change("change in an Organization being deleted", "deleting", { expectedVersion: 1, retention: null }),

    // replaceAuditExportCredential.
    replace("replace the key", "acme", { expectedVersion: 3, credential: rotated }),
    replace("replace the key, its approval", "acme", { expectedVersion: 3, credential: rotated }, approval(APPROVALS.replace)),
    replace("replace the key, a stale version", "acme", { expectedVersion: 3, credential: rotated }),
    replace("replace the key, an extra member", "acme", { expectedVersion: 4, credential: { ...rotated, sessionToken: "x" } }),
    check("check, the replaced key", "acme", { destination: destination({ prefix: "moved" }) }),

    // removeAuditExport.
    remove("remove, no version", "acme", ""),
    remove("remove, a version that is not a number", "acme", "?expectedVersion=four"),
    remove("remove", "acme", "?expectedVersion=4"),
    remove("remove, its approval", "acme", "?expectedVersion=4", approval(APPROVALS.remove)),
    remove("remove again", "acme", "?expectedVersion=5"),
    remove("remove in a frozen Organization", "frozen", "?expectedVersion=1"),

    get("get afterwards", "acme"),
    get("get beta afterwards", "beta"),
  ]);
}

function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const acme = rows.organizations!.find((o) => o.slug === "acme")!.id as string;
  return (p) => p.replaceAll("{acmeId}", acme);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build(fake: FakeS3) {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: new FixturePolicy(fake), auditExport: true };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL });
  const call: Call = async (method, path, body, token = tokens.alice) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["acme", "beta", "gamma", "frozen", "deleting"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const credentials: Record<string, { accessKeyId: string; secretAccessKey: string }> = {};
  const exportIn = async (org: string, retention: unknown) => {
    const created = await call("POST", `${ORG}/${org}/audit-export`, { destination: destination(), credential: good, retention });
    credentials[created.id] = good;
    return created;
  };
  const acme = await exportIn("acme", { mode: "governance", days: 7 });
  await exportIn("frozen", null);
  await exportIn("deleting", null);
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  const person = async (name: string, org?: string) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (org) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  };
  await person("bob", "acme");
  await person("carol");

  // Approval intents of alice2 in acme, each binding one request of the
  // table exactly as the operation binds it, at the version it will meet.
  const intent = async (id: string, binding: ApprovalBinding) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
      [
        id, alice2.credentialId, alice, orgs.acme, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        binding.expectedVersion, JSON.stringify(binding.summary),
      ],
    );
  const target = { exportId: acme.id as string };
  const moved = { endpoint: ENDPOINT, region: "us-east-1", bucket: BUCKET, prefix: "moved/", pathStyle: true };
  await intent(APPROVALS.change, {
    operation: "audit_export.change", organizationId: orgs.acme!, target, query: {}, expectedVersion: 2,
    body: { destination: moved, retention: { mode: "compliance", days: 30 }, expectedVersion: 2 },
    summary: { title: "Change the audit export of Acme", changes: [{ field: "prefix", from: "logs/", to: "moved/", loosens: true }] },
  });
  await intent(APPROVALS.replace, {
    operation: "audit_export.change", organizationId: orgs.acme!, target, query: {}, expectedVersion: 3,
    body: { credential: rotated, expectedVersion: 3 },
    summary: { title: "Replace the key of the audit export of Acme", changes: [{ field: "credential", from: null, to: null, loosens: true }] },
  });
  await intent(APPROVALS.remove, {
    operation: "audit_export.remove", organizationId: orgs.acme!, target, query: {}, expectedVersion: 4, body: { expectedVersion: 4 },
    summary: { title: "Remove the audit export of Acme", changes: [{ field: "destination", from: "s3.fixture.test/export-bucket/moved/", to: null, loosens: true }] },
  });
  await accessCountsSettled();
  return { ctx, tokens, credentials };
}

type AuditExportFixture = Fixture & { credentials: Record<string, { accessKeyId: string; secretAccessKey: string }>; exchanges: Record<string, string[]> };

/** The file's answers, recorded on its own rows, with each request's exchange with the destination. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"]; exchanges: Record<string, string[]> }> {
  const fake = new FakeS3();
  await fake.start();
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const exchanges: Record<string, string[]> = {};
  let seen = 0;
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: new FixturePolicy(fake), auditExport: true };
    const recorded = await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), f, f.requests, fillPath(f.rows), (c: RequestCase, _raw: RawAnswer) => {
      const sent = fake.requests.slice(seen);
      seen = fake.requests.length;
      if (sent.length > 0) exchanges[c.id] = sent;
    });
    return { ...recorded, exchanges };
  } finally {
    await db.close();
    await fake.stop();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and exchanges, and writes the file", async () => {
    const fake = new FakeS3();
    await fake.start();
    const { ctx, tokens, credentials } = await build(fake);
    try {
      const rows = await exportRows(ctx.db, TABLES);
      const draft: AuditExportFixture = {
        comment: "Written by services/varlatchd/test/go-audit-export-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        credentials,
        rows,
        sideTables: SIDE,
        requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
        counters: [],
        exchanges: {},
      };
      writeFileSync(FILE, JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
    } finally {
      await ctx.close();
      await fake.stop();
    }
  }, 600_000);
});

async function expectFixture(f: AuditExportFixture) {
  expect(f.serverVersion).toBe(SERVER_VERSION);
  expectCurrentTable(f, requestTable());
  expect(f.sideTables).toEqual(SIDE);
  const got = await replay(f);
  expectSameAnswers(f, got);
  expect(got.exchanges).toEqual(f.exchanges);
}

describe("the audit export fixture is this server's answers", () => {
  it("audit-export-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as AuditExportFixture;
    expect(f.ref).toBe("v0.22.0");
    await expectFixture(f);
    // The stored key went out where it should: a check with it, the change's probe.
    const stored = Object.values(f.exchanges).flat().filter((e) => e.includes(KEY_GOOD));
    expect(stored.length).toBeGreaterThan(8);
    const fake = new FakeS3();
    await fake.start();
    const { ctx } = await build(fake);
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
      await fake.stop();
    }
  }, 300_000);
  const goSealed = process.env.VARLATCH_GO_SEALED_AUDIT_EXPORT;
  it.skipIf(!goSealed)("audit export credentials the Go server sealed open here with the same exchanges", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = JSON.parse(readFileSync(goSealed!, "utf8")) as AuditExportFixture;
    expect(f.comment).toMatch(/Go/);
    await expectFixture(f);
  }, 300_000);
});
