// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.9d's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 7), on the parity kit (go-fixture-kit.ts): the converge engine
 * (domain/syncdelivery.ts) and pushSyncTarget. Between ordinary requests,
 * the table runs the engine once ("POST /__test/sync-tick", answered by
 * this test, not by the server): runSyncOnce against stateful fake GitHub,
 * Coolify and Convex services. Each tick answers with every request the
 * engine sent, so the file holds the ledger rows, the Targets' columns,
 * the audit events and the platforms' requests of every run.
 * go/server/syncs's converge parity test replays it against varlatchd's
 * engine with the same fake services.
 *
 * The fakes (fakePlatforms below, fakePlatforms in converge_parity_test.go;
 * keep them alike):
 * - GitHub (api.github.com): the public key of a fixed key pair, so each
 *   value sent is opened and logged as its plaintext; secrets stored by
 *   name; a name starting BROKEN fails with 500; a credential containing
 *   "expiring" is answered with an expiry header.
 * - Coolify (coolify.public.example): environment rows per application or
 *   service, stored as sent (POST creates, PATCH updates by key, DELETE by
 *   row uuid), a service's compose files, deploys and restarts.
 * - Convex (happy-animal-123.convex.cloud): the variable list query and
 *   the batch update.
 * "POST /__test/platform-drift" changes a Coolify value behind Varlatch's
 * back; a tick with "?repair=0" forces a repair pass.
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-converge-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { sealedBoxOpen } from "@varlatch/sync";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { runSyncOnce } from "../src/domain/syncdelivery.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/converge-v0.22.0.json", import.meta.url);
export const PUBLIC_URL = "http://127.0.0.1:8686";
const COOLIFY = "https://coolify.public.example";
const CONVEX = "https://happy-animal-123.convex.cloud";
const resolve: Resolver = async (name) => {
  if (name === "coolify.public.example") return [{ address: "93.184.216.40", family: 4 }];
  if (name === "happy-animal-123.convex.cloud") return [{ address: "93.184.216.41", family: 4 }];
  throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
};
const policy = () => new OutboundPolicy("", { resolve, log: () => {} });

// The fake GitHub's key pair: the secret key is 32 bytes of 0x11.
const SEAL_SECRET = new Uint8Array(32).fill(0x11);
const SEAL_PUBLIC = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=";
export const EXPIRES = "2026-09-01 12:00:00 UTC";
export const COMPOSE_RAW = "services:\n  web:\n    image: x\n    environment:\n      PORT: 80\n";
export const COMPOSE_GENERATED = "services:\n  web:\n    image: x\n    env_file:\n      - .env\n";

type Row = Record<string, unknown>;

/** The fake platforms: state, and the log of every request. */
export class FakePlatforms {
  log: string[] = [];
  github = new Map<string, Map<string, string>>();
  coolify = new Map<string, Row[]>();
  convex = new Map<string, string>();
  next = 1;

  constructor() {
    const flags = { is_preview: false, is_literal: true, is_multiline: true, is_shown_once: false, is_buildtime: false, is_runtime: true };
    this.coolify.set("/applications/app-uuid-1", [
      { uuid: "seed-1", key: "PORT", value: "1234", ...flags },
      // Stored as Coolify's interpreted form: rewritten even when it matches.
      { uuid: "seed-2", key: "DATABASE_URL", value: "postgres://db/prod", ...flags, is_literal: false },
    ]);
    this.coolify.set("/services/svc-uuid-1", []);
    this.convex.set("API_KEY", "key-1");
    this.convex.set("STALE", "x");
  }

  take(): string[] {
    const out = this.log;
    this.log = [];
    return out;
  }

  /** Changes a Coolify value behind Varlatch's back. */
  drift(): void {
    const row = this.coolify.get("/applications/app-uuid-1")!.find((r) => r.key === "PORT");
    if (row) row.value = "1";
  }

  fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const auth = headers.get("authorization") ?? "";
    const body = typeof init?.body === "string" ? init.body : "";
    const answer = (status: number, value: unknown, extra: Record<string, string> = {}) =>
      new Response(status === 204 ? null : JSON.stringify(value), { status, headers: { "content-type": "application/json", ...extra } });
    let line = `${method} ${url.href} ${auth}`;
    const done = (res: Response) => {
      this.log.push(line);
      return res;
    };
    if (url.host === "api.github.com") {
      const expiry: Record<string, string> = auth.includes("expiring") ? { "github-authentication-token-expiration": EXPIRES } : {};
      const m = /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/(.+)$/.exec(url.pathname);
      if (!m) return done(answer(404, { message: "Not Found" }));
      const repo = `${m[1]}/${m[2]}`;
      const name = m[3]!;
      if (name === "public-key" && method === "GET") return done(answer(200, { key_id: "k1", key: SEAL_PUBLIC }, expiry));
      const secrets = this.github.get(repo) ?? new Map<string, string>();
      this.github.set(repo, secrets);
      if (method === "PUT") {
        const sent = JSON.parse(body) as { encrypted_value: string; key_id: string };
        const opened = sealedBoxOpen(Buffer.from(sent.encrypted_value, "base64"), Buffer.from(SEAL_PUBLIC, "base64"), SEAL_SECRET);
        line += ` opened=${opened === null ? "<unopenable>" : Buffer.from(opened).toString("utf8")} key_id=${sent.key_id}`;
        if (name.startsWith("BROKEN")) return done(answer(500, { message: "boom" }));
        const existed = secrets.has(name);
        secrets.set(name, opened === null ? "" : Buffer.from(opened).toString("utf8"));
        return done(answer(existed ? 204 : 201, {}, expiry));
      }
      if (method === "DELETE") {
        const existed = secrets.delete(name);
        return done(answer(existed ? 204 : 404, { message: "Not Found" }));
      }
      return done(answer(404, { message: "Not Found" }));
    }
    if (url.host === "coolify.public.example") {
      if (body) line += ` ${body}`;
      const path = url.pathname.replace(/^\/api\/v1/, "");
      if (method === "GET" && path === "/services/svc-uuid-1") {
        return done(answer(200, { uuid: "svc-uuid-1", name: "Stack", docker_compose_raw: COMPOSE_RAW, docker_compose: COMPOSE_GENERATED, compose_parsing_version: "3" }));
      }
      const m = /^(\/(?:applications|services)\/[^/]+)(\/envs(?:\/([^/]+))?|\/start|\/restart)$/.exec(path);
      const rows = m ? this.coolify.get(m[1]!) : undefined;
      if (!m || !rows) return done(answer(404, { message: "Not found." }));
      if (m[2] === "/start" || m[2] === "/restart") return done(answer(200, { message: "Queued." }));
      if (method === "GET") return done(answer(200, rows));
      if (method === "POST") {
        const row = { uuid: `env-${this.next++}`, ...(JSON.parse(body) as Row), is_preview: false };
        rows.push(row);
        return done(answer(201, { uuid: row.uuid }));
      }
      if (method === "PATCH") {
        const sent = JSON.parse(body) as Row;
        const row = rows.find((r) => r.key === sent.key);
        if (!row) return done(answer(404, { message: "Not found." }));
        Object.assign(row, sent);
        return done(answer(201, { uuid: row.uuid }));
      }
      if (method === "DELETE" && m[3]) {
        const i = rows.findIndex((r) => r.uuid === m[3]);
        if (i < 0) return done(answer(404, { message: "Not found." }));
        rows.splice(i, 1);
        return done(answer(200, { message: "Deleted." }));
      }
      return done(answer(404, { message: "Not found." }));
    }
    if (url.host === "happy-animal-123.convex.cloud") {
      if (body) line += ` ${body}`;
      if (method === "POST" && url.pathname === "/api/query") {
        return done(answer(200, { status: "success", value: [...this.convex].map(([name, value]) => ({ name, value })) }));
      }
      if (method === "POST" && url.pathname === "/api/update_environment_variables") {
        for (const c of (JSON.parse(body) as { changes: { name: string; value: string | null }[] }).changes) {
          if (c.value === null) this.convex.delete(c.name);
          else this.convex.set(c.name, c.value);
        }
        return done(answer(200, {}));
      }
      return done(answer(404, {}));
    }
    this.log.push(line);
    throw new TypeError("fetch failed");
  }) as typeof fetch;
}

type App = ReturnType<typeof buildApp>;

/** The app, with the test's own paths: the engine's tick and the drift. */
function withTicks(ctx: AppCtx, app: App, fake: FakePlatforms): App {
  const request = async (path: string, init?: RequestInit) => {
    if (path.startsWith("/__test/sync-tick")) {
      const repair = path.endsWith("?repair=0");
      await runSyncOnce(ctx, { fetchImpl: fake.fetch, ...(repair ? { repairIntervalMs: 0 } : {}) });
      return Response.json({ exchanges: fake.take() });
    }
    if (path === "/__test/platform-drift") {
      fake.drift();
      return Response.json({ drifted: true });
    }
    return app.request(path, init);
  };
  return { request } as unknown as App;
}

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "platform_connections", orderBy: "id", random: ["credential_envelope"] },
  { name: "sync_targets", orderBy: "id" },
  { name: "sync_ledger", orderBy: "target_id, dest_name" },
  { name: "sync_runs", orderBy: "target_id, generation" },
  { name: "sync_cursor", orderBy: "singleton" },
  { name: "member_integrations", orderBy: "organization_id, identity_id, kind, resource_id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  {
    name: "sync_targets", key: ["id"], sortBy: ["canonical_destination"],
    volatile: ["created_at", "updated_at", "revoked_at", "last_attempt_at", "next_attempt_at", "lease_expires_at", "last_repair_at", "repair_cycle_started_at", "last_drift_at"],
  },
  { name: "sync_ledger", key: ["target_id", "dest_name"], sortBy: ["target_id", "dest_name"], volatile: ["updated_at", "repaired_at"] },
  { name: "sync_runs", key: ["target_id", "generation"], sortBy: ["target_id", "generation"], volatile: ["started_at", "deadline"] },
  { name: "sync_cursor", key: ["singleton"], sortBy: ["singleton"], volatile: ["occurred_at"] },
  { name: "platform_connections", key: ["id"], sortBy: ["name"], volatile: ["created_at", "updated_at", "revoked_at", "credential_expiry_seen_at", "credential_envelope"] },
];

const ORG = "/v1/organizations";
const P = `${ORG}/acme/projects/api`;
const ENV = `${P}/environments/production`;

function requestTable(): RequestCase[] {
  const tick = (name: string, repair = false): Omit<RequestCase, "id"> => ({ name, method: "POST", path: `/__test/sync-tick${repair ? "?repair=0" : ""}`, credential: "none", body: {} });
  const put = (name: string, item: string, value: string): Omit<RequestCase, "id"> => ({ name, method: "PUT", path: `${ENV}/values/${item}`, credential: "alice", body: { value } });
  const del = (name: string, item: string): Omit<RequestCase, "id"> => ({ name, method: "DELETE", path: `${ENV}/values/${item}`, credential: "alice" });
  const target = (name: string, method: string, target: string, verb = "", body?: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method, path: `${ENV}/sync-targets/${target}${verb}`, credential, ...(body === undefined ? {} : { body }) });
  return withIds([
    tick("the first run: every Target forced, read back, adopted, written, redeployed"),
    tick("nothing due"),
    put("change a value", "PORT", "9090"),
    tick("a changed value: only what changed"),
    del("remove a value", "DEBUG"),
    tick("a removed value: an orphan deleted where the Target removes orphans"),
    put("a value GitHub refuses", "BROKEN_TOKEN", "zzz"),
    tick("a failed write: degraded, backed off"),
    tick("backed off: not due"),
    target("push", "POST", "{tGh}", "/push", {}),
    target("push as a member", "POST", "{tGh}", "/push", {}, "dave"),
    target("push an unknown Target", "POST", "snt_unknownaaaaaaaaaaaaaaaaaaa", "/push", {}),
    tick("pushed: retried, and failing again"),
    del("remove the refused value", "BROKEN_TOKEN"),
    target("push again", "POST", "{tGh}", "/push", {}),
    tick("pushed: converged, the refused name deleted"),
    { name: "change a Coolify value behind Varlatch's back", method: "POST", path: "/__test/platform-drift", credential: "none", body: {} },
    tick("a repair pass: drift put back, a redeploy owed", true),
    target("pause the Coolify application's Target", "POST", "{tCoolApp}", "/pause", {}),
    put("change a value while paused", "PORT", "7070"),
    tick("a paused Target is skipped"),
    target("resume it", "POST", "{tCoolApp}", "/resume", {}),
    tick("resumed: converged, redeployed"),
    target("a new destination", "PATCH", "{tGh}", "", { expectedVersion: 1, destination: { repo: "api2" } }),
    tick("the new destination written in full"),
    { name: "revoke the Convex Connection", method: "DELETE", path: `${ORG}/acme/platform-connections/{convex}`, credential: "alice" },
    tick("a revoked Connection's Target is not selected"),
    tick("a final repair pass", true),
  ]);
}

const TARGETS = {
  tGh: "[\"github-actions\",\"acme\",\"api\"]",
  tCoolApp: "[\"coolify\",\"https://coolify.public.example\",\"app-uuid-1\"]",
} as const;

function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const pairs: [string, string][] = [];
  for (const [key, canonical] of Object.entries(TARGETS)) {
    const t = rows.sync_targets!.find((r) => r.canonical_destination === canonical);
    if (!t) throw new Error(`no Target ${canonical}`);
    pairs.push([`{${key}}`, t.id as string]);
  }
  const convex = rows.platform_connections!.find((r) => r.name === "Convex");
  pairs.push(["{convex}", convex!.id as string]);
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build() {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy() };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
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
  await call("POST", ORG, { name: "Acme", slug: "acme" });
  await call("POST", `${ORG}/acme/projects`, { slug: "api", name: "API", contractAuthority: "managed" });
  await call("POST", `${P}/environments`, { name: "production", tier: "production" });
  const items = [["API_KEY", true], ["BROKEN_TOKEN", false], ["DATABASE_URL", true], ["DEBUG", false], ["PORT", false], ["REF", false]]
    .map(([name, sensitive]) => ({ name, required: { kind: "never" }, sensitive, type: "string" }));
  const revision = await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items } });
  await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  for (const [name, value] of [["API_KEY", "key-1"], ["DATABASE_URL", "postgres://db/prod"], ["DEBUG", "false"], ["PORT", "8080"], ["REF", "http://localhost:${PORT}/x"]]) {
    await call("PUT", `${ENV}/values/${name}`, { value });
  }
  const connection = async (name: string, platform: string, baseIdentity: string, credential: string) =>
    (await call("POST", `${ORG}/acme/platform-connections`, { platform, baseIdentity, name, credential })).id as string;
  const gh = await connection("GitHub", "github-actions", "acme", "gh-token");
  const ghExpiring = await connection("Expiring", "github-actions", "acme", "gh-expiring-token");
  const coolify = await connection("Coolify", "coolify", COOLIFY, "coolify-token");
  const convex = await connection("Convex", "convex", CONVEX, "prod:convex-key");
  const target = async (connectionId: string, destination: unknown, mapping: unknown, extra: Record<string, unknown> = {}) =>
    (await call("POST", `${ENV}/sync-targets`, { connectionId, destination, mapping, ...extra })).id as string;
  await target(gh, { repo: "api" }, { kind: "wildcard" }, { removeOrphans: true });
  await target(ghExpiring, { repo: "web" }, { kind: "explicit", items: [{ name: "PORT" }] });
  await target(coolify, { applicationUuid: "app-uuid-1" }, { kind: "explicit", items: [{ name: "PORT" }, { name: "DATABASE_URL" }] }, { redeploy: true });
  await target(coolify, { serviceUuid: "svc-uuid-1" }, { kind: "wildcard", exclude: ["BROKEN_*"] });
  await target(convex, {}, { kind: "wildcard", exclude: ["DEBUG", "BROKEN_*"] }, { removeOrphans: true });
  // dave: a member without a Grant, for the refused push.
  const acmeId = (await call("GET", `${ORG}/acme`)).id as string;
  const dave = newId("identity");
  await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', 'dave', '2026-01-01T00:00:00.000Z')", [dave]);
  await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [acmeId, dave]);
  tokens.dave = (await issueCredential(ctx.db, { identityId: dave, kind: "cli" })).token;
  await accessCountsSettled();
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows, with fresh fake platforms. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"] }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    return await record(ctx, withTicks(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), new FakePlatforms()), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-converge-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        rows: await exportRows(ctx.db, TABLES),
        sideTables: SIDE,
        requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
        counters: [],
      };
      writeFileSync(FILE, JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

describe("the converge fixture is this server's answers", () => {
  it("converge-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});
