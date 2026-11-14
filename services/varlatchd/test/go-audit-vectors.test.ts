// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for Go's audit events (ADR-0059 step 3.3): what this
 * server's own audit code stores and answers, which go/server/audit must
 * store and answer byte for byte (go/server/audit/testdata/ts-vectors.json,
 * read by vectors_test.go).
 *
 * - recordings: events recorded with recordAuditEvents, one call each, in
 *   and out of a request's attribution (attribution.ts), one of every
 *   event type and the shapes the core's call sites build (a denial from
 *   decide, the incident freeze's refusal, disclosures and writes that
 *   index exposure, webhook URLs); then each stored row (columns as
 *   PostgreSQL holds them), its position, and its serialization: the
 *   event JSON (audit listing, webhook delivery; the export endpoint's line
 *   is it plus a newline) and the audit export stream's line (with its
 *   position).
 * - rawRows: rows written as stored text, then serialized: jsonb's key
 *   order, JSON.parse's (integer-like keys first), duplicate keys, numbers
 *   beyond a double, escapes, historical webhook URLs, microseconds.
 * - exposure: the member_exposure rows the recordings indexed, and
 *   exposureFromEvent and parseItems on their own.
 * - redact: redactWebhookUrl.
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change to audit/, the call sites' event shapes or this fixture,
 * regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-audit-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import type { Context } from "hono";
import { expect, it } from "vitest";
import { withAttribution, type Attribution } from "../src/audit/attribution.js";
import { AUDIT_EVENT_TYPES, recordAuditEvents, type AuditEventInput } from "../src/audit/events.js";
import { exposureFromEvent, parseItems } from "../src/audit/exposure.js";
import { redactWebhookUrl, serializeAuditEvent } from "../src/audit/serialize.js";
import { OrganizationFrozenError } from "../src/domain/liveness.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { auditFrozenRefusal } from "../src/http/organization.js";
import type { Principal } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";

const OUT = new URL("../../../go/server/audit/testdata/ts-vectors.json", import.meta.url);

const ORG = "org_acme";
const ALICE = "idn_alice";
const BOB = "idn_bob";
const SVC = "idn_svc";

const ATTRIBUTIONS: Record<string, Attribution | null> = {
  none: null,
  ordinary: { identityId: ALICE, credentialId: "crd_alice_cli", client: "varlatch CLI 0.22.0 on Linux, assisted", listener: "ordinary", tailnet: null },
  unknownClient: { identityId: ALICE, credentialId: "crd_alice_browser", client: null, listener: "ordinary", tailnet: null },
  tailnet: { identityId: ALICE, credentialId: "crd_alice_cli", client: "varlatch CLI 0.22.0 on macOS", listener: "tailnet", tailnet: { tailnet: "corp.ts.net", nodeId: "n1", nodeName: "build-1", tags: ["tag:ci"], userLogin: "alice@corp" } },
  refused: { identityId: ALICE, credentialId: "crd_alice_cli", client: null, listener: "tailnet", tailnet: { refused: "whois-failed" } },
  machine: { identityId: SVC, credentialId: "crd_svc", client: "varlatch-sdk 0.22.0", listener: "ordinary", tailnet: null },
};

interface Recording {
  name: string;
  attribution: keyof typeof ATTRIBUTIONS;
  events: AuditEventInput[];
  /** Built by auditFrozenRefusal, not given as input (the Go test builds it with FrozenRefusalEvent). */
  frozenRefusal?: { principal: string | null; credentialId: string | null; freezeId: string; method: string; route: string; requestId: string };
}

let n = 0;
const id = () => `evt_v${String(++n).padStart(3, "0")}`;

function recordings(): Recording[] {
  const out: Recording[] = [];
  // One of every type, in four shapes and every attribution.
  const shapes: ((type: AuditEventInput["eventType"], i: number) => AuditEventInput)[] = [
    (eventType, i) => ({
      id: id(), eventType, decision: "allow", actorIdentityId: ALICE, organizationId: ORG, action: "project.manage",
      resource: { projectId: "prj_web", environmentId: null }, requestId: `req_${i}`,
      metadata: { count: i, flag: i % 2 === 0, note: `n${i}`, nothing: null },
    }),
    (eventType, i) => ({ id: id(), eventType, decision: "info", metadata: { installationId: "inst_x", seq: i } }),
    (eventType, i) => ({
      id: id(), eventType, decision: "deny", actorIdentityId: BOB, organizationId: ORG, requestId: `req_${i}`,
      authz: { denial: "no-grant", requirements: [] }, resource: { z: "last", a: "first", projectId: "prj_web" },
    }),
    (eventType, i) => ({
      id: id(), eventType, decision: "allow", actorIdentityId: ALICE, credentialId: null, client: "set by the caller",
      listener: null, tailnet: { explicit: true }, organizationId: ORG, authenticationMethodId: "pk_1", metadata: {}, resource: {}, requestId: null,
      authz: { role: "admin", grantIds: [], requirements: [] },
    }),
  ];
  const attributions = Object.keys(ATTRIBUTIONS) as (keyof typeof ATTRIBUTIONS)[];
  AUDIT_EVENT_TYPES.forEach((type, i) => {
    out.push({ name: `type ${type}`, attribution: attributions[i % attributions.length]!, events: [shapes[i % shapes.length]!(type, i)] });
  });

  // The core's own shapes.
  out.push({
    name: "a denial, as decide builds it",
    attribution: "ordinary",
    events: [{
      id: id(), eventType: "authorization.denied", decision: "deny", actorIdentityId: ALICE, credentialId: "crd_alice_cli",
      organizationId: ORG, action: "secret.reveal", resource: { projectId: "prj_web", environmentId: "env_prd" },
      authz: {
        denial: "requirement-failed",
        applied: [{ grantId: "grt_1", actions: ["secret.reveal"], viaGroupId: "grp_1", roleId: "rol_1", roleVersion: 3 }],
        requirements: [{ requirementId: "req_1", requirementVersion: 2, satisfied: false, reason: "no-tailnet-context" }],
      },
      requestId: "req_denied",
    }],
  });
  out.push({
    name: "an allowed disclosure with auditAuthz",
    attribution: "tailnet",
    events: [{
      id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, action: "secret.reveal",
      resource: { projectId: "prj_web", environmentId: "env_prd" },
      authz: { role: "admin", grantIds: [], requirements: [{ requirementId: "req_1", requirementVersion: 2, satisfied: true, by: "tag:ci" }] },
      metadata: { items: "DATABASE_URL@ver_1,API_KEY@ver_2+ver_3", mode: "reveal", count: 2 }, requestId: "req_reveal",
    }],
  });
  out.push({
    name: "disclosures, writes and validations in one call",
    attribution: "ordinary",
    events: [
      { id: id(), eventType: "secret.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { projectId: "prj_web", environmentId: "env_dev" }, metadata: { items: "TOKEN@ver_9", mode: "strict-retrieval" } },
      { id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { projectId: "prj_web", environmentId: "env_dev" }, metadata: { items: "TOKEN@ver_9,@ver_x,NOAT,TRAIL@,A@b@ver_7", purpose: "export" } },
      { id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { projectId: "prj_web", environmentId: "env_dev" }, metadata: { items: "TOKEN@ver_9", purpose: "scan" } },
      { id: id(), eventType: "value.written", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { projectId: "prj_web", environmentId: "env_dev", itemName: "TOKEN", versionId: "ver_10" } },
      { id: id(), eventType: "value.rotation_started", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_stg", itemName: "KEY", versionId: "ver_11" } },
      { id: id(), eventType: "value.validated", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_dev" }, metadata: { items: "TOKEN@ver_9" } },
      { id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_dev" }, metadata: { items: "" } },
      { id: id(), eventType: "value.written", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_dev", itemName: "TOKEN" } },
    ],
  });
  out.push({
    name: "a machine's disclosure, not indexed",
    attribution: "machine",
    events: [{ id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: SVC, organizationId: ORG, resource: { environmentId: "env_dev" }, metadata: { items: "TOKEN@ver_9", mode: "strict-retrieval" } }],
  });
  out.push({
    name: "the same exposure twice in one call, and someone else's",
    attribution: "ordinary",
    events: [
      { id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_prd" }, metadata: { items: "X@ver_1,X@ver_1" } },
      { id: id(), eventType: "value.disclosed", decision: "allow", actorIdentityId: BOB, organizationId: ORG, resource: { environmentId: "env_prd" }, metadata: { items: "X@ver_1" } },
    ],
  });
  out.push({
    name: "webhook URLs",
    attribution: "ordinary",
    events: [
      { id: id(), eventType: "webhook.created", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, metadata: { url: "https://user:secret@hooks.example.com/t/abc?token=x#f", webhookId: "whk_1" } },
      { id: id(), eventType: "webhook.updated", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, metadata: { oldUrl: "https://hooks.example.com/", newUrl: "not a url", url: 42 } },
      { id: id(), eventType: "webhook.revoked", decision: "allow", actorIdentityId: ALICE, organizationId: ORG, metadata: { webhookId: "whk_1" } },
    ],
  });
  out.push({
    name: "the incident freeze's refusal",
    attribution: "ordinary",
    events: [],
    frozenRefusal: { principal: ALICE, credentialId: "crd_alice_cli", freezeId: "ofz_1", method: "GET", route: "/v1/organizations/:org/projects", requestId: "req_frozen" },
  });
  out.push({
    name: "the incident freeze's refusal without a principal",
    attribution: "none",
    events: [],
    frozenRefusal: { principal: null, credentialId: null, freezeId: "ofz_1", method: "POST", route: "/v1/organizations/:org/projects/:project", requestId: "req_frozen_2" },
  });
  out.push({
    name: "the organization.frozen event",
    attribution: "ordinary",
    events: [{
      id: id(), eventType: "organization.frozen", decision: "info", actorIdentityId: ALICE, organizationId: ORG, action: "organization.manage",
      requestId: "req_freeze", resource: { freezeId: "ofz_1" }, metadata: { freezeId: "ofz_1", reasonGiven: true, approvalsClosed: 2 },
    }],
  });
  return out;
}

// Lone UTF-16 surrogates, built from code units so this file stays ASCII.
const u = (...units: number[]) => String.fromCharCode(...units);
const HIGH = u(0xd800), LOW = u(0xdc00), PAIR = u(0xd83d, 0xde00);
/** JSON text of a JSON string holding `v`'s JSON: jsonb keeps it a string, parseMaybe parses it again. */
const twice = (v: unknown) => JSON.stringify(JSON.stringify(v));

// Rows written as stored text, then read back through jsonb.
const RAW_ROWS: Record<string, string | number | null>[] = [
  {
    id: "evt_raw1", schema_version: 1, event_type: "value.written", occurred_at: "2026-11-14T10:00:00.999999Z", decision: "allow",
    actor_identity_id: ALICE, organization_id: ORG, action: "config.value.write", request_id: "req_raw", listener: "ordinary", client: "c".repeat(64),
    resource: '{"z":1,"a":{"y":[3,{"b":1,"a":2}],"x":null},"10":"ten","2":"two","aa":true,"\u00e9":"e","b":1,"b":2}',
    metadata: '{"float":1.5,"big":12345678901234567890,"tiny":1e-7,"small":0.000001,"huge":1e21,"almost":999999999999999900000,"neg":-0,"inf":1e400,"exp":1.25e-10,"int":-42,"frac":0.1,"third":0.3333333333333333}',
    authz: '{"requirements":[],"grantIds":["b","a"],"role":"admin"}',
    tailnet: '{"tags":[],"nodeId":"n1","tailnet":"corp.ts.net"}',
  },
  {
    id: "evt_raw2", schema_version: 2, event_type: "identity.renamed", occurred_at: "2026-11-14T10:00:00.000001Z", decision: "info",
    metadata: '{"s":"line\\u2028sep \\u2029 </script> \\u0007 \\u001f \\"q\\" \\\\ \\ud83d\\ude00 \\u00ff tab\\t nl\\n cr\\r bs\\b ff\\f del\\u007f"}',
  },
  {
    id: "evt_raw3", schema_version: 1, event_type: "webhook.created", occurred_at: "2026-01-02T03:04:05Z", decision: "allow",
    metadata: '{"url":"http://EXAMPLE.com:80/a?b","newUrl":"https://example.com:8443","oldUrl":null,"other":"https://keep.example.com/x"}',
  },
  { id: "evt_raw4", schema_version: 1, event_type: "webhook.updated", occurred_at: "2026-01-02T03:04:05.5Z", decision: "allow", metadata: '["https://a.example.com/x",{"url":"https://b.example.com/y"}]' },
  { id: "evt_raw5", schema_version: 1, event_type: "webhook.revoked", occurred_at: "1999-12-31T23:59:59.999Z", decision: "allow", metadata: '"just a string"' },
  { id: "evt_raw5b", schema_version: 1, event_type: "webhook.revoked", occurred_at: "1999-12-31T23:59:59.999Z", decision: "allow", metadata: '"{\\"url\\":\\"https://x.example.com/p\\",\\"b\\":1,\\"a\\":2,\\"1\\":0}"', resource: '"[1,\\"two\\"]"', authz: '"42"' },
  { id: "evt_raw6", schema_version: 1, event_type: "webhook.updated", occurred_at: "2026-06-30T12:00:00.0005Z", decision: "allow", metadata: '{"url":"https://hooks.example.com/","4294967294":"index","4294967295":"not an index","01":"not an index","1":"index"}' },
  { id: "evt_raw7", schema_version: 1, event_type: "audit_export.created", occurred_at: "2026-06-30T12:00:00.123+02:00", decision: "info", resource: "null", metadata: "[]" },
  // Lone surrogates: jsonb refuses them as input, but a jsonb string whose
  // text is JSON reaches JSON.parse a second time (parseMaybe), which keeps
  // them, and JSON.stringify writes them as \uXXXX escapes.
  {
    id: "evt_raw8", schema_version: 1, event_type: "identity.renamed", occurred_at: "2026-06-30T12:00:01Z", decision: "info",
    metadata: twice({ high: HIGH, low: LOW, [`k${LOW}`]: `x${HIGH}y`, pair: PAIR, swapped: LOW + HIGH, twoHigh: HIGH + HIGH, end: `a${u(0xdbff)}` }),
    resource: twice(u(0xdfff)),
    authz: twice([HIGH, { [HIGH]: [LOW, PAIR] }]),
  },
  {
    id: "evt_raw9", schema_version: 1, event_type: "webhook.updated", occurred_at: "2026-06-30T12:00:02Z", decision: "allow",
    metadata: twice({ url: `https://x${HIGH}.example/`, oldUrl: `https://example.com/${LOW}?q`, newUrl: `https://example.com/#${HIGH}`, note: LOW }),
  },
];

// JSON.stringify(JSON.parse(text)) for texts with lone surrogates (\u escapes
// in the text, which is ASCII).
const BS = u(92);
const esc = (hex: string) => `${BS}u${hex}`;
const ROUND_TRIP = [
  `"${esc("d800")}"`, `"${esc("dc00")}"`, `"${esc("DBFF")}"`, `"${esc("dbff")}${esc("dfff")}"`, `"${esc("dc00")}${esc("d800")}"`,
  `"${esc("d800")}${esc("d800")}"`, `"a${esc("d800")}b"`, `"${esc("d83d")}${esc("de00")}"`, `"${esc("d83d")}x${esc("de00")}"`,
  `"${esc("d800")}${esc("0041")}"`, `"${esc("d800")}${BS}n"`, `{"${esc("d800")}":1,"k":"${esc("dfff")}"}`,
  `["${esc("d800")}",{"${esc("dc00")}":"${esc("d83d")}${esc("de00")}"}]`, `"${esc("d800")}${esc("dc00")}${esc("dc00")}"`,
  `"${esc("ffff")}${esc("fffe")}${esc("e000")}"`, `"${esc("d7ff")}${esc("e000")}"`,
];

const REDACT = [
  "https://hooks.example.com/abc?token=x#frag", "https://user:pass@example.com/", "https://example.com", "http://EXAMPLE.com:80/",
  "https://example.com:443", "https://example.com:8443/x", "https://example.com/?", "https://example.com/#", "https://example.com/.",
  "https://example.com/a/..", "https://example.com/a/../", "https://example.com/%2e%2E", "https://example.com/a/%2e%2e/b",
  "https://b\u00fccher.de/x", "https://[::1]:8080/a", "https://[0:0::1]/", "https://0x7f.1/", "https://1.2.3/", "not a url", "",
  "mailto:a@b.c", "foo://host/path", "foo://Host", "foo://host:12/", "foo://h:x/", "foo:/", "foo:x", "file:///etc/passwd",
  "file://localhost/x", "file://server/share?q", "https:example.com/x", "https:/\\example.com", " https://example.com/ ",
  "https://ex\tample.com/", "https://@example.com/", "https://user@/", "https://example.com\\path", "ws://x/", "wss://x:443/",
  "ftp://x:21/", "javascript:alert(1)", "https://example.com:0/", "https://example.com:65536/", "https://exa mple.com/",
  "https://example.com?a", "HTTPS://Example.COM/A", "https://example.com:/", "https://exa%41mple.com/", "https://a..b/",
  "https://[::1/", "https://x/#", "https://x/?#", "https://x?#y", "h://", "https://", "http://example.com:0080/",
];

const ITEMS = ["", "A@v1", "A@v1,B@v2+v3", "@v1", "A", "A@", "A@+v2", "A@v1+", "a@b@c", ",,A@v1,", "A@v1+v2+v3", "X@ver_1,X@ver_1"];

const INDEXABLE: unknown[] = [
  { eventType: "secret.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1", mode: "strict-retrieval" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1", mode: "strict-retrieval", purpose: "export" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1", purpose: "scan" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: 5 } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: 7 }, metadata: { items: "A@v1" } },
  { eventType: "value.disclosed", actorIdentityId: "", organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: null, resource: { environmentId: "env_1" }, metadata: { items: "A@v1" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "" }, metadata: { items: "A@v1" } },
  { eventType: "value.disclosed", actorIdentityId: ALICE, organizationId: ORG, metadata: { items: "A@v1" } },
  { eventType: "value.written", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1", itemName: "A", versionId: "v2" } },
  { eventType: "value.rotation_started", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1", itemName: "A", versionId: "v3" } },
  { eventType: "value.written", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1", itemName: "A" } },
  { eventType: "value.validated", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1" } },
  { eventType: "secret.validated", actorIdentityId: ALICE, organizationId: ORG, resource: { environmentId: "env_1" }, metadata: { items: "A@v1" } },
];

function fakeContext(principal: Principal | undefined, f: NonNullable<Recording["frozenRefusal"]>): Context {
  const vars = new Map<string, unknown>([["principal", principal], ["requestId", f.requestId]]);
  return { get: (k: string) => vars.get(k), set: (k: string, v: unknown) => void vars.set(k, v), req: { method: f.method, routePath: f.route } } as unknown as Context;
}

async function build() {
  const db = await migratedTestDb({ lockOrder: "off" });
  try {
    const ctx = { db, rootKek: Buffer.alloc(32) } as AppCtx;
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1, 'acme', 'Acme', '{}')", [ORG]);
    for (const [identity, kind, org] of [[ALICE, "human", null], [BOB, "human", null], [SVC, "service", ORG]]) {
      await db.query("INSERT INTO identities (id, kind, name, organization_id) VALUES ($1, $2, $1, $3)", [identity, kind, org]);
    }
    const recs = recordings();
    const times = new Map<string, string>();
    let t = Date.parse("2026-11-01T00:00:00Z");
    const recorded: { recording: Recording; ids: string[] }[] = [];
    for (const rec of recs) {
      const attribution = ATTRIBUTIONS[rec.attribution];
      const run = async (): Promise<string[]> => {
        if (rec.frozenRefusal) {
          const f = rec.frozenRefusal;
          const principal = f.principal ? ({ identity: { id: f.principal, kind: "human" }, credentialId: f.credentialId } as unknown as Principal) : undefined;
          const before = new Set(((await db.query("SELECT id FROM audit_events")).rows as { id: string }[]).map((r) => r.id));
          await auditFrozenRefusal(ctx, fakeContext(principal, f), new OrganizationFrozenError(f.freezeId, "2026-11-01T00:00:00.000Z", ORG));
          const made = ((await db.query("SELECT id FROM audit_events ORDER BY event_order")).rows as { id: string }[]).map((r) => r.id).filter((x) => !before.has(x));
          // auditFrozenRefusal makes a random ID: a fixed one, so the file is reproducible.
          const fixed = made.map(() => id());
          for (const [i, made1] of made.entries()) await db.query("UPDATE audit_events SET id = $2 WHERE id = $1", [made1, fixed[i]]);
          return fixed;
        }
        return recordAuditEvents(db, rec.events);
      };
      const ids = attribution ? await withAttribution(attribution, run) : await run();
      recorded.push({ recording: rec, ids });
      for (const eventId of ids) {
        // Fixed times, with microseconds, so the file is reproducible.
        t += 1234;
        const iso = new Date(t).toISOString().replace("Z", `${String(t % 997).padStart(3, "0")}Z`);
        times.set(eventId, iso);
        await db.query("UPDATE audit_events SET occurred_at = $2 WHERE id = $1", [eventId, iso]);
      }
    }
    // Events jsonb refuses: recordAuditEvents throws, and nothing is stored.
    const refused: { event: AuditEventInput; refused: boolean }[] = [];
    for (const event of [
      { id: "evt_bad1", eventType: "value.written", decision: "info", metadata: { s: HIGH } },
      { id: "evt_bad2", eventType: "value.written", decision: "info", resource: { [LOW]: "x" } },
      { id: "evt_bad3", eventType: "value.written", decision: "info", authz: { a: [u(0)] } },
      { id: "evt_bad4", eventType: "value.written", decision: "info", metadata: { s: PAIR, t: `${u(0xd7ff)}${u(0xe000)}` } },
    ] as AuditEventInput[]) {
      let failed = false;
      try {
        await recordAuditEvents(db, [event]);
      } catch {
        failed = true;
      }
      refused.push({ event, refused: failed });
      if (!failed) await db.query("DELETE FROM audit_events WHERE id = $1", [event.id]);
    }
    for (const row of RAW_ROWS) {
      const cols = Object.keys(row);
      await db.query(`INSERT INTO audit_events (${cols.join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`, cols.map((c) => row[c]));
    }
    const rows = (await db.query(
      `SELECT *, (extract(epoch FROM occurred_at) * 1000000)::bigint::text AS occurred_micros FROM audit_events ORDER BY event_order`,
    )).rows as Record<string, unknown>[];
    const byId = new Map(rows.map((r) => [r.id as string, r]));
    const shown = (r: Record<string, unknown>) => {
      const { occurred_micros, occurred_at: _at, ...stored } = r;
      const base = { position: Number(r.event_order), occurredAt: Number(occurred_micros), stored };
      let serialized: ReturnType<typeof serializeAuditEvent>;
      try {
        serialized = serializeAuditEvent(r);
      } catch (e) {
        // A jsonb string that is not JSON text: parseMaybe parses what
        // node-postgres already parsed, and throws.
        return { ...base, throws: (e as Error).name };
      }
      return {
        ...base,
        eventJSON: JSON.stringify(serialized),
        streamLine: JSON.stringify({ position: String(r.event_order ?? "0"), ...serialized }),
      };
    };
    const exposure = (await db.query(
      "SELECT organization_id, identity_id, version_id, item_name, environment_id, way FROM member_exposure ORDER BY organization_id, identity_id, version_id, environment_id, way",
    )).rows;
    return {
      generator: "services/varlatchd/test/go-audit-vectors.test.ts",
      eventTypes: [...AUDIT_EVENT_TYPES],
      attributions: ATTRIBUTIONS,
      recordings: recorded.map(({ recording, ids }) => ({
        name: recording.name,
        attribution: recording.attribution,
        events: recording.events,
        ...(recording.frozenRefusal ? { frozenRefusal: recording.frozenRefusal } : {}),
        rows: ids.map((eventId) => shown(byId.get(eventId)!)),
      })),
      rawRows: RAW_ROWS.map((row) => ({ input: row, ...shown(byId.get(row.id as string)!) })),
      exposure,
      parseItems: ITEMS.map((items) => ({ items, parsed: parseItems(items) })),
      exposureFromEvent: INDEXABLE.map((event) => ({ event, entry: exposureFromEvent(event as never) })),
      redact: REDACT.map((url) => ({ url, redacted: redactWebhookUrl(url) })),
      roundTrip: ROUND_TRIP.map((text) => ({ text, stringified: JSON.stringify(JSON.parse(text)) })),
      refused,
    };
  } finally {
    await db.close();
  }
}

/** One member per line, so a change shows as the vectors it touches. */
function format(vectors: Record<string, unknown>): string {
  const lines = ["{"];
  const keys = Object.keys(vectors);
  keys.forEach((k, i) => {
    const v = vectors[k];
    const tail = i < keys.length - 1 ? "," : "";
    if (Array.isArray(v)) {
      lines.push(`  ${JSON.stringify(k)}: [`);
      v.forEach((e, j) => lines.push(`    ${JSON.stringify(e)}${j < v.length - 1 ? "," : ""}`));
      lines.push(`  ]${tail}`);
    } else {
      lines.push(`  ${JSON.stringify(k)}: ${JSON.stringify(v)}${tail}`);
    }
  });
  lines.push("}");
  return `${lines.join("\n")}\n`;
}

it("the Go audit vectors are current", { timeout: 300_000 }, async () => {
  const text = format(await build());
  if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
    writeFileSync(OUT, text);
    return;
  }
  const committed = readFileSync(OUT, "utf8");
  expect(committed === text, "go/server/audit/testdata/ts-vectors.json is stale: regenerate it (see the header of this file)").toBe(true);
});
