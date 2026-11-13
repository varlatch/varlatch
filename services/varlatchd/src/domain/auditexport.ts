// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import {
  isAccessDenied,
  isPreconditionFailed,
  objectRetention,
  objectSha256,
  putObjectIfAbsent,
  storageErrorDetail,
  type StorageClient,
} from "@varlatch/backup/s3";
import { recordAuditEvents, type AuditEventInput } from "../audit/events.js";
import { serializeAuditEvent } from "../audit/serialize.js";
import type { Envelope } from "../crypto/aead.js";
import {
  decryptAuditExportCredential,
  decryptAuditExportDrainCredential,
  encryptAuditExportCredential,
  encryptAuditExportDrainCredential,
} from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import { outboundOf, outboundRefusalOf, type OutboundRefusedError } from "../net/outbound.js";
import { ApprovalNeeded, type ApprovalBinding, type ApprovalChange, type ProtectedGate, type Requester, type UsedApproval } from "./approvals.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { currentExternalEffect } from "./externaleffect.js";
import { lockLiveScope, refuseIfFrozen, refuseIfIncidentFrozen, withExternalEffect } from "./liveness.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import { lockPeople } from "./personlocks.js";
import { approvalMetadata, effectRequester } from "./protected.js";
import { assertOrganizationAccessChecked, requireOrganizationAccess } from "./requestaccess.js";

/**
 * Audit export to object storage (ADR-0056): an Organization's whole audit
 * log, in position order, copied to an S3-compatible bucket it controls,
 * with Object Lock retention nobody on the Varlatch side can shorten.
 *
 * Nothing here runs until an Organization admin creates an export: the
 * worker finds no row, sends nothing and records nothing.
 *
 * PLANS (Decision 2). Every object (the stream manifest, a batch, an hourly
 * heartbeat) is planned first: its bytes, already serialized and
 * compressed, their SHA-256 and MD5, the name, the format and the retention
 * are stored in audit_export_plans, one pending plan per export. Then it is
 * uploaded with If-None-Match: *, then committed. A retry, by this worker,
 * a later lease holder or a later release, uploads exactly the stored
 * bytes. A plan that can no longer be uploaded (its retention expired, or a
 * format this release cannot upload) ends in a stream restart, never a
 * re-plan under its name.
 *
 * BINDINGS (Decision 3). Taking the lease returns the generation, the
 * export version and the stream id; planning and committing check all
 * three under the export row FOR UPDATE. Every change, removal, restore and
 * the switch to draining increments the generation and clears the lease in
 * its own transaction, so a worker in the middle of an upload can neither
 * plan nor commit afterwards. No transaction is held during an upload.
 *
 * LOCK ORDER (ADR-0054 amendment E, domain/liveness.ts; ADR-0056 Decision
 * 14). The export row is a domain row (step 10), after every other domain
 * row its transaction takes, and the plan row comes right after it: every
 * transaction that writes or deletes a plan holds its export row FOR UPDATE
 * first. Per transaction:
 *   create: the external effect's 1 KEY SHARE and 2 (the actor), then the
 *     audit insert, then the export row and its manifest plan (inserted,
 *     like a webhook after its creation event, so the cursor can name it);
 *   a change, a credential replacement, a removal: 1 KEY SHARE; 2 (the
 *     actor, FOR UPDATE when an approval is consumed); consumption's 4, 6,
 *     7; the export row FOR UPDATE; the plan row when it deletes it; audit.
 *     A destination change runs inside an external effect (the probe);
 *   the worker: the lease is one statement on the export row; planning and
 *     committing: the export row, the plan row, then audit only for a state
 *     change. It reads audit_events without locks and never waits for an
 *     export row while holding the audit counter;
 *   a stream restart (automatic or discard-plan): the export row, the plan
 *     row, audit;
 *   restore: the live export rows in id order, then their plan rows in id
 *     order, then audit;
 *   Organization deletion's finalization: its step 1 UPDATE and domain
 *     rows, then the export row (rewrap, state, generation), before its
 *     report counters (step 11) and audit inserts;
 *   the drain deadline: the expired draining export rows (SKIP LOCKED), in
 *     id order, their plans, then audit.
 */

// ---------------------------------------------------------------------------
// Constants

export const AUDIT_EXPORT_LIMITS = {
  batchEvents: 1_000,
  /** Serialized NDJSON, before compression. */
  batchBytes: 8 * 1024 * 1024,
  objectsPerRun: 20,
  leaseSeconds: 300,
  uploadTimeoutMs: 30_000,
  intervalMs: 60_000,
  /** A plan whose retention ends within this is expired (Decision 2). */
  expiryMarginSeconds: 3_600,
  /** Failing this long records audit_export.failing, once per episode. */
  failingAfterSeconds: 900,
  drainDays: 30,
  prefixMax: 256,
  retentionDaysMax: 3_650,
} as const;

/** The object format this release writes. */
export const FORMAT_VERSION = 1;
/** The formats this release can upload from a stored plan. */
export const UPLOADABLE_FORMATS: ReadonlySet<number> = new Set([1]);
const FORMAT_NAME = "varlatch-audit-export";

/** Endpoints whose Object Lock behaviour is verified (ADR-0040's spike): AWS S3 and Backblaze B2. */
const VERIFIED_LOCK_PROVIDERS = [/(^|\.)amazonaws\.com$/i, /(^|\.)backblazeb2\.com$/i];

// ---------------------------------------------------------------------------
// Types

export interface AuditExportDestination {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  pathStyle: boolean;
}

export type RetentionMode = "compliance" | "governance";
export interface AuditExportRetention {
  mode: RetentionMode;
  days: number;
}

export interface AuditExportCredential {
  accessKeyId: string;
  secretAccessKey: string;
}

export type AuditExportState = "active" | "draining" | "removed" | "completed" | "abandoned";
export type StreamReason = "created" | "restored" | "destination_changed" | "plan_expired" | "plan_discarded";

/** An export as the Security page and the API show it: never the key. */
export interface AuditExportView {
  id: string;
  organizationId: string;
  destination: AuditExportDestination;
  retention: AuditExportRetention | null;
  state: AuditExportState;
  streamId: string;
  cursor: string;
  version: number;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  failingSince: string | null;
  keyCanRead: boolean | null;
  stoppedReason: "object_conflict" | "unsupported_format" | null;
  conditionalCheckedAt: string | null;
  lockVerified: boolean | null;
  drainDeadline: string | null;
  createdBy: string;
  createdAt: string;
  removedAt: string | null;
}

/** What a probe found (Decision 6). */
export interface ProbeResult {
  ok: boolean;
  /** Fixed wording only (storageErrorDetail, the outbound policy's messages). */
  message: string | null;
  conditionalCreation: boolean | null;
  /** "verified": a verified provider, or the retention read back; "accepted": headers accepted, not verified. */
  objectLock: "verified" | "accepted" | "not-set" | null;
  keyCanRead: boolean | null;
}

interface ExportRow {
  id: string;
  organization_id: string;
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  path_style: boolean;
  credential_envelope: Envelope | string | null;
  retention_mode: RetentionMode | null;
  retention_days: number | null;
  stream_id: string;
  stream_started_at: Date | string;
  cursor_order: string | number;
  generation: string | number;
  lease_expires_at: Date | string | null;
  state: AuditExportState;
  drain_deadline: Date | string | null;
  last_attempt_at: Date | string | null;
  last_success_at: Date | string | null;
  last_error: string | null;
  failing_since: Date | string | null;
  failing_recorded: boolean;
  key_can_read: boolean | null;
  stopped_reason: "object_conflict" | "unsupported_format" | null;
  conditional_checked_at: Date | string | null;
  lock_verified: boolean | null;
  last_heartbeat_hour: Date | string | null;
  created_by: string;
  created_at: Date | string;
  removed_at: Date | string | null;
  version: number;
}

export interface PlanRow {
  id: string;
  export_id: string;
  export_version: number;
  stream_id: string;
  generation: string | number;
  kind: "manifest" | "batch" | "heartbeat";
  object_name: string;
  body: Buffer;
  sha256: string;
  md5: string;
  content_type: string;
  format_version: number;
  retention_mode: RetentionMode | null;
  retain_until: Date | string | null;
  first_order: string | number | null;
  last_order: string | number | null;
  event_count: number | null;
  heartbeat_hour: Date | string | null;
  planned_at: Date | string;
}

/** What a worker carries from its lease (Decision 2): all three must still be current. */
export interface WorkerBinding {
  exportId: string;
  organizationId: string;
  generation: string;
  version: number;
  streamId: string;
}

const iso = (v: Date | string | null | undefined): string | null => (v === null || v === undefined ? null : new Date(v).toISOString());
const str = (v: string | number | bigint | null | undefined): string => String(v ?? "0");
const envelopeOf = (v: Envelope | string | null): Envelope | null => (v === null ? null : typeof v === "string" ? (JSON.parse(v) as Envelope) : v);

export function viewOf(row: ExportRow): AuditExportView {
  return {
    id: row.id,
    organizationId: row.organization_id,
    destination: destinationOf(row),
    retention: retentionOf(row),
    state: row.state,
    streamId: row.stream_id,
    cursor: str(row.cursor_order),
    version: row.version,
    lastAttemptAt: iso(row.last_attempt_at),
    lastSuccessAt: iso(row.last_success_at),
    lastError: row.last_error,
    failingSince: iso(row.failing_since),
    keyCanRead: row.key_can_read,
    stoppedReason: row.stopped_reason,
    conditionalCheckedAt: iso(row.conditional_checked_at),
    lockVerified: row.lock_verified,
    drainDeadline: iso(row.drain_deadline),
    createdBy: row.created_by,
    createdAt: iso(row.created_at) as string,
    removedAt: iso(row.removed_at),
  };
}

const destinationOf = (row: ExportRow): AuditExportDestination => ({
  endpoint: row.endpoint,
  region: row.region,
  bucket: row.bucket,
  prefix: row.prefix,
  pathStyle: row.path_style,
});
const retentionOf = (row: Pick<ExportRow, "retention_mode" | "retention_days">): AuditExportRetention | null =>
  row.retention_mode && row.retention_days ? { mode: row.retention_mode, days: Number(row.retention_days) } : null;

// ---------------------------------------------------------------------------
// Validation (Decision 6), without the network

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KEY_ID = /^[\x21-\x7e]{1,128}$/;
const SECRET = /^[\x21-\x7e]{1,256}$/;

/** A destination as stored: the endpoint's origin, a prefix that is empty or ends with "/". Throws VALIDATION_FAILED. */
export function normalizeDestination(input: AuditExportDestination): AuditExportDestination {
  let url: URL;
  try {
    url = new URL(input.endpoint);
  } catch {
    throw new DomainError("VALIDATION_FAILED", "endpoint: not a URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new DomainError("VALIDATION_FAILED", "endpoint: must be https");
  if (url.username || url.password) throw new DomainError("VALIDATION_FAILED", "endpoint: must not carry user info");
  if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new DomainError("VALIDATION_FAILED", "endpoint: must be a scheme, host and optional port, without a path or query");
  }
  const bucket = input.bucket;
  if (!BUCKET.test(bucket) || bucket.includes("..") || /^\d+\.\d+\.\d+\.\d+$/.test(bucket) || bucket.includes(".-") || bucket.includes("-.")) {
    throw new DomainError("VALIDATION_FAILED", "bucket: 3 to 63 lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit");
  }
  if (!REGION.test(input.region)) throw new DomainError("VALIDATION_FAILED", "region: lowercase letters, digits and hyphens");
  let prefix = input.prefix ?? "";
  if (prefix.length > 0 && !prefix.endsWith("/")) prefix += "/";
  if (prefix.length > AUDIT_EXPORT_LIMITS.prefixMax) throw new DomainError("VALIDATION_FAILED", `prefix: at most ${AUDIT_EXPORT_LIMITS.prefixMax} characters`);
  if (prefix.startsWith("/") || prefix.split("/").some((part) => part === ".." || part === ".") || /[\x00-\x1f\x7f\\]/.test(prefix)) {
    throw new DomainError("VALIDATION_FAILED", "prefix: no leading slash, no . or .. parts, no control characters");
  }
  return { endpoint: url.origin, region: input.region, bucket, prefix, pathStyle: input.pathStyle === true };
}

export function validateRetention(retention: AuditExportRetention | null): AuditExportRetention | null {
  if (retention === null) return null;
  if (retention.mode !== "compliance" && retention.mode !== "governance") {
    throw new DomainError("VALIDATION_FAILED", "retention.mode: compliance or governance");
  }
  if (!Number.isInteger(retention.days) || retention.days < 1 || retention.days > AUDIT_EXPORT_LIMITS.retentionDaysMax) {
    throw new DomainError("VALIDATION_FAILED", `retention.days: a whole number from 1 to ${AUDIT_EXPORT_LIMITS.retentionDaysMax}`);
  }
  return { mode: retention.mode, days: retention.days };
}

export function validateCredential(credential: AuditExportCredential): AuditExportCredential {
  if (!KEY_ID.test(credential.accessKeyId ?? "") || !SECRET.test(credential.secretAccessKey ?? "")) {
    throw new DomainError("VALIDATION_FAILED", "credential: an access key ID and a secret, without spaces");
  }
  return { accessKeyId: credential.accessKeyId, secretAccessKey: credential.secretAccessKey };
}

/** A person's dashboard or CLI credential: every change needs one, never a machine (Decision 9). */
function requirePerson(requester: Requester): void {
  const person = requester.identityKind === "human" && (requester.credentialKind === "browser" || requester.credentialKind === "cli");
  if (!person) {
    throw new DomainError("PERMISSION_DENIED", "Audit exports are changed by a person, never a machine credential", { reason: "machine-credential" });
  }
}

function requireSwitchOn(ctx: AppCtx): void {
  if (ctx.auditExport === false) {
    throw new DomainError(
      "PERMISSION_DENIED",
      "The host operator turned audit export off on this installation (VARLATCH_AUDIT_EXPORT=off)",
      { reason: "audit-export-off" },
    );
  }
}

// ---------------------------------------------------------------------------
// Object names and bodies (Decision 4)

const pad = (order: string | number | bigint) => BigInt(order).toString().padStart(20, "0");
export const streamBase = (prefix: string, organizationId: string, streamId: string) => `${prefix}varlatch-audit/${organizationId}/${streamId}/`;
const hourName = (hour: Date) => hour.toISOString().slice(0, 13);

interface Planned {
  kind: PlanRow["kind"];
  objectName: string;
  body: Buffer;
  contentType: string;
  firstOrder?: string;
  lastOrder?: string;
  eventCount?: number;
  heartbeatHour?: Date;
}

function manifestPlan(input: {
  prefix: string;
  organizationId: string;
  streamId: string;
  startOrder: string;
  previousStreamId: string | null;
  reason: StreamReason;
  cause?: string | undefined;
  possibleOverlap: { firstOrder: string; lastOrder: string } | null;
  plannedAt: Date;
}): Planned {
  const body = JSON.stringify({
    format: FORMAT_NAME,
    version: FORMAT_VERSION,
    kind: "stream",
    organizationId: input.organizationId,
    streamId: input.streamId,
    startOrder: input.startOrder,
    previousStreamId: input.previousStreamId,
    reason: input.reason,
    ...(input.cause ? { cause: input.cause } : {}),
    possibleOverlap: input.possibleOverlap,
    plannedAt: input.plannedAt.toISOString(),
  });
  return {
    kind: "manifest",
    objectName: `${streamBase(input.prefix, input.organizationId, input.streamId)}stream.json`,
    body: Buffer.from(`${body}\n`, "utf8"),
    contentType: "application/json",
  };
}

/**
 * The NDJSON lines of a batch: a header, then each event in the
 * serializeAuditEvent shape with its position added, so a reader can
 * de-duplicate an overlap by position as well as by event id.
 */
function batchPlan(input: {
  prefix: string;
  organizationId: string;
  streamId: string;
  previousLastOrder: string;
  rows: Record<string, unknown>[];
  plannedAt: Date;
}): Planned {
  const lines: string[] = [];
  let size = 0;
  for (const row of input.rows) {
    const line = JSON.stringify({ position: str(row.event_order as string), ...serializeAuditEvent(row) });
    const bytes = Buffer.byteLength(line, "utf8") + 1;
    if (lines.length > 0 && (lines.length >= AUDIT_EXPORT_LIMITS.batchEvents || size + bytes > AUDIT_EXPORT_LIMITS.batchBytes)) break;
    lines.push(line);
    size += bytes;
  }
  const taken = input.rows.slice(0, lines.length);
  const firstOrder = str(taken[0]?.event_order as string);
  const lastOrder = str(taken[taken.length - 1]?.event_order as string);
  const header = JSON.stringify({
    format: FORMAT_NAME,
    version: FORMAT_VERSION,
    kind: "batch",
    organizationId: input.organizationId,
    streamId: input.streamId,
    firstOrder,
    lastOrder,
    count: lines.length,
    previousLastOrder: input.previousLastOrder,
    plannedAt: input.plannedAt.toISOString(),
  });
  const ndjson = `${[header, ...lines].join("\n")}\n`;
  return {
    kind: "batch",
    objectName: `${streamBase(input.prefix, input.organizationId, input.streamId)}${pad(firstOrder)}-${pad(lastOrder)}.ndjson.gz`,
    body: gzipSync(Buffer.from(ndjson, "utf8"), { level: 9 }),
    contentType: "application/gzip",
    firstOrder,
    lastOrder,
    eventCount: lines.length,
  };
}

function heartbeatPlan(input: {
  prefix: string;
  organizationId: string;
  streamId: string;
  hour: Date;
  cursor: string;
  latestOrder: string;
  plannedAt: Date;
}): Planned {
  const body = JSON.stringify({
    format: FORMAT_NAME,
    version: FORMAT_VERSION,
    kind: "heartbeat",
    organizationId: input.organizationId,
    streamId: input.streamId,
    hour: hourName(input.hour),
    cursor: input.cursor,
    latestOrder: input.latestOrder,
    plannedAt: input.plannedAt.toISOString(),
  });
  return {
    kind: "heartbeat",
    objectName: `${streamBase(input.prefix, input.organizationId, input.streamId)}heartbeat/${hourName(input.hour)}.json`,
    body: Buffer.from(`${body}\n`, "utf8"),
    contentType: "application/json",
    heartbeatHour: input.hour,
  };
}

const sha256Hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const md5Hex = (b: Buffer) => createHash("md5").update(b).digest("hex");

/** Insert a plan for the export's current binding. The caller holds the export row FOR UPDATE. */
async function insertPlan(
  db: Querier,
  binding: { exportId: string; version: number; streamId: string; generation: string },
  planned: Planned,
  retention: AuditExportRetention | null,
  plannedAt: Date,
): Promise<string> {
  const id = newId("auditExportPlan");
  const retainUntil = retention ? new Date(plannedAt.getTime() + retention.days * 86_400_000) : null;
  await db.query(
    `INSERT INTO audit_export_plans (id, export_id, export_version, stream_id, generation, kind, object_name, body, sha256, md5,
       content_type, format_version, retention_mode, retain_until, first_order, last_order, event_count, heartbeat_hour, planned_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [
      id, binding.exportId, binding.version, binding.streamId, binding.generation, planned.kind, planned.objectName, planned.body,
      sha256Hex(planned.body), md5Hex(planned.body), planned.contentType, FORMAT_VERSION,
      retention?.mode ?? null, retainUntil, planned.firstOrder ?? null, planned.lastOrder ?? null, planned.eventCount ?? null,
      planned.heartbeatHour ?? null, plannedAt,
    ],
  );
  return id;
}

async function dbNow(db: Querier): Promise<Date> {
  const row = (await db.query("SELECT clock_timestamp() AS now")).rows[0] as { now: Date | string };
  return new Date(row.now);
}

// ---------------------------------------------------------------------------
// The S3 client, through the outbound policy (ADR-0057)

export interface AuditExportTestHooks {
  /** Called before an upload is sent. Throwing fails the attempt without anything reaching the destination. */
  beforeUpload?: (plan: PlanRow) => void | Promise<void>;
  /** Called after an upload succeeded at the destination, before the worker sees the response. Throwing loses the response. */
  afterUpload?: (plan: PlanRow) => void | Promise<void>;
  /** Called before a commit transaction. */
  beforeCommit?: (plan: PlanRow) => void | Promise<void>;
  /** Treat this endpoint as a verified Object Lock provider (MinIO in the test suite, Decision 7). */
  verifiedProvider?: (endpoint: string) => boolean;
}

let testHooks: AuditExportTestHooks = {};
/** Test-only fault injection. */
export function setAuditExportTestHooks(hooks: AuditExportTestHooks | null): void {
  testHooks = hooks ?? {};
}

/** The S3 client, built by the outbound policy (ADR-0057): every connection checked as it opens. */
function clientFor(ctx: AppCtx, destination: AuditExportDestination, credential: AuditExportCredential): StorageClient {
  return outboundOf(ctx).storageClient(
    "audit_export",
    { endpoint: destination.endpoint, region: destination.region, bucket: destination.bucket, prefix: destination.prefix, forcePathStyle: destination.pathStyle },
    { accessKeyId: credential.accessKeyId, secretAccessKey: credential.secretAccessKey },
    AUDIT_EXPORT_LIMITS.uploadTimeoutMs,
  );
}

/** A signal for one request: its own timeout, and the external effect's deadline when there is one. */
function requestSignal(): AbortSignal {
  const timeout = AbortSignal.timeout(AUDIT_EXPORT_LIMITS.uploadTimeoutMs);
  const effect = currentExternalEffect();
  return effect ? AbortSignal.any([timeout, effect.signal]) : timeout;
}


/** The words for a failed request: the outbound policy's, or storageErrorDetail's, never the store's text. */
export function failureWords(prefix: string, err: unknown): string {
  const refusal = outboundRefusalOf(err);
  if (refusal) return refusal.message;
  return `${prefix}${storageErrorDetail(err)}`;
}

interface PutInput {
  key: string;
  body: Buffer;
  sha256: string;
  md5: string;
  contentType: string;
  retentionMode: RetentionMode | null;
  retainUntil: Date | null;
}

async function putIfAbsent(s3: StorageClient, bucket: string, input: PutInput): Promise<void> {
  await putObjectIfAbsent(s3, bucket, {
    key: input.key,
    body: input.body,
    sha256: input.sha256,
    md5: input.md5,
    contentType: input.contentType,
    retention: input.retentionMode && input.retainUntil ? { mode: input.retentionMode, retainUntil: input.retainUntil } : null,
  }, requestSignal());
}

function verifiedProvider(endpoint: string): boolean {
  if (testHooks.verifiedProvider?.(endpoint)) return true;
  const host = new URL(endpoint).hostname;
  return VERIFIED_LOCK_PROVIDERS.some((re) => re.test(host));
}

/**
 * The probe (Decision 6), under `<prefix>varlatch-audit/<org>/probe/`: a
 * first write (with the retention headers when retention is set), a second
 * write of the same name that must be refused with 412, and, with a key
 * that can read, the retention read back. The probe objects stay.
 */
async function probe(
  ctx: AppCtx,
  organizationId: string,
  destination: AuditExportDestination,
  credential: AuditExportCredential,
  retention: AuditExportRetention | null,
  now: Date,
): Promise<ProbeResult> {
  const s3 = clientFor(ctx, destination, credential);
  try {
    const body = Buffer.from(`${JSON.stringify({ format: FORMAT_NAME, version: FORMAT_VERSION, kind: "probe", at: now.toISOString() })}\n`);
    const key = `${destination.prefix}varlatch-audit/${organizationId}/probe/${randomBytes(16).toString("hex")}.json`;
    const retainUntil = retention ? new Date(now.getTime() + retention.days * 86_400_000) : null;
    const put: PutInput = { key, body, sha256: sha256Hex(body), md5: md5Hex(body), contentType: "application/json", retentionMode: retention?.mode ?? null, retainUntil };
    try {
      await putIfAbsent(s3, destination.bucket, put);
    } catch (err) {
      return { ok: false, message: failureWords("The test write failed", err), conditionalCreation: null, objectLock: null, keyCanRead: null };
    }
    try {
      await putIfAbsent(s3, destination.bucket, put);
      return {
        ok: false,
        message: "This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)",
        conditionalCreation: false,
        objectLock: null,
        keyCanRead: null,
      };
    } catch (err) {
      if (!isPreconditionFailed(err)) {
        return { ok: false, message: failureWords("The conditional test write failed", err), conditionalCreation: null, objectLock: null, keyCanRead: null };
      }
    }
    if (!retention) return { ok: true, message: null, conditionalCreation: true, objectLock: "not-set", keyCanRead: null };
    let keyCanRead: boolean | null = null;
    let readBack = false;
    try {
      const got = await objectRetention(s3, destination.bucket, key, requestSignal());
      keyCanRead = true;
      readBack = got?.mode === retention.mode;
    } catch (err) {
      if (isAccessDenied(err)) keyCanRead = false;
    }
    return {
      ok: true,
      message: null,
      conditionalCreation: true,
      objectLock: readBack || verifiedProvider(destination.endpoint) ? "verified" : "accepted",
      keyCanRead,
    };
  } finally {
    s3.destroy();
  }
}

/**
 * The outbound policy's configuration-time check (ADR-0057 Decision 6),
 * before any transaction: a refused endpoint is recorded and answered in
 * the policy's words; nothing is sent.
 */
async function endpointRefusal(ctx: AppCtx, organizationId: string, endpoint: string, exportId: string | null, actorIdentityId: string): Promise<OutboundRefusedError | null> {
  const policy = outboundOf(ctx);
  const refusal = await policy.refusalFor(endpoint, "audit_export");
  if (!refusal) return null;
  await policy.recordRefusal(ctx.db, {
    organizationId,
    purpose: "audit_export",
    phase: "configuration",
    refusal,
    resource: exportId ? { exportId } : {},
    actorIdentityId,
  });
  return refusal;
}

const probeFailed = (result: ProbeResult) =>
  new DomainError("VALIDATION_FAILED", result.message ?? "The destination check failed", { check: result });

// ---------------------------------------------------------------------------
// Reading

const EXPORT_COLUMNS = "*";

async function liveExport(db: Querier, organizationId: string): Promise<ExportRow | null> {
  const res = await db.query(
    `SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE organization_id = $1 AND state IN ('active', 'draining')`,
    [organizationId],
  );
  return (res.rows[0] as ExportRow | undefined) ?? null;
}

/** The Organization's export: the live one, or else the most recent. Null when it never had one. */
export async function getAuditExport(ctx: AppCtx, organizationId: string): Promise<AuditExportView | null> {
  const res = await ctx.db.query(
    `SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE organization_id = $1
     ORDER BY (state IN ('active', 'draining')) DESC, created_at DESC, id DESC LIMIT 1`,
    [organizationId],
  );
  const row = res.rows[0] as ExportRow | undefined;
  return row ? viewOf(row) : null;
}

/** Events of the Organization not yet exported, and the age of the oldest (Decision 11). */
export async function auditExportLag(ctx: AppCtx, exportId: string): Promise<{ pending: number; oldestPendingAt: string | null }> {
  const res = await ctx.db.query(
    `SELECT count(e.*)::int AS n, min(e.occurred_at) AS oldest FROM audit_exports x
     JOIN audit_events e ON e.organization_id = x.organization_id AND e.event_order > x.cursor_order
     WHERE x.id = $1`,
    [exportId],
  );
  const row = res.rows[0] as { n: number; oldest: Date | string | null };
  return { pending: Number(row.n), oldestPendingAt: iso(row.oldest) };
}

async function lockExport(db: Querier, exportId: string): Promise<ExportRow | null> {
  const res = await lockedQuery(db, { table: "audit_exports", mode: "update" }, `SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE id = $1 FOR UPDATE`, [exportId]);
  return (res.rows[0] as ExportRow | undefined) ?? null;
}

async function lockPlan(db: Querier, exportId: string): Promise<PlanRow | null> {
  const res = await lockedQuery(db, { table: "audit_export_plans", mode: "update" }, "SELECT * FROM audit_export_plans WHERE export_id = $1 FOR UPDATE", [exportId]);
  const row = res.rows[0] as PlanRow | undefined;
  return row ? { ...row, body: Buffer.from(row.body) } : null;
}

async function readPlan(db: Querier, exportId: string): Promise<PlanRow | null> {
  const res = await db.query("SELECT * FROM audit_export_plans WHERE export_id = $1", [exportId]);
  const row = res.rows[0] as PlanRow | undefined;
  return row ? { ...row, body: Buffer.from(row.body) } : null;
}

// ---------------------------------------------------------------------------
// Create (no approval: creating only adds protection, Decision 9)

export interface CreateInput {
  destination: AuditExportDestination;
  credential: AuditExportCredential;
  retention: AuditExportRetention | null;
  /** "beginning" backfills the whole log (the default); "now" starts at the creation event. */
  from: "beginning" | "now";
}

/**
 * Create the Organization's export. The probe runs inside an external
 * effect (liveness.ts withExternalEffect): the Organization row and the
 * actor held, the passkey-verification checkpoint passed before the key is
 * sent anywhere. Refused while frozen or while a deletion is pending
 * (Decision 9), and when the host switched the export off.
 */
export async function createAuditExport(
  ctx: AppCtx,
  requester: Requester,
  org: OrgRow,
  input: CreateInput,
  options: { authorizeIn?: ((db: Querier) => Promise<void>) | undefined; requestId?: string | null } = {},
): Promise<AuditExportView> {
  requirePerson(requester);
  requireSwitchOn(ctx);
  const destination = normalizeDestination(input.destination);
  const retention = validateRetention(input.retention);
  const credential = validateCredential(input.credential);
  if (input.from !== "beginning" && input.from !== "now") throw new DomainError("VALIDATION_FAILED", "from: beginning or now");
  const actor = requester.identityId;
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  const refusal = await endpointRefusal(ctx, org.id, destination.endpoint, null, actor);
  if (refusal) throw new DomainError("VALIDATION_FAILED", refusal.message, { outbound: refusal.reason });

  const id = newId("auditExport");
  const streamId = newId("auditExportStream");
  const envelope = encryptAuditExportCredential(orgKekOf(ctx, org), org.id, id, JSON.stringify(credential));
  return withExternalEffect(ctx.db, { organizationId: org.id, people: [actor] }, async (tx) => {
    if (await liveExport(tx, org.id)) {
      throw new DomainError("VALIDATION_FAILED", "This Organization already has an audit export; change or remove it instead", { reason: "export-exists" });
    }
    await requireOrganizationAccess(tx, org.id);
    await options.authorizeIn?.(tx);
    await assertOrganizationAccessChecked(tx, org.id, "the audit export probe", { underLock: true });
    const now = await dbNow(tx);
    const checked = await probe(ctx, org.id, destination, credential, retention, now);
    if (!checked.ok) throw probeFailed(checked);

    // Audit, then the row whose cursor may name the creation event (as a
    // webhook's does), then the stream's manifest plan.
    const [createdEventId] = await recordAuditEvents(tx, [
      {
        eventType: "audit_export.created",
        decision: "info",
        actorIdentityId: actor,
        organizationId: org.id,
        action: "organization.manage",
        requestId: options.requestId ?? null,
        resource: { exportId: id },
        metadata: {
          host: new URL(destination.endpoint).host,
          bucket: destination.bucket,
          prefix: destination.prefix,
          retentionMode: retention?.mode ?? null,
          retentionDays: retention?.days ?? null,
          from: input.from,
        },
      },
      streamStartedEvent(org.id, id, streamId, null, "created", undefined, actor, options.requestId ?? null),
    ]);
    const res = await tx.query(
      `INSERT INTO audit_exports (id, organization_id, endpoint, region, bucket, prefix, path_style, credential_envelope,
         retention_mode, retention_days, stream_id, stream_started_at, cursor_order, state, created_by,
         conditional_checked_at, lock_verified, key_can_read)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(),
         CASE WHEN $12 THEN (SELECT event_order FROM audit_events WHERE id = $13) ELSE 0 END,
         'active',$14,clock_timestamp(),$15,$16)
       RETURNING ${EXPORT_COLUMNS}`,
      [
        id, org.id, destination.endpoint, destination.region, destination.bucket, destination.prefix, destination.pathStyle,
        JSON.stringify(envelope), retention?.mode ?? null, retention?.days ?? null, streamId,
        input.from === "now", createdEventId, actor,
        retention ? checked.objectLock === "verified" : null, checked.keyCanRead,
      ],
    );
    const row = res.rows[0] as ExportRow;
    await insertPlan(
      tx,
      { exportId: id, version: row.version, streamId, generation: str(row.generation) },
      manifestPlan({ prefix: destination.prefix, organizationId: org.id, streamId, startOrder: str(row.cursor_order), previousStreamId: null, reason: "created", possibleOverlap: null, plannedAt: now }),
      retention,
      now,
    );
    return viewOf(row);
  });
}

function streamStartedEvent(
  organizationId: string,
  exportId: string,
  streamId: string,
  previousStreamId: string | null,
  reason: StreamReason,
  cause: string | undefined,
  actorIdentityId: string | null,
  requestId: string | null,
  overlap: { firstOrder: string; lastOrder: string } | null = null,
): AuditEventInput {
  return {
    eventType: "audit_export.stream_started",
    decision: "info",
    actorIdentityId,
    organizationId,
    requestId,
    resource: { exportId },
    metadata: {
      streamId,
      previousStreamId,
      reason,
      ...(cause ? { cause } : {}),
      ...(overlap ? { overlapFirstOrder: overlap.firstOrder, overlapLastOrder: overlap.lastOrder } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Check (the probe without saving)

/**
 * The probe alone, nothing saved (`POST …/audit-export/check`, as
 * connection checks do). The key is the one supplied, or the stored one of
 * the live export, which is only sent to that export's own destination.
 * Records nothing: ADR-0056 Decision 13 lists no event
 * for it; a configuration-time refusal is recorded by the outbound policy.
 */
export async function checkAuditExport(
  ctx: AppCtx,
  requester: Requester,
  org: OrgRow,
  input: { destination: AuditExportDestination; credential?: AuditExportCredential | undefined; retention: AuditExportRetention | null },
  options: { authorizeIn?: ((db: Querier) => Promise<void>) | undefined } = {},
): Promise<ProbeResult> {
  requirePerson(requester);
  requireSwitchOn(ctx);
  const destination = normalizeDestination(input.destination);
  const retention = validateRetention(input.retention);
  const supplied = input.credential ? validateCredential(input.credential) : null;
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  const refusal = await endpointRefusal(ctx, org.id, destination.endpoint, null, requester.identityId);
  if (refusal) return { ok: false, message: refusal.message, conditionalCreation: null, objectLock: null, keyCanRead: null };
  return withExternalEffect(ctx.db, { organizationId: org.id, people: [requester.identityId] }, async (tx) => {
    let credential = supplied;
    if (!credential) {
      const live = await liveExport(tx, org.id);
      if (!live || live.state !== "active") throw new DomainError("RESOURCE_NOT_FOUND", "Audit export not found");
      await requireOrganizationAccess(tx, org.id);
      await options.authorizeIn?.(tx);
      // The stored key goes only to the export's own destination: sending
      // it elsewhere is a destination change, which needs an approval
      // (Decision 9). Another destination is checked with a key supplied.
      if (classifyChange({ destination: destinationOf(live), retention: null }, { destination, retention: null }).destinationChanged) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "The stored key is only checked against the export's own destination; give a key to check another one",
          { reason: "stored-key-other-destination" },
        );
      }
      credential = storedCredential(ctx, org, live);
    } else {
      await requireOrganizationAccess(tx, org.id);
      await options.authorizeIn?.(tx);
    }
    await assertOrganizationAccessChecked(tx, org.id, "the audit export probe", { underLock: true });
    return probe(ctx, org.id, destination, credential, retention, await dbNow(tx));
  });
}

function storedCredential(ctx: AppCtx, org: OrgRow, row: ExportRow): AuditExportCredential {
  const envelope = envelopeOf(row.credential_envelope);
  if (!envelope) throw new DomainError("STATE_CHANGED", "The audit export has no key");
  return JSON.parse(decryptAuditExportCredential(orgKekOf(ctx, org), org.id, row.id, envelope)) as AuditExportCredential;
}

// ---------------------------------------------------------------------------
// Change, credential replacement, removal (approval always for loosening, Decision 9)

export interface ChangeInput {
  destination?: Partial<AuditExportDestination> | undefined;
  /** undefined keeps the retention; null removes it. */
  retention?: AuditExportRetention | null | undefined;
  expectedVersion: number;
}

export interface ChangeOutcome {
  export: AuditExportView;
  changed: boolean;
  loosened: boolean;
}

interface Classified {
  changes: ApprovalChange[];
  destinationChanged: boolean;
  loosened: boolean;
}

const retentionText = (r: AuditExportRetention | null) => (r ? `${r.mode}, ${r.days} days` : "none");

/** Field by field (ADR-0054 Decision 2): any loosening part makes the whole change need the approval. */
export function classifyChange(
  current: { destination: AuditExportDestination; retention: AuditExportRetention | null },
  next: { destination: AuditExportDestination; retention: AuditExportRetention | null },
): Classified {
  const changes: ApprovalChange[] = [];
  let destinationChanged = false;
  const fields: [keyof AuditExportDestination, string][] = [["endpoint", "endpoint"], ["region", "region"], ["bucket", "bucket"], ["prefix", "prefix"], ["pathStyle", "pathStyle"]];
  for (const [key, field] of fields) {
    const from = String(current.destination[key]);
    const to = String(next.destination[key]);
    if (from !== to) {
      destinationChanged = true;
      // Redirecting the copy, like a webhook PATCH: always loosening.
      changes.push({ field, from, to, loosens: true });
    }
  }
  const a = current.retention;
  const b = next.retention;
  if (retentionText(a) !== retentionText(b)) {
    const loosens =
      b === null ? a !== null : a === null ? false : b.days < a.days || (a.mode === "compliance" && b.mode === "governance");
    changes.push({ field: "retention", from: retentionText(a), to: retentionText(b), loosens });
  }
  return { changes, destinationChanged, loosened: changes.some((c) => c.loosens) };
}

/**
 * Lock the scope at step 1, read the export without a lock, pass the
 * checkpoint: the refusals that come before any approval (amendment A).
 */
async function preflight(db: Querier, org: OrgRow, exportId: string, authorizeIn?: (db: Querier) => Promise<void>): Promise<ExportRow> {
  const row = (await db.query(`SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE id = $1 AND organization_id = $2`, [exportId, org.id])).rows[0] as ExportRow | undefined;
  if (!row || row.state !== "active") throw new DomainError("RESOURCE_NOT_FOUND", "Audit export not found");
  await requireOrganizationAccess(db, org.id);
  await authorizeIn?.(db);
  return row;
}

function versionConflict(current: number, expected: number): DomainError {
  return new DomainError("VERSION_CONFLICT", `The audit export is at version ${current}, not ${expected}: it changed meanwhile. Read it again`, { currentVersion: current });
}

/** The row FOR UPDATE, still active, still at the version the request bound. */
async function lockForChange(db: Querier, exportId: string, expectedVersion: number): Promise<ExportRow> {
  const row = await lockExport(db, exportId);
  if (!row || row.state !== "active") throw new DomainError("RESOURCE_NOT_FOUND", "Audit export not found");
  if (row.version !== expectedVersion) throw versionConflict(row.version, expectedVersion);
  return row;
}

/**
 * Change the destination or the retention. Tightening the retention needs
 * no approval; a destination change, a shorter or removed retention, or
 * compliance to governance needs the requester's step-up approval
 * (audit_export.change), always, whatever the Security Controls' modes. A
 * destination change starts a new stream at the current cursor and must
 * pass the probe first, inside an external effect; under an approval, the
 * probe runs only after a precheck found it (amendment D).
 */
export async function changeAuditExport(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  exportId: string,
  input: ChangeInput,
  options: { authorizeIn?: ((db: Querier) => Promise<void>) | undefined; requestId?: string | null } = {},
): Promise<ChangeOutcome> {
  requirePerson(gate.requester);
  requireSwitchOn(ctx);
  const actor = gate.requester.identityId;
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  const seen = (await ctx.db.query(`SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE id = $1 AND organization_id = $2`, [exportId, org.id])).rows[0] as ExportRow | undefined;
  if (!seen || seen.state !== "active") throw new DomainError("RESOURCE_NOT_FOUND", "Audit export not found");
  const nextOf = (row: ExportRow) => ({
    destination: normalizeDestination({ ...destinationOf(row), ...(input.destination ?? {}) }),
    retention: input.retention === undefined ? retentionOf(row) : validateRetention(input.retention),
  });
  const planned = nextOf(seen);
  const willProbe = classifyChange({ destination: destinationOf(seen), retention: retentionOf(seen) }, planned).destinationChanged;
  if (willProbe) {
    const refusal = await endpointRefusal(ctx, org.id, planned.destination.endpoint, exportId, actor);
    if (refusal) throw new DomainError("VALIDATION_FAILED", refusal.message, { outbound: refusal.reason });
  }

  const run = async (tx: Querier): Promise<ChangeOutcome> => {
    const row = await preflight(tx, org, exportId, options.authorizeIn);
    if (row.version !== input.expectedVersion) throw versionConflict(row.version, input.expectedVersion);
    const current = { destination: destinationOf(row), retention: retentionOf(row) };
    const next = nextOf(row);
    const classified = classifyChange(current, next);
    if (classified.changes.length === 0) return { export: viewOf(row), changed: false, loosened: false };
    if (classified.destinationChanged !== willProbe) throw new DomainError("STATE_CHANGED", "The audit export changed meanwhile; read it again");
    const binding: ApprovalBinding | null = classified.loosened
      ? {
          operation: "audit_export.change",
          organizationId: org.id,
          target: { exportId },
          body: { destination: next.destination, retention: next.retention, expectedVersion: input.expectedVersion },
          query: {},
          expectedVersion: input.expectedVersion,
          summary: { title: `Change the audit export of ${org.name}`, changes: classified.changes },
        }
      : null;
    if (binding && gate.approvalId === null) throw new ApprovalNeeded(binding);
    let probed: ProbeResult | null = null;
    let now = await dbNow(tx);
    if (classified.destinationChanged) {
      // Amendment D: an unapproved request never sends the key out.
      if (binding) await gate.precheck?.(tx, binding);
      await assertOrganizationAccessChecked(tx, org.id, "the audit export probe", { underLock: true });
      probed = await probe(ctx, org.id, next.destination, storedCredential(ctx, org, row), next.retention, now);
      if (!probed.ok) throw probeFailed(probed);
      now = await dbNow(tx);
    }
    // Step 2 (the effect took the actor already; reuse), then consumption's 4, 6, 7.
    if (!classified.destinationChanged) await lockPeople(tx, [{ id: actor, mode: binding ? "update" : "key share" }]);
    const approval: UsedApproval | null = binding ? await gate.require(tx, binding) : null;
    if (binding) await options.authorizeIn?.(tx);
    const locked = await lockForChange(tx, exportId, input.expectedVersion);
    const events: AuditEventInput[] = [];
    let streamId = locked.stream_id;
    if (classified.destinationChanged) {
      // A new stream at the current cursor; the pending plan goes (Decision 3).
      const plan = await lockPlan(tx, exportId);
      if (plan) await tx.query("DELETE FROM audit_export_plans WHERE id = $1", [plan.id]);
      streamId = newId("auditExportStream");
    }
    const res = await tx.query(
      `UPDATE audit_exports SET endpoint = $2, region = $3, bucket = $4, prefix = $5, path_style = $6,
         retention_mode = $7, retention_days = $8, stream_id = $9,
         stream_started_at = CASE WHEN $9 <> stream_id THEN clock_timestamp() ELSE stream_started_at END,
         stopped_reason = CASE WHEN $9 <> stream_id THEN NULL ELSE stopped_reason END,
         conditional_checked_at = CASE WHEN $10 THEN clock_timestamp() ELSE conditional_checked_at END,
         lock_verified = CASE WHEN $10 THEN $11::boolean WHEN $8::int IS NULL THEN NULL ELSE lock_verified END,
         key_can_read = CASE WHEN $10 THEN COALESCE($12::boolean, key_can_read) ELSE key_can_read END,
         generation = generation + 1, lease_expires_at = NULL, version = version + 1, updated_at = now()
       WHERE id = $1 RETURNING ${EXPORT_COLUMNS}`,
      [
        exportId, next.destination.endpoint, next.destination.region, next.destination.bucket, next.destination.prefix, next.destination.pathStyle,
        next.retention?.mode ?? null, next.retention?.days ?? null, streamId,
        probed !== null, probed && next.retention ? probed.objectLock === "verified" : null, probed?.keyCanRead ?? null,
      ],
    );
    const updated = res.rows[0] as ExportRow;
    if (classified.destinationChanged) {
      await insertPlan(
        tx,
        { exportId, version: updated.version, streamId, generation: str(updated.generation) },
        manifestPlan({
          prefix: next.destination.prefix, organizationId: org.id, streamId, startOrder: str(updated.cursor_order),
          previousStreamId: locked.stream_id, reason: "destination_changed", possibleOverlap: null, plannedAt: now,
        }),
        next.retention,
        now,
      );
    }
    events.push({
      eventType: "audit_export.changed",
      decision: "info",
      actorIdentityId: actor,
      organizationId: org.id,
      action: "organization.manage",
      requestId: options.requestId ?? null,
      resource: { exportId },
      metadata: {
        ...Object.fromEntries(classified.changes.flatMap((c) => [[`from_${c.field}`, c.from], [`to_${c.field}`, c.to]])),
        loosened: classified.loosened,
        loosenedFields: classified.changes.filter((c) => c.loosens).map((c) => c.field).join(","),
        ...approvalMetadata(approval),
      },
    });
    if (classified.destinationChanged) {
      events.push(streamStartedEvent(org.id, exportId, streamId, locked.stream_id, "destination_changed", undefined, actor, options.requestId ?? null));
    }
    await recordAuditEvents(tx, events);
    return { export: viewOf(updated), changed: true, loosened: classified.loosened };
  };

  if (willProbe) return withExternalEffect(ctx.db, { organizationId: org.id, people: [effectRequester(gate)] }, run);
  return withTx(ctx.db, async (tx) => {
    await lockLiveScope(tx, { organizationId: org.id, people: [], accessCheck: "deferred" });
    return run(tx);
  });
}

/**
 * Replace the export's key: always an approval (audit_export.change, a
 * wrong key stops delivery). The stream and the pending plan are kept; the
 * next lease holder uploads the plan with the new key (Decision 3). No
 * probe: ADR-0056 checks the destination at creation and on a destination
 * change; `checkAuditExport` with the new key checks it first.
 */
export async function replaceAuditExportCredential(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  exportId: string,
  input: { credential: AuditExportCredential; expectedVersion: number },
  options: { authorizeIn?: ((db: Querier) => Promise<void>) | undefined; requestId?: string | null } = {},
): Promise<AuditExportView> {
  requirePerson(gate.requester);
  requireSwitchOn(ctx);
  const credential = validateCredential(input.credential);
  const actor = gate.requester.identityId;
  const envelope = encryptAuditExportCredential(orgKekOf(ctx, org), org.id, exportId, JSON.stringify(credential));
  return withTx(ctx.db, async (tx) => {
    await lockLiveScope(tx, { organizationId: org.id, people: [], accessCheck: "deferred" });
    const row = await preflight(tx, org, exportId, options.authorizeIn);
    if (row.version !== input.expectedVersion) throw versionConflict(row.version, input.expectedVersion);
    const binding: ApprovalBinding = {
      operation: "audit_export.change",
      organizationId: org.id,
      target: { exportId },
      // The intent keeps only the body's keyed hash; the summary never names the key.
      body: { credential, expectedVersion: input.expectedVersion },
      query: {},
      expectedVersion: input.expectedVersion,
      summary: { title: `Replace the key of the audit export of ${org.name}`, changes: [{ field: "credential", from: null, to: null, loosens: true }] },
    };
    if (gate.approvalId === null) throw new ApprovalNeeded(binding);
    await lockPeople(tx, [{ id: actor, mode: "update" }]);
    const approval = await gate.require(tx, binding);
    await options.authorizeIn?.(tx);
    await lockForChange(tx, exportId, input.expectedVersion);
    const res = await tx.query(
      `UPDATE audit_exports SET credential_envelope = $2, key_can_read = NULL, generation = generation + 1, lease_expires_at = NULL,
         version = version + 1, updated_at = now()
       WHERE id = $1 RETURNING ${EXPORT_COLUMNS}`,
      [exportId, JSON.stringify(envelope)],
    );
    await recordAuditEvents(tx, [{
      eventType: "audit_export.credential_replaced",
      decision: "info",
      actorIdentityId: actor,
      organizationId: org.id,
      action: "organization.manage",
      requestId: options.requestId ?? null,
      resource: { exportId },
      metadata: { ...approvalMetadata(approval) },
    }]);
    return viewOf(res.rows[0] as ExportRow);
  });
}

/**
 * Remove the export: always an approval (audit_export.remove). In one
 * transaction: `removed`, the pending plan deleted, the key cleared, the
 * generation incremented (Decision 9). Allowed with the switch off, so an
 * Organization can still take its key out of an installation that stopped
 * exporting.
 */
export async function removeAuditExport(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  exportId: string,
  input: { expectedVersion: number },
  options: { authorizeIn?: ((db: Querier) => Promise<void>) | undefined; requestId?: string | null } = {},
): Promise<AuditExportView> {
  requirePerson(gate.requester);
  const actor = gate.requester.identityId;
  return withTx(ctx.db, async (tx) => {
    await lockLiveScope(tx, { organizationId: org.id, people: [], accessCheck: "deferred" });
    const row = await preflight(tx, org, exportId, options.authorizeIn);
    if (row.version !== input.expectedVersion) throw versionConflict(row.version, input.expectedVersion);
    const binding: ApprovalBinding = {
      operation: "audit_export.remove",
      organizationId: org.id,
      target: { exportId },
      body: { expectedVersion: input.expectedVersion },
      query: {},
      expectedVersion: input.expectedVersion,
      summary: {
        title: `Remove the audit export of ${org.name}`,
        changes: [{ field: "destination", from: `${new URL(row.endpoint).host}/${row.bucket}/${row.prefix}`, to: null, loosens: true }],
      },
    };
    if (gate.approvalId === null) throw new ApprovalNeeded(binding);
    await lockPeople(tx, [{ id: actor, mode: "update" }]);
    const approval = await gate.require(tx, binding);
    await options.authorizeIn?.(tx);
    await lockForChange(tx, exportId, input.expectedVersion);
    const plan = await lockPlan(tx, exportId);
    if (plan) await tx.query("DELETE FROM audit_export_plans WHERE id = $1", [plan.id]);
    const res = await tx.query(
      `UPDATE audit_exports SET state = 'removed', removed_at = now(), credential_envelope = NULL, generation = generation + 1,
         lease_expires_at = NULL, version = version + 1, updated_at = now()
       WHERE id = $1 RETURNING ${EXPORT_COLUMNS}`,
      [exportId],
    );
    await recordAuditEvents(tx, [{
      eventType: "audit_export.removed",
      decision: "info",
      actorIdentityId: actor,
      organizationId: org.id,
      action: "organization.manage",
      requestId: options.requestId ?? null,
      resource: { exportId },
      metadata: { streamId: row.stream_id, pendingPlanDeleted: plan !== null, ...approvalMetadata(approval) },
    }]);
    return viewOf(res.rows[0] as ExportRow);
  });
}

// ---------------------------------------------------------------------------
// The worker (Decisions 2 and 3)

/** Take the lease on the database clock: one statement, returning the binding and what the worker needs. */
async function takeLease(db: Querier, exportId: string): Promise<ExportRow | null> {
  const res = await db.query(
    `UPDATE audit_exports SET generation = generation + 1, lease_expires_at = now() + make_interval(secs => $2)
     WHERE id = $1 AND state IN ('active', 'draining') AND stopped_reason IS NULL
       AND (lease_expires_at IS NULL OR lease_expires_at < now())
     RETURNING ${EXPORT_COLUMNS}`,
    [exportId, AUDIT_EXPORT_LIMITS.leaseSeconds],
  );
  return (res.rows[0] as ExportRow | undefined) ?? null;
}

const bindingOf = (row: ExportRow): WorkerBinding => ({
  exportId: row.id,
  organizationId: row.organization_id,
  generation: str(row.generation),
  version: row.version,
  streamId: row.stream_id,
});
const bound = (row: ExportRow | null, b: WorkerBinding): row is ExportRow =>
  row !== null && str(row.generation) === b.generation && row.version === b.version && row.stream_id === b.streamId &&
  (row.state === "active" || row.state === "draining");

/** The export's key, as the worker reads it: under the Organization KEK while active, the Root KEK while draining. */
async function workerCredential(ctx: AppCtx, row: ExportRow): Promise<AuditExportCredential> {
  const envelope = envelopeOf(row.credential_envelope);
  if (!envelope) throw new Error("audit export without a key");
  if (row.state === "draining") {
    return JSON.parse(decryptAuditExportDrainCredential(ctx.rootKek, row.organization_id, row.id, envelope)) as AuditExportCredential;
  }
  const org = (await ctx.db.query("SELECT id, wrapped_org_kek FROM organizations WHERE id = $1", [row.organization_id])).rows[0] as OrgRow;
  return JSON.parse(decryptAuditExportCredential(orgKekOf(ctx, org), row.organization_id, row.id, envelope)) as AuditExportCredential;
}

/**
 * Plan the next object, or null when there is nothing to write: an hourly
 * heartbeat when its hour has none yet, else the next batch after the
 * cursor. Serialized and compressed outside any transaction, then stored
 * in one short transaction that checks the binding, the cursor it read and
 * that no plan is pending.
 */
export async function planNext(ctx: AppCtx, binding: WorkerBinding): Promise<PlanRow | null> {
  const row = (await ctx.db.query(`SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE id = $1`, [binding.exportId])).rows[0] as ExportRow | undefined;
  if (!row || !bound(row, binding)) return null;
  const cursor = str(row.cursor_order);
  const now = await dbNow(ctx.db);
  const hour = new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);
  let planned: Planned | null = null;
  const lastHeartbeat = row.last_heartbeat_hour ? new Date(row.last_heartbeat_hour).getTime() : null;
  if (lastHeartbeat === null || lastHeartbeat < hour.getTime()) {
    const latest = (await ctx.db.query("SELECT max(event_order) AS m FROM audit_events WHERE organization_id = $1", [row.organization_id])).rows[0] as { m: string | number | null };
    planned = heartbeatPlan({ prefix: row.prefix, organizationId: row.organization_id, streamId: row.stream_id, hour, cursor, latestOrder: str(latest.m), plannedAt: now });
  } else {
    const events = (await ctx.db.query(
      "SELECT * FROM audit_events WHERE organization_id = $1 AND event_order > $2 ORDER BY event_order LIMIT $3",
      [row.organization_id, cursor, AUDIT_EXPORT_LIMITS.batchEvents],
    )).rows as Record<string, unknown>[];
    if (events.length > 0) {
      planned = batchPlan({ prefix: row.prefix, organizationId: row.organization_id, streamId: row.stream_id, previousLastOrder: cursor, rows: events, plannedAt: now });
    }
  }
  if (!planned) return null;
  const toStore = planned;
  return withTx(ctx.db, async (tx) => {
    const locked = await lockExport(tx, binding.exportId);
    if (!bound(locked, binding) || str(locked.cursor_order) !== cursor) return null;
    if (await lockPlan(tx, binding.exportId)) return null;
    await insertPlan(tx, binding, toStore, retentionOf(locked), now);
    return lockPlan(tx, binding.exportId);
  });
}

export type UploadOutcome = { kind: "delivered"; keyCanRead: boolean | null } | { kind: "conflict" } | { kind: "failed"; message: string };

/** Upload a plan exactly as stored. 412 means an earlier attempt of this plan landed (Decision 4). */
export async function uploadPlan(s3: StorageClient, bucket: string, plan: PlanRow, keyCanRead: boolean | null): Promise<UploadOutcome> {
  try {
    await testHooks.beforeUpload?.(plan);
    await putIfAbsent(s3, bucket, {
      key: plan.object_name,
      body: plan.body,
      sha256: plan.sha256,
      md5: plan.md5,
      contentType: plan.content_type,
      retentionMode: plan.retention_mode,
      retainUntil: plan.retain_until ? new Date(plan.retain_until) : null,
    });
    await testHooks.afterUpload?.(plan);
    return { kind: "delivered", keyCanRead };
  } catch (err) {
    if (!isPreconditionFailed(err)) return { kind: "failed", message: failureWords("Upload failed", err) };
  }
  if (keyCanRead === false) return { kind: "delivered", keyCanRead: false };
  try {
    const sha256 = await objectSha256(s3, bucket, plan.object_name, requestSignal());
    return sha256 === plan.sha256 ? { kind: "delivered", keyCanRead: true } : { kind: "conflict" };
  } catch (err) {
    if (isAccessDenied(err)) return { kind: "delivered", keyCanRead: false };
    return { kind: "failed", message: failureWords("The check of an existing object failed", err) };
  }
}

/**
 * Commit a delivered plan: in one short transaction under the export row,
 * only if the binding, the pending plan and its stream are all still
 * current. A batch moves the cursor; a heartbeat records its hour. A drain
 * whose batch holds organization.deleted completes.
 */
export async function commitPlan(ctx: AppCtx, binding: WorkerBinding, plan: PlanRow, keyCanRead: boolean | null): Promise<boolean> {
  await testHooks.beforeCommit?.(plan);
  return withTx(ctx.db, async (tx) => {
    const locked = await lockExport(tx, binding.exportId);
    if (!bound(locked, binding)) return false;
    const pending = await lockPlan(tx, binding.exportId);
    if (!pending || pending.id !== plan.id || pending.stream_id !== locked.stream_id) return false;
    await tx.query("DELETE FROM audit_export_plans WHERE id = $1", [plan.id]);
    const cursor = plan.kind === "batch" ? str(plan.last_order) : str(locked.cursor_order);
    const completes = locked.state === "draining" && plan.kind === "batch" && (await tx.query(
      "SELECT 1 FROM audit_events WHERE organization_id = $1 AND event_type = 'organization.deleted' AND event_order <= $2 LIMIT 1",
      [locked.organization_id, cursor],
    )).rows.length > 0;
    await tx.query(
      `UPDATE audit_exports SET cursor_order = $2,
         last_heartbeat_hour = CASE WHEN $3::timestamptz IS NOT NULL THEN $3::timestamptz ELSE last_heartbeat_hour END,
         last_success_at = clock_timestamp(), last_attempt_at = clock_timestamp(), last_error = NULL,
         failing_since = NULL, failing_recorded = false, key_can_read = COALESCE($4::boolean, key_can_read),
         state = CASE WHEN $5 THEN 'completed' ELSE state END,
         credential_envelope = CASE WHEN $5 THEN NULL ELSE credential_envelope END,
         lease_expires_at = CASE WHEN $5 THEN NULL ELSE lease_expires_at END
       WHERE id = $1`,
      [binding.exportId, cursor, plan.kind === "heartbeat" ? plan.heartbeat_hour : null, keyCanRead, completes],
    );
    const events: AuditEventInput[] = [];
    if (locked.failing_recorded) {
      events.push({
        eventType: "audit_export.recovered",
        decision: "info",
        actorIdentityId: null,
        organizationId: locked.organization_id,
        resource: { exportId: binding.exportId },
        metadata: { failingSince: iso(locked.failing_since) },
      });
    }
    if (completes) {
      events.push({
        eventType: "audit_export.completed",
        decision: "info",
        actorIdentityId: null,
        organizationId: locked.organization_id,
        resource: { exportId: binding.exportId },
        metadata: { streamId: locked.stream_id, lastOrder: cursor },
      });
    }
    if (events.length > 0) await recordAuditEvents(tx, events);
    return true;
  });
}

/**
 * A failed attempt: the plan stays. The status records the attempt and the
 * fixed wording; failing for 15 minutes records audit_export.failing once
 * per episode (Decision 11).
 */
async function recordFailure(ctx: AppCtx, binding: WorkerBinding, message: string): Promise<void> {
  await withTx(ctx.db, async (tx) => {
    const locked = await lockExport(tx, binding.exportId);
    if (!bound(locked, binding)) return;
    const res = await tx.query(
      `UPDATE audit_exports SET last_attempt_at = clock_timestamp(), last_error = $2, failing_since = COALESCE(failing_since, clock_timestamp())
       WHERE id = $1 RETURNING failing_since, failing_recorded, failing_since <= clock_timestamp() - make_interval(secs => $3) AS due`,
      [binding.exportId, message, AUDIT_EXPORT_LIMITS.failingAfterSeconds],
    );
    const r = res.rows[0] as { failing_since: Date | string; failing_recorded: boolean; due: boolean };
    if (r.due && !r.failing_recorded) {
      await tx.query("UPDATE audit_exports SET failing_recorded = true WHERE id = $1", [binding.exportId]);
      await recordAuditEvents(tx, [{
        eventType: "audit_export.failing",
        decision: "info",
        actorIdentityId: null,
        organizationId: locked.organization_id,
        resource: { exportId: binding.exportId },
        metadata: { failingSince: iso(r.failing_since), error: message },
      }]);
    }
  });
}

/** Stop the export until a person acts: an object conflict, or a plan this release cannot upload. */
async function stopExport(ctx: AppCtx, binding: WorkerBinding, reason: "object_conflict" | "unsupported_format", message: string): Promise<void> {
  await withTx(ctx.db, async (tx) => {
    const locked = await lockExport(tx, binding.exportId);
    if (!bound(locked, binding)) return;
    await tx.query(
      `UPDATE audit_exports SET stopped_reason = $2, last_error = $3, last_attempt_at = clock_timestamp(),
         failing_since = COALESCE(failing_since, clock_timestamp()), lease_expires_at = NULL
       WHERE id = $1`,
      [binding.exportId, reason, message],
    );
  });
}

export const UNSUPPORTED_FORMAT = (format: number) =>
  `A pending object was planned in format ${format}, which this release cannot upload; finish it with an earlier release or run \`varlatchd admin audit-export discard-plan\``;
export const OBJECT_CONFLICT = "An object with this name exists with other content; nothing was overwritten";

async function planExpired(db: Querier, plan: PlanRow): Promise<boolean> {
  if (!plan.retain_until) return false;
  const res = await db.query("SELECT $1::timestamptz < clock_timestamp() + make_interval(secs => $2) AS expired", [plan.retain_until, AUDIT_EXPORT_LIMITS.expiryMarginSeconds]);
  return (res.rows[0] as { expired: boolean }).expired;
}

/**
 * One export, one lease: up to 20 objects. Returns what happened, for
 * tests. Never throws for a destination's failure.
 */
export async function exportOnce(ctx: AppCtx, exportId: string): Promise<{ committed: number; outcome: "idle" | "lost" | "failed" | "stopped" | "restarted" | "done" | "busy" }> {
  const leased = await takeLease(ctx.db, exportId);
  if (!leased) return { committed: 0, outcome: "busy" };
  const binding = bindingOf(leased);
  let credential: AuditExportCredential;
  try {
    credential = await workerCredential(ctx, leased);
  } catch {
    await recordFailure(ctx, binding, "The export's key could not be read on this installation");
    return { committed: 0, outcome: "failed" };
  }
  const s3 = clientFor(ctx, destinationOf(leased), credential);
  let committed = 0;
  let keyCanRead = leased.key_can_read;
  let outcome: "idle" | "lost" | "failed" | "stopped" | "restarted" | "done" = "done";
  try {
    for (let i = 0; i < AUDIT_EXPORT_LIMITS.objectsPerRun; i++) {
      let plan = await readPlan(ctx.db, exportId);
      if (plan && plan.stream_id !== binding.streamId) {
        outcome = "lost";
        break;
      }
      if (!plan) plan = await planNext(ctx, binding);
      if (!plan) {
        outcome = committed > 0 ? "done" : "idle";
        break;
      }
      if (!UPLOADABLE_FORMATS.has(plan.format_version)) {
        await stopExport(ctx, binding, "unsupported_format", UNSUPPORTED_FORMAT(plan.format_version));
        outcome = "stopped";
        break;
      }
      if (await planExpired(ctx.db, plan)) {
        await restartStream(ctx, exportId, plan.id, "plan_expired");
        outcome = "restarted";
        break;
      }
      const uploaded = await uploadPlan(s3, leased.bucket, plan, keyCanRead);
      if (uploaded.kind === "failed") {
        await recordFailure(ctx, binding, uploaded.message);
        outcome = "failed";
        break;
      }
      if (uploaded.kind === "conflict") {
        await stopExport(ctx, binding, "object_conflict", OBJECT_CONFLICT);
        outcome = "stopped";
        break;
      }
      keyCanRead = uploaded.keyCanRead ?? keyCanRead;
      if (!(await commitPlan(ctx, binding, plan, uploaded.keyCanRead))) {
        outcome = "lost";
        break;
      }
      committed++;
    }
  } catch (err) {
    // A database failure: the plan stays, the next lease holder retries it.
    console.error(`audit export ${exportId} failed:`, err instanceof Error ? err.message : err);
    outcome = "failed";
  } finally {
    s3.destroy();
    await ctx.db.query("UPDATE audit_exports SET lease_expires_at = NULL WHERE id = $1 AND generation = $2", [exportId, binding.generation]).catch(() => {});
  }
  return { committed, outcome };
}

/** One pass: every live export whose lease is free. Never throws. */
export async function runAuditExportsOnce(ctx: AppCtx): Promise<void> {
  const due = (await ctx.db.query(
    `SELECT id FROM audit_exports WHERE state IN ('active', 'draining') AND stopped_reason IS NULL
       AND (lease_expires_at IS NULL OR lease_expires_at < now()) ORDER BY id`,
  )).rows as { id: string }[];
  for (const { id } of due) {
    try {
      await exportOnce(ctx, id);
    } catch (err) {
      console.error(`audit export ${id} failed:`, err instanceof Error ? err.message : err);
    }
  }
}

/** The loop in every `varlatchd serve` process, next to the webhook loop; it pauses for backup maintenance. */
export function startAuditExportLoop(ctx: AppCtx, intervalMs: number = AUDIT_EXPORT_LIMITS.intervalMs): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try {
      await runAuditExportsOnce(ctx);
    } catch (err) {
      console.error("audit export loop error:", err);
    } finally {
      busy = false;
      leave?.();
    }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  void tick();
  return () => clearInterval(timer);
}

// ---------------------------------------------------------------------------
// Stream restarts (Decision 2)

/**
 * Restart the stream after a plan that can no longer be uploaded as
 * planned. One fenced transaction: the plan must still be the pending one
 * (another process may have committed or restarted first: then nothing
 * happens, so the restart is audited once); the generation incremented and
 * the lease cleared; the plan deleted; the committed cursor kept; a new
 * stream with its manifest, which records the dropped batch's range as a
 * possible overlap. Returns whether this call restarted it.
 */
export async function restartStream(
  ctx: AppCtx,
  exportId: string,
  planId: string,
  reason: "plan_expired" | "plan_discarded",
  cause?: "expired" | "unsupported-format",
): Promise<boolean> {
  return withTx(ctx.db, async (tx) => {
    const locked = await lockExport(tx, exportId);
    if (!locked || (locked.state !== "active" && locked.state !== "draining")) return false;
    const plan = await lockPlan(tx, exportId);
    if (!plan || plan.id !== planId) return false;
    if (reason === "plan_expired" && !(await planExpired(tx, plan))) return false;
    await tx.query("DELETE FROM audit_export_plans WHERE id = $1", [plan.id]);
    const streamId = newId("auditExportStream");
    const overlap = plan.kind === "batch" ? { firstOrder: str(plan.first_order), lastOrder: str(plan.last_order) } : null;
    const res = await tx.query(
      `UPDATE audit_exports SET stream_id = $2, stream_started_at = clock_timestamp(), stopped_reason = NULL,
         generation = generation + 1, lease_expires_at = NULL
       WHERE id = $1 RETURNING ${EXPORT_COLUMNS}`,
      [exportId, streamId],
    );
    const updated = res.rows[0] as ExportRow;
    const now = await dbNow(tx);
    await insertPlan(
      tx,
      { exportId, version: updated.version, streamId, generation: str(updated.generation) },
      manifestPlan({
        prefix: updated.prefix, organizationId: updated.organization_id, streamId, startOrder: str(updated.cursor_order),
        previousStreamId: locked.stream_id, reason, cause, possibleOverlap: overlap, plannedAt: now,
      }),
      retentionOf(updated),
      now,
    );
    await recordAuditEvents(tx, [streamStartedEvent(updated.organization_id, exportId, streamId, locked.stream_id, reason, cause, null, null, overlap)]);
    return true;
  });
}

/**
 * `varlatchd admin audit-export discard-plan --export <id> --reason
 * <expired|unsupported-format>`: the host's escape hatch. The same restart,
 * refused when the pending plan is neither expired nor in a format this
 * release cannot upload, so it never skips events.
 */
export async function discardPlan(ctx: AppCtx, exportId: string, reason: "expired" | "unsupported-format"): Promise<{ streamId: string }> {
  const plan = await readPlan(ctx.db, exportId);
  if (!plan) throw new DomainError("RESOURCE_NOT_FOUND", "This audit export has no pending plan");
  if (reason === "expired" && !(await planExpired(ctx.db, plan))) {
    throw new DomainError("VALIDATION_FAILED", "The pending plan's retention has not expired; it can still be uploaded, so it is not discarded");
  }
  if (reason === "unsupported-format" && UPLOADABLE_FORMATS.has(plan.format_version)) {
    throw new DomainError("VALIDATION_FAILED", `The pending plan is in format ${plan.format_version}, which this release uploads; it is not discarded`);
  }
  if (!(await restartStream(ctx, exportId, plan.id, "plan_discarded", reason))) {
    throw new DomainError("STATE_CHANGED", "The pending plan changed meanwhile (committed, or another restart); nothing was discarded");
  }
  const row = (await ctx.db.query("SELECT stream_id FROM audit_exports WHERE id = $1", [exportId])).rows[0] as { stream_id: string };
  return { streamId: row.stream_id };
}

// ---------------------------------------------------------------------------
// Restore (Decision 5)

/**
 * The restore step that records `installation.restored`: in its
 * transaction, every live export gets a new stream at its restored cursor,
 * its generation incremented and its pending plan deleted, and
 * `audit_export.stream_started` (reason `restored`) is recorded after
 * `installation.restored`. The old streams' objects stay at their
 * destinations: they hold events the restore removed, which is evidence.
 */
export async function recordRestore(db: Querier, restored: AuditEventInput): Promise<void> {
  await withTx(db, async (tx) => {
    const rows = (await lockedQuery(
      tx,
      { table: "audit_exports", mode: "update" },
      `SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE state IN ('active', 'draining') ORDER BY id FOR UPDATE`,
    )).rows as ExportRow[];
    const plans = rows.length === 0 ? [] : ((await lockedQuery(
      tx,
      { table: "audit_export_plans", mode: "update" },
      "SELECT id FROM audit_export_plans WHERE export_id = ANY($1) ORDER BY id FOR UPDATE",
      [rows.map((r) => r.id)],
    )).rows as { id: string }[]);
    if (plans.length > 0) await tx.query("DELETE FROM audit_export_plans WHERE id = ANY($1)", [plans.map((p) => p.id)]);
    const events: AuditEventInput[] = [restored];
    const now = rows.length > 0 ? await dbNow(tx) : new Date();
    for (const row of rows) {
      const streamId = newId("auditExportStream");
      const res = await tx.query(
        `UPDATE audit_exports SET stream_id = $2, stream_started_at = clock_timestamp(), stopped_reason = NULL,
           generation = generation + 1, lease_expires_at = NULL
         WHERE id = $1 RETURNING ${EXPORT_COLUMNS}`,
        [row.id, streamId],
      );
      const updated = res.rows[0] as ExportRow;
      await insertPlan(
        tx,
        { exportId: row.id, version: updated.version, streamId, generation: str(updated.generation) },
        manifestPlan({
          prefix: row.prefix, organizationId: row.organization_id, streamId, startOrder: str(row.cursor_order),
          previousStreamId: row.stream_id, reason: "restored", possibleOverlap: null, plannedAt: now,
        }),
        retentionOf(row),
        now,
      );
      events.push(streamStartedEvent(row.organization_id, row.id, streamId, row.stream_id, "restored", undefined, null, null));
    }
    await recordAuditEvents(tx, events);
  });
}

// ---------------------------------------------------------------------------
// Organization deletion (Decision 10)

/**
 * In the finalization transaction, before the Organization KEK is
 * destroyed and before its audit inserts: the live export's key is
 * encrypted again under the Root KEK (purpose audit-export-drain), its
 * state becomes `draining`, its generation is incremented, and a fixed
 * deadline is stored, 30 days from now. Only this key: the Organization KEK
 * is never kept. The pending plan stays; it holds its bytes. Returns the
 * export drained, if any.
 */
export async function rewrapForDrain(ctx: AppCtx, db: Querier, organizationId: string): Promise<string | null> {
  const row = (await lockedQuery(
    db,
    { table: "audit_exports", mode: "update" },
    `SELECT ${EXPORT_COLUMNS} FROM audit_exports WHERE organization_id = $1 AND state = 'active' FOR UPDATE`,
    [organizationId],
  )).rows[0] as ExportRow | undefined;
  if (!row) return null;
  const org = (await db.query("SELECT id, wrapped_org_kek FROM organizations WHERE id = $1", [organizationId])).rows[0] as OrgRow;
  const envelope = envelopeOf(row.credential_envelope) as Envelope;
  const plaintext = decryptAuditExportCredential(orgKekOf(ctx, org), organizationId, row.id, envelope);
  const drained = encryptAuditExportDrainCredential(ctx.rootKek, organizationId, row.id, plaintext);
  await db.query(
    `UPDATE audit_exports SET state = 'draining', credential_envelope = $2,
       drain_deadline = now() + make_interval(days => $3), generation = generation + 1, lease_expires_at = NULL, updated_at = now()
     WHERE id = $1`,
    [row.id, JSON.stringify(drained), AUDIT_EXPORT_LIMITS.drainDays],
  );
  return row.id;
}

/**
 * The drain's bound, in the deletion worker's loop, whatever
 * VARLATCH_AUDIT_EXPORT says: a drain not completed by its deadline loses
 * its key, becomes `abandoned` and records audit_export.abandoned.
 */
export async function abandonExpiredDrains(db: Querier): Promise<string[]> {
  // Found without a transaction or a lock (the partial index on draining
  // rows): an installation without a drain past its deadline opens none.
  const due = await db.query("SELECT 1 FROM audit_exports WHERE state = 'draining' AND drain_deadline <= now() LIMIT 1");
  if (due.rows.length === 0) return [];
  return withTx(db, async (tx) => {
    const rows = (await lockedQuery(
      tx,
      { table: "audit_exports", mode: "update" },
      `SELECT id, organization_id, stream_id, cursor_order, drain_deadline FROM audit_exports
       WHERE state = 'draining' AND drain_deadline <= now() ORDER BY id FOR UPDATE SKIP LOCKED`,
    )).rows as Pick<ExportRow, "id" | "organization_id" | "stream_id" | "cursor_order" | "drain_deadline">[];
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const plans = (await lockedQuery(
      tx,
      { table: "audit_export_plans", mode: "update" },
      "SELECT id FROM audit_export_plans WHERE export_id = ANY($1) ORDER BY id FOR UPDATE",
      [ids],
    )).rows as { id: string }[];
    if (plans.length > 0) await tx.query("DELETE FROM audit_export_plans WHERE id = ANY($1)", [plans.map((p) => p.id)]);
    await tx.query(
      `UPDATE audit_exports SET state = 'abandoned', credential_envelope = NULL, generation = generation + 1, lease_expires_at = NULL, updated_at = now()
       WHERE id = ANY($1)`,
      [ids],
    );
    await recordAuditEvents(tx, rows.map((r): AuditEventInput => ({
      eventType: "audit_export.abandoned",
      decision: "info",
      actorIdentityId: null,
      organizationId: r.organization_id,
      resource: { exportId: r.id },
      metadata: { streamId: r.stream_id, cursor: str(r.cursor_order), drainDeadline: iso(r.drain_deadline) },
    })));
    return ids;
  });
}
