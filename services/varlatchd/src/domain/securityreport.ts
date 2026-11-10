// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Action } from "../authz/evaluate.js";
import { recordAuditEvents, type AuditEventInput } from "../audit/events.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { credentialEvidence } from "./passkeys.js";
import { SECURITY_CONTROLS, type ControlMode, type LifetimeConfig, type SecurityControlName } from "./securitycontrols.js";

/**
 * Report counters (ADR-0054 Decisions 5 and 9). A Security Control in
 * `report` mode refuses and changes nothing: each time it would have
 * refused, asked for an approval or changed an outcome, a counter keyed by
 * (Organization, control, configuration version, semantic operation,
 * actor, reason, hour) goes up by one. A worker turns each hour's rows
 * into `security_control.would_block` audit events once the hour has been
 * over for 10 minutes. Nothing is counted for a control that is `off`, and
 * `enforce` (not offered yet) will refuse instead of counting.
 *
 * What is counted, and when:
 *
 * - A protected write (admin-step-up, requirement-protection,
 *   credential-lifetime) counts in its own transaction with
 *   reportProtectedWrite, so only a write that commits is counted: a
 *   rolled-back attempt, a refused one and one that changed nothing leave
 *   no count. The mode and its version are read in that transaction,
 *   after the operation took the Organization row (lockLiveScope), so a
 *   concurrent control change either committed before or waits.
 * - A retrieval-time check (passkey-verification) is evaluated where the
 *   request enters the Organization (http/organization.ts), against the
 *   mode and version read there, inside a retrieval's snapshot when there
 *   is one, and counted afterwards with countWouldBlockAfter in a separate
 *   short transaction, only when the request succeeded and its person is
 *   still a member: never inside the read-only snapshot, and never for a
 *   refused or failed request.
 *
 * Only fixed fields are stored: the identifiers of the Organization and
 * the actor, the control, its version, the operation and the reason from
 * the lists below, the hour, a count and two times. Never a request body,
 * a URL, a token, a hash or a value, and no target.
 *
 * LOCK ORDER (approvals.ts, step 8). A transaction that counts does all its
 * counter upserts after its own domain rows and before the exposure and
 * integration indexes and its first audit insert, and when it counts
 * several, in key order (countWouldBlock sorts them). The summary worker
 * claims rows FOR UPDATE SKIP LOCKED in key order, so it never waits for a
 * counter, and inserts its audit events after: a transaction holding the
 * audit counter never waits for a counter row, so the two cannot deadlock.
 *
 * LATE INCREMENTS. An increment upserts its bucket, the hour the attempt
 * was decided in (the transaction's start, or the decision time for a
 * retrieval), with ON CONFLICT ... DO UPDATE ... WHERE emitted_at IS NULL.
 * When the worker already emitted that bucket, the upsert inserts and
 * updates nothing and the increment goes to the bucket of the current
 * hour (clock_timestamp()), which the worker cannot have emitted yet.
 * Under READ COMMITTED an upsert that waited for the worker re-checks
 * emitted_at against the committed row and falls back; under SERIALIZABLE
 * (withSerializableTx) PostgreSQL fails it with 40001 and the whole
 * mutation, increment included, runs again. Every committed increment
 * reaches exactly one summary.
 */

/** admin-step-up's operations (Decision 5), by semantic name. */
export const ADMIN_STEP_UP_OPERATIONS = [
  "identity.create",
  "credential.issue",
  "identity.reactivate",
  "oidc_binding.create",
  "oidc_binding.delete",
  "grant.create",
  "grant.replace",
  "grant.revoke",
  "role.create",
  "role.update",
  "role.delete",
  "group.create",
  "group.update",
  "group.delete",
  "group.member_add",
  "group.member_remove",
  "team.create",
  "team.update",
  "team.delete",
  "team.member_add",
  "team.member_remove",
  "team.project_add",
  "team.project_remove",
  "member.invite_admin",
  "member.promote",
  "member.demote",
  "member.remove",
  "webhook.create",
  "webhook.update",
  "webhook.delete",
  "connection.create",
  "connection.replace_credential",
  "connection.delete",
  "github_app.register",
  "github_app.import",
  "github_app.replace_key",
  "github_app.remove",
  "project.delete",
  "organization.delete",
  "secret.export",
] as const;
export type AdminStepUpOperation = (typeof ADMIN_STEP_UP_OPERATIONS)[number];

export const REQUIREMENT_PROTECTION_OPERATIONS = ["requirement.update", "requirement.revoke"] as const;
export type RequirementProtectionOperation = (typeof REQUIREMENT_PROTECTION_OPERATIONS)[number];

/** credential-lifetime applies to machine-credential issuance (Decision 5); OIDC and agent-run keep their own caps. */
export const CREDENTIAL_LIFETIME_OPERATIONS = ["identity.create", "credential.issue"] as const;
export type CredentialLifetimeOperation = (typeof CREDENTIAL_LIFETIME_OPERATIONS)[number];

/**
 * passkey-verification's operations: the first action the request was
 * authorized for in the Organization, `organization.access` for a request
 * that succeeded without an action of the evaluator, and `convex.token`
 * for each Organization in an Application Plane token.
 */
export type PasskeyVerificationOperation = Action | "organization.access" | "convex.token";

export type ReportOperation =
  | AdminStepUpOperation
  | RequirementProtectionOperation
  | CredentialLifetimeOperation
  | PasskeyVerificationOperation;

export const REPORT_REASONS = [
  // admin-step-up and requirement-protection: done without an approval, by
  // a person, or by a machine credential, which can never pass one.
  "no-approval",
  "machine-credential",
  // passkey-verification: the credential carries no sign-in evidence (a
  // sign-in from before the upgrade), the authenticator did not verify the
  // person, or the passkey that signed in is not (or no longer) trusted.
  "no-evidence",
  "not-user-verified",
  "untrusted-passkey",
  // credential-lifetime: no TTL given (would get the default), or a TTL
  // above the maximum (would be refused).
  "would-default",
  "would-refuse",
] as const;
export type ReportReason = (typeof REPORT_REASONS)[number];

/** One attempt a control would have refused or changed. */
export interface WouldBlock {
  control: SecurityControlName;
  /** The control's version when the attempt was decided. */
  configVersion: number;
  operation: ReportOperation;
  actorIdentityId: string;
  reason: ReportReason;
}

/** A control in report mode, as a decision read it. */
export interface ReportingControl {
  version: number;
  config: LifetimeConfig | null;
}

/**
 * The Organization's controls in `report` mode, with their versions and
 * configuration, read in `db` (the operation's transaction or snapshot).
 * Empty when every control is off, which is all most operations pay.
 */
export async function reportingControls(db: Querier, organizationId: string): Promise<Map<SecurityControlName, ReportingControl>> {
  const rows = (await db.query(
    "SELECT control, version, config FROM security_controls WHERE organization_id = $1 AND mode = $2",
    [organizationId, "report" satisfies ControlMode],
  )).rows as { control: SecurityControlName; version: number; config: LifetimeConfig | string | null }[];
  return new Map(rows.map((r) => {
    const config = typeof r.config === "string" ? (JSON.parse(r.config) as LifetimeConfig) : r.config;
    return [r.control, {
      version: r.version,
      config: config ? { defaultTtlSeconds: Number(config.defaultTtlSeconds), maxTtlSeconds: Number(config.maxTtlSeconds) } : null,
    }];
  }));
}

const keyOf = (organizationId: string, a: WouldBlock) =>
  [organizationId, a.control, String(a.configVersion).padStart(10, "0"), a.operation, a.actorIdentityId, a.reason];

function compareKeys(a: string[], b: string[]): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return 0;
}

const UPSERT = (bucket: string) => `
  INSERT INTO security_control_counters AS c
    (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen)
  VALUES ($1, $2, $3, $4, $5, $6, date_trunc('hour', ${bucket}, 'UTC'), $7, clock_timestamp(), clock_timestamp())
  ON CONFLICT (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour)
  DO UPDATE SET count = c.count + EXCLUDED.count, last_seen = greatest(c.last_seen, EXCLUDED.last_seen)
  WHERE c.emitted_at IS NULL
  RETURNING bucket_hour`;

/**
 * Count `attempts` in `db`, which must be the counting operation's own
 * transaction: after its domain rows, before the indexes and its first
 * audit insert (see the lock order above). Equal attempts add up; buckets
 * are upserted in key order. `at` is when the attempts were decided,
 * the transaction's start by default.
 */
export async function countWouldBlock(
  db: Querier,
  organizationId: string,
  attempts: readonly WouldBlock[],
  opts: { at?: Date | undefined } = {},
): Promise<void> {
  if (attempts.length === 0) return;
  const merged = new Map<string, { key: string[]; attempt: WouldBlock; count: number }>();
  for (const attempt of attempts) {
    if (!(REPORT_REASONS as readonly string[]).includes(attempt.reason)) throw new Error(`Unknown report reason ${attempt.reason}`);
    const key = keyOf(organizationId, attempt);
    const id = key.join("\u0000");
    const entry = merged.get(id);
    if (entry) entry.count += 1;
    else merged.set(id, { key, attempt, count: 1 });
  }
  const ordered = [...merged.values()].sort((a, b) => compareKeys(a.key, b.key));
  for (const { attempt, count } of ordered) {
    const params = [organizationId, attempt.control, attempt.configVersion, attempt.operation, attempt.actorIdentityId, attempt.reason, count];
    const target = await db.query(
      UPSERT(opts.at ? `$8::timestamptz` : "now()"),
      opts.at ? [...params, opts.at.toISOString()] : params,
    );
    if (target.rows[0]) continue;
    // The bucket was already emitted: count in the current hour's instead.
    const current = await db.query(UPSERT("clock_timestamp()"), params);
    if (!current.rows[0]) {
      // The current hour cannot have been emitted (the worker waits until
      // ten minutes after an hour ends). Losing a count must never change
      // the operation's outcome, so this only says so.
      console.error(`security report: the current hour's ${attempt.control} counter was already summarized; one count dropped`);
    }
  }
}

/**
 * A protected write's checks, evaluated against the controls in report
 * mode in the write's own transaction and counted there. Call it after
 * the operation's own rows and before its indexes and first audit insert.
 */
export type ProtectedCheck =
  | { control: "admin-step-up"; operation: AdminStepUpOperation }
  | { control: "requirement-protection"; operation: RequirementProtectionOperation }
  /** ttlSeconds as requested: undefined when none was given. */
  | { control: "credential-lifetime"; operation: CredentialLifetimeOperation; ttlSeconds: number | undefined };

export async function reportProtectedWrite(
  db: Querier,
  input: { organizationId: string; actorIdentityId: string; checks: readonly ProtectedCheck[] },
): Promise<WouldBlock[]> {
  const reporting = await reportingControls(db, input.organizationId);
  if (reporting.size === 0) return [];
  const attempts: WouldBlock[] = [];
  let approvalReason: ReportReason | undefined;
  for (const check of input.checks) {
    const control = reporting.get(check.control);
    if (!control) continue;
    let reason: ReportReason | null;
    if (check.control === "credential-lifetime") {
      reason = lifetimeReason(control.config, check.ttlSeconds);
    } else {
      // No operation of Decision 5 accepts an approval yet, so each one is
      // done without one. A machine credential can never pass an approval:
      // it is told apart, as enforce will refuse it outright.
      approvalReason ??= await actorKind(db, input.actorIdentityId) === "human" ? "no-approval" : "machine-credential";
      reason = approvalReason;
    }
    if (reason) attempts.push({ control: check.control, configVersion: control.version, operation: check.operation, actorIdentityId: input.actorIdentityId, reason });
  }
  await countWouldBlock(db, input.organizationId, attempts);
  return attempts;
}

/** What credential-lifetime would have done with a requested TTL: default it, refuse it, or nothing. */
export function lifetimeReason(config: LifetimeConfig | null, ttlSeconds: number | undefined): ReportReason | null {
  if (!config) return null;
  if (ttlSeconds === undefined) return "would-default";
  return ttlSeconds > config.maxTtlSeconds ? "would-refuse" : null;
}

async function actorKind(db: Querier, identityId: string): Promise<string | null> {
  const row = (await db.query("SELECT kind FROM identities WHERE id = $1", [identityId])).rows[0] as { kind: string } | undefined;
  return row?.kind ?? null;
}

/** Who is entering an Organization: the requesting credential and its identity. */
export interface EntryRequester {
  identityId: string;
  identityKind: string;
  credentialId: string;
  credentialKind: string;
}

/** A passkey-verification attempt decided at entry, counted once the request succeeded. */
export interface PendingAccessReport {
  organizationId: string;
  actorIdentityId: string;
  configVersion: number;
  reason: ReportReason;
  /** When it was decided: the snapshot's time for a retrieval. */
  at: Date;
}

/**
 * passkey-verification for one request entering these Organizations
 * (Decision 7): for a human credential (browser or cli) whose sign-in
 * evidence lacks user verification or comes from a passkey that is not
 * trusted now, one pending report per Organization whose control is in
 * report mode. Machine credentials are exempt by kind and read nothing.
 * Reads only, so it can run inside a retrieval's snapshot.
 */
export async function passkeyVerificationReports(
  db: Querier,
  requester: EntryRequester,
  organizationIds: readonly string[],
): Promise<PendingAccessReport[]> {
  if (requester.identityKind !== "human" || (requester.credentialKind !== "browser" && requester.credentialKind !== "cli")) return [];
  if (organizationIds.length === 0) return [];
  const reporting = (await db.query(
    `SELECT organization_id, version, now() AS at FROM security_controls
     WHERE organization_id = ANY($1) AND control = 'passkey-verification' AND mode = 'report'
     ORDER BY organization_id`,
    [[...organizationIds]],
  )).rows as { organization_id: string; version: number; at: Date | string }[];
  if (reporting.length === 0) return [];
  const evidence = await credentialEvidence(db, requester.credentialId);
  const reason: ReportReason | null = !evidence
    ? "no-evidence"
    : !evidence.userVerified
      ? "not-user-verified"
      : !evidence.passkeyTrusted
        ? "untrusted-passkey"
        : null;
  if (!reason) return [];
  return reporting.map((r) => ({
    organizationId: r.organization_id,
    actorIdentityId: requester.identityId,
    configVersion: r.version,
    reason,
    at: new Date(r.at),
  }));
}

/**
 * Count a retrieval-time attempt after the decision, in a short
 * transaction of its own, never inside a retrieval's snapshot: only while
 * the Organization is live (its row FOR KEY SHARE, lock step 1, before the
 * counter) and the person still holds a live membership, so neither an
 * outsider nor a removed member is ever counted. Failing to count never
 * fails the request.
 */
export async function countWouldBlockAfter(
  ctx: AppCtx,
  report: PendingAccessReport,
  operation: PasskeyVerificationOperation,
): Promise<boolean> {
  try {
    return await withTx(ctx.db, async (db) => {
      const live = await db.query("SELECT 1 FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR KEY SHARE", [report.organizationId]);
      if (!live.rows[0]) return false;
      const member = await db.query(
        "SELECT 1 FROM org_memberships WHERE organization_id = $1 AND identity_id = $2 AND removed_at IS NULL",
        [report.organizationId, report.actorIdentityId],
      );
      if (!member.rows[0]) return false;
      await countWouldBlock(db, report.organizationId, [{
        control: "passkey-verification",
        configVersion: report.configVersion,
        operation,
        actorIdentityId: report.actorIdentityId,
        reason: report.reason,
      }], { at: report.at });
      return true;
    });
  } catch (err) {
    console.error("security report: a passkey-verification count failed:", err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Closing buckets: the summary worker.

export const SECURITY_REPORT = {
  /** A bucket is summarized once its hour has been over this long. */
  closeAfterMinutes: 10,
  /** Counter rows are deleted this long after their summary. */
  retentionDays: 35,
  /** Rows per worker transaction. */
  batch: 200,
  /** The worker's transaction-level advisory lock: one emitting process at a time. */
  workerLock: 7330035,
} as const;

interface CounterRow {
  organization_id: string;
  control: SecurityControlName;
  config_version: number;
  operation: string;
  actor_identity_id: string;
  reason: ReportReason;
  bucket_hour: Date | string;
  count: string | number;
  first_seen: Date | string;
  last_seen: Date | string;
}

const iso = (v: Date | string) => new Date(v).toISOString();

/**
 * One worker pass: in one transaction, claim up to `batch` unemitted rows
 * whose hour ended at least ten minutes ago, FOR UPDATE SKIP LOCKED in key
 * order, mark them emitted, and write one immutable
 * `security_control.would_block` event per row. Several workers, or a
 * worker that died before committing, produce each summary once. Returns
 * how many it emitted.
 *
 * `exclusive` (the daemon's loop) first takes a transaction-level advisory
 * lock and does nothing when another process holds it. `onClaimed` is a
 * test hook that runs while the rows are held, before the audit insert.
 */
export async function emitDueSummaries(
  ctx: AppCtx,
  opts: { batch?: number; exclusive?: boolean; onClaimed?: (rows: number) => Promise<void> } = {},
): Promise<number> {
  return withTx(ctx.db, async (db) => {
    if (opts.exclusive) {
      const held = (await db.query("SELECT pg_try_advisory_xact_lock($1) AS held", [SECURITY_REPORT.workerLock])).rows[0] as { held: boolean };
      if (!held.held) return 0;
    }
    const claimed = (await db.query(
      `SELECT organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen
       FROM security_control_counters
       WHERE emitted_at IS NULL AND bucket_hour <= clock_timestamp() - make_interval(hours => 1, mins => $1)
       ORDER BY organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour
       LIMIT $2
       FOR UPDATE SKIP LOCKED`,
      [SECURITY_REPORT.closeAfterMinutes, opts.batch ?? SECURITY_REPORT.batch],
    )).rows as CounterRow[];
    if (claimed.length === 0) return 0;
    await opts.onClaimed?.(claimed.length);
    for (const r of claimed) {
      await db.query(
        `UPDATE security_control_counters SET emitted_at = clock_timestamp()
         WHERE organization_id = $1 AND control = $2 AND config_version = $3 AND operation = $4
           AND actor_identity_id = $5 AND reason = $6 AND bucket_hour = $7`,
        [r.organization_id, r.control, r.config_version, r.operation, r.actor_identity_id, r.reason, r.bucket_hour],
      );
    }
    // Audit last, after every counter row is held (the lock order above).
    await recordAuditEvents(db, claimed.map((r): AuditEventInput => ({
      eventType: "security_control.would_block",
      decision: "info",
      // The actor whose attempts these are; no credential, client or
      // listener: a summary is not a request.
      actorIdentityId: r.actor_identity_id,
      credentialId: null,
      client: null,
      listener: null,
      tailnet: null,
      organizationId: r.organization_id,
      resource: { control: r.control },
      metadata: {
        control: r.control,
        configVersion: r.config_version,
        operation: r.operation,
        reason: r.reason,
        bucketHour: iso(r.bucket_hour),
        count: Number(r.count),
        firstSeen: iso(r.first_seen),
        lastSeen: iso(r.last_seen),
      },
    })));
    return claimed.length;
  });
}

/** Retention: delete counter rows 35 days after their summary, a batch at a time. */
export async function deleteExpiredCounters(ctx: AppCtx, batch = 1000): Promise<number> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      `DELETE FROM security_control_counters c
       USING (
         SELECT organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour
         FROM security_control_counters
         WHERE emitted_at IS NOT NULL AND emitted_at <= clock_timestamp() - make_interval(days => $1)
         ORDER BY organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour
         LIMIT $2
         FOR UPDATE SKIP LOCKED
       ) d
       WHERE c.organization_id = d.organization_id AND c.control = d.control AND c.config_version = d.config_version
         AND c.operation = d.operation AND c.actor_identity_id = d.actor_identity_id AND c.reason = d.reason
         AND c.bucket_hour = d.bucket_hour
       RETURNING 1`,
      [SECURITY_REPORT.retentionDays, batch],
    );
    return res.rows.length;
  });
}

/** One run of the loop: emit every due summary, then apply retention. */
export async function runSecurityReportWorker(ctx: AppCtx): Promise<{ emitted: number; deleted: number }> {
  let emitted = 0;
  for (;;) {
    const n = await emitDueSummaries(ctx, { exclusive: true });
    emitted += n;
    if (n < SECURITY_REPORT.batch) break;
  }
  let deleted = 0;
  for (;;) {
    const n = await deleteExpiredCounters(ctx);
    deleted += n;
    if (n < 1000) break;
  }
  return { emitted, deleted };
}

/**
 * The daemon's summary loop, like the other periodic workers: one pass at
 * a time in this process, none during installation maintenance, and the
 * advisory lock keeps other processes from emitting at the same time.
 */
export function startSecurityReportLoop(ctx: AppCtx, intervalMs = 60_000): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try {
      await runSecurityReportWorker(ctx);
    } catch (err) {
      console.error("security report loop error:", err);
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
// Reading the counts (GET /v1/organizations/:org/security/control-report).

export interface ReportEntry {
  configVersion: number;
  operation: string;
  reason: ReportReason;
  actor: { id: string; name: string | null; kind: string | null };
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface ControlReport {
  control: SecurityControlName;
  mode: ControlMode;
  version: number;
  /** Every count in the window. */
  total: number;
  /** Counted in the current hour. */
  currentHour: number;
  /** Counted but not summarized in the audit log yet. */
  pending: number;
  entries: ReportEntry[];
}

export interface SecurityControlReport {
  organizationId: string;
  days: number;
  since: string;
  generatedAt: string;
  summaryDelayMinutes: number;
  controls: ControlReport[];
}

/**
 * The counts of the last `days` days (1 to 30), per control, with the
 * current hour's live counters and what is not yet summarized, and per
 * configuration version, operation, reason and actor. Read from the
 * counter rows, which outlive their summaries by 35 days, so the window
 * holds the same counts the audit summaries carry.
 */
export async function securityControlReport(db: Querier, organizationId: string, days: number): Promise<SecurityControlReport> {
  if (!Number.isInteger(days) || days < 1 || days > 30) throw new DomainError("VALIDATION_FAILED", "days must be an integer in 1..30");
  const window = (await db.query(
    "SELECT clock_timestamp() AS now, date_trunc('hour', clock_timestamp() - make_interval(days => $1), 'UTC') AS since, date_trunc('hour', clock_timestamp(), 'UTC') AS hour",
    [days],
  )).rows[0] as { now: Date | string; since: Date | string; hour: Date | string };
  const rows = (await db.query(
    `SELECT c.control, c.config_version, c.operation, c.reason, c.actor_identity_id, i.name AS actor_name, i.kind AS actor_kind,
            sum(c.count)::bigint AS count,
            sum(c.count) FILTER (WHERE c.bucket_hour = $3)::bigint AS current_hour,
            sum(c.count) FILTER (WHERE c.emitted_at IS NULL)::bigint AS pending,
            min(c.first_seen) AS first_seen, max(c.last_seen) AS last_seen
     FROM security_control_counters c LEFT JOIN identities i ON i.id = c.actor_identity_id
     WHERE c.organization_id = $1 AND c.bucket_hour >= $2
     GROUP BY c.control, c.config_version, c.operation, c.reason, c.actor_identity_id, i.name, i.kind
     ORDER BY count DESC, c.control, c.operation, c.reason, c.actor_identity_id, c.config_version`,
    [organizationId, window.since, window.hour],
  )).rows as {
    control: SecurityControlName; config_version: number; operation: string; reason: ReportReason; actor_identity_id: string;
    actor_name: string | null; actor_kind: string | null; count: string | number; current_hour: string | number | null;
    pending: string | number | null; first_seen: Date | string; last_seen: Date | string;
  }[];
  const states = (await db.query(
    "SELECT control, mode, version FROM security_controls WHERE organization_id = $1",
    [organizationId],
  )).rows as { control: SecurityControlName; mode: ControlMode; version: number }[];
  return {
    organizationId,
    days,
    since: iso(window.since),
    generatedAt: iso(window.now),
    summaryDelayMinutes: SECURITY_REPORT.closeAfterMinutes,
    controls: SECURITY_CONTROLS.map((control) => {
      const state = states.find((s) => s.control === control);
      const mine = rows.filter((r) => r.control === control);
      const sum = (pick: (r: (typeof rows)[number]) => string | number | null) => mine.reduce((n, r) => n + Number(pick(r) ?? 0), 0);
      return {
        control,
        mode: state?.mode ?? "off",
        version: state?.version ?? 0,
        total: sum((r) => r.count),
        currentHour: sum((r) => r.current_hour),
        pending: sum((r) => r.pending),
        entries: mine.map((r) => ({
          configVersion: r.config_version,
          operation: r.operation,
          reason: r.reason,
          actor: { id: r.actor_identity_id, name: r.actor_name, kind: r.actor_kind },
          count: Number(r.count),
          firstSeen: iso(r.first_seen),
          lastSeen: iso(r.last_seen),
        })),
      };
    }),
  };
}

/** reportProtectedWrite for one admin-step-up operation (Decision 5's list). */
export function reportAdminStepUp(
  db: Querier,
  organizationId: string,
  actorIdentityId: string,
  operation: AdminStepUpOperation,
): Promise<WouldBlock[]> {
  return reportProtectedWrite(db, { organizationId, actorIdentityId, checks: [{ control: "admin-step-up", operation }] });
}
