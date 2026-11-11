// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { ApprovalChange, ApprovalGate, UsedApproval } from "./approvals.js";
import { closeOpenApprovals } from "./approvals.js";
import { lockPerson } from "./personlocks.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { lockLiveScope } from "./liveness.js";

/**
 * Security Controls (ADR-0054 Decisions 1, 2 and 10): per Organization,
 * each `off`, `report` or `enforce`, with a version. A missing row is
 * `off` at version 0; rows are never deleted.
 *
 * Changing one needs organization.manage and a person's credential
 * (checked by the caller and again here, inside the transaction). A change
 * is compared field by field with the current state: it is loosening when
 * the mode moves towards off, a lifetime grows, or configuration is
 * cleared, even alongside tightening, and loosening needs a step-up
 * approval bound to that exact change (approvals.ts). Tightening needs
 * none.
 *
 * Concurrency: a change locks the Organization row FOR UPDATE and checks
 * the expected version. Every transaction here follows the lock order
 * written down at the top of liveness.ts (Organization, person, intent,
 * session, credential, then security_controls and audit). A protected operation takes the Organization row
 * FOR KEY SHARE (lockLiveScope's default for writes) and reads the mode
 * with controlMode inside its own transaction, after that lock, so a
 * protected write either commits before a control change or sees the new
 * mode.
 *
 * `enforce` is refused with CONTROL_MODE_UNAVAILABLE until the enforcement
 * step ships. What `report` counts, where and when: securityreport.ts.
 */

export const SECURITY_CONTROLS = ["requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"] as const;
export type SecurityControlName = (typeof SECURITY_CONTROLS)[number];
export type ControlMode = "off" | "report" | "enforce";
/** The modes a change may set in this release. */
export const AVAILABLE_MODES: readonly ControlMode[] = ["off", "report"];

const MODE_RANK: Record<ControlMode, number> = { off: 0, report: 1, enforce: 2 };

export interface LifetimeConfig {
  defaultTtlSeconds: number;
  maxTtlSeconds: number;
}

export interface ControlState {
  control: SecurityControlName;
  mode: ControlMode;
  config: LifetimeConfig | null;
  version: number;
  changedAt: string | null;
  changedBy: { id: string; name: string | null } | null;
}

interface ControlRow {
  control: SecurityControlName;
  mode: ControlMode;
  config: LifetimeConfig | string | null;
  version: number;
  changed_at: Date | string;
  changed_by: string | null;
  changed_by_name: string | null;
}

function toState(r: ControlRow): ControlState {
  const config = typeof r.config === "string" ? (JSON.parse(r.config) as LifetimeConfig) : r.config;
  return {
    control: r.control,
    mode: r.mode,
    config: config ? { defaultTtlSeconds: Number(config.defaultTtlSeconds), maxTtlSeconds: Number(config.maxTtlSeconds) } : null,
    version: r.version,
    changedAt: new Date(r.changed_at).toISOString(),
    changedBy: r.changed_by ? { id: r.changed_by, name: r.changed_by_name } : null,
  };
}

const offState = (control: SecurityControlName): ControlState => ({
  control, mode: "off", config: null, version: 0, changedAt: null, changedBy: null,
});

const CONTROLS_OF = `
  SELECT s.control, s.mode, s.config, s.version, s.changed_at, s.changed_by, i.name AS changed_by_name
  FROM security_controls s LEFT JOIN identities i ON i.id = s.changed_by
  WHERE s.organization_id = $1`;

/** Every control of the Organization, in SECURITY_CONTROLS order; missing ones off at version 0. */
export async function listControls(db: Querier, organizationId: string): Promise<ControlState[]> {
  const rows = (await db.query(CONTROLS_OF, [organizationId])).rows as ControlRow[];
  return SECURITY_CONTROLS.map((control) => {
    const row = rows.find((r) => r.control === control);
    return row ? toState(row) : offState(control);
  });
}

async function readControl(db: Querier, organizationId: string, control: SecurityControlName): Promise<ControlState> {
  const row = (await db.query(`${CONTROLS_OF} AND s.control = $2`, [organizationId, control])).rows[0] as ControlRow | undefined;
  return row ? toState(row) : offState(control);
}

/**
 * The control's mode for a protected operation: call it inside the
 * operation's transaction, after lockLiveScope took the Organization row,
 * so a concurrent change either committed before or waits for it.
 */
export async function controlMode(db: Querier, organizationId: string, control: SecurityControlName): Promise<ControlMode> {
  const row = (await db.query(
    "SELECT mode FROM security_controls WHERE organization_id = $1 AND control = $2",
    [organizationId, control],
  )).rows[0] as { mode: ControlMode } | undefined;
  return row?.mode ?? "off";
}

const describeConfig = (value: number | undefined) => (value === undefined ? null : String(value));

/**
 * Compare a change field by field: what changes, and which of those
 * changes weaken the control. The mode moving towards off, a lifetime
 * growing, and configuration being cleared all loosen; setting a lifetime
 * where there was none, or shrinking one, tightens.
 */
export function classifyChange(
  before: { mode: ControlMode; config: LifetimeConfig | null },
  after: { mode: ControlMode; config: LifetimeConfig | null },
): { changes: ApprovalChange[]; loosened: string[] } {
  const changes: ApprovalChange[] = [];
  if (before.mode !== after.mode) {
    changes.push({ field: "mode", from: before.mode, to: after.mode, loosens: MODE_RANK[after.mode] < MODE_RANK[before.mode] });
  }
  for (const field of ["defaultTtlSeconds", "maxTtlSeconds"] as const) {
    const from = before.config?.[field];
    const to = after.config?.[field];
    if (from === to) continue;
    // Cleared (a bound removed) or grown loosens; newly set or shrunk tightens.
    const loosens = from !== undefined && (to === undefined || to > from);
    changes.push({ field, from: describeConfig(from), to: describeConfig(to), loosens });
  }
  return { changes, loosened: changes.filter((c) => c.loosens).map((c) => c.field) };
}

const sameConfig = (a: LifetimeConfig | null, b: LifetimeConfig | null) =>
  a === b || (a !== null && b !== null && a.defaultTtlSeconds === b.defaultTtlSeconds && a.maxTtlSeconds === b.maxTtlSeconds);

/** A control's state as flat audit metadata (audit metadata holds scalars only). */
function stateMetadata(prefix: "from" | "to", state: Pick<ControlState, "mode" | "config" | "version">) {
  return {
    [`${prefix}Mode`]: state.mode,
    [`${prefix}Version`]: state.version,
    [`${prefix}DefaultTtlSeconds`]: state.config?.defaultTtlSeconds ?? null,
    [`${prefix}MaxTtlSeconds`]: state.config?.maxTtlSeconds ?? null,
  } as Record<string, string | number | null>;
}

export function controlModeUnavailable(control: SecurityControlName, mode: ControlMode): DomainError {
  return new DomainError(
    "CONTROL_MODE_UNAVAILABLE",
    `This server does not offer ${mode} yet: a control can be off or report`,
    { control, mode, availableModes: [...AVAILABLE_MODES] },
  );
}

export interface ControlChange {
  control: ControlState;
  changed: boolean;
  loosened: boolean;
}

/**
 * Change one control. In one transaction: lock the Organization FOR
 * UPDATE (refused while it is being deleted), recheck the requester's
 * authorization (`authorizeIn`, against this transaction), compare
 * expectedVersion with the current version, classify the change, and for
 * a loosening one consume the approval bound to exactly this change (or
 * throw ApprovalNeeded through the gate). Then write the new state with
 * the next version and record `security_control.changed`. A request that
 * changes nothing records nothing and needs no approval.
 */
export async function changeControl(
  ctx: AppCtx,
  gate: ApprovalGate,
  input: {
    organizationId: string;
    control: SecurityControlName;
    mode?: ControlMode | undefined;
    /** undefined keeps the configuration; null clears it. */
    config?: LifetimeConfig | null | undefined;
    expectedVersion: number;
    actorIdentityId: string;
    requestId: string;
    authorizeIn: (db: Querier) => Promise<void>;
  },
): Promise<ControlChange> {
  if (input.mode === "enforce") throw controlModeUnavailable(input.control, input.mode);
  if (input.config && input.control !== "credential-lifetime") {
    throw new DomainError("VALIDATION_FAILED", `config: ${input.control} has no configuration`);
  }
  if (input.config && !(input.config.defaultTtlSeconds > 0 && input.config.defaultTtlSeconds <= input.config.maxTtlSeconds)) {
    throw new DomainError("VALIDATION_FAILED", "config: 0 < defaultTtlSeconds <= maxTtlSeconds");
  }
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId: input.organizationId, organizationMode: "update", people: [] });
    await input.authorizeIn(db);
    const current = await readControl(db, input.organizationId, input.control);
    if (current.version !== input.expectedVersion) {
      throw new DomainError(
        "VERSION_CONFLICT",
        `${input.control} is at version ${current.version}, not ${input.expectedVersion}: it changed meanwhile. Read it again`,
        { currentVersion: current.version },
      );
    }
    const next = {
      mode: input.mode ?? current.mode,
      config: input.config === undefined ? current.config : input.config,
    };
    if (input.control === "credential-lifetime" && next.mode !== "off" && next.config === null) {
      throw new DomainError("VALIDATION_FAILED", "config: credential-lifetime needs defaultTtlSeconds and maxTtlSeconds unless it is off");
    }
    if (next.mode === current.mode && sameConfig(next.config, current.config)) {
      return { control: current, changed: false, loosened: false };
    }
    const { changes, loosened } = classifyChange(current, next);
    // Step 2 of the lock order (liveness.ts), before changed_by's foreign
    // key references the person: FOR UPDATE when loosening consumes the
    // person's approval (consumption takes no person lock of its own), FOR
    // KEY SHARE otherwise.
    await lockPerson(db, input.actorIdentityId, loosened.length > 0 ? "update" : "key share");
    let approval: UsedApproval | null = null;
    if (loosened.length > 0) {
      const org = (await db.query("SELECT name FROM organizations WHERE id = $1", [input.organizationId])).rows[0] as { name: string };
      approval = await gate.require(db, {
        operation: "security_control.change",
        organizationId: input.organizationId,
        target: { control: input.control },
        // The normalized request: the state it asks for, and the version it expects.
        body: { mode: next.mode, config: next.config, expectedVersion: input.expectedVersion },
        query: {},
        expectedVersion: input.expectedVersion,
        summary: {
          title: next.mode === "off" && current.mode !== "off"
            ? `Turn off the ${input.control} security control of ${org.name}`
            : `Loosen the ${input.control} security control of ${org.name}`,
          changes,
        },
      });
    }
    await db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, clock_timestamp())
       ON CONFLICT (organization_id, control) DO UPDATE
         SET mode = EXCLUDED.mode, config = EXCLUDED.config, version = EXCLUDED.version,
             changed_by = EXCLUDED.changed_by, changed_at = EXCLUDED.changed_at`,
      [input.organizationId, input.control, next.mode, next.config ? JSON.stringify(next.config) : null, current.version + 1,
        input.actorIdentityId],
    );
    const updated = await readControl(db, input.organizationId, input.control);
    await recordAuditEvent(db, {
      eventType: "security_control.changed",
      decision: "info",
      actorIdentityId: input.actorIdentityId,
      organizationId: input.organizationId,
      action: "organization.manage",
      requestId: input.requestId,
      resource: { control: input.control },
      metadata: {
        control: input.control,
        ...stateMetadata("from", current),
        ...stateMetadata("to", updated),
        loosened: loosened.length > 0,
        // The fields that weakened the control, comma-separated; empty for tightening.
        loosenedFields: loosened.join(","),
        approvalId: approval?.id ?? null,
        ...(approval ? { approvalPasskeyId: approval.passkeyId, approvalUserVerified: approval.userVerified } : {}),
      },
    });
    return { control: updated, changed: true, loosened: loosened.length > 0 };
  });
}

export interface ResetOutcome {
  organization: { id: string; slug: string };
  reset: { control: SecurityControlName; from: ControlMode; version: number }[];
  approvalsClosed: number;
}

/**
 * The host operator's reset (ADR-0054 Decision 10): set the named controls
 * to off, close their open approvals, and record `security_control.reset`
 * for each. No API reaches it. It works while the Organization is being
 * deleted and never touches the deletion, suspended identities, passkeys
 * or Grants. A control already off keeps its row and version; its open
 * approvals are still closed.
 */
export async function resetControls(
  ctx: AppCtx,
  input: { organization: string; controls: readonly SecurityControlName[] | "all" },
): Promise<ResetOutcome> {
  const controls = input.controls === "all" ? [...SECURITY_CONTROLS] : SECURITY_CONTROLS.filter((c) => input.controls.includes(c));
  if (controls.length === 0) throw new DomainError("VALIDATION_FAILED", "Name at least one control, or all");
  return withTx(ctx.db, async (db) => {
    const org = (await db.query(
      "SELECT id, slug FROM organizations WHERE (id = $1 OR slug = $1) AND deleted_at IS NULL",
      [input.organization],
    )).rows[0] as { id: string; slug: string } | undefined;
    if (!org) throw new DomainError("RESOURCE_NOT_FOUND", `No live Organization ${input.organization}`);
    await lockLiveScope(db, { organizationId: org.id, organizationMode: "update", allowFrozen: true, people: [] });
    const reset: ResetOutcome["reset"] = [];
    const events = [];
    const approvalsClosed = await closeOpenApprovals(db, { organizationId: org.id, reason: "reset", controls });
    for (const control of controls) {
      const current = await readControl(db, org.id, control);
      let version = current.version;
      if (current.mode !== "off") {
        version = current.version + 1;
        await db.query(
          `UPDATE security_controls SET mode = 'off', version = $3, changed_by = NULL, changed_at = clock_timestamp()
           WHERE organization_id = $1 AND control = $2`,
          [org.id, control, version],
        );
      }
      reset.push({ control, from: current.mode, version });
      events.push({ control, current, version });
    }
    for (const e of events) {
      await recordAuditEvent(db, {
        eventType: "security_control.reset",
        decision: "info",
        actorIdentityId: null,
        organizationId: org.id,
        resource: { control: e.control },
        metadata: {
          control: e.control,
          operator: true,
          ...stateMetadata("from", e.current),
          ...stateMetadata("to", { ...e.current, mode: "off", version: e.version }),
          // Every open approval of the reset controls, closed by this reset.
          approvalsClosed,
        },
      });
    }
    return { organization: org, reset, approvalsClosed };
  });
}

export const RESET_USAGE =
  "Usage: varlatchd admin security reset --org <slug or id> (--control <name> ... | --all) [--json]\n" +
  `Controls: ${SECURITY_CONTROLS.join(", ")}`;

/** `admin security reset`'s arguments (after "security reset"), or why they are wrong. */
export function parseResetArgs(args: readonly string[]):
  | { organization: string; controls: SecurityControlName[] | "all"; json: boolean }
  | { error: string } {
  let organization: string | undefined;
  let all = false;
  let json = false;
  const named: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--org") organization = args[++i];
    else if (a === "--control") named.push(args[++i] ?? "");
    else if (a === "--all") all = true;
    else if (a === "--json") json = true;
    else return { error: `Unknown argument: ${a}\n${RESET_USAGE}` };
  }
  if (!organization) return { error: RESET_USAGE };
  if (all === named.length > 0) return { error: RESET_USAGE };
  const unknown = named.filter((n) => !(SECURITY_CONTROLS as readonly string[]).includes(n));
  if (unknown.length > 0) return { error: `Unknown control: ${unknown.join(", ")}\n${RESET_USAGE}` };
  return { organization, controls: all ? "all" : [...new Set(named)] as SecurityControlName[], json };
}

/** What the reset prints for a person. */
export function resetReportLines(outcome: ResetOutcome): string[] {
  return [
    `Security controls of ${outcome.organization.slug} [${outcome.organization.id}] reset to off:`,
    ...outcome.reset.map((r) => `  ${r.control}: ${r.from === "off" ? "already off" : `${r.from} -> off (version ${r.version})`}`),
    `Open approvals closed: ${outcome.approvalsClosed}.`,
    "Deletion, suspended identities, passkeys and Grants were not touched. Recorded as security_control.reset.",
  ];
}
