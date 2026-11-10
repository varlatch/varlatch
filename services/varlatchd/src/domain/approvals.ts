// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import { recordAuditEvent } from "../audit/events.js";
import { assertionChallenge, assertionOptions, verifyAssertion, type RelyingParty } from "../auth/approval-assertion.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { listOwnPasskeys } from "./passkeys.js";

/**
 * Step-up approvals (ADR-0054 Decision 3): a fresh WebAuthn assertion, with
 * user verification required, by a trusted passkey (Decision 4) of the
 * person who asked, for one exact operation. The CLI and the dashboard use
 * the same mechanism.
 *
 * 1. A protected operation that arrives without an approval throws
 *    ApprovalNeeded inside its own transaction, with the exact binding: the
 *    semantic operation, the Organization (none for an account operation),
 *    the stable target ids, the normalized body and the query parameters it
 *    reads, the target's expected version and a summary for the approver.
 *    The transaction rolls back; withApproval then stores an Approval
 *    Intent for the requesting credential and its person, in a transaction
 *    of its own, and answers STEP_UP_REQUIRED with it.
 * 2. Only that person sees the intent (anyone else gets not-found) and
 *    approves it in the dashboard, with a challenge bound to the intent,
 *    the person and their browser session, by a trusted passkey with user
 *    verification.
 * 3. The client repeats the operation with the intent id (the
 *    Varlatch-Approval header). Inside the operation's transaction one
 *    conditional update consumes it: approved, not consumed or closed, not
 *    expired by clock_timestamp(), and the same person, operation,
 *    Organization, target, body hash, query hash and expected version, from
 *    the same requester: for an intent the CLI asked for, the exact
 *    credential; for one the dashboard asked for, a browser bearer of the
 *    same Better Auth session (the dashboard re-mints its bearer from the
 *    session, so a refresh during the approval keeps it usable, and
 *    another session of the person cannot use it). Then the requesting
 *    credential is revalidated; the operation
 *    rechecks its own authorization and version. Consumption and the
 *    mutation commit or roll back together: a failed attempt leaves the
 *    approval usable until it expires, a successful one can never be
 *    reused.
 *
 * Lifetimes are fixed at creation and never restarted: 2 minutes for an
 * intent the dashboard created (a browser credential), 10 for one the CLI
 * created. Bounds: at most 5 open intents per credential and 30 created
 * per person per 10 minutes; polls by the requesting credential follow
 * device sign-in's interval and SLOW_DOWN; approval challenges are capped
 * per person. Intent ids carry 128 random bits, so a lookup cannot guess
 * one, and another person's id is not found.
 *
 * Time is PostgreSQL's live clock, clock_timestamp(), read after the locks
 * are held, as in device sign-in.
 */

export const APPROVALS = {
  dashboardLifetimeSeconds: 120,
  cliLifetimeSeconds: 600,
  /** Seconds between polls; SLOW_DOWN adds slowDownSeconds. */
  intervalSeconds: 5,
  slowDownSeconds: 5,
  openPerCredential: 5,
  createdPerPerson: 30,
  windowSeconds: 600,
  /** An approval challenge lives this long, and never past its intent. */
  challengeSeconds: 120,
  challengesPerPerson: 20,
  /** Ended intents are deleted this long after they end. */
  retentionSeconds: 86_400,
} as const;

export const APPROVAL_OPERATIONS = ["security_control.change", "passkey.remove"] as const;
export type ApprovalOperation = (typeof APPROVAL_OPERATIONS)[number];

export interface ApprovalChange {
  field: string;
  from: string | null;
  to: string | null;
  loosens: boolean;
}

/** What the approver reads: written by the server from the parsed request, never a secret value. */
export interface ApprovalSummary {
  title: string;
  changes: ApprovalChange[];
}

/** One exact operation an approval is for. */
export interface ApprovalBinding {
  operation: ApprovalOperation;
  /** The Organization it acts in; null for an account operation. */
  organizationId: string | null;
  /** Stable target ids. */
  target: Record<string, string>;
  /** The parsed, normalized request body the operation acts on. */
  body: unknown;
  /** The query parameters the operation reads. */
  query: Record<string, string>;
  /** The target's version the request expects, where the target has one. */
  expectedVersion: number | null;
  summary: ApprovalSummary;
}

/** The credential that asked, and its person. */
export interface Requester {
  identityId: string;
  identityKind: string;
  credentialId: string;
  credentialKind: string;
  /** A browser bearer's Better Auth session: what a dashboard intent is bound to. */
  authSessionId?: string | null | undefined;
}

/** An approval as its person sees it (protocol schema Approval). */
export interface ApprovalView {
  id: string;
  operation: ApprovalOperation;
  organization: { id: string; slug: string; name: string } | null;
  summary: ApprovalSummary;
  state: "pending" | "approved" | "consumed" | "expired" | "closed";
  closeReason: "cancelled" | "reset" | "organization-deleted" | null;
  requestedBy: { credentialKind: "browser" | "cli"; client: string | null };
  url: string | null;
  interval: number;
  createdAt: string;
  expiresAt: string;
  approvedAt: string | null;
  consumedAt: string | null;
  closedAt: string | null;
}

/** The approval a consumption used, for the operation's audit record. */
export interface UsedApproval {
  id: string;
  passkeyId: string;
  userVerified: boolean;
}

/**
 * Thrown inside a protected operation's transaction when it needs an
 * approval it was not given. Never leaves withApproval.
 */
export class ApprovalNeeded extends Error {
  override name = "ApprovalNeeded";
  constructor(readonly binding: ApprovalBinding) {
    super(`${binding.operation} needs a step-up approval`);
  }
}

/** JSON with object keys sorted, so equal values hash equally whatever their key order. */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

/**
 * A keyed hash of a normalized body or query: an HMAC under the root KEK,
 * so a stored hash says nothing about a low-entropy value it covers.
 */
export function approvalHash(key: Buffer, kind: "body" | "query", value: unknown): string {
  return "hmac-v1:" + createHmac("sha256", key).update(`varlatch:approval:${kind}:v1\0`).update(canonicalJson(value), "utf8").digest("hex");
}

const ID = /^apr_[a-z2-7]{26}$/;

/** An approval id from a header or route; null when it cannot be one. */
export function parseApprovalId(value: string | undefined): string | null {
  if (value === undefined) return null;
  const id = value.trim();
  return ID.test(id) ? id : null;
}

/** Where a person approves: the dashboard's /approve/<id> under the public URL. */
export function approvalUrl(publicUrl: string | null | undefined, id: string): string | null {
  if (!publicUrl) return null;
  const base = new URL(publicUrl);
  return `${base.origin}${base.pathname.replace(/\/+$/, "")}/approve/${id}`;
}

/** What a protected operation gets: whether it was handed an approval, and how to require one. */
export interface ApprovalGate {
  /**
   * Inside the operation's transaction: consume the approval this request
   * carries for exactly `binding` and revalidate the requesting credential,
   * or, when it carries none, throw ApprovalNeeded (the operation rolls
   * back and the caller answers STEP_UP_REQUIRED).
   */
  require(db: Querier, binding: ApprovalBinding): Promise<UsedApproval>;
}

/**
 * Run a protected operation. When it throws ApprovalNeeded (it needs an
 * approval it was not given), store an Approval Intent for the binding and
 * answer STEP_UP_REQUIRED with it; anything else passes through.
 */
export async function withApproval<T>(
  ctx: AppCtx,
  input: { requester: Requester; approvalId: string | null; publicUrl: string | null | undefined },
  run: (gate: ApprovalGate) => Promise<T>,
): Promise<T> {
  const gate: ApprovalGate = {
    require: async (db, binding) => {
      if (input.approvalId === null) throw new ApprovalNeeded(binding);
      return consumeApproval(db, ctx.rootKek, input.requester, input.approvalId, binding);
    },
  };
  try {
    return await run(gate);
  } catch (err) {
    if (!(err instanceof ApprovalNeeded)) throw err;
    const approval = await createApproval(ctx, input.requester, err.binding, input.publicUrl);
    throw new DomainError(
      "STEP_UP_REQUIRED",
      approval.url
        ? `This needs your approval with a trusted passkey: open ${approval.url} and approve, then repeat the request with the Varlatch-Approval header`
        : "This needs your approval with a trusted passkey in the dashboard, then the request repeated with the Varlatch-Approval header",
      { approval },
    );
  }
}

/** Serializes one person's intent creation, so the caps hold under concurrency. */
const CREATE_LOCK = 7330054;

async function sweep(db: Querier): Promise<void> {
  // Every intent has ended by its expiry at the latest.
  await db.query(
    "DELETE FROM approval_intents WHERE expires_at < clock_timestamp() - make_interval(secs => $1)",
    [APPROVALS.retentionSeconds],
  );
}

/**
 * Store a pending Approval Intent for the binding, requested by this
 * credential, within the bounds. Only a person's dashboard or CLI
 * credential can be approved; a machine credential is refused.
 */
export async function createApproval(
  ctx: AppCtx,
  requester: Requester,
  binding: ApprovalBinding,
  publicUrl: string | null | undefined,
): Promise<ApprovalView> {
  if (requester.identityKind !== "human" || (requester.credentialKind !== "browser" && requester.credentialKind !== "cli")) {
    throw new DomainError(
      "PERMISSION_DENIED",
      "This needs a person's approval with a passkey, which a machine credential cannot give",
      { reason: "machine-credential" },
    );
  }
  if (!publicUrl) {
    throw new DomainError(
      "PERMISSION_DENIED",
      "This needs an approval with a passkey, and this server has no public URL to approve it at",
      { reason: "approvals-unavailable" },
    );
  }
  const origin = requester.credentialKind === "browser" ? "dashboard" : "cli";
  if (origin === "dashboard" && !requester.authSessionId) {
    throw new DomainError(
      "PERMISSION_DENIED",
      "This dashboard sign-in has no session to bind an approval to; reload the page and sign in again",
      { reason: "no-session" },
    );
  }
  const lifetime = origin === "dashboard" ? APPROVALS.dashboardLifetimeSeconds : APPROVALS.cliLifetimeSeconds;
  return withTx(ctx.db, async (db) => {
    await db.query("SELECT pg_advisory_xact_lock($1, hashtext($2))", [CREATE_LOCK, requester.identityId]);
    await sweep(db);
    const open = (await db.query(
      `SELECT count(*)::int AS n FROM approval_intents
       WHERE credential_id = $1 AND consumed_at IS NULL AND closed_at IS NULL AND expires_at > clock_timestamp()`,
      [requester.credentialId],
    )).rows[0] as { n: number };
    if (open.n >= APPROVALS.openPerCredential) {
      throw new DomainError(
        "RATE_LIMITED",
        `At most ${APPROVALS.openPerCredential} approvals may be open for one credential; approve, cancel or let one expire`,
        { cap: "open-per-credential" },
      );
    }
    const window = (await db.query(
      `SELECT count(*)::int AS n, min(created_at) + make_interval(secs => $2) AS retry_at FROM approval_intents
       WHERE identity_id = $1 AND created_at > clock_timestamp() - make_interval(secs => $2)`,
      [requester.identityId, APPROVALS.windowSeconds],
    )).rows[0] as { n: number; retry_at: Date | string | null };
    if (window.n >= APPROVALS.createdPerPerson) {
      const retryAt = new Date(window.retry_at ?? Date.now()).toISOString();
      throw new DomainError("RATE_LIMITED", `Too many approvals asked for; try again after ${retryAt}`, {
        cap: "per-person",
        retryAt,
      });
    }
    const id = newId("approvalIntent");
    await db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version,
          summary, origin, created_at, expires_at, poll_interval, auth_session_id)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, $11, clock_timestamp(),
               clock_timestamp() + make_interval(secs => $12), $13, $14)`,
      [
        id, requester.credentialId, requester.identityId, binding.organizationId, binding.operation,
        canonicalJson(binding.target), approvalHash(ctx.rootKek, "body", binding.body),
        approvalHash(ctx.rootKek, "query", binding.query), binding.expectedVersion, JSON.stringify(binding.summary),
        origin, lifetime, APPROVALS.intervalSeconds, origin === "dashboard" ? requester.authSessionId : null,
      ],
    );
    return (await viewOf(db, id, requester.identityId, publicUrl))!;
  });
}

interface IntentRow {
  id: string;
  credential_id: string;
  identity_id: string;
  organization_id: string | null;
  org_slug: string | null;
  org_name: string | null;
  operation: ApprovalOperation;
  summary: ApprovalSummary | string;
  credential_kind: "browser" | "cli";
  client: string | null;
  poll_interval: number;
  created_at: Date | string;
  expires_at: Date | string;
  approved_at: Date | string | null;
  consumed_at: Date | string | null;
  closed_at: Date | string | null;
  close_reason: ApprovalView["closeReason"];
  lapsed: boolean;
}

const iso = (v: Date | string | null): string | null => (v === null ? null : new Date(v).toISOString());

function stateOf(r: Pick<IntentRow, "closed_at" | "consumed_at" | "lapsed" | "approved_at">): ApprovalView["state"] {
  if (r.closed_at) return "closed";
  if (r.consumed_at) return "consumed";
  if (r.lapsed) return "expired";
  return r.approved_at ? "approved" : "pending";
}

const INTENT = `
  SELECT a.id, a.credential_id, a.identity_id, a.organization_id, o.slug AS org_slug, o.name AS org_name,
         a.operation, a.summary, c.kind AS credential_kind, c.client, a.poll_interval, a.created_at, a.expires_at,
         a.approved_at, a.consumed_at, a.closed_at, a.close_reason, a.expires_at <= clock_timestamp() AS lapsed
  FROM approval_intents a
  JOIN credentials c ON c.id = a.credential_id
  LEFT JOIN organizations o ON o.id = a.organization_id
  WHERE a.id = $1 AND a.identity_id = $2`;

async function intentRow(db: Querier, id: string, identityId: string): Promise<IntentRow | null> {
  return ((await db.query(INTENT, [id, identityId])).rows[0] as IntentRow | undefined) ?? null;
}

function toView(r: IntentRow, publicUrl: string | null | undefined): ApprovalView {
  return {
    id: r.id,
    operation: r.operation,
    organization: r.organization_id && r.org_slug !== null && r.org_name !== null
      ? { id: r.organization_id, slug: r.org_slug, name: r.org_name }
      : null,
    summary: typeof r.summary === "string" ? (JSON.parse(r.summary) as ApprovalSummary) : r.summary,
    state: stateOf(r),
    closeReason: r.close_reason,
    requestedBy: { credentialKind: r.credential_kind, client: r.client },
    url: approvalUrl(publicUrl, r.id),
    interval: r.poll_interval,
    createdAt: iso(r.created_at)!,
    expiresAt: iso(r.expires_at)!,
    approvedAt: iso(r.approved_at),
    consumedAt: iso(r.consumed_at),
    closedAt: iso(r.closed_at),
  };
}

async function viewOf(db: Querier, id: string, identityId: string, publicUrl: string | null | undefined): Promise<ApprovalView | null> {
  const row = await intentRow(db, id, identityId);
  return row ? toView(row, publicUrl) : null;
}

function notFound(): DomainError {
  return new DomainError("RESOURCE_NOT_FOUND", "Approval not found");
}

export type ApprovalRefusal =
  | "not-found" | "pending" | "approved" | "expired" | "consumed" | "closed" | "mismatch" | "stale" | "session-ended";

const REFUSAL_MESSAGES: Record<ApprovalRefusal, string> = {
  "not-found": "No approval of yours has this id",
  pending: "This approval has not been approved yet",
  approved: "This approval was already approved",
  expired: "This approval expired; ask for a new one",
  consumed: "This approval was already used; ask for a new one",
  closed: "This approval was cancelled or reset; ask for a new one",
  mismatch: "This approval was given for another request: another operation, target, body or credential",
  stale: "This approval was given for another version of the target; ask for a new one",
  "session-ended": "The dashboard session this approval was asked from has ended (signed out or expired); ask for a new one",
};

export function approvalInvalid(reason: ApprovalRefusal, approvalId: string | null): DomainError {
  return new DomainError("APPROVAL_INVALID", REFUSAL_MESSAGES[reason], { reason, approvalId });
}

/** Why an approval that is not usable now is not, from its row. */
function unusableReason(r: Pick<IntentRow, "closed_at" | "consumed_at" | "lapsed" | "approved_at">): ApprovalRefusal {
  if (r.closed_at) return "closed";
  if (r.consumed_at) return "consumed";
  if (r.lapsed) return "expired";
  return r.approved_at ? "approved" : "pending";
}

/**
 * Consume an approved intent for exactly this request, inside the
 * operation's transaction, then revalidate the requesting credential (live,
 * its person enabled). Refuses with APPROVAL_INVALID and a reason;
 * INVALID_CREDENTIAL when the credential ended meanwhile.
 */
export async function consumeApproval(
  db: Querier,
  key: Buffer,
  requester: Requester,
  approvalId: string,
  binding: ApprovalBinding,
): Promise<UsedApproval> {
  const bodyHash = approvalHash(key, "body", binding.body);
  const queryHash = approvalHash(key, "query", binding.query);
  // The person's row before the intent's, as starting and approving take
  // them: the operation may then write rows that reference the person
  // (security_controls.changed_by), whose foreign key would otherwise take
  // the person's row while this holds the intent, against a start that
  // holds the person and waits for the intent.
  await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [requester.identityId]);
  const consumed = (await db.query(
    `UPDATE approval_intents SET consumed_at = clock_timestamp()
     WHERE id = $1 AND approved_at IS NOT NULL AND consumed_at IS NULL AND closed_at IS NULL
       AND expires_at > clock_timestamp()
       AND identity_id = $3 AND operation = $4
       AND ((origin = 'cli' AND credential_id = $2)
            OR (origin = 'dashboard' AND $10::text = 'browser' AND auth_session_id = $11::text))
       AND organization_id IS NOT DISTINCT FROM $5 AND target = $6::jsonb
       AND body_hash = $7 AND query_hash = $8 AND expected_version IS NOT DISTINCT FROM $9
     RETURNING id, approved_with_passkey_id, approval_user_verified, auth_session_id`,
    [approvalId, requester.credentialId, requester.identityId, binding.operation, binding.organizationId,
      canonicalJson(binding.target), bodyHash, queryHash, binding.expectedVersion, requester.credentialKind,
      requester.authSessionId ?? null],
  )).rows[0] as
    | { id: string; approved_with_passkey_id: string; approval_user_verified: boolean; auth_session_id: string | null }
    | undefined;
  if (!consumed) {
    const row = (await db.query(
      `SELECT credential_id, origin, auth_session_id, operation, organization_id, target = $3::jsonb AS same_target, body_hash, query_hash,
              expected_version, approved_at, consumed_at, closed_at, expires_at <= clock_timestamp() AS lapsed
       FROM approval_intents WHERE id = $1 AND identity_id = $2`,
      [approvalId, requester.identityId, canonicalJson(binding.target)],
    )).rows[0] as
      | (Pick<IntentRow, "credential_id" | "operation" | "organization_id" | "approved_at" | "consumed_at" | "closed_at" | "lapsed"> & {
          same_target: boolean; body_hash: string; query_hash: string; expected_version: number | null;
          origin: "dashboard" | "cli"; auth_session_id: string | null;
        })
      | undefined;
    if (!row) throw approvalInvalid("not-found", approvalId);
    if (row.closed_at || row.consumed_at || row.lapsed || !row.approved_at) {
      throw approvalInvalid(unusableReason(row), approvalId);
    }
    const sameRequester = row.origin === "cli"
      ? row.credential_id === requester.credentialId
      : requester.credentialKind === "browser" && row.auth_session_id === (requester.authSessionId ?? null);
    const sameRequest = sameRequester && row.operation === binding.operation &&
      row.organization_id === binding.organizationId && row.same_target && row.body_hash === bodyHash && row.query_hash === queryHash;
    throw approvalInvalid(sameRequest && row.expected_version !== binding.expectedVersion ? "stale" : "mismatch", approvalId);
  }
  // A dashboard intent needs its Better Auth session alive: it exists (sign
  // out deletes it, without revoking the browser bearers minted from it),
  // it has not expired, and it is the requesting person's. Taken FOR KEY
  // SHARE, the weakest lock that conflicts with a DELETE: a sign-out in
  // flight either committed first (no row: refused) or waits for this
  // operation to end, while Better Auth's refresh of the session (an update
  // of non-key columns) is not held up. Before the credential's lock below,
  // in the order the public-URL change ends sessions and then revokes
  // credentials.
  if (consumed.auth_session_id !== null) {
    const session = (await db.query(
      `SELECT 1 FROM "session" s JOIN auth_user_links l ON l.better_auth_user_id = s."userId"
       WHERE s.id = $1 AND l.identity_id = $2 AND s."expiresAt" > clock_timestamp()
       FOR KEY SHARE OF s`,
      [consumed.auth_session_id, requester.identityId],
    )).rows[0];
    if (!session) throw approvalInvalid("session-ended", approvalId);
  }
  // Revalidate: the requesting credential is still live and its person
  // enabled; for a dashboard intent, it is a browser bearer of the intent's
  // session. Taken FOR SHARE, so a revocation in flight waits for this
  // operation to end.
  const live = (await db.query(
    `SELECT 1 FROM credentials c JOIN identities i ON i.id = c.identity_id
     WHERE c.id = $1 AND c.identity_id = $2 AND c.revoked_at IS NULL
       AND (c.expires_at IS NULL OR c.expires_at > clock_timestamp()) AND NOT i.disabled
       AND ($3::text IS NULL OR (c.kind = 'browser' AND c.auth_session_id = $3::text))
     FOR SHARE OF c`,
    [requester.credentialId, requester.identityId, consumed.auth_session_id],
  )).rows[0];
  if (!live) throw new DomainError("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired");
  return { id: consumed.id, passkeyId: consumed.approved_with_passkey_id, userVerified: consumed.approval_user_verified };
}

/**
 * The person's own approval. Polls by the requesting credential closer
 * together than its interval answer SLOW_DOWN and lengthen it, as device
 * sign-in does; the dashboard (another credential of the same person)
 * reads it without counting.
 */
export async function getApproval(
  ctx: AppCtx,
  input: { approvalId: string; requester: Requester; publicUrl: string | null | undefined },
): Promise<ApprovalView> {
  return withTx(ctx.db, async (db) => {
    const locked = (await db.query(
      "SELECT id FROM approval_intents WHERE id = $1 AND identity_id = $2 FOR UPDATE",
      [input.approvalId, input.requester.identityId],
    )).rows[0];
    if (!locked) throw notFound();
    const poll = (await db.query(
      `SELECT credential_id = $2 AS own,
              (last_polled_at IS NOT NULL AND last_polled_at > clock_timestamp() - make_interval(secs => poll_interval)) AS too_soon
       FROM approval_intents WHERE id = $1`,
      [input.approvalId, input.requester.credentialId],
    )).rows[0] as { own: boolean; too_soon: boolean };
    if (poll.own) {
      if (poll.too_soon) {
        const slowed = (await db.query(
          `UPDATE approval_intents SET poll_interval = poll_interval + $2, last_polled_at = clock_timestamp()
           WHERE id = $1 RETURNING poll_interval`,
          [input.approvalId, APPROVALS.slowDownSeconds],
        )).rows[0] as { poll_interval: number };
        return { slowDown: slowed.poll_interval } as const;
      }
      await db.query("UPDATE approval_intents SET last_polled_at = clock_timestamp() WHERE id = $1", [input.approvalId]);
    }
    return { view: (await viewOf(db, input.approvalId, input.requester.identityId, input.publicUrl))! } as const;
  }).then((outcome) => {
    if ("slowDown" in outcome) {
      throw new DomainError("SLOW_DOWN", `Polled too soon; wait ${outcome.slowDown} seconds between polls`, { interval: outcome.slowDown });
    }
    return outcome.view;
  });
}

/** Lock the person's intent and read it on the live clock, after the lock is held. */
async function lockIntent(db: Querier, approvalId: string, identityId: string): Promise<IntentRow> {
  const locked = (await db.query(
    "SELECT id FROM approval_intents WHERE id = $1 AND identity_id = $2 FOR UPDATE",
    [approvalId, identityId],
  )).rows[0];
  if (!locked) throw notFound();
  return (await intentRow(db, approvalId, identityId))!;
}

/**
 * A fresh approval challenge for one of the person's pending intents: the
 * options list only their trusted passkeys and require user verification.
 * Bound to the intent, the person and their dashboard session; it expires
 * with the intent at the latest. An earlier unused challenge of the same
 * three is superseded. At most APPROVALS.challengesPerPerson per person
 * per window.
 */
export async function startApproval(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { approvalId: string; identityId: string; authSessionId: string },
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return withTx(ctx.db, async (db) => {
    // The person's row first, then the intent, in every approval path:
    // the challenge's insert takes the person's row for its foreign key, and
    // approving takes it first. Holding it also serializes the per-person
    // challenge count with the insert, across intents and sessions.
    await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [input.identityId]);
    const intent = await lockIntent(db, input.approvalId, input.identityId);
    const state = stateOf(intent);
    if (state !== "pending") throw approvalInvalid(unusableReason(intent), input.approvalId);
    const window = (await db.query(
      `SELECT count(*)::int AS issued, min(created_at) + make_interval(secs => $2) AS retry_at
       FROM approval_intent_challenges
       WHERE identity_id = $1 AND created_at > clock_timestamp() - make_interval(secs => $2)`,
      [input.identityId, APPROVALS.windowSeconds],
    )).rows[0] as { issued: number; retry_at: Date | string | null };
    if (window.issued >= APPROVALS.challengesPerPerson) {
      const retryAt = new Date(window.retry_at ?? Date.now()).toISOString();
      throw new DomainError("RATE_LIMITED", `Too many approvals started; try again after ${retryAt}`, { retryAt });
    }
    const remainingMs = Math.max(1000, new Date(intent.expires_at).getTime() - Date.now());
    const trusted = (await listOwnPasskeys(db, input.identityId)).filter((p) => p.trust === "trusted").map((p) => p.id);
    const options = await assertionOptions(db, rp, input.identityId, Math.min(APPROVALS.challengeSeconds * 1000, remainingMs), {
      userVerification: "required",
      passkeyIds: trusted,
    });
    if (!options) {
      throw new DomainError(
        "PERMISSION_DENIED",
        "You have no trusted passkey to approve with. Confirm a passkey with a trusted one under Account, Security, or ask whoever runs this Varlatch server for a link that enrolls a trusted one (varlatch admin reenroll)",
        { reason: "no-trusted-passkey" },
      );
    }
    await db.query(
      `UPDATE approval_intent_challenges SET consumed_at = clock_timestamp()
       WHERE intent_id = $1 AND identity_id = $2 AND auth_session_id = $3 AND consumed_at IS NULL`,
      [input.approvalId, input.identityId, input.authSessionId],
    );
    await db.query(
      `INSERT INTO approval_intent_challenges (id, intent_id, identity_id, auth_session_id, challenge, created_at, expires_at)
       SELECT $1, $2, $3, $4, $5, clock_timestamp(),
              least(clock_timestamp() + make_interval(secs => $6), a.expires_at)
       FROM approval_intents a WHERE a.id = $2`,
      [newId("approvalIntentChallenge"), input.approvalId, input.identityId, input.authSessionId, options.challenge,
        APPROVALS.challengeSeconds],
    );
    return options;
  });
}

/**
 * Approve one of the person's pending intents. In one transaction, under
 * the intent's row lock: check it is still pending on the live clock,
 * consume the challenge (issued for this intent, person and session;
 * unused; unexpired), verify the assertion with one of the person's
 * trusted passkeys, user verification required, and mark the intent
 * approved with the passkey that asserted. A refused challenge or
 * assertion stays consumed and is audited as `authentication.failed`.
 * The expiry stays what it was.
 */
export async function approveApproval(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { approvalId: string; identityId: string; authSessionId: string; assertion: unknown; requestId: string;
    publicUrl: string | null | undefined },
): Promise<ApprovalView> {
  const challenge = assertionChallenge(input.assertion);
  const outcome = await withTx(ctx.db, async (db) => {
    // The person's row first, as passkey confirmation and removal take it:
    // verifying advances a passkey's counter, and a removal holds that
    // passkey while it consumes an approval, so both go in one order.
    await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [input.identityId]);
    const intent = await lockIntent(db, input.approvalId, input.identityId);
    if (stateOf(intent) !== "pending") throw approvalInvalid(unusableReason(intent), input.approvalId);
    const bound = challenge
      ? ((await db.query(
          `SELECT id FROM approval_intent_challenges
           WHERE challenge = $1 AND intent_id = $2 AND identity_id = $3 AND auth_session_id = $4 FOR UPDATE`,
          [challenge, input.approvalId, input.identityId, input.authSessionId],
        )).rows[0] as { id: string } | undefined)
      : undefined;
    const consumed = bound
      ? (await db.query(
          `UPDATE approval_intent_challenges SET consumed_at = clock_timestamp()
           WHERE id = $1 AND consumed_at IS NULL AND expires_at > clock_timestamp() RETURNING id`,
          [bound.id],
        )).rows[0]
      : undefined;
    const trusted = (await listOwnPasskeys(db, input.identityId)).filter((p) => p.trust === "trusted").map((p) => p.id);
    const verified = consumed && challenge
      ? await verifyAssertion(db, rp, input.identityId, input.assertion, challenge, { requireUserVerification: true, passkeyIds: trusted })
      : ({ ok: false, reason: "challenge" } as const);
    if (!verified.ok) {
      await recordAuditEvent(db, {
        eventType: "authentication.failed",
        decision: "deny",
        actorIdentityId: input.identityId,
        organizationId: intent.organization_id,
        requestId: input.requestId,
        resource: { approvalId: input.approvalId },
        metadata: { method: "step-up-approval", operation: intent.operation, reason: verified.reason },
      });
      return { kind: "refused" as const, reason: verified.reason };
    }
    const approved = (await db.query(
      `UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = $3
       WHERE id = $1 AND approved_at IS NULL AND consumed_at IS NULL AND closed_at IS NULL AND expires_at > clock_timestamp()
       RETURNING id`,
      [input.approvalId, verified.passkeyId, verified.userVerified],
    )).rows[0];
    if (!approved) throw approvalInvalid("expired", input.approvalId);
    return { kind: "approved" as const, view: (await viewOf(db, input.approvalId, input.identityId, input.publicUrl))! };
  });
  if (outcome.kind === "approved") return outcome.view;
  throw new DomainError(
    "PERMISSION_DENIED",
    outcome.reason === "challenge"
      ? "This approval challenge was not issued for this approval and session, or it was used or expired; start again"
      : outcome.reason === "user-verification-required"
        ? "The passkey did not verify you with a PIN, fingerprint or face; approve with a passkey that does"
        : "The approval could not be verified with one of your trusted passkeys",
    { reason: outcome.reason },
  );
}

/** Cancel one of the person's approvals that is pending, or approved and not used yet. */
export async function cancelApproval(
  ctx: AppCtx,
  input: { approvalId: string; identityId: string; publicUrl: string | null | undefined },
): Promise<ApprovalView> {
  return withTx(ctx.db, async (db) => {
    const intent = await lockIntent(db, input.approvalId, input.identityId);
    const state = stateOf(intent);
    if (state !== "pending" && state !== "approved") throw approvalInvalid(unusableReason(intent), input.approvalId);
    await db.query(
      "UPDATE approval_intents SET closed_at = clock_timestamp(), close_reason = 'cancelled' WHERE id = $1",
      [input.approvalId],
    );
    return (await viewOf(db, input.approvalId, input.identityId, input.publicUrl))!;
  });
}

/**
 * Close every open intent the filter selects, with a reason: the host
 * operator's reset (the reset controls' intents) and Organization
 * deletion (all of the Organization's). Returns how many it closed.
 */
export async function closeOpenApprovals(
  db: Querier,
  input: { organizationId: string; reason: "reset" | "organization-deleted"; controls?: readonly string[] },
): Promise<number> {
  const res = await db.query(
    `UPDATE approval_intents SET closed_at = clock_timestamp(), close_reason = $2
     WHERE organization_id = $1 AND consumed_at IS NULL AND closed_at IS NULL AND expires_at > clock_timestamp()
       AND ($3::text[] IS NULL OR (operation = 'security_control.change' AND target ->> 'control' = ANY($3::text[])))
     RETURNING id`,
    [input.organizationId, input.reason, input.controls ? [...input.controls] : null],
  );
  return res.rows.length;
}
