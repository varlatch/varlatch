// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { generateToken, hashToken } from "../auth/credentials.js";
import { createCanary, verifyKekAgainstCanary } from "../crypto/canary.js";
import type { Envelope } from "../crypto/aead.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * Installation lifecycle, bootstrap, and break-glass (ADR-0010/0019/0020).
 * Setup grants are short-lived, single-use, purpose-limited; issuing them is
 * host-exec authority (the Infrastructure Operator's explicit front door) and
 * every issuance/consumption is audited.
 */

const SETUP_GRANT_TTL_MS = 15 * 60 * 1000;
/** Invites are handed to another human; give them a practical window. */
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Re-enrollment links also travel to other people, but each one binds a
 * passkey to an existing identity, Installation Admins included: a day by
 * default, a week at most.
 */
export const REENROLL_TTL_DEFAULT_HOURS = 24;
export const REENROLL_TTL_MAX_HOURS = 7 * 24;

export interface InstallationRow {
  id: string;
  kek_canary: Envelope | string;
  bootstrapped_at: string | null;
}

export async function getInstallation(db: Querier): Promise<InstallationRow | null> {
  const res = await db.query("SELECT * FROM installation LIMIT 1");
  return (res.rows[0] as InstallationRow | undefined) ?? null;
}

/** Idempotent: creates the installation row + KEK canary on first start. */
export async function ensureInstallation(ctx: AppCtx): Promise<InstallationRow> {
  const existing = await getInstallation(ctx.db);
  if (existing) return existing;
  return withTx(ctx.db, async (db) => {
    const raced = await getInstallation(db);
    if (raced) return raced;
    const id = newId("installation");
    const canary = createCanary(ctx.rootKek, id);
    await db.query("INSERT INTO installation (id, kek_canary) VALUES ($1,$2)", [
      id,
      JSON.stringify(canary),
    ]);
    await recordAuditEvent(db, {
      eventType: "installation.initialized",
      decision: "info",
      metadata: { installationId: id },
    });
    return { id, kek_canary: canary, bootstrapped_at: null };
  });
}

function canaryOf(inst: InstallationRow): Envelope {
  return typeof inst.kek_canary === "string"
    ? (JSON.parse(inst.kek_canary) as Envelope)
    : inst.kek_canary;
}

/** Startup/readiness and `varlatch admin kek verify` (ADR-0019 §16). */
export async function verifyLoadedKek(ctx: AppCtx, candidate?: Buffer): Promise<boolean> {
  const inst = await getInstallation(ctx.db);
  if (!inst) return false;
  return verifyKekAgainstCanary(candidate ?? ctx.rootKek, canaryOf(inst), inst.id);
}

export async function issueBootstrapGrant(ctx: AppCtx): Promise<{ token: string; expiresAt: string }> {
  const inst = await ensureInstallation(ctx);
  if (inst.bootstrapped_at) {
    const stranded = await adminsWithoutPasskey(ctx.db);
    const hint = stranded.length
      ? ` Enabled Installation Admin(s) without an enrolled passkey: ${stranded.join(", ")} — ` +
        `if enrollment was interrupted, run: admin recover --identity ${stranded[0]}`
      : "";
    throw new DomainError("VALIDATION_FAILED", `Installation is already bootstrapped; use recovery instead.${hint}`);
  }
  return withTx(ctx.db, async (db) => {
    const token = generateToken("cli").replace("vlt_cli_", "vlt_setup_");
    const expiresAt = new Date(Date.now() + SETUP_GRANT_TTL_MS).toISOString();
    await db.query(
      "INSERT INTO setup_grants (id, kind, token_hash, expires_at) VALUES ($1,'bootstrap',$2,$3)",
      [newId("setupGrant"), hashToken(token), expiresAt],
    );
    await recordAuditEvent(db, {
      eventType: "bootstrap.grant_issued",
      decision: "info",
      metadata: { expiresAt },
    });
    return { token, expiresAt };
  });
}

/**
 * Enabled Installation Admins with no passkey (issue #23 diagnostics). Before
 * the fix, a cancelled bootstrap ceremony left exactly this state behind; the
 * headless `--cli-credential` bootstrap also produces it by design, which is
 * why this only informs the refusal message and never changes behavior.
 */
export async function adminsWithoutPasskey(db: Querier): Promise<string[]> {
  const res = await db.query(
    `SELECT i.id FROM identities i
      WHERE i.installation_admin AND NOT i.disabled
        AND NOT EXISTS (
          SELECT 1 FROM auth_user_links l JOIN "passkey" p ON p."userId" = l.better_auth_user_id
           WHERE l.identity_id = i.id)
      ORDER BY i.id`,
  );
  return (res.rows as { id: string }[]).map((r) => r.id);
}

export interface BootstrapStatus {
  initialized: boolean;
  bootstrapped: boolean;
  admins: { id: string; enabled: boolean; hasPasskey: boolean }[];
}

/**
 * What `varlatch setup` needs to decide its bootstrap phase (ADR-0035 D7):
 * complete only when an enabled Installation Admin has a passkey — an admin
 * identity alone (interrupted enrollment, headless bootstrap) is not enough.
 * Read-only.
 */
export async function bootstrapStatus(db: Querier): Promise<BootstrapStatus> {
  const inst = await getInstallation(db);
  if (!inst) return { initialized: false, bootstrapped: false, admins: [] };
  const res = await db.query(
    `SELECT i.id, NOT i.disabled AS enabled,
            EXISTS (SELECT 1 FROM auth_user_links l JOIN "passkey" p ON p."userId" = l.better_auth_user_id
                     WHERE l.identity_id = i.id) AS has_passkey
       FROM identities i WHERE i.installation_admin ORDER BY i.created_at, i.id`,
  );
  return {
    initialized: true,
    bootstrapped: Boolean(inst.bootstrapped_at),
    admins: (res.rows as { id: string; enabled: boolean; has_passkey: boolean }[])
      .map((r) => ({ id: r.id, enabled: r.enabled, hasPasskey: r.has_passkey })),
  };
}

async function enabledInstallationAdminCount(db: Querier): Promise<number> {
  const res = await db.query(
    "SELECT count(*)::int AS n FROM identities WHERE installation_admin AND NOT disabled",
  );
  return (res.rows[0] as { n: number }).n;
}

/**
 * Break-glass (ADR-0020 §1): recovery targets a named existing Installation
 * Admin; recovering a disabled admin requires explicit enable intent;
 * creating a new admin is allowed only when zero enabled admins exist.
 */
export async function issueRecoveryGrant(
  ctx: AppCtx,
  input:
    | { mode: "identity"; identityId: string; enable?: boolean }
    | { mode: "new-admin" },
): Promise<{ token: string; expiresAt: string }> {
  const inst = await getInstallation(ctx.db);
  if (!inst?.bootstrapped_at) {
    throw new DomainError("VALIDATION_FAILED", "Installation is not bootstrapped yet; use bootstrap");
  }
  return withTx(ctx.db, async (db) => {
    let subjectId: string | null = null;
    if (input.mode === "identity") {
      const res = await db.query(
        "SELECT id, disabled, installation_admin FROM identities WHERE id = $1",
        [input.identityId],
      );
      const row = res.rows[0] as
        | { id: string; disabled: boolean; installation_admin: boolean }
        | undefined;
      if (!row || !row.installation_admin) {
        throw new DomainError("RESOURCE_NOT_FOUND", "Installation Admin identity not found");
      }
      if (row.disabled && !input.enable) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "Identity is disabled; pass --enable to explicitly re-enable during recovery",
        );
      }
      if (row.disabled && input.enable) {
        await db.query("UPDATE identities SET disabled = false WHERE id = $1", [row.id]);
        await recordAuditEvent(db, {
          eventType: "recovery.identity_reenabled",
          decision: "info",
          resource: { identityId: row.id },
        });
      }
      subjectId = row.id;
    } else {
      const enabled = await enabledInstallationAdminCount(db);
      if (enabled > 0) {
        throw new DomainError(
          "VALIDATION_FAILED",
          `--new-admin is only allowed when zero enabled Installation Admins exist (found ${enabled})`,
        );
      }
    }
    const token = generateToken("cli").replace("vlt_cli_", "vlt_recover_");
    const expiresAt = new Date(Date.now() + SETUP_GRANT_TTL_MS).toISOString();
    await db.query(
      "INSERT INTO setup_grants (id, kind, subject_identity_id, token_hash, expires_at) VALUES ($1,'recover',$2,$3,$4)",
      [newId("setupGrant"), subjectId, hashToken(token), expiresAt],
    );
    await recordAuditEvent(db, {
      eventType: "recovery.grant_issued",
      decision: "info",
      resource: subjectId ? { identityId: subjectId } : { newAdmin: "true" },
      metadata: { expiresAt },
    });
    return { token, expiresAt };
  });
}

/**
 * Invitations (ADR-0006/0010 §6): an Organization Admin issues a one-time
 * enrollment link for a new human. Consumption creates an installation-level
 * identity (never an Installation Admin) plus the organization membership.
 */
export async function issueInviteGrant(
  ctx: AppCtx,
  input: { organizationId: string; role: "admin" | "member"; name: string },
  actorIdentityId: string,
): Promise<{ id: string; token: string; expiresAt: string }> {
  return withTx(ctx.db, async (db) => {
    const id = newId("setupGrant");
    const token = generateToken("cli").replace("vlt_cli_", "vlt_invite_");
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    await db.query(
      `INSERT INTO setup_grants (id, kind, token_hash, expires_at, invite_organization_id, invite_role, invite_name, created_by)
       VALUES ($1,'invite',$2,$3,$4,$5,$6,$7)`,
      [id, hashToken(token), expiresAt, input.organizationId, input.role, input.name, actorIdentityId],
    );
    await recordAuditEvent(db, {
      eventType: "invitation.issued",
      decision: "info",
      actorIdentityId,
      organizationId: input.organizationId,
      action: "identity.manage",
      // The invitation's ID (never anything token-derived) links this event
      // to a later invitation.revoked or invitation.accepted.
      resource: { invitationId: id },
      metadata: { role: input.role, inviteeName: input.name, expiresAt },
    });
    return { id, token, expiresAt };
  });
}

export interface ReenrollmentGrant {
  identityId: string;
  name: string;
  installationAdmin: boolean;
  token: string;
  expiresAt: string;
}

/**
 * Re-enrollment links (issue #103): one per enabled human identity, or per
 * named identity, each adding a passkey to that existing identity. Issuing
 * is host-exec authority, like recovery. A new link for a person revokes the
 * unused ones issued before, so at most one is live per person.
 */
export async function issueReenrollmentGrants(
  ctx: AppCtx,
  input: { identityIds: string[] | "all"; ttlHours?: number },
): Promise<ReenrollmentGrant[]> {
  const inst = await getInstallation(ctx.db);
  if (!inst?.bootstrapped_at) {
    throw new DomainError("VALIDATION_FAILED", "Installation is not bootstrapped yet; use bootstrap");
  }
  const ttlHours = input.ttlHours ?? REENROLL_TTL_DEFAULT_HOURS;
  if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > REENROLL_TTL_MAX_HOURS) {
    throw new DomainError("VALIDATION_FAILED", `Link lifetime must be more than 0 and at most ${REENROLL_TTL_MAX_HOURS} hours`);
  }
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      `SELECT id, name, installation_admin, kind, disabled FROM identities
        WHERE ${input.identityIds === "all" ? "kind = 'human' AND NOT disabled" : "id = ANY($1)"}
        ORDER BY installation_admin DESC, created_at, id`,
      input.identityIds === "all" ? [] : [input.identityIds],
    );
    const rows = res.rows as { id: string; name: string; installation_admin: boolean; kind: string; disabled: boolean }[];
    if (input.identityIds !== "all") {
      for (const id of input.identityIds) {
        const row = rows.find((r) => r.id === id);
        if (!row || row.kind !== "human") throw new DomainError("RESOURCE_NOT_FOUND", `No person with identity ${id}`);
        if (row.disabled) throw new DomainError("VALIDATION_FAILED", `Identity ${id} is disabled`);
      }
    }
    const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString();
    const grants: ReenrollmentGrant[] = [];
    for (const row of rows) {
      await db.query(
        `UPDATE setup_grants SET revoked_at = now()
          WHERE kind = 'reenroll' AND subject_identity_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL`,
        [row.id],
      );
      const token = generateToken("cli").replace("vlt_cli_", "vlt_reenroll_");
      await db.query(
        "INSERT INTO setup_grants (id, kind, subject_identity_id, token_hash, expires_at) VALUES ($1,'reenroll',$2,$3,$4)",
        [newId("setupGrant"), row.id, hashToken(token), expiresAt],
      );
      await recordAuditEvent(db, {
        eventType: "reenrollment.grant_issued",
        decision: "info",
        resource: { identityId: row.id },
        metadata: { expiresAt, installationAdmin: row.installation_admin },
      });
      grants.push({ identityId: row.id, name: row.name, installationAdmin: row.installation_admin, token, expiresAt });
    }
    return grants;
  });
}

/** What a move to another public URL affects, read-only (issue #103). */
export interface MoveFacts {
  people: number;
  installationAdmins: number;
  passkeys: number;
  sessions: number;
  tailnetConstraints: number;
  pendingInvitations: number;
}

export async function moveFacts(db: Querier): Promise<MoveFacts> {
  const one = async (sql: string) => ((await db.query(sql)).rows[0] as { n: number }).n;
  return {
    people: await one("SELECT count(*)::int AS n FROM identities WHERE kind = 'human' AND NOT disabled"),
    installationAdmins: await one("SELECT count(*)::int AS n FROM identities WHERE installation_admin AND NOT disabled"),
    passkeys: await one(`SELECT count(*)::int AS n FROM "passkey"`),
    sessions: await one(`SELECT count(*)::int AS n FROM "session"`),
    tailnetConstraints: await one("SELECT count(*)::int AS n FROM requirements WHERE kind = 'tailnet' AND revoked_at IS NULL"),
    pendingInvitations: await one(
      "SELECT count(*)::int AS n FROM setup_grants WHERE kind = 'invite' AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
    ),
  };
}

/**
 * The installation now answers at another public URL, so another WebAuthn
 * relying party (issue #103): every passkey registered for the old one can
 * never sign in again. Remove them and end every browser session, so that
 * nothing (setup's bootstrap check, the Security page, the last-passkey rule)
 * mistakes them for working credentials. Explicit, never automatic: a typo
 * in VARLATCH_PUBLIC_URL must not erase anyone's passkeys. The archive taken
 * before the move keeps them, for a move back.
 */
export async function completePublicUrlChange(
  ctx: AppCtx,
  input: { from: string; to: string },
): Promise<{ from: string; to: string; passkeysRemoved: number; sessionsEnded: number; browserCredentialsRevoked: number }> {
  const from = new URL(input.from).origin;
  const to = new URL(input.to).origin;
  if (from === to) throw new DomainError("VALIDATION_FAILED", "The installation already answers at this address");
  return withTx(ctx.db, async (db) => {
    const passkeys = await db.query(`DELETE FROM "passkey" RETURNING id`);
    const sessions = await db.query(`DELETE FROM "session" RETURNING id`);
    // The dashboard's bearer tokens were minted from those sessions. CLI,
    // agent, and machine credentials hold no address and keep working.
    const browser = await db.query(
      `UPDATE credentials SET revoked_at = now()
        WHERE kind = 'browser' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) RETURNING id`,
    );
    const result = {
      from, to,
      passkeysRemoved: passkeys.rows.length,
      sessionsEnded: sessions.rows.length,
      browserCredentialsRevoked: browser.rows.length,
    };
    await recordAuditEvent(db, {
      eventType: "installation.public_url_changed",
      decision: "info",
      metadata: result,
    });
    return result;
  });
}

type SetupGrantKind = "bootstrap" | "recover" | "invite" | "reenroll";

async function rejectSetupGrant(ctx: AppCtx): Promise<never> {
  // Rejection must survive any transaction that declined consumption.
  await recordAuditEvent(ctx.db, {
    eventType: "setup.grant_rejected", decision: "deny",
    metadata: { reason: "invalid-consumed-or-expired" },
  });
  throw new DomainError("INVALID_CREDENTIAL", "Setup token is invalid, consumed, or expired");
}

/**
 * Check a setup grant WITHOUT consuming it (issue #23). Passkey enrollment
 * calls this when the WebAuthn ceremony starts; consumption waits until the
 * ceremony has produced a verified credential, so a cancelled browser prompt
 * leaves the grant usable until it expires. Returns the display name the
 * authenticator should show for the enrolling human.
 */
export async function peekSetupGrant(
  ctx: AppCtx,
  token: string,
): Promise<{ grantId: string; kind: SetupGrantKind; displayName: string }> {
  const res = await ctx.db.query(
    `SELECT g.id, g.kind, g.invite_name, i.name AS subject_name
       FROM setup_grants g LEFT JOIN identities i ON i.id = g.subject_identity_id
      WHERE g.token_hash = $1 AND g.consumed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at > now()`,
    [hashToken(token)],
  );
  const row = res.rows[0] as
    | { id: string; kind: SetupGrantKind; invite_name: string | null; subject_name: string | null }
    | undefined;
  if (!row) return rejectSetupGrant(ctx);
  const displayName =
    row.kind === "invite"
      ? (row.invite_name ?? "Invited user")
      : (row.subject_name ?? "Installation Admin");
  return { grantId: row.id, kind: row.kind, displayName };
}

/**
 * Consume a setup grant. For bootstrap and new-admin recovery this creates
 * the Installation Admin identity; for invites it creates an ordinary human
 * identity plus the organization membership; the caller (auth layer) then
 * runs enrollment/credential issuance for the returned identity.
 *
 * Single use holds under concurrency: the grant row is locked FOR UPDATE, so
 * of two racing consumers exactly one sees it unconsumed. `onConsumed` runs in
 * the same transaction, so whatever the caller links to the new identity
 * commits or rolls back together with the consumption.
 */
export async function consumeSetupGrant(
  ctx: AppCtx,
  token: string,
  input: { adminName?: string },
  onConsumed?: (db: Querier, identityId: string, grantId: string) => Promise<void>,
): Promise<{ identityId: string; kind: SetupGrantKind; grantId: string }> {
  const result = await withTx(ctx.db, async (db) => {
    const res = await db.query("SELECT * FROM setup_grants WHERE token_hash = $1 FOR UPDATE", [
      hashToken(token),
    ]);
    const grant = res.rows[0] as
      | {
          id: string;
          kind: SetupGrantKind;
          subject_identity_id: string | null;
          expires_at: string;
          consumed_at: string | null;
          invite_organization_id: string | null;
          invite_role: "admin" | "member" | null;
          invite_name: string | null;
          revoked_at: string | null;
        }
      | undefined;
    // A revoked invitation is dead at once, even for a ceremony that
    // started before the revocation (the row lock orders the two).
    if (!grant || grant.consumed_at || grant.revoked_at || new Date(grant.expires_at).getTime() <= Date.now()) {
      return null;
    }
    if (grant.kind === "reenroll") {
      // The person may have been disabled since the link was issued.
      const subject = await db.query("SELECT disabled FROM identities WHERE id = $1", [grant.subject_identity_id]);
      if ((subject.rows[0] as { disabled: boolean } | undefined)?.disabled !== false) return null;
    }
    await db.query("UPDATE setup_grants SET consumed_at = now() WHERE id = $1", [grant.id]);

    let identityId = grant.subject_identity_id;
    if (!identityId && grant.kind === "invite") {
      identityId = newId("identity");
      await db.query(
        "INSERT INTO identities (id, kind, name, installation_admin) VALUES ($1,'human',$2,false)",
        [identityId, grant.invite_name ?? input.adminName ?? "Invited user"],
      );
      await db.query(
        "INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1,$2,$3)",
        [grant.invite_organization_id, identityId, grant.invite_role],
      );
    } else if (!identityId) {
      identityId = newId("identity");
      await db.query(
        "INSERT INTO identities (id, kind, name, installation_admin) VALUES ($1,'human',$2,true)",
        [identityId, input.adminName ?? "Installation Admin"],
      );
    }
    if (grant.kind === "bootstrap") {
      await db.query("UPDATE installation SET bootstrapped_at = now() WHERE bootstrapped_at IS NULL");
    }
    await recordAuditEvent(db, {
      eventType:
        grant.kind === "bootstrap"
          ? "bootstrap.completed"
          : grant.kind === "invite"
            ? "invitation.accepted"
            : grant.kind === "reenroll"
              ? "reenrollment.completed"
              : "recovery.completed",
      decision: "info",
      actorIdentityId: identityId,
      organizationId: grant.invite_organization_id,
      resource: grant.kind === "invite" ? { identityId, invitationId: grant.id } : { identityId },
    });
    if (onConsumed) await onConsumed(db, identityId, grant.id);
    return { identityId, kind: grant.kind, grantId: grant.id };
  });
  if (!result) return rejectSetupGrant(ctx);
  return result;
}
