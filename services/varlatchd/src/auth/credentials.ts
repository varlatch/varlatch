// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";

/**
 * Opaque bearer credentials (ADR-0007): high-entropy, server-resolved, stored
 * hashed, individually listable/revocable. Credentials establish identity
 * only; authorization is always evaluated server-side per request.
 */

export type CredentialKind = "service" | "cli" | "browser" | "agent-run" | "oidc";

const PREFIX: Record<CredentialKind, string> = {
  service: "vlt_svc_",
  cli: "vlt_cli_",
  browser: "vlt_web_",
  // Agent metadata credential (ADR-0023): short-lived, read-only at the
  // HTTP layer, broker-issued for one Agent Run.
  "agent-run": "vlt_agr_",
  // Minted by exchanging a verified external OIDC token against a binding;
  // short-lived, no stored secret exists for the workload.
  oidc: "vlt_oidc_",
};

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function generateToken(kind: CredentialKind): string {
  return `${PREFIX[kind]}${randomBytes(32).toString("base64url")}`;
}

export interface CredentialRow {
  id: string;
  identity_id: string;
  kind: CredentialKind;
  name: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  max_uses: number | null;
  use_count: number;
}

export interface IdentityRow {
  id: string;
  kind: "human" | "service" | "workload" | "ci" | "broker" | "agent";
  name: string;
  disabled: boolean;
  installation_admin: boolean;
  organization_id: string | null;
}

export async function issueCredential(
  db: Querier,
  input: {
    identityId: string;
    kind: CredentialKind;
    name?: string;
    expiresAt?: string | undefined;
    maxUses?: number | undefined;
    actorIdentityId?: string;
    metadata?: Record<string, unknown>;
    /** Readable client label (client-label.ts), never a raw User-Agent. */
    client?: string | null;
  },
): Promise<{ credentialId: string; token: string }> {
  const token = generateToken(input.kind);
  const credentialId = newId("credential");
  return withTx(db, async (tx) => {
    await tx.query(
      `INSERT INTO credentials (id, identity_id, kind, name, token_hash, expires_at, max_uses, client)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        credentialId,
        input.identityId,
        input.kind,
        input.name ?? null,
        hashToken(token),
        input.expiresAt ?? null,
        input.maxUses ?? null,
        input.client ?? null,
      ],
    );
    await recordAuditEvent(tx, {
      eventType: "credential.issued",
      decision: "info",
      actorIdentityId: input.actorIdentityId ?? input.identityId,
      credentialId,
      resource: { identityId: input.identityId },
      metadata: {
        kind: input.kind,
        ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
        ...(input.maxUses ? { maxUses: input.maxUses } : {}),
        ...input.metadata,
      },
    });
    // The token is returned exactly once and never stored in plaintext.
    return { credentialId, token };
  });
}

export async function revokeCredential(
  db: Querier,
  credentialId: string,
  actorIdentityId: string,
  options?: { organizationId?: string },
): Promise<void> {
  await withTx(db, async (tx) => {
    // ADR-0034 §6: every revocation path records the credential's kind and
    // owning identity, so the audit line is interpretable on its own.
    const res = await tx.query(
      "UPDATE credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING kind, identity_id",
      [credentialId],
    );
    const row = res.rows[0] as { kind: CredentialKind; identity_id: string } | undefined;
    await recordAuditEvent(tx, {
      eventType: "credential.revoked",
      decision: "info",
      actorIdentityId,
      credentialId,
      organizationId: options?.organizationId ?? null,
      ...(row
        ? { resource: { identityId: row.identity_id }, metadata: { kind: row.kind } }
        : {}),
    });
  });
}

export type AuthResult =
  | { ok: true; identity: IdentityRow; credential: CredentialRow }
  | {
      ok: false;
      reason: "invalid" | "revoked" | "expired" | "exhausted" | "identity-disabled";
    };

/**
 * Resolve a bearer token. Failure reasons are collapsed for callers into
 * INVALID_CREDENTIAL; the distinction exists for audit only.
 */
export async function authenticateBearer(
  db: Querier,
  token: string,
): Promise<AuthResult> {
  const digest = hashToken(token);
  const res = await db.query(
    `SELECT c.id, c.identity_id, c.kind, c.name, c.expires_at, c.revoked_at, c.token_hash,
            c.max_uses, c.use_count,
            i.kind AS identity_kind, i.name AS identity_name, i.disabled,
            i.installation_admin, i.organization_id
     FROM credentials c JOIN identities i ON i.id = c.identity_id
     WHERE c.token_hash = $1`,
    [digest],
  );
  const row = res.rows[0] as
    | (CredentialRow & {
        token_hash: string;
        identity_kind: IdentityRow["kind"];
        identity_name: string;
        disabled: boolean;
        installation_admin: boolean;
        organization_id: string | null;
      })
    | undefined;
  if (!row) return { ok: false, reason: "invalid" };
  // Defense in depth against lookup-layer surprises.
  if (!timingSafeEqual(Buffer.from(row.token_hash, "hex"), Buffer.from(digest, "hex"))) {
    return { ok: false, reason: "invalid" };
  }
  if (row.revoked_at) return { ok: false, reason: "revoked" };
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return { ok: false, reason: "expired" };
  }
  if (row.disabled) return { ok: false, reason: "identity-disabled" };
  if (row.max_uses !== null) {
    // Atomic consume: concurrent requests race on the same row, and the
    // guarded UPDATE ensures the budget is never overspent. Unbudgeted
    // credentials skip this so their auth path stays read-only.
    const consumed = await db.query(
      `UPDATE credentials SET use_count = use_count + 1
       WHERE id = $1 AND revoked_at IS NULL AND use_count < max_uses
       RETURNING use_count`,
      [row.id],
    );
    if (!consumed.rows[0]) return { ok: false, reason: "exhausted" };
  }
  // Last-used (ADR-0034): an operational signal ("is anything still using
  // this?"), not an audit record. The WHERE guard throttles to at most one
  // write per credential per 60 seconds so the auth hot path does not gain
  // an unconditional write per request.
  const touched = await db.query(
    `UPDATE credentials SET last_used_at = now()
     WHERE id = $1
       AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')
     RETURNING id`,
    [row.id],
  );
  if (touched.rows[0]) {
    await db.query("UPDATE identities SET last_seen_at = now() WHERE id = $1", [
      row.identity_id,
    ]);
  }
  return {
    ok: true,
    credential: {
      id: row.id,
      identity_id: row.identity_id,
      kind: row.kind,
      name: row.name,
      expires_at: row.expires_at,
      revoked_at: row.revoked_at,
      max_uses: row.max_uses,
      use_count: row.use_count,
    },
    identity: {
      id: row.identity_id,
      kind: row.identity_kind,
      name: row.identity_name,
      disabled: row.disabled,
      installation_admin: row.installation_admin,
      organization_id: row.organization_id,
    },
  };
}
