// SPDX-License-Identifier: AGPL-3.0-or-later
import { createPrivateKey, randomBytes } from "node:crypto";
import type { AccessCheck } from "@varlatch/sync";
import { recordAuditEvent } from "../audit/events.js";
import { hashToken } from "../auth/credentials.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptGitHubAppKey, encryptGitHubAppKey } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { lockLiveScope, refuseIfFrozen, refuseIfIncidentFrozen, withExternalEffect } from "./liveness.js";
import { assertOrganizationAccessChecked, requireOrganizationAccess } from "./requestaccess.js";
import { guardEffectFetch } from "./externaleffect.js";
import { ApprovalNeeded, type ProtectedGate } from "./approvals.js";
import type { ProtectedOptions } from "./identities.js";
import { githubAppImportBinding, githubAppRegisterBinding, type PendingConversion } from "./integrationstepup.js";
import {
  approvalMetadata,
  effectRequester,
  prepareProtectedOperation,
  refuseMachineUnderEnforce,
  startProtectedOperation,
  type ProtectedOperationInput,
} from "./protected.js";
import { lockedQuery } from "../db/locks.js";
import {
  GITHUB_API,
  GITHUB_HEADERS,
  GITHUB_TIMEOUT_MS,
  GITHUB_UNREACHABLE,
  githubUnreachable,
  NOT_GITHUB,
  appRequest,
  readJwtRefusal,
} from "./githubjwt.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import { outboundOf, outboundRefusalOf } from "../net/outbound.js";

/**
 * GitHub App registration (ADR-0047 Decision 1, with its 2026-10-09
 * amendment): an Organization registers its own App through GitHub's
 * manifest flow, on the GitHub account it serves.
 *
 * Start records a single-use state, bound to the actor, the Organization,
 * and the intended GitHub account, and returns the manifest and where the
 * browser posts it. GitHub sends the browser back to the dashboard with a
 * code, and the dashboard completes the registration with its own bearer:
 * no cookie authenticates /v1, and varlatchd sends no redirect.
 *
 * Complete claims the state atomically, exchanges the code, and checks the
 * App's owner against the intended account before storing anything: GitHub
 * creates the App on the person's own account when they may not register
 * Apps on the intended one, and its answer looks like a success. Only a
 * match is stored, with the private key wrapped under the Organization KEK.
 * The client and webhook secrets are never read.
 *
 * Registration is staged (ADR-0054 amendment D), because an approval asked
 * for at the end of the callback could never be replayed: the state is
 * claimed and GitHub's code is spent by then.
 *
 * 1. Start (not protected): the registration gets a stable id, returned
 *    with the state; it is the registration's target from then on.
 * 2. Conversion (the callback, not protected; completeRegistration): an
 *    external effect (liveness.ts withExternalEffect), one transaction
 *    holding the Organization row and the person from its checkpoint,
 *    after the registration was found, until the writes are done. It
 *    claims the state, exchanges the code, checks GitHub's answer and the
 *    owner, then stores the conversion as pending on the registration row:
 *    the App's id, slug, client id and owner, and its private key wrapped
 *    under the Organization KEK and bound to the registration id. Pending
 *    material is written once and never updated (migration 50).
 * 3. Attachment (github_app.register, protected; attachInTx), in amendment
 *    E's order: the Organization FOR KEY SHARE, the existence preflight
 *    and the passkey-verification checkpoint, the person (FOR UPDATE when
 *    an approval is consumed, FOR KEY SHARE otherwise), the registration
 *    FOR UPDATE (step 10) and its checks (still pending, not expired by
 *    clock_timestamp(), started by this person), then the github_apps
 *    insert, the pending key deleted, the audit event. It calls nothing
 *    outside Varlatch.
 *    - With no approval needed, it runs in the callback's transaction: the
 *      claim, the exchange, the conversion and the attachment commit or
 *      roll back together, as before staging.
 *    - When one is needed, ApprovalNeeded comes before the attachment
 *      writes anything: the callback's transaction commits the conversion
 *      as pending, and the completion answers STEP_UP_REQUIRED for the
 *      registration. The client repeats the attachment on its own route
 *      (attachRegistration, a transaction of its own) with the approval,
 *      never the callback.
 *
 * Terminal refusals end a registration (the pending conversion expired,
 * was discarded or already attached; the Organization got another App;
 * another Organization uses this App). In the callback's transaction the
 * registration is ended there, with its audit event, as a refusal was
 * before staging. On the attach route the attempt rolls back, consumption
 * included, then a cleanup of its own deletes the pending key, if it is
 * still pending, and audits. STEP_UP_REQUIRED, an approval that does not
 * fit, and transient failures on the attach route keep the registration
 * until its own expiry.
 *
 * Attachment, discard and the expiry sweep each lock the registration row
 * FOR UPDATE and check again under it that it is still pending; whichever
 * commits first wins. Attachment and discard take the Organization first;
 * the sweep takes no Organization row and skips rows another transaction
 * holds, so it never waits for an attachment.
 */

export const GITHUB_WEB = "https://github.com";
/** GitHub's code is valid for an hour, and so is the state. */
export const REGISTRATION_TTL_SECONDS = 3600;
/** A pending conversion expires one hour after it was stored (amendment D). */
export const PENDING_TTL_SECONDS = 3600;
export const GITHUB_APP_PERMISSIONS = { secrets: "write", environments: "write", metadata: "read" } as const;
/** GitHub's limit on an App's name. */
const APP_NAME_MAX = 34;
const LOGIN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,99}$/;
/** Installation pages read at most: 3,000 installations. */
const MAX_INSTALLATION_PAGES = 30;

export type GitHubAccountType = "organization" | "user";

export interface GitHubAccount {
  login: string;
  type: GitHubAccountType;
}

export interface GitHubAppRow {
  id: string;
  organization_id: string;
  github_app_id: string | number;
  slug: string;
  client_id: string;
  owner_login: string;
  owner_id: string | number;
  owner_type: GitHubAccountType;
  created_by: string | null;
  created_at: string | Date;
  version: number;
  updated_at: string | Date | null;
}

export const APP_COLUMNS =
  "id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, created_by, created_at, version, updated_at";

/** Where the browser goes back to after GitHub: the dashboard's page for this Organization. */
export function registrationRedirectUrl(base: URL, org: OrgRow): string {
  return `${base.origin}${base.pathname.replace(/\/+$/, "")}/o/${encodeURIComponent(org.slug)}/connections/github-app`;
}

/** Where the owner of a GitHub App deletes it. */
export function githubAppDeleteUrl(slug: string, owner: GitHubAccount): string {
  return owner.type === "organization"
    ? `${GITHUB_WEB}/organizations/${encodeURIComponent(owner.login)}/settings/apps/${encodeURIComponent(slug)}/advanced`
    : `${GITHUB_WEB}/settings/apps/${encodeURIComponent(slug)}/advanced`;
}

export interface RegistrationStart {
  /** The registration's stable id: what an attachment's approval is bound to (ADR-0054 amendment D). */
  id: string;
  /** The state: returned once, never stored (only its SHA-256 is). */
  state: string;
  /** Where the browser posts the manifest (a form field named `manifest`, its JSON). */
  action: string;
  manifest: Record<string, unknown>;
  account: GitHubAccount;
  expiresAt: string;
}

async function liveApp(db: Querier, organizationId: string): Promise<GitHubAppRow | null> {
  const res = await db.query(
    `SELECT ${APP_COLUMNS} FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL`,
    [organizationId],
  );
  return (res.rows[0] as GitHubAppRow | undefined) ?? null;
}

export async function getGitHubApp(ctx: AppCtx, organizationId: string): Promise<GitHubAppRow> {
  const app = await liveApp(ctx.db, organizationId);
  if (!app) throw new DomainError("RESOURCE_NOT_FOUND", "This Organization has no GitHub App");
  return app;
}

export async function startRegistration(
  ctx: AppCtx,
  org: OrgRow,
  account: GitHubAccount,
  actorIdentityId: string,
  base: URL,
): Promise<RegistrationStart> {
  // No stored credential or external call while the Organization is being deleted (ADR-0051).
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  if (!LOGIN_PATTERN.test(account.login)) {
    throw new DomainError("VALIDATION_FAILED", "account.login: not a GitHub account name");
  }
  const state = randomBytes(32).toString("base64url");
  const manifest = {
    name: `Varlatch ${org.slug}`.slice(0, APP_NAME_MAX).trimEnd(),
    url: base.origin,
    description: `Varlatch writes GitHub Actions secrets for the ${org.name} Organization.`,
    redirect_url: registrationRedirectUrl(base, org),
    public: false,
    default_permissions: GITHUB_APP_PERMISSIONS,
    default_events: [],
  };
  const action =
    account.type === "organization"
      ? `${GITHUB_WEB}/organizations/${encodeURIComponent(account.login)}/settings/apps/new?state=${state}`
      : `${GITHUB_WEB}/settings/apps/new?state=${state}`;
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId: org.id, people: [actorIdentityId] });
    // Ended registrations, a day past their expiry. One still pending keeps
    // its key until the sweep ends it with its audit event.
    await db.query(
      "DELETE FROM github_app_registrations WHERE expires_at < clock_timestamp() - interval '1 day' AND (converted_at IS NULL OR ended_at IS NOT NULL)",
    );
    if (await liveApp(db, org.id)) {
      throw new DomainError("STATE_CHANGED", "This Organization already has a GitHub App. Remove it from Varlatch before registering another.");
    }
    const id = newId("githubAppRegistration");
    const res = await db.query(
      `INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp() + make_interval(secs => $7))
       RETURNING expires_at`,
      [id, hashToken(state), org.id, actorIdentityId, account.login, account.type, REGISTRATION_TTL_SECONDS],
    );
    const expiresAt = new Date((res.rows[0] as { expires_at: string | Date }).expires_at).toISOString();
    return { id, state, action, manifest, account, expiresAt };
  });
}

export type RegistrationOutcome =
  | { outcome: "registered"; app: GitHubAppRow }
  | {
      outcome: "refused";
      reason: RefusalReason;
      app: { githubAppId: number; slug: string; owner: GitHubAccount };
      account: GitHubAccount;
      /**
       * Where the App's owner deletes it on GitHub; null for
       * `registration-ended`, whose App may be the one this Organization
       * attached (a retry after a lost answer must not send anyone to
       * delete a working App).
       */
      deleteUrl: string | null;
      message: string;
    }
  | { outcome: "failed"; retryable: boolean; httpStatus?: number; message: string };

/**
 * Why a registration was refused: the owner check at conversion, or a
 * terminal refusal of its attachment (amendment D): another App in the
 * Organization, an App another Organization uses, a pending conversion that
 * expired, or a registration that already ended (attached, discarded or
 * refused before).
 */
export type RefusalReason = "owner-mismatch" | "organization-has-app" | "app-in-use" | "expired" | "registration-ended";

interface Conversion {
  id: number;
  slug: string;
  clientId: string;
  pem: string;
  owner: GitHubAccount & { id: number };
}

/** GitHub's conversion answer, or null when it is not GitHub's (or has no usable key). */
function readConversion(body: unknown): Conversion | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  const owner = b.owner as Record<string, unknown> | null | undefined;
  if (
    !Number.isSafeInteger(b.id) || (b.id as number) <= 0 ||
    typeof b.slug !== "string" || !SLUG_PATTERN.test(b.slug) ||
    typeof b.client_id !== "string" || b.client_id.length === 0 || b.client_id.length > 100 ||
    typeof b.pem !== "string" ||
    typeof owner !== "object" || owner === null ||
    typeof owner.login !== "string" || !LOGIN_PATTERN.test(owner.login) ||
    !Number.isSafeInteger(owner.id) || (owner.id as number) <= 0 ||
    (owner.type !== "Organization" && owner.type !== "User")
  ) {
    return null;
  }
  try {
    if (createPrivateKey(b.pem).asymmetricKeyType !== "rsa") return null;
  } catch {
    return null;
  }
  return {
    id: b.id as number,
    slug: b.slug,
    clientId: b.client_id,
    pem: b.pem,
    owner: { login: owner.login, id: owner.id as number, type: owner.type === "Organization" ? "organization" : "user" },
  };
}

const sameAccount = (a: GitHubAccount, b: GitHubAccount) =>
  a.type === b.type && a.login.toLowerCase() === b.login.toLowerCase();

/**
 * The callback (conversion, amendment D step 2), then the attachment
 * (step 3) in the same request. `gate` is the attachment's: an approval
 * the callback carries is never used for it (the callback is never
 * repeated), so the route hands it a gate without one. When the
 * attachment needs an approval, it throws ApprovalNeeded, which the
 * route's withApproval turns into STEP_UP_REQUIRED for the registration;
 * the conversion stays pending.
 */
/**
 * The callback (conversion, amendment D step 2), then the attachment
 * (step 3). Both run as one external effect (liveness.ts
 * withExternalEffect): one transaction holding the Organization row and
 * the person from the checkpoint, after the registration was found, until
 * the code exchange and the writes are done.
 *
 * `gate` is the attachment's: an approval the callback carries is never
 * used for it (the callback is never repeated), so the route hands it a
 * gate without one. When no approval is needed, the attachment runs in
 * the same transaction, so the outcome is the one before staging: the App
 * attached, or refused and audited, in one commit. When one is needed,
 * the conversion commits as pending, and ApprovalNeeded is thrown after
 * the effect: the route's withApproval turns it into STEP_UP_REQUIRED for
 * the registration, and the client repeats the attachment on its own
 * route.
 */
export async function completeRegistration(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  input: { state: string; code: string },
  /** Test hook; GitHub is otherwise reached through the outbound policy (ADR-0057). */
  fetchImpl?: typeof fetch,
  options: ProtectedOptions = {},
): Promise<RegistrationOutcome> {
  const actorIdentityId = gate.requester.identityId;
  // No stored credential or external call while the Organization is being deleted (ADR-0051).
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  // A machine credential can never approve the attachment: under enforce it
  // is refused here, before the state is claimed or the code spent. An early
  // refusal only (protected.ts): the attachment decides again under the lock.
  await refuseMachineUnderEnforce(ctx.db, gate, org.id, [{ control: "admin-step-up", operation: "github_app.register" }]);
  // What the attachment left for after the effect: an approval to ask for,
  // or a machine credential's refusal, once the conversion committed.
  let deferred: Error | null = null;
  // The external-effect contract (liveness.ts withExternalEffect): from
  // here to the end, one transaction holding the Organization row and the
  // actor, with passkey-verification after the lookups and before the
  // first decryption or call (ADR-0054 Decisions 2 and 7).
  const outcome = await withExternalEffect(ctx.db, { organizationId: org.id, people: [actorIdentityId] }, async (tx) => {
    const tctx: AppCtx = { ...ctx, db: tx };
    const stateHash = hashToken(input.state);
    // The registration exists (a missing one keeps its not-found); then
    // passkey-verification, before the claim and the call to GitHub
    // (ADR-0054 Decision 7).
    const registered = await tx.query(
      "SELECT 1 FROM github_app_registrations WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3",
      [stateHash, org.id, actorIdentityId],
    );
    if (!registered.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this state");
    await requireOrganizationAccess(tx, org.id);
    // The registration row (step 10) in the strongest mode this
    // transaction needs, before its first write: the claim, the conversion
    // and the attachment then reuse it.
    await lockedQuery(
      tx,
      { table: "github_app_registrations", mode: "update", key: "state_hash" },
      "SELECT state_hash FROM github_app_registrations WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3 FOR UPDATE",
      [stateHash, org.id, actorIdentityId],
    );
    // Claim the state: one completion per registration, by the actor who
    // started it, in this Organization, within the hour.
    const claimed = await tx.query(
      `UPDATE github_app_registrations SET consumed_at = clock_timestamp()
       WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3
         AND consumed_at IS NULL AND expires_at > clock_timestamp()
       RETURNING id, account_login, account_type`,
      [stateHash, org.id, actorIdentityId],
    );
    const claim = claimed.rows[0] as { id: string; account_login: string; account_type: GitHubAccountType } | undefined;
    if (!claim) {
      const found = (await tx.query(
        `SELECT id, consumed_at IS NOT NULL AS consumed, converted_at IS NOT NULL AND ended_at IS NULL AS pending
         FROM github_app_registrations
         WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3`,
        [stateHash, org.id, actorIdentityId],
      )).rows[0] as { id: string; consumed: boolean; pending: boolean } | undefined;
      if (!found) throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this state");
      if (found.consumed) {
        // A conversion still pending can be attached on its own route.
        throw new DomainError(
          "CONSUMED",
          found.pending
            ? "This GitHub App registration is waiting to be attached; attach it from Connections"
            : "This GitHub App registration was already completed",
          // Details only for a pending conversion: otherwise the answer is
          // the one it was before staging.
          found.pending ? { registrationId: found.id, pending: true } : undefined,
        );
      }
      throw new DomainError("EXPIRED", "This GitHub App registration expired. Start again.");
    }
    const registrationId = claim.id;
    const account: GitHubAccount = { login: claim.account_login, type: claim.account_type };

    let res: Response;
    try {
      res = await (guardEffectFetch(fetchImpl ?? outboundOf(tctx).fetch("github", { db: tx, organizationId: org.id, resource: {} })))(`${GITHUB_API}/app-manifests/${encodeURIComponent(input.code)}/conversions`, {
        method: "POST",
        headers: GITHUB_HEADERS,
        redirect: "error",
        signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
      });
    } catch (err) {
      // No answer: GitHub may not have seen the code, so the state is released
      // for another attempt within the hour.
      await tx.query("UPDATE github_app_registrations SET consumed_at = NULL WHERE state_hash = $1 AND converted_at IS NULL", [stateHash]);
      // Refused by the outbound policy (ADR-0057 Decision 7): its own words.
      const refusal = outboundRefusalOf(err);
      return {
        outcome: "failed" as const,
        retryable: true,
        message: refusal
          ? refusal.message
          : "Varlatch could not reach api.github.com to finish the registration. Check that this server can reach it, then try again.",
      };
    }
    if (res.status !== 201) {
      return {
        outcome: "failed" as const,
        retryable: false,
        httpStatus: res.status,
        message: `GitHub did not hand over the App (HTTP ${res.status}): the code may have been used already, or be more than an hour old. If GitHub created the App, delete it on GitHub, then start again.`,
      };
    }
    const conversion = readConversion(await res.json().catch(() => undefined));
    if (!conversion) {
      return {
        outcome: "failed" as const,
        retryable: false,
        httpStatus: res.status,
        message: "The answer from api.github.com was not GitHub's, so Varlatch kept nothing. A proxy between this server and GitHub may be in the way.",
      };
    }

    if (!sameAccount(conversion.owner, account)) {
      const created = { githubAppId: conversion.id, slug: conversion.slug, owner: { login: conversion.owner.login, type: conversion.owner.type } };
      await recordAuditEvent(tx, refusedEvent(org.id, actorIdentityId, "owner-mismatch", { ...pendingOf(conversion, registrationId), account }));
      return {
        outcome: "refused" as const,
        reason: "owner-mismatch" as const,
        app: created,
        account,
        deleteUrl: githubAppDeleteUrl(conversion.slug, created.owner),
        message: `GitHub created the App ${conversion.slug} on ${conversion.owner.login}'s own account, not on ${account.login}, because ${conversion.owner.login} cannot register Apps there. Varlatch did not keep it. ${conversion.owner.login} can delete it on GitHub. An owner or App manager of ${account.login} has to register the App, or register one and import it.`,
      };
    }

    // Store the conversion as pending (step 2), on the row already held. Its
    // key is wrapped under the Organization KEK, bound to the registration id.
    const envelope = encryptGitHubAppKey(orgKekOf(tctx, org), org.id, registrationId, conversion.pem);
    await tx.query(
      `UPDATE github_app_registrations SET converted_at = clock_timestamp(),
         pending_expires_at = clock_timestamp() + make_interval(secs => $2),
         pending_github_app_id = $3, pending_slug = $4, pending_client_id = $5,
         pending_owner_login = $6, pending_owner_id = $7, pending_owner_type = $8, pending_key_envelope = $9
       WHERE id = $1`,
      [registrationId, PENDING_TTL_SECONDS, conversion.id, conversion.slug, conversion.clientId,
        conversion.owner.login, conversion.owner.id, conversion.owner.type, JSON.stringify(envelope)],
    );
    // The attachment (step 3), in this transaction while it needs no
    // approval. ApprovalNeeded is thrown before it writes anything, so the
    // conversion stays and commits pending.
    try {
      return await attachInTx(tctx, tx, gate, org, registrationId, options);
    } catch (err) {
      if (err instanceof TerminalRefusal) return endRefusedIn(tx, org, err, actorIdentityId);
      if (err instanceof ApprovalNeeded) {
        deferred = err;
        return null;
      }
      if (err instanceof DomainError && err.details?.reason === "machine-credential") {
        // A machine credential that got past the early refusal (the control
        // was enforced meanwhile): its attachment can never be approved, so
        // the pending key is deleted now rather than left for the sweep.
        if (await endPending(tx, registrationId, "refused")) {
          await recordAuditEvent(tx, abandonedEvent(org.id, actorIdentityId, "machine-credential", pendingOf(conversion, registrationId)));
        }
        deferred = err;
        return null;
      }
      throw err;
    }
  });
  if (deferred) throw deferred;
  return outcome!;
}

/** A pending conversion as its binding names it, from GitHub's answer. */
function pendingOf(conversion: Conversion, registrationId: string): PendingConversion {
  return {
    registrationId,
    githubAppId: conversion.id,
    slug: conversion.slug,
    clientId: conversion.clientId,
    owner: { login: conversion.owner.login, id: conversion.owner.id, type: conversion.owner.type },
  };
}

/** sync.github_app_registration_refused, as before staging. */
function refusedEvent(
  organizationId: string,
  actorIdentityId: string,
  reason: "owner-mismatch" | "organization-has-app" | "app-in-use",
  p: PendingConversion & { account: GitHubAccount },
) {
  return {
    eventType: "sync.github_app_registration_refused" as const,
    decision: "deny" as const,
    actorIdentityId,
    organizationId,
    action: "config.sync.manage" as const,
    resource: { organizationId },
    metadata: {
      reason,
      appId: p.githubAppId,
      slug: p.slug,
      owner: p.owner.login,
      ownerType: p.owner.type,
      account: p.account.login,
      accountType: p.account.type,
    },
  };
}

interface RegistrationRow {
  id: string;
  organization_id: string;
  actor_identity_id: string;
  account_login: string;
  account_type: GitHubAccountType;
  converted_at: unknown;
  ended_at: unknown;
  end_reason: "attached" | "discarded" | "expired" | "refused" | null;
  lapsed: boolean;
  pending_github_app_id: string | number | null;
  pending_slug: string | null;
  pending_client_id: string | null;
  pending_owner_login: string | null;
  pending_owner_id: string | number | null;
  pending_owner_type: GitHubAccountType | null;
  pending_key_envelope: Envelope | string | null;
}

const REGISTRATION_COLUMNS = `id, organization_id, actor_identity_id, account_login, account_type, converted_at, ended_at, end_reason,
  converted_at IS NOT NULL AND pending_expires_at <= clock_timestamp() AS lapsed,
  pending_github_app_id, pending_slug, pending_client_id, pending_owner_login, pending_owner_id, pending_owner_type, pending_key_envelope`;

/** A converted registration's pending conversion, as its binding names it. */
function pendingFrom(row: RegistrationRow): PendingConversion {
  return {
    registrationId: row.id,
    githubAppId: Number(row.pending_github_app_id),
    slug: row.pending_slug!,
    clientId: row.pending_client_id!,
    owner: { login: row.pending_owner_login!, id: Number(row.pending_owner_id), type: row.pending_owner_type! },
  };
}

/** A terminal refusal of an attachment (amendment D): its transaction rolls back, then a cleanup of its own ends the registration. */
class TerminalRefusal extends Error {
  constructor(readonly reason: RefusalReason, readonly row: RegistrationRow) {
    super(`GitHub App registration refused: ${reason}`);
  }
}

/**
 * Whether a converted registration can be attached now, read in the
 * attempt's transaction: a terminal refusal when it cannot, null when it
 * can. Not-found (another person's registration, one not yet converted)
 * changes nothing.
 */
async function attachRefusal(db: Querier, organizationId: string, row: RegistrationRow | undefined): Promise<TerminalRefusal | null> {
  if (!row || row.converted_at === null) {
    throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization is waiting to be attached");
  }
  if (row.ended_at !== null) return new TerminalRefusal("registration-ended", row);
  if (row.lapsed) return new TerminalRefusal("expired", row);
  if (await liveApp(db, organizationId)) return new TerminalRefusal("organization-has-app", row);
  const inUse = (await db.query("SELECT 1 FROM github_apps WHERE github_app_id = $1 AND removed_at IS NULL", [row.pending_github_app_id])).rows[0];
  if (inUse) return new TerminalRefusal("app-in-use", row);
  return null;
}

/**
 * Attach a pending registration (amendment D step 3): github_app.register,
 * protected, in a transaction of its own. Only the person who started it
 * may attach it; for anyone else it is not found, and nothing changes. A
 * terminal refusal rolls the attempt back, consumption included, then ends
 * the registration in a cleanup of its own.
 */
export async function attachRegistration(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  registrationId: string,
  options: ProtectedOptions = {},
): Promise<RegistrationOutcome> {
  try {
    return await withTx(ctx.db, (db) => attachInTx({ ...ctx, db }, db, gate, org, registrationId, options));
  } catch (err) {
    if (!(err instanceof TerminalRefusal)) throw err;
    return endRefused(ctx, org, err, gate.requester.identityId);
  }
}

/** The registration, locked first when asked, then read: expiry by clock_timestamp() after the lock (amendment D). */
async function readRegistration(db: Querier, org: OrgRow, registrationId: string, actorIdentityId: string, lock: boolean): Promise<RegistrationRow | undefined> {
  if (lock) {
    await lockedQuery(
      db,
      { table: "github_app_registrations", mode: "update", key: "state_hash" },
      "SELECT state_hash FROM github_app_registrations WHERE id = $1 AND organization_id = $2 AND actor_identity_id = $3 FOR UPDATE",
      [registrationId, org.id, actorIdentityId],
    );
  }
  return (await db.query(
    `SELECT ${REGISTRATION_COLUMNS} FROM github_app_registrations WHERE id = $1 AND organization_id = $2 AND actor_identity_id = $3`,
    [registrationId, org.id, actorIdentityId],
  )).rows[0] as RegistrationRow | undefined;
}

/**
 * The attachment's transaction body, in the caller's transaction `db`: the
 * attach route's own, or the callback's external effect (which holds the
 * registration row already, and never consumes). In amendment E's order:
 * the Organization FOR KEY SHARE, the existence preflight and the
 * passkey-verification checkpoint, the binding when an approval is needed;
 * the person (FOR UPDATE when an approval is consumed, FOR KEY SHARE
 * otherwise, since github_apps references it through created_by) and
 * consumption; then the registration row FOR UPDATE (step 10) and its
 * checks by the live clock, the github_apps insert, the pending key
 * deleted, the count and the audit event. Throws TerminalRefusal for the
 * caller to end the registration.
 */
async function attachInTx(
  ctx: AppCtx,
  db: Querier,
  gate: ProtectedGate,
  org: OrgRow,
  registrationId: string,
  options: ProtectedOptions,
): Promise<RegistrationOutcome> {
  const actorIdentityId = gate.requester.identityId;
  const prepared = await prepareProtectedOperation(db, gate, {
    scope: { organizationId: org.id, people: [actorIdentityId] },
    checks: [{ control: "admin-step-up", operation: "github_app.register" }],
    // The registration exists for this person and was converted: another
    // person's, or one not converted yet, is not found (before the checkpoint).
    preflight: async (db) => {
      const row = await readRegistration(db, org, registrationId, actorIdentityId, false);
      if (!row || row.converted_at === null) {
        throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization is waiting to be attached");
      }
    },
    binding: async (db) => {
      // Refusals first (amendment A): a terminal refusal ends the
      // registration without asking anyone to approve it.
      const row = await readRegistration(db, org, registrationId, actorIdentityId, false);
      const refusal = await attachRefusal(db, org.id, row);
      if (refusal) throw refusal;
      return githubAppRegisterBinding(org, pendingFrom(row!));
    },
    authorizeIn: options.authorizeIn,
  });
  // Step 10: the registration row, then the checks under its lock, by the
  // live clock.
  const row = await readRegistration(db, org, registrationId, actorIdentityId, true);
  const refusal = await attachRefusal(db, org.id, row);
  if (refusal) throw refusal;
  const pending = pendingFrom(row!);
  const keyEnvelope = typeof row!.pending_key_envelope === "string"
    ? (JSON.parse(row!.pending_key_envelope) as Envelope)
    : (row!.pending_key_envelope as Envelope);
  // The checkpoint passed in this transaction (prepareProtectedOperation),
  // under the Organization lock, before the pending key is decrypted.
  await assertOrganizationAccessChecked(db, org.id, "decryption of a pending GitHub App key", { underLock: true });
  const pem = decryptGitHubAppKey(orgKekOf(ctx, org), org.id, registrationId, keyEnvelope);
  const id = newId("githubApp");
  const envelope = encryptGitHubAppKey(orgKekOf(ctx, org), org.id, id, pem);
  const inserted = await db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT DO NOTHING
     RETURNING ${APP_COLUMNS}`,
    [id, org.id, pending.githubAppId, pending.slug, pending.clientId, pending.owner.login, pending.owner.id, pending.owner.type,
      JSON.stringify(envelope), actorIdentityId],
  );
  const app = inserted.rows[0] as GitHubAppRow | undefined;
  if (!app) {
    throw new TerminalRefusal((await liveApp(db, org.id)) ? "organization-has-app" : "app-in-use", row!);
  }
  await db.query(
    "UPDATE github_app_registrations SET ended_at = clock_timestamp(), end_reason = 'attached', pending_key_envelope = NULL WHERE id = $1",
    [registrationId],
  );
  // Report mode (ADR-0054 Decision 9), before the audit insert.
  await prepared.count(db);
  await recordAuditEvent(db, {
    eventType: "sync.github_app_registered",
    decision: "info",
    actorIdentityId,
    organizationId: org.id,
    action: "config.sync.manage",
    resource: { githubAppId: id },
    metadata: {
      via: "manifest",
      appId: pending.githubAppId,
      slug: pending.slug,
      owner: pending.owner.login,
      ownerType: pending.owner.type,
      ...approvalMetadata(prepared.approval),
    },
  });
  return { outcome: "registered" as const, app };
}

/**
 * The cleanup after a terminal refusal of the attach route, in a
 * transaction of its own: the Organization FOR KEY SHARE and the person,
 * the checkpoint, then endRefusedIn. The answer is the refusal.
 */
async function endRefused(ctx: AppCtx, org: OrgRow, refusal: TerminalRefusal, actorIdentityId: string): Promise<RegistrationOutcome> {
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId: org.id, people: [actorIdentityId], accessCheck: "deferred" });
    // The registration was found by the attempt; then passkey-verification.
    await requireOrganizationAccess(db, org.id);
    return endRefusedIn(db, org, refusal, actorIdentityId);
  });
}

/**
 * A terminal refusal's end, in `db` (which holds the Organization and the
 * person): the registration row FOR UPDATE and, only if it is still
 * pending, its key deleted and the audit event:
 * sync.github_app_registration_refused for a conflict, as before staging,
 * sync.github_app_registration_abandoned for an expiry. The answer is the
 * refusal, with GitHub's delete page for the App, except for a
 * registration that already ended (its App may be the one attached).
 */
async function endRefusedIn(db: Querier, org: OrgRow, refusal: TerminalRefusal, actorIdentityId: string): Promise<RegistrationOutcome> {
  const pending = pendingFrom(refusal.row);
  const account: GitHubAccount = { login: refusal.row.account_login, type: refusal.row.account_type };
  if (await endPending(db, refusal.row.id, refusal.reason === "expired" ? "expired" : "refused")) {
    if (refusal.reason === "expired") {
      await recordAuditEvent(db, abandonedEvent(org.id, actorIdentityId, "expired", pending));
    } else if (refusal.reason === "organization-has-app" || refusal.reason === "app-in-use") {
      await recordAuditEvent(db, refusedEvent(org.id, actorIdentityId, refusal.reason, { ...pending, account }));
    }
  }
  const app = { githubAppId: pending.githubAppId, slug: pending.slug, owner: { login: pending.owner.login, type: pending.owner.type } };
  const messages: Record<RefusalReason, string> = {
    "owner-mismatch": "",
    "organization-has-app": `This Organization got another GitHub App while this one was being created, so Varlatch did not keep ${pending.slug}. Delete it on GitHub.`,
    "app-in-use": `Another Organization on this Varlatch already uses the App ${pending.slug}, so Varlatch did not keep it here.`,
    expired: `This registration was not attached within the hour, so Varlatch deleted its key and did not keep ${pending.slug}. Delete it on GitHub, then start again.`,
    "registration-ended": `This registration already ended: ${pending.slug} was attached, discarded or refused before.`,
  };
  return {
    outcome: "refused",
    reason: refusal.reason,
    app,
    account,
    deleteUrl: refusal.reason === "registration-ended" ? null : githubAppDeleteUrl(pending.slug, app.owner),
    message: messages[refusal.reason],
  };
}

/**
 * The registration row FOR UPDATE (step 10) and, only while it is still
 * pending, its end: the key deleted. Whether it ended it.
 */
async function endPending(db: Querier, registrationId: string, reason: "discarded" | "expired" | "refused"): Promise<boolean> {
  const row = (await lockedQuery(
    db,
    { table: "github_app_registrations", mode: "update", key: "state_hash" },
    "SELECT state_hash, converted_at IS NOT NULL AND ended_at IS NULL AS pending FROM github_app_registrations WHERE id = $1 FOR UPDATE",
    [registrationId],
  )).rows[0] as { pending: boolean } | undefined;
  if (!row?.pending) return false;
  await db.query(
    "UPDATE github_app_registrations SET ended_at = clock_timestamp(), end_reason = $2, pending_key_envelope = NULL WHERE id = $1",
    [registrationId, reason],
  );
  return true;
}

/** sync.github_app_registration_abandoned: a pending key deleted (discarded or expired). */
function abandonedEvent(
  organizationId: string,
  actorIdentityId: string | null,
  reason: "discarded" | "expired" | "machine-credential",
  p: PendingConversion,
) {
  return {
    eventType: "sync.github_app_registration_abandoned" as const,
    decision: "info" as const,
    actorIdentityId,
    organizationId,
    action: "config.sync.manage" as const,
    resource: { organizationId },
    metadata: { reason, appId: p.githubAppId, slug: p.slug, owner: p.owner.login, ownerType: p.owner.type, registrationId: p.registrationId },
  };
}

/**
 * Discard a pending registration (its person's): the key is deleted and
 * sync.github_app_registration_abandoned recorded. The App stays on
 * GitHub. One that is no longer pending changes nothing. Not protected: it
 * only deletes a key Varlatch holds.
 */
export async function discardRegistration(ctx: AppCtx, org: OrgRow, registrationId: string, actorIdentityId: string): Promise<{ discarded: boolean; deleteUrl: string | null }> {
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId: org.id, people: [actorIdentityId], accessCheck: "deferred" });
    const row = (await db.query(
      `SELECT ${REGISTRATION_COLUMNS} FROM github_app_registrations WHERE id = $1 AND organization_id = $2 AND actor_identity_id = $3`,
      [registrationId, org.id, actorIdentityId],
    )).rows[0] as RegistrationRow | undefined;
    if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this id");
    // Existence first, then passkey-verification (ADR-0054 Decision 7).
    await requireOrganizationAccess(db, org.id);
    if (row.converted_at === null) return { discarded: false, deleteUrl: null };
    const pending = pendingFrom(row);
    const deleteUrl = githubAppDeleteUrl(pending.slug, { login: pending.owner.login, type: pending.owner.type });
    if (!(await endPending(db, registrationId, "discarded"))) return { discarded: false, deleteUrl };
    await recordAuditEvent(db, abandonedEvent(org.id, actorIdentityId, "discarded", pending));
    return { discarded: true, deleteUrl };
  });
}

/**
 * The expiry sweep: pending conversions past their hour, claimed FOR
 * UPDATE SKIP LOCKED in key order (the row key, state_hash), without the Organization row, so it never
 * waits for an attachment or deadlocks with one. Each loses its key, and
 * sync.github_app_registration_abandoned is recorded with the App's id and
 * slug. Expiry is decided by clock_timestamp() after the row lock. Returns
 * how many it ended.
 */
export async function sweepExpiredRegistrations(ctx: AppCtx, limit = 100): Promise<number> {
  return withTx(ctx.db, async (db) => {
    const claimed = (await lockedQuery(
      db,
      { table: "github_app_registrations", mode: "update", key: "state_hash" },
      `SELECT state_hash FROM github_app_registrations
       WHERE converted_at IS NOT NULL AND ended_at IS NULL AND pending_expires_at <= clock_timestamp()
       ORDER BY state_hash COLLATE "C" LIMIT $1 FOR UPDATE SKIP LOCKED`,
      [limit],
    )).rows as { state_hash: string }[];
    if (claimed.length === 0) return 0;
    // Read after the lock: expiry by clock_timestamp() now, as amendment D says.
    const rows = (await db.query(
      `SELECT ${REGISTRATION_COLUMNS} FROM github_app_registrations WHERE state_hash = ANY($1::text[])`,
      [claimed.map((r) => r.state_hash)],
    )).rows as RegistrationRow[];
    const expired = rows.filter((r) => r.lapsed && r.ended_at === null);
    if (expired.length === 0) return 0;
    await db.query(
      "UPDATE github_app_registrations SET ended_at = clock_timestamp(), end_reason = 'expired', pending_key_envelope = NULL WHERE id = ANY($1::text[])",
      [expired.map((r) => r.id)],
    );
    for (const row of expired) {
      await recordAuditEvent(db, abandonedEvent(row.organization_id, null, "expired", pendingFrom(row)));
    }
    return expired.length;
  });
}

/** The sweep's loop, in every `varlatchd serve` process. */
export function startRegistrationSweepLoop(ctx: AppCtx, intervalMs = 60_000): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try {
      await sweepExpiredRegistrations(ctx);
    } catch (err) {
      console.error("GitHub App registration sweep error:", err);
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
// The App's own calls (ADR-0047 Decisions 1 and 2): import, and its installations.

/** GitHub's permission levels, weakest first. */
const LEVELS = ["read", "write", "admin"];
const allows = (granted: unknown, needed: string) =>
  typeof granted === "string" && LEVELS.indexOf(granted) >= LEVELS.indexOf(needed);

function readAccount(value: unknown): (GitHubAccount & { id: number }) | null {
  if (typeof value !== "object" || value === null) return null;
  const a = value as Record<string, unknown>;
  if (typeof a.login !== "string" || !LOGIN_PATTERN.test(a.login)) return null;
  if (!Number.isSafeInteger(a.id) || (a.id as number) <= 0) return null;
  if (a.type !== "Organization" && a.type !== "User") return null;
  return { login: a.login, id: a.id as number, type: a.type === "Organization" ? "organization" : "user" };
}

export function isRsaKey(pem: string): boolean {
  try {
    return createPrivateKey(pem).asymmetricKeyType === "rsa";
  } catch {
    return false;
  }
}

/** The live App and its private key, unwrapped. */
export async function appWithKey(ctx: AppCtx, org: OrgRow): Promise<{ app: GitHubAppRow; pem: string }> {
  const res = await ctx.db.query(
    `SELECT ${APP_COLUMNS}, key_envelope FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL`,
    [org.id],
  );
  const row = res.rows[0] as (GitHubAppRow & { key_envelope: Envelope | string }) | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "This Organization has no GitHub App");
  // The App exists; then a request's passkey-verification, before its key
  // is unwrapped (ADR-0054 Decision 7), in the caller's external-effect
  // transaction. Nothing for background work.
  await requireOrganizationAccess(ctx.db, org.id);
  const envelope = typeof row.key_envelope === "string" ? (JSON.parse(row.key_envelope) as Envelope) : row.key_envelope;
  const { key_envelope: _key, ...app } = row;
  return { app, pem: decryptGitHubAppKey(orgKekOf(ctx, org), org.id, row.id, envelope) };
}

export type ImportOutcome = { outcome: "registered"; app: GitHubAppRow } | ({ outcome: "failed" } & AccessCheck);

/**
 * Import an App someone registered on GitHub (Decision 1): its id and
 * private key. The pair is verified first, with a JWT signed by the key
 * (issued as the App id, the only identifier given) and GET /app answering
 * that id; the client id, slug, and owner are then GitHub's. The App needs
 * the permissions Varlatch pushes with; it may have more, which the audit
 * event names with their levels. The stored key keeps everything the App
 * holds: tokens Varlatch mints are narrowed per use, but whoever has the
 * key could mint broader ones.
 *
 * A protected operation (ADR-0054): admin-step-up's github_app.import,
 * bound to the App id and the key itself (the intent keeps only its keyed
 * hash). Under enforce, GitHub is asked only after a precheck found an
 * approved intent for exactly this binding (amendment D): an unapproved
 * request never sends the supplied key out. Consumption stays in the final
 * transaction; a key GitHub does not confirm leaves the approval
 * unconsumed.
 */
export async function importGitHubApp(
  ctx: AppCtx,
  gate: ProtectedGate,
  org: OrgRow,
  input: { appId: number; privateKey: string },
  /** Test hook; GitHub is otherwise reached through the outbound policy (ADR-0057). */
  fetchImpl?: typeof fetch,
  now: number = Date.now(),
  options: ProtectedOptions = {},
): Promise<ImportOutcome> {
  const actorIdentityId = gate.requester.identityId;
  // No stored credential or external call while the Organization is being deleted (ADR-0051).
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  if (!isRsaKey(input.privateKey)) {
    throw new DomainError("VALIDATION_FAILED", "privateKey: not an RSA private key in PEM, as GitHub issues them");
  }
  const protectedInput: ProtectedOperationInput = {
    scope: { organizationId: org.id, people: [actorIdentityId] },
    checks: [{ control: "admin-step-up", operation: "github_app.import" }],
    // Refused before the checkpoint, as before: an Organization with a live App.
    preflight: async (db) => {
      if (await liveApp(db, org.id)) {
        throw new DomainError("STATE_CHANGED", "This Organization already has a GitHub App. Remove it from Varlatch before importing another.");
      }
    },
    binding: async (db) => {
      // The App id is known up front: one another Organization uses is
      // refused before an approval is asked for or GitHub is called.
      if ((await db.query("SELECT 1 FROM github_apps WHERE github_app_id = $1 AND removed_at IS NULL", [input.appId])).rows[0]) {
        throw new DomainError("STATE_CHANGED", `Another Organization on this Varlatch already uses the App ${input.appId}.`);
      }
      return githubAppImportBinding(org, input);
    },
    authorizeIn: options.authorizeIn,
  };
  // The external-effect contract (liveness.ts withExternalEffect): from
  // here to the end, one transaction holding the Organization row and the
  // actor (FOR UPDATE when the request carries an approval it may consume),
  // with passkey-verification after the lookups and before the first call.
  // Under enforce, an approved intent for exactly this key must exist
  // before GitHub is called (the precheck, amendment D); it is consumed
  // only after GitHub confirmed the key, before the App row is written.
  return withExternalEffect(ctx.db, { organizationId: org.id, people: [effectRequester(gate)] }, async (tx) => {
    const tctx: AppCtx = { ...ctx, db: tx };
    const started = await startProtectedOperation(tx, gate, protectedInput, { precheck: true });
    const { res, claims, refusal } = await appRequest(guardEffectFetch(fetchImpl ?? outboundOf(tctx).fetch("github", { db: tx, organizationId: org.id, resource: {} })), "/app", String(input.appId), input.privateKey, now);
    if (!res) return { outcome: "failed", ...githubUnreachable(refusal) };
    if (res.status === 401) return { outcome: "failed", ...readJwtRefusal(res, claims) };
    if (!res.ok) {
      return {
        outcome: "failed",
        status: "failed",
        where: "connection",
        httpStatus: res.status,
        message: `GitHub did not confirm App ${input.appId} with this key (HTTP ${res.status}).`,
      };
    }
    const body = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
    const owner = readAccount(body?.owner);
    const permissions = body?.permissions as Record<string, unknown> | undefined;
    if (
      !body || typeof body !== "object" || Array.isArray(body) || !owner ||
      !Number.isSafeInteger(body.id) ||
      typeof body.slug !== "string" || !SLUG_PATTERN.test(body.slug) ||
      typeof body.client_id !== "string" || body.client_id.length === 0 || body.client_id.length > 100 ||
      typeof permissions !== "object" || permissions === null || Array.isArray(permissions)
    ) {
      return { outcome: "failed", ...NOT_GITHUB(res.status) };
    }
    if (body.id !== input.appId) {
      return { outcome: "failed", ...NOT_GITHUB(res.status) };
    }
    const missing = Object.entries(GITHUB_APP_PERMISSIONS)
      .filter(([name, level]) => !allows(permissions[name], level))
      .map(([name, level]) => `${name}: ${level}`);
    if (missing.length > 0) {
      return {
        outcome: "failed",
        status: "permission-missing",
        where: "connection",
        httpStatus: res.status,
        message: `The App ${body.slug} lacks ${missing.join(", ")}. Give it those permissions in its settings on GitHub (and have the installation accept them), then import it again.`,
      };
    }
    const extra = Object.keys(permissions)
      .filter((name) => !(name in GITHUB_APP_PERMISSIONS))
      .sort()
      .map((name) => `${name}:${String(permissions[name])}`);
    const slug = body.slug;
    const clientId = body.client_id;
    const id = newId("githubApp");
    const envelope = encryptGitHubAppKey(orgKekOf(tctx, org), org.id, id, input.privateKey);
    // Consumption (steps 4, 6, 7, the person held since step 2), now that
    // GitHub confirmed the key, then the App row.
    const prepared = await started.finish(tx);
    const db = tx;
    const inserted = await db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT DO NOTHING
       RETURNING ${APP_COLUMNS}`,
      [id, org.id, input.appId, slug, clientId, owner.login, owner.id, owner.type, JSON.stringify(envelope), actorIdentityId],
    );
    const app = inserted.rows[0] as GitHubAppRow | undefined;
    if (!app) {
      throw new DomainError(
        "STATE_CHANGED",
        (await liveApp(db, org.id))
          ? "This Organization already has a GitHub App. Remove it from Varlatch before importing another."
          : `Another Organization on this Varlatch already uses the App ${slug}.`,
      );
    }
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "sync.github_app_registered",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { githubAppId: id },
      metadata: {
        via: "import",
        appId: input.appId,
        slug,
        owner: owner.login,
        ownerType: owner.type,
        ...(extra.length > 0 ? { extraPermissions: extra.join(",") } : {}),
        ...approvalMetadata(prepared.approval),
      },
    });
    return { outcome: "registered" as const, app };
  });
}

export interface AppInstallation {
  installationId: number;
  account: GitHubAccount & { id: number };
  repositorySelection: "all" | "selected";
  suspended: boolean;
}

export interface InstallationListing {
  check: AccessCheck;
  items: AppInstallation[];
  truncated: boolean;
}

/**
 * Where the App is installed (Decision 2: the user picks one to create a
 * Connection), signed as the App. Every entry must be GitHub's, and this
 * App's (its app_id): one that is not fails the listing rather than being
 * skipped. Audited like a
 * destination listing, as a use of the stored key.
 */
export async function listAppInstallations(
  ctx: AppCtx,
  org: OrgRow,
  actorIdentityId: string,
  /** Test hook; GitHub is otherwise reached through the outbound policy (ADR-0057). */
  fetchImpl?: typeof fetch,
  now: number = Date.now(),
): Promise<InstallationListing> {
  await refuseIfFrozen(ctx.db, org.id);
  await refuseIfIncidentFrozen(ctx.db, org.id);
  // The external-effect contract (liveness.ts withExternalEffect): from
  // here to the end, one transaction holding the Organization row and the
  // actor, with passkey-verification after the lookups and before the
  // first decryption or call (ADR-0054 Decisions 2 and 7).
  return withExternalEffect(ctx.db, { organizationId: org.id, people: [actorIdentityId] }, async (tx) => {
    const tctx: AppCtx = { ...ctx, db: tx };
    const { app, pem } = await appWithKey(tctx, org);
    const listing = await readInstallations(guardEffectFetch(fetchImpl ?? outboundOf(tctx).fetch("github", { db: tctx.db, organizationId: org.id, resource: {} })), Number(app.github_app_id), app.client_id, pem, now);
    await recordAuditEvent(tctx.db, {
      eventType: "sync.github_app_installations_listed",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { githubAppId: app.id },
      metadata: {
        status: listing.check.status,
        httpStatus: listing.check.httpStatus ?? null,
        count: listing.items.length,
        truncated: listing.truncated,
      },
    });
    return listing;
  });
}

async function readInstallations(fetchImpl: typeof fetch, githubAppId: number, clientId: string, pem: string, now: number): Promise<InstallationListing> {
  const failed = (check: AccessCheck): InstallationListing => ({ check, items: [], truncated: false });
  const items: AppInstallation[] = [];
  for (let page = 1; page <= MAX_INSTALLATION_PAGES; page++) {
    const { res, claims, refusal } = await appRequest(fetchImpl, `/app/installations?per_page=100&page=${page}`, clientId, pem, now);
    if (!res) return failed(githubUnreachable(refusal));
    if (res.status === 401) return failed(readJwtRefusal(res, claims));
    if (!res.ok) {
      return failed({ status: "failed", where: "connection", httpStatus: res.status, message: `GitHub refused to list the App's installations (HTTP ${res.status}).` });
    }
    const body = await res.json().catch(() => undefined);
    if (!Array.isArray(body)) return failed(NOT_GITHUB(res.status));
    for (const entry of body as unknown[]) {
      const e = entry as Record<string, unknown> | null;
      const account = readAccount(e?.account);
      // Every installation must be this App's: a foreign or missing app_id
      // is not GitHub's answer to this App, and fails the whole listing.
      if (
        !e || !account || !Number.isSafeInteger(e.id) || (e.id as number) <= 0 ||
        e.app_id !== githubAppId ||
        (e.repository_selection !== "all" && e.repository_selection !== "selected")
      ) {
        return failed(NOT_GITHUB(res.status));
      }
      items.push({
        installationId: e.id as number,
        account,
        repositorySelection: e.repository_selection,
        suspended: e.suspended_at !== null && e.suspended_at !== undefined,
      });
    }
    if (body.length < 100) return { check: { status: "ok", where: "connection", message: "listed" }, items, truncated: false };
  }
  return { check: { status: "ok", where: "connection", message: "listed" }, items, truncated: true };
}
