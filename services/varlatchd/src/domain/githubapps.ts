// SPDX-License-Identifier: AGPL-3.0-or-later
import { createPrivateKey, randomBytes } from "node:crypto";
import { recordAuditEvent } from "../audit/events.js";
import { hashToken } from "../auth/credentials.js";
import { encryptGitHubAppKey } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { orgKekOf, type OrgRow } from "./orgs.js";

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
 */

export const GITHUB_WEB = "https://github.com";
export const GITHUB_API = "https://api.github.com";
/** GitHub's code is valid for an hour, and so is the state. */
export const REGISTRATION_TTL_SECONDS = 3600;
export const GITHUB_APP_PERMISSIONS = { secrets: "write", environments: "write", metadata: "read" } as const;
/** GitHub's limit on an App's name. */
const APP_NAME_MAX = 34;
const LOGIN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,99}$/;
const TIMEOUT_MS = 10_000;

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

const APP_COLUMNS =
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
    await db.query("DELETE FROM github_app_registrations WHERE expires_at < clock_timestamp() - interval '1 day'");
    if (await liveApp(db, org.id)) {
      throw new DomainError("STATE_CHANGED", "This Organization already has a GitHub App. Remove it from Varlatch before registering another.");
    }
    const res = await db.query(
      `INSERT INTO github_app_registrations (state_hash, organization_id, actor_identity_id, account_login, account_type, expires_at)
       VALUES ($1, $2, $3, $4, $5, clock_timestamp() + make_interval(secs => $6))
       RETURNING expires_at`,
      [hashToken(state), org.id, actorIdentityId, account.login, account.type, REGISTRATION_TTL_SECONDS],
    );
    const expiresAt = new Date((res.rows[0] as { expires_at: string | Date }).expires_at).toISOString();
    return { state, action, manifest, account, expiresAt };
  });
}

export type RegistrationOutcome =
  | { outcome: "registered"; app: GitHubAppRow }
  | {
      outcome: "refused";
      reason: "owner-mismatch" | "organization-has-app" | "app-in-use";
      app: { githubAppId: number; slug: string; owner: GitHubAccount };
      account: GitHubAccount;
      deleteUrl: string;
      message: string;
    }
  | { outcome: "failed"; retryable: boolean; httpStatus?: number; message: string };

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

export async function completeRegistration(
  ctx: AppCtx,
  org: OrgRow,
  input: { state: string; code: string },
  actorIdentityId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RegistrationOutcome> {
  const stateHash = hashToken(input.state);
  // Claim the state: one completion per registration, by the actor who
  // started it, in this Organization, within the hour.
  const claimed = await ctx.db.query(
    `UPDATE github_app_registrations SET consumed_at = clock_timestamp()
     WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3
       AND consumed_at IS NULL AND expires_at > clock_timestamp()
     RETURNING account_login, account_type`,
    [stateHash, org.id, actorIdentityId],
  );
  const claim = claimed.rows[0] as { account_login: string; account_type: GitHubAccountType } | undefined;
  if (!claim) {
    const found = (await ctx.db.query(
      `SELECT consumed_at IS NOT NULL AS consumed FROM github_app_registrations
       WHERE state_hash = $1 AND organization_id = $2 AND actor_identity_id = $3`,
      [stateHash, org.id, actorIdentityId],
    )).rows[0] as { consumed: boolean } | undefined;
    if (!found) throw new DomainError("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this state");
    if (found.consumed) throw new DomainError("CONSUMED", "This GitHub App registration was already completed");
    throw new DomainError("EXPIRED", "This GitHub App registration expired. Start again.");
  }
  const account: GitHubAccount = { login: claim.account_login, type: claim.account_type };

  let res: Response;
  try {
    res = await fetchImpl(`${GITHUB_API}/app-manifests/${encodeURIComponent(input.code)}/conversions`, {
      method: "POST",
      headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "varlatch" },
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    // No answer: GitHub may not have seen the code, so the state is released
    // for another attempt within the hour.
    await ctx.db.query("UPDATE github_app_registrations SET consumed_at = NULL WHERE state_hash = $1", [stateHash]);
    return {
      outcome: "failed",
      retryable: true,
      message: "Varlatch could not reach api.github.com to finish the registration. Check that this server can reach it, then try again.",
    };
  }
  if (res.status !== 201) {
    return {
      outcome: "failed",
      retryable: false,
      httpStatus: res.status,
      message: `GitHub did not hand over the App (HTTP ${res.status}): the code may have been used already, or be more than an hour old. If GitHub created the App, delete it on GitHub, then start again.`,
    };
  }
  const conversion = readConversion(await res.json().catch(() => undefined));
  if (!conversion) {
    return {
      outcome: "failed",
      retryable: false,
      httpStatus: res.status,
      message: "The answer from api.github.com was not GitHub's, so Varlatch kept nothing. A proxy between this server and GitHub may be in the way.",
    };
  }
  const created = { githubAppId: conversion.id, slug: conversion.slug, owner: { login: conversion.owner.login, type: conversion.owner.type } };
  const deleteUrl = githubAppDeleteUrl(conversion.slug, created.owner);
  const refused = async (db: Querier, reason: "owner-mismatch" | "organization-has-app" | "app-in-use", message: string) => {
    await recordAuditEvent(db, {
      eventType: "sync.github_app_registration_refused",
      decision: "deny",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { organizationId: org.id },
      metadata: {
        reason,
        appId: conversion.id,
        slug: conversion.slug,
        owner: conversion.owner.login,
        ownerType: conversion.owner.type,
        account: account.login,
        accountType: account.type,
      },
    });
    return { outcome: "refused" as const, reason, app: created, account, deleteUrl, message };
  };

  if (!sameAccount(conversion.owner, account)) {
    return withTx(ctx.db, (db) =>
      refused(
        db,
        "owner-mismatch",
        `GitHub created the App ${conversion.slug} on ${conversion.owner.login}'s own account, not on ${account.login}, because ${conversion.owner.login} cannot register Apps there. Varlatch did not keep it. ${conversion.owner.login} can delete it on GitHub. An owner or App manager of ${account.login} has to register the App, or register one and import it.`,
      ),
    );
  }

  const id = newId("githubApp");
  const envelope = encryptGitHubAppKey(orgKekOf(ctx, org), org.id, id, conversion.pem);
  return withTx(ctx.db, async (db) => {
    const inserted = await db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT DO NOTHING
       RETURNING ${APP_COLUMNS}`,
      [id, org.id, conversion.id, conversion.slug, conversion.clientId, conversion.owner.login, conversion.owner.id, conversion.owner.type, JSON.stringify(envelope), actorIdentityId],
    );
    const app = inserted.rows[0] as GitHubAppRow | undefined;
    if (!app) {
      if (await liveApp(db, org.id)) {
        return refused(
          db,
          "organization-has-app",
          `This Organization got another GitHub App while this one was being created, so Varlatch did not keep ${conversion.slug}. Delete it on GitHub.`,
        );
      }
      return refused(db, "app-in-use", `Another Organization on this Varlatch already uses the App ${conversion.slug}, so Varlatch did not keep it here.`);
    }
    await recordAuditEvent(db, {
      eventType: "sync.github_app_registered",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { githubAppId: id },
      metadata: {
        via: "manifest",
        appId: conversion.id,
        slug: conversion.slug,
        owner: conversion.owner.login,
        ownerType: conversion.owner.type,
      },
    });
    return { outcome: "registered" as const, app };
  });
}
