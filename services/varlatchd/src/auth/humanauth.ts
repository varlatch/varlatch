// SPDX-License-Identifier: AGPL-3.0-or-later
import { hkdfSync } from "node:crypto";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { APIError } from "better-auth/api";
import pg from "pg";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "../domain/ctx.js";
import { consumeSetupGrant, peekSetupGrant } from "../domain/bootstrap.js";
import { DomainError } from "../domain/errors.js";
import { recordAuditEvent } from "../audit/events.js";

/**
 * The HumanAuth boundary (ADR-0008/0009): Better Auth embedded as a library,
 * passkey-only, subordinate to the Secret Plane trust model. Better Auth
 * answers "who is this human?"; Varlatch answers everything else. Better Auth
 * user IDs never leave this module — auth_user_links maps them to Varlatch
 * Identities.
 *
 * Its secret is derived from the root KEK via HKDF: no additional secret for
 * operators to manage, and it rotates with the KEK.
 */

export interface HumanAuthDeps {
  ctx: AppCtx;
  databaseUrl: string;
  /** Browser-visible base URL; also the WebAuthn rpID/origin source. */
  publicUrl: string;
}

export interface HumanAuth {
  handler: (request: Request) => Promise<Response>;
  /** Resolve a request's Better Auth session to a Varlatch Identity ID. */
  identityForSession: (headers: Headers) => Promise<string | null>;
}

function deriveSecret(rootKek: Buffer): string {
  return Buffer.from(
    hkdfSync("sha256", rootKek, "varlatch", "better-auth-secret", 32),
  ).toString("base64url");
}

async function linkIdentity(
  db: Querier,
  betterAuthUserId: string,
  identityId: string,
): Promise<void> {
  await db.query(
    "INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ($1,$2) ON CONFLICT (better_auth_user_id) DO NOTHING",
    [betterAuthUserId, identityId],
  );
}

const PROVISIONAL_PREFIX = "setup:";

function asApiError(err: unknown): never {
  if (err instanceof DomainError && err.code === "INVALID_CREDENTIAL") {
    throw new APIError("BAD_REQUEST", { message: err.message });
  }
  throw err;
}

/** Ceremony start: validate the grant, consume nothing, create nothing. */
export async function enrollmentUser(
  ctx: AppCtx,
  context: string | null | undefined,
): Promise<{ id: string; name: string }> {
  if (!context) throw new APIError("BAD_REQUEST", { message: "Enrollment requires a setup token" });
  const grant = await peekSetupGrant(ctx, context).catch(asApiError);
  return { id: `${PROVISIONAL_PREFIX}${grant.grantId}`, name: grant.displayName };
}

/**
 * Ceremony end, after WebAuthn verification and before the passkey row is
 * written: consume the grant and link the Better Auth user in one
 * transaction. Racing verifications of the same grant: exactly one consumes;
 * the other throws here, before any passkey is stored.
 */
export async function completeEnrollment(
  ctx: AppCtx,
  provisionalUserId: string,
  context: string | null | undefined,
): Promise<{ userId: string } | undefined> {
  if (!provisionalUserId.startsWith(PROVISIONAL_PREFIX)) return undefined;
  if (!context) throw new APIError("BAD_REQUEST", { message: "Enrollment requires a setup token" });
  const expectedGrantId = provisionalUserId.slice(PROVISIONAL_PREFIX.length);
  let userId = "";
  await consumeSetupGrant(ctx, context, {}, async (db, identityId, grantId) => {
    // Both values come from the same server-side challenge record; a mismatch
    // means tampering or a bug, and throwing here rolls the consumption back.
    if (grantId !== expectedGrantId) {
      throw new APIError("BAD_REQUEST", { message: "Setup token does not match this enrollment" });
    }
    const nameRes = await db.query("SELECT name FROM identities WHERE id = $1", [identityId]);
    const name = (nameRes.rows[0] as { name: string } | undefined)?.name ?? "Installation Admin";
    // Re-enrollment for an existing identity reuses its linked user.
    const linked = await db.query(
      "SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = $1",
      [identityId],
    );
    const existing = (linked.rows[0] as { better_auth_user_id: string } | undefined)
      ?.better_auth_user_id;
    userId = existing ?? `bau_${identityId}`;
    if (existing) return;
    // First enrollment: create the Better Auth user row ourselves (v1.7
    // contract) with a non-routable placeholder email — no SMTP, ever
    // (ADR-0006).
    await db.query(
      `INSERT INTO "user" (id, name, email, "emailVerified", "updatedAt")
       VALUES ($1, $2, $3, false, now()) ON CONFLICT (id) DO NOTHING`,
      [userId, name, `${identityId}@varlatch.placeholder.invalid`],
    );
    await linkIdentity(db, userId, identityId);
    await recordAuditEvent(db, {
      eventType: "authentication.passkey_enrollment_started",
      decision: "info",
      actorIdentityId: identityId,
      authenticationMethodId: "passkey",
    });
  }).catch(asApiError);
  return { userId };
}

export function buildHumanAuth(deps: HumanAuthDeps): HumanAuth {
  const { ctx, publicUrl } = deps;
  const url = new URL(publicUrl);

  const authPool = new pg.Pool({ connectionString: deps.databaseUrl, max: 4 });
  // Idle-client failures (e.g. backends terminated while the daemon is gated
  // during a restore) must not become unhandled 'error' events that kill the
  // process; the pool reconnects on the next query.
  authPool.on("error", () => console.error("Auth PostgreSQL idle connection failed; reconnecting on next query"));
  const auth = betterAuth({
    database: authPool,
    secret: deriveSecret(ctx.rootKek),
    baseURL: publicUrl,
    basePath: "/auth",
    trustedOrigins: [url.origin],
    telemetry: { enabled: false },
    advanced: {
      // Follow the actual scheme, not NODE_ENV: https deployments get Secure
      // cookies; plain-http local/dev does not silently lose its session.
      useSecureCookies: url.protocol === "https:",
    },
    plugins: [
      passkey({
        rpID: url.hostname,
        rpName: "Varlatch",
        origin: url.origin,
        registration: {
          requireSession: false,
          /**
           * Pre-session passkey enrollment (bootstrap/recovery/invite): the
           * browser passes a setup-grant token as `context`. Issue #23: the
           * grant is only CHECKED when the ceremony starts, and consumed in
           * afterVerification once the authenticator has produced a verified
           * credential — a cancelled prompt, failed authenticator, or closed
           * tab leaves the grant usable until it expires.
           *
           * The provisional user id carries the grant id; afterVerification
           * only consumes when it sees that prefix, so a browser that already
           * has a session (resolveUser is skipped) keeps today's behavior of
           * adding the passkey to the signed-in user and ignoring the token.
           */
          resolveUser: ({ context }: { context?: string | null | undefined }) =>
            enrollmentUser(ctx, context),
          afterVerification: ({
            user,
            context,
          }: {
            user: { id: string };
            context?: string | null | undefined;
          }) => completeEnrollment(ctx, user.id, context),
        },
      }),
    ],
  });

  return {
    handler: (request) => auth.handler(request),
    identityForSession: async (headers) => {
      const session = await auth.api.getSession({ headers });
      if (!session?.user?.id) return null;
      const res = await ctx.db.query(
        "SELECT identity_id FROM auth_user_links WHERE better_auth_user_id = $1",
        [session.user.id],
      );
      return (res.rows[0] as { identity_id: string } | undefined)?.identity_id ?? null;
    },
  };
}
