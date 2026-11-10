// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from "node:async_hooks";
import { hkdfSync } from "node:crypto";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { APIError, createAuthMiddleware, isAPIError } from "better-auth/api";
import pg from "pg";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "../domain/ctx.js";
import { consumeSetupGrant, peekSetupGrant } from "../domain/bootstrap.js";
import { DomainError } from "../domain/errors.js";
import { recordAuditEvent } from "../audit/events.js";
import { hashToken } from "./credentials.js";
import { recordPasskeyProvenance, recordSessionEvidence, type SetupGrantKind } from "../domain/passkeys.js";

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
  /**
   * Resolve a request's Better Auth session to a Varlatch Identity ID and
   * the session's id (which device sign-in approval challenges bind to).
   */
  sessionFor: (headers: Headers) => Promise<{ identityId: string; sessionId: string } | null>;
  /** End Better Auth's own connection pool (tests; the daemon keeps it for its lifetime). */
  close: () => Promise<void>;
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

/**
 * Better Auth's native passkey removal deletes with the session cookie
 * alone. It is turned off; the dashboard removes passkeys through DELETE
 * /v1/me/passkeys/{passkey} (ADR-0054 Decision 4), where a later rule can
 * ask for an approval.
 */
export const DISABLED_AUTH_PATHS = ["/passkey/delete-passkey"] as const;

/**
 * What one /auth request's WebAuthn ceremony proved, kept in request-local
 * state (ADR-0054 Decision 6). Better Auth's afterVerification hooks run
 * before the session or the passkey row exists; the session-creation hook
 * and the after-hook of the same request read it and write it onto that
 * session, or that passkey, only. Never looked up by user: two sign-ins of
 * one person, concurrent or not, each see their own.
 */
interface CeremonyState {
  signIn?: { credentialId: string; userVerified: boolean };
  registration?: {
    credentialId: string;
    userVerified: boolean;
    /** Set when a setup grant was consumed for this passkey (bootstrap, invitation, recover, reenroll). */
    setupGrantKind: SetupGrantKind | null;
  };
  /**
   * Set when one of this request's Better Auth queries failed with a unique
   * violation of passkey_credential_id_unique: the passkey insert lost to
   * another registration of the same credential id.
   */
  duplicateCredentialId?: true;
}

const ALREADY_REGISTERED = "This passkey is already registered";
/** Migration 39's unique index on passkey."credentialID". */
const CREDENTIAL_ID_UNIQUE = "passkey_credential_id_unique";

/** PostgreSQL's unique_violation, on the credential id index and nothing else. */
function isDuplicateCredentialId(err: unknown): boolean {
  const e = err as { code?: unknown; constraint?: unknown } | null;
  return e?.code === "23505" && e.constraint === CREDENTIAL_ID_UNIQUE;
}
const SIGN_IN_PATH = "/passkey/verify-authentication";
const REGISTRATION_PATH = "/passkey/verify-registration";

async function setupGrantKindOf(ctx: AppCtx, context: string | null | undefined): Promise<SetupGrantKind | null> {
  if (!context) return null;
  const res = await ctx.db.query("SELECT kind FROM setup_grants WHERE token_hash = $1", [hashToken(context)]);
  return (res.rows[0] as { kind: SetupGrantKind } | undefined)?.kind ?? null;
}

export function buildHumanAuth(deps: HumanAuthDeps): HumanAuth {
  const { ctx, publicUrl } = deps;
  const url = new URL(publicUrl);

  const authPool = new pg.Pool({ connectionString: deps.databaseUrl, max: 4 });
  // Idle-client failures (e.g. backends terminated while the daemon is gated
  // during a restore) must not become unhandled 'error' events that kill the
  // process; the pool reconnects on the next query.
  authPool.on("error", () => console.error("Auth PostgreSQL idle connection failed; reconnecting on next query"));
  const ceremonies = new AsyncLocalStorage<CeremonyState>();
  // Better Auth turns a failed insert into a generic 500 and keeps the
  // database error to itself. Each pooled client's queries are observed
  // here, in the request that runs them: a unique violation of the
  // credential id index is noted in that request's ceremony state, and the
  // query's own result, rejection included, reaches Better Auth unchanged.
  authPool.on("connect", (client) => {
    const query = client.query.bind(client) as (...args: unknown[]) => unknown;
    (client as unknown as { query: (...args: unknown[]) => unknown }).query = (...args: unknown[]) => {
      const result = query(...args);
      const state = ceremonies.getStore();
      if (state && result && typeof (result as Promise<unknown>).then === "function") {
        (result as Promise<unknown>).then(undefined, (err: unknown) => {
          if (isDuplicateCredentialId(err)) state.duplicateCredentialId = true;
        });
      }
      return result;
    };
  });
  // Recording evidence or provenance never fails a sign-in or an
  // enrollment: what is not recorded counts as unverified, or unconfirmed.
  const logFailure = (what: string) => (err: unknown) =>
    console.error(`Could not record ${what}: ${err instanceof Error ? err.message : String(err)}`);
  const auth = betterAuth({
    database: authPool,
    secret: deriveSecret(ctx.rootKek),
    baseURL: publicUrl,
    basePath: "/auth",
    trustedOrigins: [url.origin],
    telemetry: { enabled: false },
    disabledPaths: [...DISABLED_AUTH_PATHS],
    databaseHooks: {
      session: {
        create: {
          // Runs after the session row is committed (Better Auth defers it
          // past a surrounding transaction), in the request that created it.
          after: async (session, endpoint) => {
            const state = ceremonies.getStore();
            if (!state) return;
            const pending = endpoint?.path === SIGN_IN_PATH
              ? state.signIn
              : endpoint?.path === REGISTRATION_PATH
                ? state.registration
                : undefined;
            if (!pending) return;
            // One session per ceremony.
            if (endpoint?.path === SIGN_IN_PATH) delete state.signIn;
            await recordSessionEvidence(ctx.db, {
              sessionId: session.id,
              betterAuthUserId: session.userId,
              credentialId: pending.credentialId,
              userVerified: pending.userVerified,
              ceremony: endpoint?.path === SIGN_IN_PATH ? "sign-in" : "enrollment",
            }).catch(logFailure("sign-in evidence"));
          },
        },
      },
    },
    hooks: {
      // disabledPaths compares the request's path; refusing here too covers
      // any other form of the URL that reaches the native removal endpoint.
      before: createAuthMiddleware(async (actx) => {
        if ((DISABLED_AUTH_PATHS as readonly string[]).includes(actx.path)) throw new APIError("NOT_FOUND");
      }),
      // A new passkey's provenance, once its row exists (ADR-0054
      // Decision 4): trusted when this request consumed a setup grant for
      // it, unconfirmed when a signed-in session added it.
      after: createAuthMiddleware(async (actx) => {
        if (actx.path !== REGISTRATION_PATH) return;
        const returned = actx.context.returned as { id?: unknown; credentialID?: unknown } | undefined;
        const registration = ceremonies.getStore()?.registration;
        if (isAPIError(returned)) {
          // The credential id is unique in the database (migration 39). A
          // registration that passed the check in afterVerification but lost
          // the race to a concurrent one fails at Better Auth's insert, which
          // Better Auth reports as an internal error. Only when this
          // request's own query failed with that unique violation is it said
          // to be a duplicate; every other failure stays a 500. A Response
          // of our own, because Better Auth keeps the endpoint's 500 status
          // for anything else an after-hook returns or throws.
          if (returned.statusCode === 500 && ceremonies.getStore()?.duplicateCredentialId) {
            return new Response(JSON.stringify({ code: "PASSKEY_ALREADY_REGISTERED", message: ALREADY_REGISTERED }), {
              status: 400,
              headers: { "Content-Type": "application/json" },
            });
          }
          return;
        }
        if (!returned || typeof returned.id !== "string") return;
        const setupGrantKind = registration && registration.credentialId === returned.credentialID
          ? registration.setupGrantKind
          : null;
        await recordPasskeyProvenance(ctx.db, returned.id, setupGrantKind ? { setupGrantKind } : { addedBySession: true })
          .catch(logFailure("passkey provenance"));
      }),
    },
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
          afterVerification: async ({ user, context, verification }) => {
            const info = verification.registrationInfo;
            if (!info) throw new APIError("BAD_REQUEST", { message: "Registration could not be verified" });
            // WebAuthn §7.1 step 22: a credential id already registered, for
            // anyone, is refused, so a credential id names one passkey and
            // evidence recorded by it is unambiguous. Checked here so a
            // setup grant is not used up for a duplicate; the unique index
            // (migration 39) settles concurrent registrations at the insert.
            const taken = await ctx.db.query(`SELECT 1 FROM passkey WHERE "credentialID" = $1 LIMIT 1`, [info.credential.id]);
            if (taken.rows[0]) throw new APIError("BAD_REQUEST", { message: ALREADY_REGISTERED });
            const setupGrantKind = user.id.startsWith(PROVISIONAL_PREFIX) ? await setupGrantKindOf(ctx, context) : null;
            const state = ceremonies.getStore();
            if (state) state.registration = { credentialId: info.credential.id, userVerified: info.userVerified, setupGrantKind: null };
            const enrolled = await completeEnrollment(ctx, user.id, context);
            if (state?.registration && enrolled) state.registration.setupGrantKind = setupGrantKind;
            return enrolled;
          },
        },
        authentication: {
          afterVerification: ({ verification }) => {
            const state = ceremonies.getStore();
            if (state) {
              state.signIn = {
                credentialId: verification.authenticationInfo.credentialID,
                userVerified: verification.authenticationInfo.userVerified,
              };
            }
          },
        },
      }),
    ],
  });

  return {
    // Each request gets its own ceremony state (see CeremonyState).
    handler: (request) => ceremonies.run({}, () => auth.handler(request)),
    sessionFor: async (headers) => {
      const session = await auth.api.getSession({ headers });
      if (!session?.user?.id || !session.session?.id) return null;
      const res = await ctx.db.query(
        "SELECT identity_id FROM auth_user_links WHERE better_auth_user_id = $1",
        [session.user.id],
      );
      const identityId = (res.rows[0] as { identity_id: string } | undefined)?.identity_id;
      return identityId ? { identityId, sessionId: session.session.id } : null;
    },
    close: () => authPool.end(),
  };
}
