// SPDX-License-Identifier: AGPL-3.0-or-later
import { backupStatus } from "@varlatch/backup";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import {
  SEMANTICS_VERSIONS,
  TIERS,
  semanticsVersionOf,
  type ConfigurationContract,
} from "@varlatch/contract";
import { CAPABILITIES, type TailnetDevice } from "@varlatch/protocol";
import { PLATFORMS as SYNC_PLATFORMS } from "@varlatch/sync";
import { authenticateBearer } from "../auth/credentials.js";
import { clientLabel } from "../auth/client-label.js";
import { withAttribution } from "../audit/attribution.js";
import { recordAuditEvent } from "../audit/events.js";
import { auditFilterConditions, parseAuditFilters } from "../audit/filters.js";
import { serializeAuditEvent } from "../audit/serialize.js";
import type { AppCtx } from "../domain/ctx.js";
import { DomainError, notFound } from "../domain/errors.js";
import { schemaIsCurrent } from "../db/migrate.js";
import { getInstallation, issueInviteGrant, verifyLoadedKek } from "../domain/bootstrap.js";
import {
  createOrganization,
  getOrganization,
  getOrgRole,
  listOrganizationsFor,
  renameOrganization,
  type OrgRow,
} from "../domain/orgs.js";
import { createProject, renameProject, getProject, listProjects, type ProjectRow } from "../domain/projects.js";
import {
  createEnvironment,
  deleteEnvironment,
  getEnvironment,
  listEnvironments,
  rootIdOf,
  type EnvironmentRow,
} from "../domain/environments.js";
import {
  activateRevision,
  activeContractOf,
  getRevision,
  sensitivityOf,
  type ContractRevisionRow,
} from "../domain/contracts.js";
import { pushRevision } from "../domain/contracts.js";
import {
  applyChangeSet,
  beginRotation,
  completeRotation,
  deleteValue,
  DISCLOSURE_PURPOSES,
  discloseSecrets,
  effectiveConfiguration,
  setValue,
  validateEnvironment,
  type ValidationAccess,
} from "../domain/values.js";
import {
  createMachineIdentity,
  issueMachineCredential,
  listIdentityCredentials,
  listOrgIdentities,
  reactivateIdentity,
  renameIdentity,
  retireIdentity,
  SERVICE_CREDENTIAL_KINDS,
} from "../domain/identities.js";
import { createWebhook, listWebhooks, revokeWebhook, updateWebhook, type WebhookRow } from "../domain/webhooks.js";
import { invitationStatus, listInvitations, revokeInvitation, type InvitationRow } from "../domain/invitations.js";
import {
  createAppConnection,
  createConnection,
  createTarget,
  getConnection,
  getTarget,
  listConnections,
  listTargets,
  mappingWidens,
  normalizeMapping,
  replaceConnectionCredential,
  requestPush,
  requiredDisclosureActions,
  revokeConnection,
  checkConnectionAccess,
  listConnectionDestinations,
  setTargetState,
  targetLedger,
  updateTarget,
  type AccessCheckInput,
  type CredentialInput,
  type PlatformConnectionRow,
  type SyncMapping,
  type SyncTargetRow,
} from "../domain/sync.js";
import {
  GITHUB_WEB,
  completeRegistration,
  getGitHubApp,
  importGitHubApp,
  listAppInstallations,
  startRegistration,
  type GitHubAppRow,
} from "../domain/githubapps.js";
import {
  createOidcBinding,
  exchangeOidcToken,
  listOidcBindings,
  revokeOidcBinding,
  type OidcBindingRow,
} from "../domain/oidc.js";
import {
  captureExercise,
  checkIssuancePrecondition,
  exerciseCapability,
  type PreflightItem,
  issueCapability,
  listCapabilities,
  revokeCapability,
} from "../domain/capabilities.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import { captureState, inSnapshot } from "../domain/retrieval.js";
import { STATE_CATEGORIES, manifestOf, type CallerView } from "../domain/manifest.js";
import { strictRetrieval } from "../domain/strict.js";
import { mintConvexToken, publicJwks } from "../auth/jwt.js";
import { issueCredential, revokeCredential } from "../auth/credentials.js";
import { ENROLL_HTML } from "../enroll/page.js";
import { relyingPartyOf } from "../auth/approval-assertion.js";
import {
  approveDeviceSignIn,
  denyDeviceSignIn,
  findSignInByCode,
  issueApprovalChallenge,
  pollDeviceSignIn,
  requestDeviceSignIn,
} from "../domain/device-sign-in.js";
import {
  STATUS_BY_CODE,
  authorize,
  bodyHash,
  decide,
  recordDenial,
  reject,
  type Decision,
  decodeCursor,
  encodeCursor,
  errorBody,
  loadGrants,
  loadTailnetRequirements,
  requestId,
  type Principal,
} from "./support.js";

export const SERVER_VERSION = "0.16.0";

import { evaluate, requirementsCovering, type Action, type TailnetContext } from "../authz/evaluate.js";
import type { WhoisResult } from "../tailnet/whois.js";
import { tailnetBrowserGate, type TailnetBrowserOptions } from "./tailnet-browser.js";
import {
  addGroupMember,
  addTeamProject,
  createGroup,
  createRole,
  deleteGroup,
  deleteRole,
  listGroupMembers,
  listGroups,
  listRoles,
  listTeamProjects,
  removeGroupMember,
  removeTeamProject,
  updateGroup,
  updateRole,
} from "../domain/policy.js";

type Vars = {
  requestId: string;
  principal: Principal;
  tailnetContext: TailnetContext | undefined;
  /** What the tailnet listener resolved the peer to, or why not (for audit, ADR-0046 Decision 8). */
  tailnetResolution: Record<string, unknown> | undefined;
};

/**
 * The device a tailnet listener request's own connection resolved to, or
 * why there is none, in the protocol's TailnetDevice shape (ADR-0046
 * Decision 5). The one serializer for GET /v1/tailnet/context and the
 * tailnet field of GET /v1/me; it evaluates no Requirement.
 */
function tailnetDeviceOf(c: Context<{ Variables: Vars }>): TailnetDevice {
  const device = c.get("tailnetContext");
  if (!device) {
    const resolution = c.get("tailnetResolution") as { refused?: TailnetDevice["reason"] } | undefined;
    return { recognized: false, reason: resolution?.refused ?? "unrecognized" };
  }
  return {
    recognized: true,
    tailnet: device.tailnet,
    nodeId: device.nodeId,
    ...(device.nodeName ? { nodeName: device.nodeName } : {}),
    tags: device.tags,
    ...(device.userLogin ? { userLogin: device.userLogin } : {}),
  };
}

export interface BuildAppOptions {
  /** JWT issuer identifier for Application Plane tokens (public URL). */
  issuer?: string;
  /** Human authentication (Better Auth) — present only under serve. */
  humanAuth?: import("../auth/humanauth.js").HumanAuth;
  /** Absolute path to the bundled enrollment client JS. */
  enrollBundlePath?: string;
  /**
   * Present ONLY on the dedicated tailnet listener (ADR-0014 §7): resolves
   * the true socket peer to verified Tailnet Context. The ordinary listener
   * never receives a resolver, so trusted Tailnet Context is structurally
   * impossible there — headers and source IPs can never create it.
   */
  resolveTailnetContext?: (c: Context) => Promise<TailnetContext | WhoisResult | null>;
  /**
   * Present ONLY on the tailnet browser endpoint (ADR-0046), alongside
   * resolveTailnetContext: answers the node's own name only, lets the
   * allowlisted origins call the browser read routes cross-origin, and
   * serves GET /v1/tailnet/context.
   */
  tailnetBrowser?: TailnetBrowserOptions;
  /**
   * The browser endpoint's URL when this installation serves one, given to
   * every listener: GET /v1/tailnet/endpoint returns it and /v1/meta then
   * advertises tailnet.browser-reads. Unset or null: off.
   */
  browserEndpoint?: string | null;
  /** Test hook: fetch used for OIDC issuer discovery/JWKS retrieval. */
  oidcFetch?: typeof fetch;
  /** Test hook: fetch used by Platform Connection access checks. */
  syncFetch?: typeof fetch;
  clientAddress?: (c: Context) => string;
  /**
   * The browser-visible base URL (the dashboard's origin). Device sign-in
   * builds its verification address from it and runs only when it is
   * HTTPS, or a loopback address in local development.
   */
  publicUrl?: string;
  /**
   * Outbound sync installation switch (ADR-0031 §9). Undefined = enabled,
   * all bundled adapters; null = disabled (creation hidden, delivery
   * stopped, the UI points at the CLI mode); otherwise an optional adapter
   * allowlist narrowing.
   */
  sync?: { adapters: string[] | null } | null;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

/**
 * The base URL device sign-in runs on, or null when it must not run: the
 * device code and the issued credential travel only over HTTPS, except to
 * a loopback server in local development. GitHub App registration sends
 * GitHub's code back to the same base, under the same rule.
 */
function deviceSignInBase(publicUrl: string | undefined): URL | null {
  if (!publicUrl) return null;
  const url = new URL(publicUrl);
  if (url.protocol === "https:") return url;
  return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname) ? url : null;
}

function iso(v: string | Date): string {
  return new Date(v).toISOString();
}

const serialize = {
  org: (o: OrgRow) => ({ id: o.id, slug: o.slug, name: o.name, createdAt: iso(o.created_at) }),
  project: (p: ProjectRow) => ({
    id: p.id,
    organizationId: p.organization_id,
    slug: p.slug,
    name: p.name,
    contractAuthority: p.contract_authority,
    activeContractRevisionId: p.active_contract_revision_id,
    createdAt: iso(p.created_at),
  }),
  environment: (e: EnvironmentRow) => ({
    id: e.id,
    projectId: e.project_id,
    name: e.name,
    kind: e.kind,
    tier: e.tier,
    parentEnvironmentId: e.parent_environment_id,
    ownerIdentityId: e.owner_identity_id,
    expiresAt: e.expires_at ? iso(e.expires_at) : null,
    createdAt: iso(e.created_at),
  }),
  revision: (r: ContractRevisionRow, activeId: string | null) => {
    const contract = (
      typeof r.contract === "string" ? JSON.parse(r.contract) : r.contract
    ) as ConfigurationContract;
    return {
      id: r.id,
      projectId: r.project_id,
      contentHash: r.content_hash,
      semanticsVersion: semanticsVersionOf(contract),
      active: r.id === activeId,
      contract,
      provenance:
        typeof r.provenance === "string" ? JSON.parse(r.provenance) : r.provenance ?? undefined,
      createdAt: iso(r.created_at),
    };
  },
};

function serializeInvitation(r: InvitationRow) {
  return {
    id: r.id,
    name: r.invite_name ?? "Invited user",
    orgRole: r.invite_role,
    status: invitationStatus(r),
    createdAt: iso(r.created_at),
    expiresAt: iso(r.expires_at),
    createdByIdentityId: r.created_by ?? null,
    consumedAt: r.consumed_at ? iso(r.consumed_at) : null,
    revokedAt: r.revoked_at ? iso(r.revoked_at) : null,
  };
}

/** A list's `limit` query parameter: an integer in 1..500, 100 when absent. */
function parseLimit(raw: string | undefined): number {
  if (raw === undefined) return 100;
  const limit = Number(raw);
  if (!/^\d{1,3}$/.test(raw) || limit < 1 || limit > 500) {
    throw new DomainError("VALIDATION_FAILED", "limit must be an integer in 1..500");
  }
  return limit;
}

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new DomainError(
      "VALIDATION_FAILED",
      parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; "),
    );
  }
  return parsed.data;
}

/** How a withheld class is reported: an unmet Requirement, or a missing permission. */
function accessOf(decision: Decision): ValidationAccess {
  if (decision.allowed) return "allowed";
  if (decision.error.code.startsWith("TAILNET_")) return "requirement";
  if (decision.error.code === "PERMISSION_DENIED" || decision.error.code === "RESOURCE_NOT_FOUND") return "permission";
  throw decision.error;
}

/**
 * Read a JSON body before a retrieval snapshot starts, but surface a
 * malformed body only when it is used, after authorization has decided.
 */
async function readJson(c: Context): Promise<() => unknown> {
  const read = await c.req.json().then(
    (value: unknown) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  return () => {
    if (!read.ok) throw read.error;
    return read.value;
  };
}

function routeParam(c: Context, name: string): string {
  const value = c.req.param(name);
  if (!value) throw new DomainError("VALIDATION_FAILED", `Missing route parameter: ${name}`);
  return value;
}

async function scope(ctx: AppCtx, c: Context) {
  const org = await getOrganization(ctx, routeParam(c, "org"));
  return { org };
}

async function projectScope(ctx: AppCtx, c: Context) {
  const org = await getOrganization(ctx, routeParam(c, "org"));
  const project = await getProject(ctx, org.id, routeParam(c, "project"));
  return { org, project };
}

async function envScope(ctx: AppCtx, c: Context) {
  const { org, project } = await projectScope(ctx, c);
  const env = await getEnvironment(ctx, project.id, decodeURIComponent(routeParam(c, "environment")));
  return { org, project, env };
}

function envResource(org: OrgRow, project: ProjectRow, env: EnvironmentRow) {
  return {
    organizationId: org.id,
    projectId: project.id,
    environment: { id: env.id, rootId: rootIdOf(env), tier: env.tier },
  };
}

/**
 * Environments as their callers see them. tailnetRequired says reading
 * values here (non-sensitive ones included) needs verified Tailnet Context:
 * derived per response from the active Requirements with the evaluator's
 * own targeting, never stored. The covering Requirements' IDs are policy,
 * so they go only to callers holding policy.read.
 */
async function environmentsOut(
  ctx: AppCtx,
  c: Context,
  principal: Principal,
  org: OrgRow,
  project: ProjectRow,
  envs: EnvironmentRow[],
) {
  const requirements = await loadTailnetRequirements(ctx, org.id);
  const covering = envs.map((e) => requirementsCovering(requirements, envResource(org, project, e)));
  const showIds =
    covering.some((r) => r.length > 0) &&
    (await decide(ctx, c, principal, "policy.read", { organizationId: org.id })).allowed;
  return envs.map((e, i) => ({
    ...serialize.environment(e),
    tailnetRequired: covering[i]!.length > 0,
    ...(showIds && covering[i]!.length > 0 ? { tailnetRequirementIds: covering[i]!.map((r) => r.id) } : {}),
  }));
}

/** Idempotency-Key support (ADR-0018 §8). */
async function withIdempotency(
  ctx: AppCtx, c: Context, principal: Principal, endpoint: string, body: unknown,
  run: (ctx: AppCtx) => Promise<{ status: number; payload: unknown }>,
): Promise<{ status: number; payload: unknown }> {
  const key = c.req.header("Idempotency-Key");
  if (!key) return run(ctx);
  if (key.length > 200) throw new DomainError("VALIDATION_FAILED", "Idempotency-Key exceeds 200 characters");
  const digest = bodyHash(body, ctx.rootKek);
  return withTx(ctx.db, async (db) => {
    // INSERT's unique constraint waits for the first owner's transaction.
    // Both the mutation and cached response roll back if either fails.
    const claimed = await db.query(
      `INSERT INTO idempotency_keys (identity_id, endpoint, idempotency_key, body_hash, response)
       VALUES ($1,$2,$3,$4,'null'::jsonb) ON CONFLICT DO NOTHING RETURNING identity_id`,
      [principal.identity.id, endpoint, key, digest],
    );
    if (!claimed.rows[0]) {
      const existing = await db.query(
        "SELECT body_hash, response FROM idempotency_keys WHERE identity_id = $1 AND endpoint = $2 AND idempotency_key = $3",
        [principal.identity.id, endpoint, key],
      );
      const row = existing.rows[0] as { body_hash: string; response: unknown };
      if (row.body_hash !== digest) throw new DomainError("IDEMPOTENCY_CONFLICT", "Idempotency key reused with a different request body");
      return (typeof row.response === "string" ? JSON.parse(row.response) : row.response) as { status: number; payload: unknown };
    }
    const result = await run({ ...ctx, db });
    await db.query(
      "UPDATE idempotency_keys SET response = $4 WHERE identity_id = $1 AND endpoint = $2 AND idempotency_key = $3",
      [principal.identity.id, endpoint, key, JSON.stringify(result)],
    );
    return result;
  });
}

export function buildApp(ctx: AppCtx, options: BuildAppOptions = {}): Hono<{ Variables: Vars }> {
  const app = new Hono<{ Variables: Vars }>();

  app.use("*", async (c, next) => {
    const id = requestId();
    c.set("requestId", id);
    c.header("X-Request-Id", id);
    await next();
  });

  // The browser endpoint refuses foreign hosts and origins, and answers
  // preflights, before anything costs a WhoIs lookup or authentication.
  if (options.tailnetBrowser) app.use("*", tailnetBrowserGate(options.tailnetBrowser));

  const resolveTailnetContext = options.resolveTailnetContext;
  if (resolveTailnetContext) {
    app.use("*", async (c, next) => {
      const resolved = await resolveTailnetContext(c);
      // The listener's resolver says why a peer has no context; a test
      // resolver may hand over a context, or null, directly.
      const result: WhoisResult =
        resolved === null ? { ok: false, reason: "unrecognized" } : "ok" in resolved ? resolved : { ok: true, context: resolved };
      if (result.ok) c.set("tailnetContext", result.context);
      c.set("tailnetResolution", result.ok ? { ...result.context } : { refused: result.reason });
      await next();
    });
  }

  // Admission precedes authentication: even GETs can write audit/session state.
  app.use("*", async (c, next) => {
    if (!ctx.maintenance || c.req.path === "/healthz") return next();
    if (c.req.path === "/readyz" && ctx.maintenance.gate) return c.json({ ready: false, checks: { maintenance: false } }, 503);
    // Mirror publication must be able to authenticate with a cold Convex key
    // cache while draining capture work, as well as during restore reconciliation.
    // This endpoint only reads public keys; it never creates keys or audit rows.
    const gate = ctx.maintenance.gate;
    if (c.req.path === "/.well-known/jwks.json" &&
      (gate?.phase === "reconciling" || (gate?.kind === "capture" && gate.phase === "draining"))) return next();
    const leave = ctx.maintenance.enter();
    if (!leave) {
      c.header("Retry-After", "5");
      return c.json({ error: { code: "MAINTENANCE", message: "Installation maintenance; retry later", requestId: c.get("requestId") } }, 503);
    }
    try { await next(); } finally { leave(); }
  });

  app.use("*", bodyLimit({
    maxSize: 1024 * 1024,
    onError: c => c.json(errorBody("VALIDATION_FAILED", "Request body exceeds 1 MiB", c.get("requestId")), 413),
  }));
  // Bound per-process work before authentication or audit insertion. Never
  // trust caller-supplied forwarding headers for the peer identity. On the
  // tailnet listeners every forwarded peer is 127.0.0.1, so a recognized
  // device gets a window of its own (ADR-0046, Consequences).
  const windows = new Map<string, { until: number; count: number }>();
  app.use("*", async (c, next) => {
    if (c.req.path === "/healthz" || c.req.path === "/readyz") return next();
    const now = Date.now();
    const device = c.get("tailnetContext");
    const peer = device ? `node:${device.nodeId}` : options.clientAddress?.(c) ?? "local";
    let window = windows.get(peer);
    if (!window || window.until <= now) {
      for (const [key, value] of windows) if (value.until <= now) windows.delete(key);
      if (windows.size >= 10_000 && !windows.has(peer)) {
        c.header("Retry-After", "60");
        return c.json(errorBody("PERMISSION_DENIED", "Request rate exceeded", c.get("requestId")), 429);
      }
      window = { until: now + 60_000, count: 0 };
      windows.set(peer, window);
    }
    if (++window.count > 600) {
      c.header("Retry-After", String(Math.max(1, Math.ceil((window.until - now) / 1000))));
      return c.json(errorBody("PERMISSION_DENIED", "Request rate exceeded", c.get("requestId")), 429);
    }
    await next();
  });

  app.onError((err, c) => {
    const reqId = (c.get("requestId") as string) ?? requestId();
    if (err instanceof DomainError) {
      return c.json(
        errorBody(err.code, err.message, reqId, err.details),
        STATUS_BY_CODE[err.code] as 400,
      );
    }
    // Never leak internals.
    return c.json(errorBody("INTERNAL", "Internal error", reqId), 500);
  });

  app.get("/healthz", (c) => c.json({ status: "ok" }));

  app.get("/readyz", async (c) => {
    const checks = {
      schema: await schemaIsCurrent(ctx.db).catch(() => false),
      kek: await verifyLoadedKek(ctx).catch(() => false),
      installation: (await getInstallation(ctx.db).catch(() => null)) !== null,
    };
    const ready = Object.values(checks).every(Boolean);
    return c.json({ ready, checks }, ready ? 200 : 503);
  });

  // Public JWKS for Application Plane verifiers (Convex custom JWT).
  app.get("/.well-known/jwks.json", async (c) => c.json(await publicJwks(ctx)));

  // ---- Human authentication surface (ADR-0008/0009/0018 §2): /auth/* and
  // /enroll are implementation-facing, outside the /v1 compatibility contract.
  if (options.humanAuth) {
    const humanAuth = options.humanAuth;

    // Session -> Varlatch credential exchange (ADR-0018 §6): the browser's
    // httpOnly session mints a short-lived opaque /v1 bearer. Cookies still
    // never authenticate /v1 itself.
    app.post("/auth/varlatch-token", async (c) => {
      const session = await humanAuth.sessionFor(c.req.raw.headers);
      if (!session) {
        throw new DomainError("AUTHENTICATION_REQUIRED", "No authenticated session");
      }
      const { identityId } = session;
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      const issued = await issueCredential(ctx.db, {
        identityId,
        kind: "browser",
        name: "dashboard session bearer",
        expiresAt,
        actorIdentityId: identityId,
        client: clientLabel(c.req.header("User-Agent")),
        // Binds device sign-in approval challenges to this session.
        authSessionId: session.sessionId,
      });
      return c.json({ token: issued.token, identityId, expiresAt });
    });

    app.all("/auth/*", (c) => humanAuth.handler(c.req.raw));

    app.get("/enroll", (c) => c.html(ENROLL_HTML));
    app.get("/enroll.js", async (c) => {
      if (!options.enrollBundlePath) {
        throw new DomainError("RESOURCE_NOT_FOUND", "Enrollment bundle not built");
      }
      const { readFile } = await import("node:fs/promises");
      const js = await readFile(options.enrollBundlePath, "utf8");
      return c.body(js, 200, { "Content-Type": "text/javascript" });
    });
  }

  const deviceBase = deviceSignInBase(options.publicUrl);

  app.get("/v1/meta", async (c) => {
    const inst = await getInstallation(ctx.db).catch(() => null);
    // sync.targets is advertised only when the installation switch is on;
    // syncAdapters lets the dashboard offer exactly what varlatchd will push.
    const syncOn = options.sync !== null;
    // auth.device only where device sign-in can run (an HTTPS public URL).
    const hidden = new Set([
      ...(syncOn ? [] : ["sync.targets"]),
      ...(deviceBase ? [] : ["auth.device"]),
      // Advertised when configured; the endpoint itself is never in this
      // unauthenticated document (GET /v1/tailnet/endpoint has it).
      ...(options.browserEndpoint ? [] : ["tailnet.browser-reads"]),
    ]);
    return c.json({
      apiMajor: 1,
      serverVersion: SERVER_VERSION,
      // Contract Semantics versions this server evaluates (ADR-0038).
      semanticsVersions: [...SEMANTICS_VERSIONS],
      capabilities: CAPABILITIES.filter((cap) => !hidden.has(cap)),
      ...(syncOn
        ? { syncAdapters: options.sync?.adapters ?? [...SYNC_PLATFORMS] }
        : {}),
      ...(inst ? { installationId: inst.id } : {}),
    });
  });

  // ---- Bearer-only authentication for everything else under /v1 (ADR-0018 §6).
  app.use("/v1/*", async (c, next) => {
    if (c.req.path === "/v1/meta") return next();
    // The OIDC exchange authenticates with the external token itself.
    if (c.req.path === "/v1/oidc/token" && c.req.method === "POST") return next();
    // Device sign-in's CLI calls: the device code is their only bearer.
    if ((c.req.path === "/v1/auth/device" || c.req.path === "/v1/auth/device/token") && c.req.method === "POST") return next();
    const header = c.req.header("Authorization");
    if (!header?.startsWith("Bearer ")) {
      throw new DomainError("AUTHENTICATION_REQUIRED", "Provide a Varlatch bearer credential");
    }
    const result = await authenticateBearer(ctx.db, header.slice("Bearer ".length).trim());
    if (!result.ok) {
      await recordAuditEvent(ctx.db, {
        eventType: "authentication.failed",
        decision: "deny",
        requestId: c.get("requestId"),
        metadata: { reason: result.reason },
      });
      throw new DomainError("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired");
    }
    // Agent-run credentials (ADR-0023) are read-only at the HTTP layer:
    // metadata access for an Agent Run, nothing that mutates or exercises.
    // The plaintext-producing endpoints (disclosures, capability exercises)
    // are POSTs, so this also structurally excludes them regardless of what
    // the Agent's Grants say.
    if (result.credential.kind === "agent-run" && !["GET", "HEAD"].includes(c.req.method)) {
      throw new DomainError(
        "PERMISSION_DENIED",
        "Agent-run credentials are read-only: this credential cannot perform write operations",
      );
    }
    c.set("principal", {
      identity: result.identity,
      credentialId: result.credential.id,
      credentialKind: result.credential.kind,
      credentialName: result.credential.name,
      credentialExpiresAt: result.credential.expires_at,
      authSessionId: result.credential.auth_session_id ?? null,
    });
    // The rest of the request is attributed to this credential and client:
    // every audit event its identity records names them (ADR-0016 §9).
    return withAttribution(
      {
        identityId: result.identity.id,
        credentialId: result.credential.id,
        client: clientLabel(c.req.header("User-Agent")),
        // And which listener it came in on, with the device or the reason
        // there is none (ADR-0046 Decision 8).
        listener: options.resolveTailnetContext ? "tailnet" : "ordinary",
        tailnet: (c.get("tailnetResolution") as Record<string, unknown> | undefined) ?? null,
      },
      () => next(),
    );
  });

  // Where a browser reads tailnet-protected values, for any authenticated
  // caller; null when this installation serves no browser endpoint. Says
  // nothing about whether this browser can reach it (ADR-0046 Decision 6).
  app.get("/v1/tailnet/endpoint", (c) => c.json({ browserEndpoint: options.browserEndpoint ?? null }));

  // The caller's own device as this endpoint verified it, on this request's
  // connection; evaluates no Requirement. The dashboard's Connect action
  // (ADR-0046 Decision 5).
  if (options.tailnetBrowser) {
    app.get("/v1/tailnet/context", (c) => c.json(tailnetDeviceOf(c)));
  }

  app.get("/v1/installation/backups", (c) => {
    if (!c.get("principal").identity.installation_admin) throw new DomainError("PERMISSION_DENIED", "Installation Admin required");
    return c.json(ctx.maintenance ? backupStatus(ctx.maintenance.dir) : { archives: [], warnings: ["Backup supervisor is not configured"] });
  });

  // ---- Application Plane token exchange (ADR-0018 §6): a Secret Plane
  // credential mints a short-lived Convex-only JWT. One-way: varlatchd never
  // accepts these back.
  app.post("/v1/tokens/convex", async (c) => {
    const principal = c.get("principal");
    const orgs = await listOrganizationsFor(ctx, principal.identity.id);
    const issuer = options.issuer ?? "varlatch";
    const minted = await mintConvexToken(ctx, issuer, {
      sub: principal.identity.id,
      name: principal.identity.name,
      orgIds:
        principal.identity.kind === "human"
          ? orgs.map((o) => o.id)
          : principal.identity.organization_id
            ? [principal.identity.organization_id]
            : [],
      installationAdmin: principal.identity.installation_admin,
    });
    return c.json(minted);
  });

  // ---- Who am I (capability identity.whoami): the caller as this request
  // authenticated it, for any principal, human or machine, with no Grant.
  // Only the caller's own identity, organization, presenting credential and
  // connection: nothing here can name another identity, so there is nothing
  // to hide. As for the other /v1/me reads, a successful call records no
  // audit event (ADR-0016: describing the caller exercises no authority); a
  // refused credential is the bearer middleware's authentication.failed.
  app.get("/v1/me", async (c) => {
    const principal = c.get("principal");
    const { identity } = principal;
    let email: string | null = null;
    let organization: ReturnType<typeof serialize.org> | null = null;
    if (identity.kind === "human") {
      // The profile's email; its image (up to 100 KB) stays in /v1/me/profile.
      const res = await ctx.db.query(
        `SELECT u."email" AS email
         FROM auth_user_links l JOIN "user" u ON u.id = l.better_auth_user_id
         WHERE l.identity_id = $1`,
        [identity.id],
      );
      email = (res.rows[0] as { email: string | null } | undefined)?.email ?? null;
    } else if (identity.organization_id) {
      // A machine identity belongs to exactly one organization; a human to
      // none, joining organizations as a member (GET /v1/organizations).
      const res = await ctx.db.query("SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL", [
        identity.organization_id,
      ]);
      const row = res.rows[0] as OrgRow | undefined;
      organization = row ? serialize.org(row) : null;
    }
    const listener = options.resolveTailnetContext ? "tailnet" : "ordinary";
    // On the tailnet listener, the device this request's own connection
    // resolved to, as GET /v1/tailnet/context reports it.
    const tailnet = listener === "tailnet" ? tailnetDeviceOf(c) : undefined;
    return c.json({
      identity: { id: identity.id, name: identity.name, kind: identity.kind, email },
      organization,
      // The presenting credential only, never its token or its siblings.
      credential: {
        id: principal.credentialId,
        name: principal.credentialName ?? null,
        kind: principal.credentialKind,
        expiresAt: principal.credentialExpiresAt ? iso(principal.credentialExpiresAt) : null,
      },
      listener,
      ...(tailnet ? { tailnet } : {}),
    });
  });

  // ---- My profile (user-scoped). Humans only: the display name and the
  // Better Auth "user" row's email/image behind auth_user_links. Machine
  // identities have no profile; the resource simply does not exist for them.
  const loadOwnProfile = async (
    db: AppCtx["db"],
    identityId: string,
    name: string,
  ): Promise<{ identityId: string; name: string; email: string | null; image: string | null }> => {
    const res = await db.query(
      `SELECT u."email" AS email, u."image" AS image
       FROM auth_user_links l JOIN "user" u ON u.id = l.better_auth_user_id
       WHERE l.identity_id = $1`,
      [identityId],
    );
    const row = res.rows[0] as { email: string; image: string | null } | undefined;
    return { identityId, name, email: row?.email ?? null, image: row?.image ?? null };
  };

  app.get("/v1/me/profile", async (c) => {
    const principal = c.get("principal");
    if (principal.identity.kind !== "human") {
      throw new DomainError("RESOURCE_NOT_FOUND", "Machine identities have no profile");
    }
    return c.json(await loadOwnProfile(ctx.db, principal.identity.id, principal.identity.name));
  });

  app.patch("/v1/me/profile", async (c) => {
    const principal = c.get("principal");
    if (principal.identity.kind !== "human") {
      throw new DomainError("RESOURCE_NOT_FOUND", "Machine identities have no profile");
    }
    const body = parseBody(
      z.object({
        name: z.string().min(1).max(200).optional(),
        // Avatar: an inline data URL or an https URL; hard 100KB budget so a
        // profile row can never become a blob store.
        image: z.string().max(102_400).nullable().optional(),
      }),
      await c.req.json(),
    );
    if (typeof body.image === "string") {
      if (!/^data:image\/[a-z0-9.+-]+;/i.test(body.image) && !/^https:\/\//i.test(body.image)) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "image must be a data:image/… URL or an https:// URL",
        );
      }
      if (new TextEncoder().encode(body.image).length > 102_400) {
        throw new DomainError("VALIDATION_FAILED", "image must be at most 100KB");
      }
    }
    const profile = await withTx(ctx.db, async (db) => {
      if (body.name !== undefined) {
        // identities.name is what org listings and audit provenance show —
        // keep it authoritative alongside the Better Auth display name.
        await db.query("UPDATE identities SET name = $1 WHERE id = $2", [
          body.name,
          principal.identity.id,
        ]);
      }
      if (body.name !== undefined || body.image !== undefined) {
        await db.query(
          `UPDATE "user" u SET
             "name" = COALESCE($1, u."name"),
             "image" = CASE WHEN $3 THEN $2 ELSE u."image" END,
             "updatedAt" = now()
           FROM auth_user_links l
           WHERE l.better_auth_user_id = u.id AND l.identity_id = $4`,
          [body.name ?? null, body.image ?? null, body.image !== undefined, principal.identity.id],
        );
      }
      await recordAuditEvent(db, {
        eventType: "identity.profile_updated",
        decision: "info",
        actorIdentityId: principal.identity.id,
        resource: { identityId: principal.identity.id },
        metadata: {
          nameChanged: body.name !== undefined,
          imageChanged: body.image !== undefined,
        },
      });
      return loadOwnProfile(db, principal.identity.id, body.name ?? principal.identity.name);
    });
    return c.json(profile);
  });

  // ---- My credentials (user-scoped; ADR-0007's individually revocable
  // credentials made visible). Callers manage only their own.
  app.get("/v1/me/credentials", async (c) => {
    const principal = c.get("principal");
    const res = await ctx.db.query(
      `SELECT id, kind, name, created_at, expires_at, revoked_at, max_uses, use_count, client
       FROM credentials
       WHERE identity_id = $1 ORDER BY created_at DESC`,
      [principal.identity.id],
    );
    return c.json({
      items: (res.rows as Record<string, string | number | null>[]).map((r) => ({
        id: r.id,
        kind: r.kind,
        name: r.name,
        createdAt: iso(r.created_at as string),
        expiresAt: r.expires_at ? iso(r.expires_at as string) : null,
        revokedAt: r.revoked_at ? iso(r.revoked_at as string) : null,
        maxUses: r.max_uses ?? null,
        useCount: r.use_count ?? 0,
        current: r.id === principal.credentialId,
        client: r.client ?? null,
      })),
      nextCursor: null,
    });
  });

  app.delete("/v1/me/credentials/:credential", async (c) => {
    const principal = c.get("principal");
    const res = await ctx.db.query(
      "SELECT id FROM credentials WHERE id = $1 AND identity_id = $2",
      [c.req.param("credential"), principal.identity.id],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Credential not found");
    await revokeCredential(ctx.db, c.req.param("credential"), principal.identity.id);
    return c.body(null, 204);
  });

  // ---- CLI credential exchange (ADR-0024): the browser handoff delivers
  // the dashboard's 15-minute session bearer, which only needs to survive
  // the handoff itself. The CLI trades it here for a longer-lived `cli`
  // credential; the presenting bearer is revoked so the exchange is
  // one-shot. Restricted to browser bearers so a leaked CLI credential
  // cannot mint successors.
  app.post("/v1/me/credentials/cli", async (c) => {
    const principal = c.get("principal");
    if (principal.identity.kind !== "human" || principal.credentialKind !== "browser") {
      throw new DomainError(
        "PERMISSION_DENIED",
        "Only a browser session bearer may be exchanged for a CLI credential",
      );
    }
    const body = parseBody(
      z.object({
        ttlSeconds: z.number().int().min(60).max(86_400).optional(),
        name: z.string().min(1).max(200).optional(),
      }),
      await c.req.json().catch(() => ({})),
    );
    const ttlSeconds = body.ttlSeconds ?? 43_200;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const issued = await withTx(ctx.db, async (db) => {
      const consumed = await db.query(
        `UPDATE credentials SET revoked_at = now()
         WHERE id = $1 AND kind = 'browser' AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now()) RETURNING id`,
        [principal.credentialId],
      );
      if (!consumed.rows[0]) throw new DomainError("INVALID_CREDENTIAL", "Browser credential was already consumed or expired");
      await recordAuditEvent(db, { eventType: "credential.revoked", decision: "info",
        actorIdentityId: principal.identity.id, credentialId: principal.credentialId });
    return issueCredential(db, {
      identityId: principal.identity.id,
      kind: "cli",
      name: body.name ?? "browser-handoff login",
      expiresAt,
      actorIdentityId: principal.identity.id,
      metadata: { exchangedFromCredentialId: principal.credentialId, ttlSeconds },
      // The CLI's own User-Agent: this request comes from the CLI, not the browser.
      client: clientLabel(c.req.header("User-Agent")),
    });
    });
    c.header("Cache-Control", "no-store");
    return c.json({ id: issued.credentialId, token: issued.token, expiresAt }, 201);
  });

  // ---- Device-authorization sign-in (ADR-0043 Decision 2; design notes
  // "Device-authorization sign-in"). The CLI's two calls are
  // unauthenticated: the device code, kept in the CLI's private state, is
  // their bearer. Deciding takes the dashboard's session-derived browser
  // bearer of a human (an Authorization header, never an ambient cookie, so
  // no cross-site request can carry it), and approving also a fresh passkey
  // assertion bound to the sign-in, the identity, and the session.
  const deviceAvailable = (): URL => {
    if (!deviceBase) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Device sign-in is not available: this server's public URL is not HTTPS");
    }
    return deviceBase;
  };
  const devicePeer = (c: Context) => options.clientAddress?.(c) ?? "local";

  app.post("/v1/auth/device", async (c) => {
    const base = deviceAvailable();
    c.header("Cache-Control", "no-store");
    const body = parseBody(
      z.object({
        ttlSeconds: z.number().int().min(60).max(86_400).optional(),
        name: z.string().min(1).max(200).optional(),
      }),
      await c.req.json().catch(() => ({})),
    );
    const created = await requestDeviceSignIn(ctx, {
      ttlSeconds: body.ttlSeconds,
      name: body.name,
      peer: devicePeer(c),
      userAgent: c.req.header("User-Agent") ?? null,
      requestId: c.get("requestId"),
    });
    return c.json({
      deviceCode: created.deviceCode,
      userCode: created.userCode,
      verificationUri: `${base.origin}${base.pathname.replace(/\/+$/, "")}/device`,
      expiresIn: created.expiresIn,
      interval: created.interval,
    }, 201);
  });

  app.post("/v1/auth/device/token", async (c) => {
    deviceAvailable();
    c.header("Cache-Control", "no-store");
    const body = parseBody(z.object({ deviceCode: z.string().min(1).max(200) }), await c.req.json().catch(() => ({})));
    const outcome = await pollDeviceSignIn(ctx, {
      deviceCode: body.deviceCode,
      userAgent: c.req.header("User-Agent") ?? null,
      requestId: c.get("requestId"),
    });
    const reqId = c.get("requestId");
    switch (outcome.kind) {
      case "issued":
        return c.json({ id: outcome.id, token: outcome.token, expiresAt: outcome.expiresAt }, 201);
      case "pending":
        c.header("Retry-After", String(outcome.interval));
        return c.json(errorBody("AUTHORIZATION_PENDING", "Waiting for the person to approve this sign-in", reqId, { interval: outcome.interval }), 428);
      case "slow_down":
        c.header("Retry-After", String(outcome.interval));
        return c.json(errorBody("SLOW_DOWN", `Polled too soon; wait ${outcome.interval} seconds between polls`, reqId, { interval: outcome.interval }), 429);
      case "denied":
        return c.json(errorBody("ACCESS_DENIED", "The sign-in was denied", reqId), 403);
      case "consumed":
        return c.json(errorBody("CONSUMED", "The credential of this sign-in was already collected", reqId, { credentialId: outcome.credentialId }), 410);
      case "expired":
      case "unknown":
        return c.json(errorBody("EXPIRED", "The sign-in expired, or no sign-in has this device code", reqId), 410);
    }
  });

  const approver = (c: Context) => {
    const principal = c.get("principal") as Principal;
    if (principal.identity.kind !== "human" || principal.credentialKind !== "browser" || !principal.authSessionId) {
      throw new DomainError("PERMISSION_DENIED", "Only a person signed in to the dashboard may decide a device sign-in");
    }
    return { identityId: principal.identity.id, authSessionId: principal.authSessionId };
  };
  const pendingForCode = async (c: Context, identityId: string, userCode: string) => {
    const found = await findSignInByCode(ctx, { identityId, peer: devicePeer(c), userCode, requestId: c.get("requestId") });
    if (found.kind === "locked") {
      throw new DomainError("RATE_LIMITED", `Too many wrong codes; code entry is paused until ${found.retryAt}`, { retryAt: found.retryAt });
    }
    if (found.kind === "wrong") {
      throw new DomainError("RESOURCE_NOT_FOUND", "No pending sign-in has this code: check the code the CLI shows (it expires after 10 minutes)");
    }
    return found.signIn;
  };
  const userCodeField = z.string().min(1).max(64);

  // The typed code's sign-in, for the confirmation screen, with a fresh
  // approval challenge. Wrong codes count against the attempt limits.
  app.post("/v1/auth/device/lookup", async (c) => {
    const base = deviceAvailable();
    c.header("Cache-Control", "no-store");
    const who = approver(c);
    const body = parseBody(z.object({ userCode: userCodeField }), await c.req.json().catch(() => ({})));
    const signIn = await pendingForCode(c, who.identityId, body.userCode);
    const publicKey = await issueApprovalChallenge(ctx, relyingPartyOf(base.toString()), {
      signInId: signIn.id,
      identityId: who.identityId,
      authSessionId: who.authSessionId,
    });
    return c.json({
      signIn: {
        userCode: signIn.userCode,
        ttlSeconds: signIn.requestedTtl,
        name: signIn.requestedName,
        requesterIp: signIn.requesterIp,
        requesterUserAgent: signIn.requesterUserAgent,
        requestedAt: signIn.createdAt,
        expiresAt: signIn.expiresAt,
      },
      approval: publicKey ? { publicKey } : null,
    });
  });

  app.post("/v1/auth/device/approve", async (c) => {
    const base = deviceAvailable();
    c.header("Cache-Control", "no-store");
    const who = approver(c);
    const body = parseBody(
      z.object({
        userCode: userCodeField,
        decision: z.enum(["approve", "deny"]),
        assertion: z.record(z.string(), z.unknown()).optional(),
      }),
      await c.req.json().catch(() => ({})),
    );
    if (body.decision === "approve" && !body.assertion) {
      throw new DomainError("VALIDATION_FAILED", "assertion: approving needs a fresh passkey assertion");
    }
    const signIn = await pendingForCode(c, who.identityId, body.userCode);
    if (body.decision === "deny") {
      await denyDeviceSignIn(ctx, { signInId: signIn.id, identityId: who.identityId, requestId: c.get("requestId") });
      return c.json({ decision: "denied" });
    }
    await approveDeviceSignIn(ctx, relyingPartyOf(base.toString()), {
      signInId: signIn.id,
      identityId: who.identityId,
      authSessionId: who.authSessionId,
      assertion: body.assertion,
      requestId: c.get("requestId"),
    });
    return c.json({ decision: "approved" });
  });

  // ---- Organizations
  app.get("/v1/organizations", async (c) => {
    const principal = c.get("principal");
    const orgs = await listOrganizationsFor(ctx, principal.identity.id);
    return c.json({ items: orgs.map(serialize.org), nextCursor: null });
  });

  app.post("/v1/organizations", async (c) => {
    const principal = c.get("principal");
    if (principal.identity.kind !== "human") {
      throw new DomainError("PERMISSION_DENIED", "Only humans may create organizations");
    }
    const body = parseBody(
      z.object({ name: z.string().min(1).max(200), slug: z.string() }),
      await c.req.json(),
    );
    const org = await createOrganization(ctx, body, principal.identity.id);
    return c.json(serialize.org(org), 201);
  });

  app.get("/v1/organizations/:org", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.read", { organizationId: org.id }, { hideExistence: true });
    return c.json(serialize.org(org));
  });

  // Display name only (capability organizations.rename); the slug never
  // changes. Organization administration, like the org's webhooks.
  app.patch("/v1/organizations/:org", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(z.object({ name: z.string().trim().min(1).max(200) }), await c.req.json());
    const renamed = await renameOrganization(ctx, org.id, body.name, principal.identity.id);
    return c.json(serialize.org(renamed));
  });

  // ---- Cross-project Config Item name search (ADR-0030, capability
  // search.items). Names only — Values never participate in matching or
  // response. Candidate Environments are established from the caller's
  // per-Environment config.metadata.read entitlement BEFORE matching, so a
  // hit the caller may not see is indistinguishable from no hit and hidden
  // candidates never affect counts, page boundaries, or cursors.
  app.get("/v1/organizations/:org/config-items", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    if (principal.identity.kind !== "human" && principal.identity.organization_id !== org.id) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Organization not found");
    }
    const q = c.req.query("q");
    if (!q || q.length > 256) {
      throw new DomainError("VALIDATION_FAILED", "q is required (1-256 characters); an empty query never lists all");
    }
    const limitRaw = c.req.query("limit");
    const limit = limitRaw === undefined ? 20 : Number(limitRaw);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new DomainError("VALIDATION_FAILED", "limit must be an integer in 1..100");
    }
    const cursorRaw = c.req.query("cursor");
    let after: string[] | null = null;
    if (cursorRaw !== undefined) {
      after = decodeCursor(cursorRaw);
      if (!after || after.length !== 3) throw new DomainError("VALIDATION_FAILED", "Invalid cursor");
    }

    const orgRole =
      principal.identity.kind === "human" ? await getOrgRole(ctx, org.id, principal.identity.id) : null;
    const grants = await loadGrants(ctx, org.id, principal.identity.id);
    if (principal.identity.kind === "human" && orgRole === null && grants.length === 0) {
      // Zero visibility: not-found-equivalent (anti-enumeration, ADR-0018 §11).
      throw new DomainError("RESOURCE_NOT_FOUND", "Organization not found");
    }

    const envRes = await ctx.db.query(
      `SELECT e.id, e.name, e.tier, e.parent_environment_id, e.project_id,
              p.slug AS project_slug, p.name AS project_name
       FROM environments e JOIN projects p ON p.id = e.project_id
       WHERE p.organization_id = $1 AND e.deleted_at IS NULL
         AND (e.expires_at IS NULL OR e.expires_at > now())`,
      [org.id],
    );
    type SearchEnv = {
      id: string;
      name: string;
      tier: "development" | "staging" | "production";
      parent_environment_id: string | null;
      project_id: string;
      project_slug: string;
      project_name: string;
    };
    // config.metadata.read is not tailnet-constrained, so Requirements never
    // apply here and the evaluator runs with none.
    const eligible = (envRes.rows as SearchEnv[]).filter(
      (e) =>
        evaluate({
          action: "config.metadata.read",
          resource: {
            organizationId: org.id,
            projectId: e.project_id,
            environment: { id: e.id, rootId: e.parent_environment_id ?? e.id, tier: e.tier },
          },
          orgRole,
          grants,
          requirements: [],
          tailnetContext: null,
        }).allowed,
    );

    // Effective presence (ADR-0030 §3): a live entry in the Environment or
    // inherited from its parent, matching resolveItems' resolution.
    const envIds = [
      ...new Set([
        ...eligible.map((e) => e.id),
        ...eligible.map((e) => e.parent_environment_id).filter((p): p is string => p !== null),
      ]),
    ];
    const namesByEnv = new Map<string, Set<string>>();
    if (envIds.length > 0) {
      const items = await ctx.db.query(
        "SELECT environment_id, item_name FROM env_values WHERE environment_id = ANY($1) AND deleted_at IS NULL AND current_version_id IS NOT NULL",
        [envIds],
      );
      for (const r of items.rows as { environment_id: string; item_name: string }[]) {
        (namesByEnv.get(r.environment_id) ?? namesByEnv.set(r.environment_id, new Set()).get(r.environment_id))!.add(
          r.item_name,
        );
      }
    }

    // Literal case-insensitive substring: every character of q is literal.
    const needle = q.toLowerCase();
    interface Hit {
      projectId: string;
      projectSlug: string;
      projectName: string;
      name: string;
      environments: SearchEnv[];
    }
    const hits = new Map<string, Hit>();
    for (const e of eligible) {
      const effective = new Set([
        ...(namesByEnv.get(e.id) ?? []),
        ...(e.parent_environment_id ? (namesByEnv.get(e.parent_environment_id) ?? []) : []),
      ]);
      for (const name of effective) {
        if (!name.toLowerCase().includes(needle)) continue;
        const key = `${e.project_id}\0${name}`;
        const hit =
          hits.get(key) ??
          hits
            .set(key, {
              projectId: e.project_id,
              projectSlug: e.project_slug,
              projectName: e.project_name,
              name,
              environments: [],
            })
            .get(key)!;
        hit.environments.push(e);
      }
    }

    // Deterministic ordering: project slug, exact item name, project id.
    const tuple = (h: Hit) => [h.projectSlug, h.name, h.projectId] as const;
    const lt = (a: readonly string[], b: readonly string[]) => {
      for (let i = 0; i < 3; i++) {
        if (a[i]! < b[i]!) return true;
        if (a[i]! > b[i]!) return false;
      }
      return false;
    };
    let sorted = [...hits.values()].sort((a, b) => (lt(tuple(a), tuple(b)) ? -1 : 1));
    if (after) {
      const cursorTuple = after as unknown as readonly string[];
      sorted = sorted.filter((h) => lt(cursorTuple, tuple(h)));
    }
    const page = sorted.slice(0, limit);
    const last = page[page.length - 1];
    const nextCursor = sorted.length > limit && last ? encodeCursor([...tuple(last)]) : null;

    // Sensitivity from the active Contract's effective metadata; items
    // absent from the Contract default to sensitive.
    const projectIds = [...new Set(page.map((h) => h.projectId))];
    const contracts = new Map<string, Awaited<ReturnType<typeof activeContractOf>>>();
    if (projectIds.length > 0) {
      const projects = await ctx.db.query("SELECT * FROM projects WHERE id = ANY($1)", [projectIds]);
      for (const p of projects.rows as ProjectRow[]) {
        contracts.set(p.id, await activeContractOf(ctx, p));
      }
    }

    const MAX_ENVIRONMENTS = 50;
    return c.json({
      items: page.map((h) => ({
        project: { id: h.projectId, slug: h.projectSlug, name: h.projectName },
        name: h.name,
        sensitive: sensitivityOf(contracts.get(h.projectId) ?? null, h.name),
        environments: h.environments
          .slice(0, MAX_ENVIRONMENTS)
          .map((e) => ({ id: e.id, name: e.name, tier: e.tier })),
        ...(h.environments.length > MAX_ENVIRONMENTS ? { environmentsTruncated: true } : {}),
      })),
      nextCursor,
    });
  });

  // ---- Projects
  app.get("/v1/organizations/:org/projects", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "project.read", { organizationId: org.id }, { hideExistence: true });
    const projects = await listProjects(ctx, org.id);
    return c.json({ items: projects.map(serialize.project), nextCursor: null });
  });

  app.post("/v1/organizations/:org/projects", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "project.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        name: z.string().min(1).max(200),
        slug: z.string(),
        contractAuthority: z.enum(["git", "managed"]),
      }),
      await c.req.json(),
    );
    const project = await createProject(ctx, org.id, body, principal.identity.id);
    return c.json(serialize.project(project), 201);
  });

  app.get("/v1/organizations/:org/projects/:project", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "project.read", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    return c.json(serialize.project(project));
  });

  // Display name only (capability projects.rename); the slug never changes.
  app.patch("/v1/organizations/:org/projects/:project", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "project.manage", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    const body = parseBody(z.object({ name: z.string().min(1).max(200) }), await c.req.json());
    const renamed = await renameProject(ctx, org.id, project.id, body.name, principal.identity.id);
    return c.json(serialize.project(renamed));
  });

  // ---- Environments
  app.get("/v1/organizations/:org/projects/:project/environments", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "project.read", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    const envs = await listEnvironments(ctx, project.id);
    return c.json({ items: await environmentsOut(ctx, c, principal, org, project, envs), nextCursor: null });
  });

  app.post("/v1/organizations/:org/projects/:project/environments", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    const body = parseBody(
      z.object({
        name: z.string().min(1),
        tier: z.enum(TIERS).optional(),
        kind: z.enum(["shared", "personal", "preview"]).optional(),
        parentEnvironmentId: z.string().optional(),
        expiresAt: z.string().datetime().optional(),
      }),
      await c.req.json(),
    );
    // Creating a derived environment is environment.manage on the parent's
    // context; creating a root is project-level management.
    if (body.parentEnvironmentId) {
      const parent = await getEnvironment(ctx, project.id, body.parentEnvironmentId);
      await authorize(ctx, c, principal, "environment.manage", envResource(org, project, parent), { hideExistence: true });
    } else {
      await authorize(ctx, c, principal, "project.manage", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    }
    const env = await createEnvironment(ctx, org.id, project.id, body, principal.identity.id);
    return c.json((await environmentsOut(ctx, c, principal, org, project, [env]))[0], 201);
  });

  app.get("/v1/organizations/:org/projects/:project/environments/:environment", async (c) => {
    const principal = c.get("principal");
    const { org, project, env } = await envScope(ctx, c);
    await authorize(ctx, c, principal, "environment.read", envResource(org, project, env), { hideExistence: true });
    return c.json((await environmentsOut(ctx, c, principal, org, project, [env]))[0]);
  });

  app.delete("/v1/organizations/:org/projects/:project/environments/:environment", async (c) => {
    const principal = c.get("principal");
    const { org, project, env } = await envScope(ctx, c);
    // Deletion mirrors creation (ADR-0025): a derived environment is
    // environment.manage on its root's context (envResource carries the
    // root id); a root is project-level management.
    if (env.parent_environment_id) {
      await authorize(ctx, c, principal, "environment.manage", envResource(org, project, env), { hideExistence: true });
    } else {
      await authorize(ctx, c, principal, "project.manage", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    }
    await deleteEnvironment(ctx, org.id, project, env, principal.identity.id);
    return c.body(null, 204);
  });

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/validate",
    async (c) => {
      const principal = c.get("principal");
      // Snapshot phase (ADR-0038 Decision 6): every read, and authorization
      // evaluated on the snapshot's inputs, writing nothing.
      const phase = await inSnapshot(ctx, async (sctx, now) => {
        const scope = await envScope(sctx, c);
        const resource = envResource(scope.org, scope.project, scope.env);
        const read = await decide(sctx, c, principal, "environment.read", resource, { hideExistence: true });
        if (!read.allowed) return { denied: read };
        // Verdicts are value-derived, so each class needs the right to read
        // what it describes (secret.reveal for Secrets, with its Requirements).
        const decisions = {
          metadata: await decide(sctx, c, principal, "config.metadata.read", resource),
          plain: await decide(sctx, c, principal, "config.value.read", resource),
          secret: await decide(sctx, c, principal, "secret.reveal", resource),
        };
        const state = await captureState(sctx, scope, now, (item) =>
          decisions.metadata.allowed && (item.sensitive ? decisions.secret.allowed : decisions.plain.allowed),
        );
        return { state, decisions };
      });
      if ("denied" in phase) return reject(ctx, phase.denied);
      // Without the right the item is "not evaluated"; nothing is decrypted.
      // A class's denial is recorded only if validation consults it.
      const consult = (decision: Decision) => {
        let consulted: Promise<ValidationAccess> | undefined;
        return () =>
          (consulted ??= (async (): Promise<ValidationAccess> => {
            if (decision.allowed) return "allowed";
            await recordDenial(ctx, decision);
            if (decision.error.code.startsWith("TAILNET_")) return "requirement";
            if (decision.error.code === "PERMISSION_DENIED" || decision.error.code === "RESOURCE_NOT_FOUND") {
              return "permission";
            }
            throw decision.error;
          })());
      };
      const report = await validateEnvironment(ctx, phase.state, {
        access: {
          metadata: consult(phase.decisions.metadata),
          plain: consult(phase.decisions.plain),
          secret: consult(phase.decisions.secret),
        },
        actorIdentityId: principal.identity.id,
        requestId: c.get("requestId"),
      });
      c.header("Cache-Control", "no-store");
      return c.json(report);
    },
  );

  // ---- Values
  app.put(
    "/v1/organizations/:org/projects/:project/environments/:environment/values/:item",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      await authorize(ctx, c, principal, "config.value.write", envResource(org, project, env), { hideExistence: true });
      const body = parseBody(
        z.object({ value: z.string(), expectedVersionId: z.string().optional() }),
        await c.req.json(),
      );
      const endpoint = `PUT values ${env.id}/${c.req.param("item")}`;
      const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => {
        const result = await setValue(ctx, org, project, env, c.req.param("item"), body, principal.identity.id);
        return {
          status: 200,
          payload: {
            versionId: result.versionId,
            itemName: result.itemName,
            environmentId: result.environmentId,
            sensitive: result.sensitive,
            previousVersionId: result.previousVersionId,
            createdAt: new Date().toISOString(),
          },
        };
      });
      return c.json(payload as Record<string, unknown>, status as 200);
    },
  );

  app.delete(
    "/v1/organizations/:org/projects/:project/environments/:environment/values/:item",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      await authorize(ctx, c, principal, "config.value.write", envResource(org, project, env), { hideExistence: true });
      await deleteValue(ctx, org, project, env, c.req.param("item"), principal.identity.id);
      return c.body(null, 204);
    },
  );

  // Dual-phase rotation (ADR-0027): begin overlaps the new primary with the
  // prior value for a grace window; complete drops the retiring value early.
  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      await authorize(ctx, c, principal, "config.value.write", envResource(org, project, env), { hideExistence: true });
      const body = parseBody(
        z.object({
          value: z.string(),
          expectedVersionId: z.string().optional(),
          graceSeconds: z.number().int().min(1).max(2_592_000).optional(),
        }),
        await c.req.json(),
      );
      const result = await beginRotation(ctx, org, project, env, c.req.param("item"), body, principal.identity.id);
      return c.json(
        {
          itemName: result.itemName,
          environmentId: result.environmentId,
          primaryVersionId: result.primaryVersionId,
          retiringVersionId: result.retiringVersionId,
          rotationDeadline: result.rotationDeadline,
          sensitive: result.sensitive,
        },
        201,
      );
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations/complete",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      await authorize(ctx, c, principal, "config.value.write", envResource(org, project, env), { hideExistence: true });
      const result = await completeRotation(ctx, org, project, env, c.req.param("item"), principal.identity.id);
      return c.json({
        itemName: result.itemName,
        environmentId: result.environmentId,
        primaryVersionId: result.primaryVersionId,
        sensitive: result.sensitive,
      });
    },
  );

  app.get(
    "/v1/organizations/:org/projects/:project/environments/:environment/effective-configuration",
    async (c) => {
      const principal = c.get("principal");
      const includeValues = c.req.query("include") === "values";
      const phase = await inSnapshot(ctx, async (sctx, now) => {
        const scope = await envScope(sctx, c);
        const resource = envResource(scope.org, scope.project, scope.env);
        const metadata = await decide(sctx, c, principal, "config.metadata.read", resource, { hideExistence: true });
        if (!metadata.allowed) return { denied: metadata };
        // include=values returns NON-SENSITIVE plaintext only (design R2):
        // Secrets always require the explicit POST disclosure operation.
        const plain = includeValues ? await decide(sctx, c, principal, "config.value.read", resource) : null;
        const state = await captureState(sctx, scope, now, (item) => !item.sensitive && plain?.allowed === true);
        return { state, plain };
      });
      if ("denied" in phase) return reject(ctx, phase.denied);
      const { state, plain } = phase;
      if (plain && !plain.allowed) {
        await recordDenial(ctx, plain);
        if (plain.error.code.startsWith("TAILNET_")) throw plain.error;
      }
      const { items, unexpanded } = await effectiveConfiguration(ctx, state, {
        includeValues,
        mayReadValue: (sensitive) => !sensitive && plain?.allowed === true,
        actorIdentityId: principal.identity.id,
        requestId: c.get("requestId"),
      });
      // Non-sensitive values withheld from this caller; Secrets are never on this path.
      const withheld: CallerView["withheld"] =
        plain && !plain.allowed
          ? state.items
              .filter((i) => !i.sensitive)
              .map((i) => ({
                name: i.name,
                requires: "config.value.read" as const,
                reason: accessOf(plain) === "requirement" ? ("requirement" as const) : ("permission" as const),
              }))
          : [];
      return c.json({
        environmentId: state.env.id,
        items,
        ...manifestOf(state),
        callerView: { withheld, unexpanded },
      });
    },
  );

  // Requested Secret disclosure: an explicit POST security operation. The
  // request declares its items or an intentional all-authorized scope; the
  // single audit event enumerates exactly what was returned. Never cacheable.
  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/disclosures",
    async (c) => {
      const principal = c.get("principal");
      const input = await readJson(c);
      const phase = await inSnapshot(ctx, async (sctx, now) => {
        const scope = await envScope(sctx, c);
        const resource = envResource(scope.org, scope.project, scope.env);
        const reveal = await decide(sctx, c, principal, "secret.reveal", resource, { hideExistence: true });
        if (!reveal.allowed) return { denied: reveal };
        // A declared purpose is recorded in the audit events, and only a
        // known one is accepted (ADR-0038 Decision 14).
        const purpose = z.enum(DISCLOSURE_PURPOSES).optional();
        const body = parseBody(
          z.union([
            z.object({ items: z.array(z.string().min(1)).min(1), purpose }),
            z.object({ scope: z.literal("all-authorized-secrets"), purpose }),
          ]),
          input(),
        );
        // Reference expansion may pull non-sensitive values into disclosed
        // Secrets only if this caller could read them directly anyway.
        const plain = await decide(sctx, c, principal, "config.value.read", resource);
        // The manifest lists every item, so it goes only to a caller who may see them.
        const metadata = await decide(sctx, c, principal, "config.metadata.read", resource);
        const requested = "items" in body ? new Set(body.items) : null;
        const state = await captureState(sctx, scope, now, (item) =>
          item.sensitive ? (requested?.has(item.name) ?? true) : plain.allowed,
        );
        return { state, body, plain, metadata };
      });
      if ("denied" in phase) return reject(ctx, phase.denied);
      const { state, body, plain, metadata } = phase;
      if (!plain.allowed) {
        await recordDenial(ctx, plain);
        if (plain.error.code.startsWith("TAILNET_")) throw plain.error;
      }
      const { unexpanded, ...result } = await discloseSecrets(ctx, state, body, {
        actorIdentityId: principal.identity.id,
        requestId: c.get("requestId"),
        mayReadPlain: plain.allowed,
      });
      c.header("Cache-Control", "no-store");
      return c.json(
        metadata.allowed
          ? { ...result, ...manifestOf(state), callerView: { withheld: [], unexpanded } }
          : result,
      );
    },
  );

  // Strict retrieval (ADR-0038 Decision 6): every value this caller may
  // receive, the state manifest, the caller view, the Contract, and the
  // validation of exactly the values returned, from one snapshot, in one
  // response. Each class is authorized separately; a failure after the
  // snapshot returns an error and no values. Never cacheable.
  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/retrievals",
    async (c) => {
      const principal = c.get("principal");
      const input = await readJson(c);
      const phase = await inSnapshot(ctx, async (sctx, now) => {
        const scope = await envScope(sctx, c);
        const resource = envResource(scope.org, scope.project, scope.env);
        const metadata = await decide(sctx, c, principal, "config.metadata.read", resource, { hideExistence: true });
        if (!metadata.allowed) return { denied: metadata };
        const { mode } = parseBody(z.object({ mode: z.enum(["strict", "preflight"]) }), input());
        const plain = await decide(sctx, c, principal, "config.value.read", resource);
        const secret = await decide(sctx, c, principal, "secret.reveal", resource);
        const contract = await decide(sctx, c, principal, "contract.read", {
          organizationId: scope.org.id,
          projectId: scope.project.id,
        });
        const state = await captureState(sctx, scope, now, (item) => (item.sensitive ? secret : plain).allowed);
        return { state, plain, secret, contract, mode };
      });
      if ("denied" in phase) return reject(ctx, phase.denied);
      for (const decision of [phase.plain, phase.secret, phase.contract]) await recordDenial(ctx, decision);
      const result = await strictRetrieval(
        ctx,
        phase.state,
        { plain: accessOf(phase.plain), secret: accessOf(phase.secret), contract: phase.contract.allowed },
        {
          mode: phase.mode,
          actorIdentityId: principal.identity.id,
          requestId: c.get("requestId"),
          listener: options.resolveTailnetContext ? "tailnet" : "ordinary",
        },
      );
      c.header("Cache-Control", "no-store");
      return c.json(result);
    },
  );

  // ---- Capabilities (ADR-0022): broker-authenticated mediation surface.
  // Structural authorization is kind-based — only broker identities in-org
  // may issue/list/revoke/exercise; the Agent's secret.use is what exercise
  // evaluates. Humans with policy authority may list/revoke for oversight.
  const requireBroker = (principal: Principal, org: OrgRow): void => {
    if (principal.identity.kind !== "broker" || principal.identity.organization_id !== org.id) {
      // Non-broker machine identities and out-of-org callers learn nothing.
      throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    }
  };

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/capabilities",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      requireBroker(principal, org);
      const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
      const body = parseBody(
        z.object({
          agentIdentityId: z.string(),
          items: z.array(z.string().min(1)).min(1).max(200),
          destinations: z.array(z.string().min(1)).min(1).max(50),
          // Substitution targets per item (ADR-0039): required, but checked
          // in the domain so the error names the item, the rule, or the
          // minimum CLI version when an older CLI sends none.
          targets: z.record(z.string(), z.array(z.string()).max(8)).optional(),
          ttlSeconds: z.number().int().positive(),
          runId: z.string().max(200).optional(),
          // Agent-safe strict preflight (ADR-0038 Decision 7): the state the
          // operator's preflight retrieval saw. Confers no authority.
          precondition: z
            .object({
              projectId: z.string(),
              environmentId: z.string(),
              stateDigest: digest,
              stateDigests: z.record(z.enum(STATE_CATEGORIES), digest),
            })
            .optional(),
        }),
        await c.req.json(),
      );
      const { precondition, ...input } = body;
      let preflight: PreflightItem[] | undefined;
      if (precondition) {
        const tailnetContext = (c.get("tailnetContext") as TailnetContext | undefined) ?? null;
        const checked = await inSnapshot(ctx, async (sctx, now) =>
          checkIssuancePrecondition(sctx, { org, project, env }, now, precondition, input, tailnetContext),
        );
        if (checked.changed) {
          // Categories only, never identifiers: the client retries both requests once.
          throw new DomainError("STATE_CHANGED", "The configuration changed since the preflight retrieval", {
            categories: checked.changed,
          });
        }
        preflight = checked.items;
      }
      const issued = await issueCapability(ctx, org, project, env, principal.identity.id, input);
      c.header("Cache-Control", "no-store");
      return c.json(preflight ? { ...issued, preflightItems: preflight } : issued, 201);
    },
  );

  app.get(
    "/v1/organizations/:org/projects/:project/environments/:environment/capabilities",
    async (c) => {
      const principal = c.get("principal");
      const { org, env } = await envScope(ctx, c);
      // Brokers see their own; humans with policy.read see all (oversight).
      let brokerFilter: string | undefined;
      if (principal.identity.kind === "broker" && principal.identity.organization_id === org.id) {
        brokerFilter = principal.identity.id;
      } else {
        await authorize(ctx, c, principal, "policy.read", { organizationId: org.id }, { hideExistence: true });
      }
      const rows = await listCapabilities(ctx, org, env, { brokerIdentityId: brokerFilter });
      return c.json({
        items: rows.map((r) => ({
          id: r.id,
          brokerIdentityId: r.broker_identity_id,
          agentIdentityId: r.agent_identity_id,
          environmentId: r.environment_id,
          items: r.items,
          destinations: r.destinations,
          runId: r.run_id,
          expiresAt: iso(r.expires_at),
          revokedAt: r.revoked_at ? iso(r.revoked_at) : null,
          createdAt: iso(r.created_at),
        })),
        nextCursor: null,
      });
    },
  );

  app.delete(
    "/v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability",
    async (c) => {
      const principal = c.get("principal");
      const { org } = await envScope(ctx, c);
      let brokerFilter: string | undefined;
      if (principal.identity.kind === "broker" && principal.identity.organization_id === org.id) {
        brokerFilter = principal.identity.id;
      } else {
        await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
      }
      await revokeCapability(ctx, org, c.req.param("capability"), {
        actorIdentityId: principal.identity.id,
        brokerIdentityId: brokerFilter,
      });
      return c.body(null, 204);
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability/exercises",
    async (c) => {
      const principal = c.get("principal");
      const input = await readJson(c);
      const tailnetContext = (c.get("tailnetContext") as TailnetContext | undefined) ?? null;
      const phase = await inSnapshot(ctx, async (sctx, now) => {
        const scope = await envScope(sctx, c);
        requireBroker(principal, scope.org);
        const body = parseBody(
          z.object({
            capabilitySecret: z.string().min(1),
            destination: z.object({
              host: z.string().min(1),
              port: z.number().int().min(1).max(65535),
            }),
            // Each substitution the Broker will make (ADR-0039 Decision 7).
            placements: z.array(z.object({ item: z.string().min(1), target: z.string().min(1) })).max(200).optional(),
          }),
          input(),
        );
        const captured = await captureExercise(sctx, scope, now, c.req.param("capability"), tailnetContext);
        return { captured, body };
      });
      const result = await exerciseCapability(
        ctx,
        phase.captured,
        principal.identity.id,
        { capabilityId: c.req.param("capability"), ...phase.body },
        {
          tailnetContext,
          requestId: c.get("requestId"),
          listener: options.resolveTailnetContext ? "tailnet" : "ordinary",
        },
      );
      c.header("Cache-Control", "no-store");
      return c.json(result);
    },
  );

  // Atomic change set: one reviewed save = one all-or-nothing transaction
  // with expected-version guards on sets and deletes.
  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/changes",
    async (c) => {
      const principal = c.get("principal");
      const { org, project, env } = await envScope(ctx, c);
      await authorize(ctx, c, principal, "config.value.write", envResource(org, project, env), { hideExistence: true });
      const body = parseBody(
        z.object({
          changes: z
            .array(
              z.discriminatedUnion("op", [
                z.object({
                  op: z.literal("set"),
                  item: z.string().min(1),
                  value: z.string(),
                  expectedVersionId: z.string().optional(),
                }),
                z.object({
                  op: z.literal("delete"),
                  item: z.string().min(1),
                  expectedVersionId: z.string().optional(),
                }),
              ]),
            )
            .min(1)
            .max(200),
        }),
        await c.req.json(),
      );
      const endpoint = `POST changes ${env.id}`;
      const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => {
        const result = await applyChangeSet(
          ctx,
          org,
          project,
          env,
          body.changes,
          principal.identity.id,
          c.get("requestId"),
        );
        return { status: 200, payload: result };
      });
      return c.json(payload as Record<string, unknown>, status as 200);
    },
  );

  // ---- Contracts
  app.get("/v1/organizations/:org/projects/:project/contract", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "contract.read", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    if (!project.active_contract_revision_id) {
      throw new DomainError("RESOURCE_NOT_FOUND", "No active Contract revision");
    }
    const revision = await getRevision(ctx, project.id, project.active_contract_revision_id);
    return c.json(serialize.revision(revision, project.active_contract_revision_id));
  });

  app.post("/v1/organizations/:org/projects/:project/contract/revisions", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "contract.submit", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        contract: z.unknown(),
        provenance: z.record(z.string(), z.string()).optional(),
      }),
      await c.req.json(),
    );
    const revision = await pushRevision(ctx, org.id, project.id, body.contract, body.provenance, principal.identity.id);
    return c.json(serialize.revision(revision, project.active_contract_revision_id), 201);
  });

  // Revisions are immutable and hold no values: generated types and exported
  // run contexts name one, and fetch exactly that one (ADR-0038 D6, D13).
  app.get("/v1/organizations/:org/projects/:project/contract/revisions/:revision", async (c) => {
    const principal = c.get("principal");
    const { org, project } = await projectScope(ctx, c);
    await authorize(ctx, c, principal, "contract.read", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
    const revision = await getRevision(ctx, project.id, c.req.param("revision"));
    return c.json(serialize.revision(revision, project.active_contract_revision_id));
  });

  app.post(
    "/v1/organizations/:org/projects/:project/contract/revisions/:revision/activate",
    async (c) => {
      const principal = c.get("principal");
      const { org, project } = await projectScope(ctx, c);
      await authorize(ctx, c, principal, "contract.activate", { organizationId: org.id, projectId: project.id }, { hideExistence: true });
      const revision = await activateRevision(ctx, org.id, project, c.req.param("revision"), principal.identity.id);
      return c.json(serialize.revision(revision, revision.id));
    },
  );

  // ---- Identities
  app.get("/v1/organizations/:org/identities", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.read", { organizationId: org.id }, { hideExistence: true });
    const identities = await listOrgIdentities(ctx, org.id);
    return c.json({
      items: identities.map((i) => ({
        id: i.id,
        name: i.name,
        kind: i.kind,
        disabled: i.disabled,
        // Operational signal (ADR-0034 §5): most recent successful
        // authentication by any of the identity's credentials, ~60s granular.
        lastSeenAt: i.last_seen_at ? iso(i.last_seen_at) : null,
        orgRole: i.org_role ?? null,
        // Better Auth profile data for humans; machines are always null.
        email: i.email ?? null,
        image: i.image ?? null,
      })),
      nextCursor: null,
    });
  });

  app.post("/v1/organizations/:org/identities", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        name: z.string().min(1).max(200),
        kind: z.enum(["service", "workload", "ci", "broker", "agent"]),
        // Optional lifetime limits for the issued service credential:
        // wall-clock TTL and/or a use budget (1 = one-shot token).
        credentialTtlSeconds: z.number().int().min(1).max(315_360_000).optional(),
        credentialMaxUses: z.number().int().min(1).max(1_000_000).optional(),
      }),
      await c.req.json(),
    );
    const { identity, credential, credentialExpiresAt } = await createMachineIdentity(
      ctx,
      org.id,
      body,
      principal.identity.id,
    );
    return c.json(
      {
        id: identity.id,
        name: identity.name,
        kind: identity.kind,
        disabled: false,
        credential,
        credentialExpiresAt,
      },
      201,
    );
  });

  // ---- Agent metadata credentials (ADR-0023, foreseen by ADR-0022 §8).
  // An in-org Broker mints a short-lived, read-only "agent-run" credential
  // for an Agent Identity so an Agent Run can read configuration metadata
  // directly. The credential establishes identity only — authority is the
  // Agent's Grants, evaluated per request as always — and the HTTP layer
  // additionally refuses every non-read operation for this credential kind.
  const loadAgentIdentity = async (c: Context, orgId: string) => {
    const res = await ctx.db.query(
      "SELECT id, kind, disabled FROM identities WHERE id = $1 AND organization_id = $2",
      [c.req.param("identity"), orgId],
    );
    const row = res.rows[0] as { id: string; kind: string; disabled: boolean } | undefined;
    // Wrong org, wrong kind, and disabled all collapse to not-found: a
    // broker learns nothing about identities it cannot mint for.
    if (!row || row.kind !== "agent" || row.disabled) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    }
    return row;
  };

  // Non-Broker path (capability identity.credentials.issue): identity.manage
  // issues another service credential for an in-org machine identity of a
  // kind creation issues one for (ADR-0034 §3's deliberate issuance, the new
  // half of a rotation, one credential per program sharing an identity).
  // Humans, ci and agent identities, disabled ones, and other organizations'
  // all collapse to not-found. The token is returned exactly once.
  const issueServiceCredential = async (c: Context, principal: Principal, org: OrgRow) => {
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    if (!SERVICE_CREDENTIAL_KINDS.has(identity.kind) || identity.disabled) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    }
    const body = parseBody(
      z.object({
        name: z.string().min(1).max(200),
        // The limits identity creation takes for its credential.
        ttlSeconds: z.number().int().min(1).max(315_360_000).optional(),
        maxUses: z.number().int().min(1).max(1_000_000).optional(),
      }),
      await c.req.json(),
    );
    const issued = await issueMachineCredential(ctx, org.id, identity.id, body, principal.identity.id);
    c.header("Cache-Control", "no-store");
    return c.json(
      {
        id: issued.credentialId,
        kind: "service" as const,
        name: body.name,
        token: issued.token,
        expiresAt: issued.expiresAt,
        maxUses: issued.maxUses,
      },
      201,
    );
  };

  app.post("/v1/organizations/:org/identities/:identity/credentials", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    if (principal.identity.kind !== "broker") return issueServiceCredential(c, principal, org);
    requireBroker(principal, org);
    const agent = await loadAgentIdentity(c, org.id);
    const body = parseBody(
      z.object({
        ttlSeconds: z.number().int().min(1).max(3600),
        runId: z.string().max(200).optional(),
      }),
      await c.req.json(),
    );
    const expiresAt = new Date(Date.now() + body.ttlSeconds * 1000).toISOString();
    const issued = await issueCredential(ctx.db, {
      identityId: agent.id,
      kind: "agent-run",
      name: body.runId ?? "agent-run",
      expiresAt,
      actorIdentityId: principal.identity.id,
      organizationId: org.id,
      metadata: { ...(body.runId ? { runId: body.runId } : {}), ttlSeconds: body.ttlSeconds },
    });
    c.header("Cache-Control", "no-store");
    return c.json({ id: issued.credentialId, token: issued.token, expiresAt }, 201);
  });

  app.delete("/v1/organizations/:org/identities/:identity/credentials/:credential", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    if (principal.identity.kind === "broker") {
      requireBroker(principal, org);
      const agent = await loadAgentIdentity(c, org.id);
      // Brokers may revoke only agent-run credentials of in-org agents —
      // never an identity's other credentials (ADR-0023's structural rule).
      const res = await ctx.db.query(
        "SELECT id FROM credentials WHERE id = $1 AND identity_id = $2 AND kind = 'agent-run'",
        [c.req.param("credential"), agent.id],
      );
      if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
      await revokeCredential(ctx.db, c.req.param("credential"), principal.identity.id, {
        organizationId: org.id,
      });
      return c.body(null, 204);
    }
    // Non-Broker path (ADR-0034 §1): identity.manage may revoke service/oidc
    // credentials of in-org machine identities — the kill switch for a leaked
    // long-term machine credential. cli/browser stay under /me/credentials.
    // Revoking one's own current credential is allowed ("burn this machine").
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    const res = await ctx.db.query(
      "SELECT id FROM credentials WHERE id = $1 AND identity_id = $2 AND kind IN ('service','oidc')",
      [c.req.param("credential"), identity.id],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    await revokeCredential(ctx.db, c.req.param("credential"), principal.identity.id, {
      organizationId: org.id,
    });
    return c.body(null, 204);
  });

  // ---- Machine identity lifecycle (ADR-0034; capability identity.lifecycle).
  app.get("/v1/organizations/:org/identities/:identity/credentials", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    // Revocation without enumeration is unusable (ADR-0034 §2). Metadata
    // only — token material is unrecoverable by construction (ADR-0007).
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    const creds = await listIdentityCredentials(ctx, identity.id);
    return c.json({
      items: creds.map((cr) => ({
        id: cr.id,
        kind: cr.kind,
        name: cr.name,
        createdAt: iso(cr.created_at),
        expiresAt: cr.expires_at ? iso(cr.expires_at) : null,
        revokedAt: cr.revoked_at ? iso(cr.revoked_at) : null,
        lastUsedAt: cr.last_used_at ? iso(cr.last_used_at) : null,
        client: cr.client ?? null,
      })),
      nextCursor: null,
    });
  });

  app.post("/v1/organizations/:org/identities/:identity/retire", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    await retireIdentity(ctx, org.id, identity.id, principal.identity.id);
    return c.json({ id: identity.id, disabled: true });
  });

  app.post("/v1/organizations/:org/identities/:identity/reactivate", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    await reactivateIdentity(ctx, org.id, identity.id, principal.identity.id);
    return c.json({ id: identity.id, disabled: false });
  });

  app.patch("/v1/organizations/:org/identities/:identity", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    const body = parseBody(
      z.object({ name: z.string().min(1).max(200) }),
      await c.req.json(),
    );
    await renameIdentity(ctx, org.id, identity.id, body.name, principal.identity.id);
    return c.json({ id: identity.id, name: body.name });
  });

  // ---- OIDC machine authentication (capability auth.oidc; ADR-0007 foresaw
  // CI federation). Bindings map a verified external OIDC token to one
  // machine Identity; the exchange mints a short-lived 'oidc' credential.
  // No stored secret exists for the workload at all.
  const loadMachineIdentity = async (c: Context, orgId: string) => {
    const res = await ctx.db.query(
      "SELECT id, kind, disabled FROM identities WHERE id = $1 AND organization_id = $2",
      [c.req.param("identity"), orgId],
    );
    const row = res.rows[0] as { id: string; kind: string; disabled: boolean } | undefined;
    if (!row || row.kind === "human") throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    return row;
  };
  const serializeBinding = (b: OidcBindingRow) => ({
    id: b.id,
    identityId: b.identity_id,
    issuer: b.issuer,
    audience: b.audience,
    subject: b.subject,
    claims: typeof b.claims === "string" ? (JSON.parse(b.claims) as Record<string, string>) : b.claims,
    createdAt: iso(b.created_at),
  });

  app.post("/v1/organizations/:org/identities/:identity/oidc-bindings", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    const body = parseBody(
      z.object({
        issuer: z.string().min(1).max(2000),
        audience: z.string().min(1).max(2000),
        subject: z.string().min(1).max(2000),
        claims: z.record(z.string(), z.string().max(2000)).optional(),
      }),
      await c.req.json(),
    );
    const binding = await createOidcBinding(ctx, org.id, identity.id, body, principal.identity.id);
    return c.json(serializeBinding(binding), 201);
  });

  app.get("/v1/organizations/:org/identities/:identity/oidc-bindings", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    const bindings = await listOidcBindings(ctx, org.id, identity.id);
    return c.json({ items: bindings.map(serializeBinding), nextCursor: null });
  });

  app.delete("/v1/organizations/:org/identities/:identity/oidc-bindings/:binding", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const identity = await loadMachineIdentity(c, org.id);
    await revokeOidcBinding(ctx, org.id, identity.id, c.req.param("binding"), principal.identity.id);
    return c.body(null, 204);
  });

  app.post("/v1/oidc/token", async (c) => {
    const body = parseBody(
      z.object({
        token: z.string().min(1).max(100_000),
        organization: z.string().min(1).max(200),
        ttlSeconds: z.number().int().min(1).max(3600).optional(),
      }),
      await c.req.json(),
    );
    const issued = await exchangeOidcToken(ctx, body.token, {
      organization: body.organization,
      ttlSeconds: body.ttlSeconds,
      requestId: c.get("requestId"),
      ...(options.oidcFetch ? { fetchImpl: options.oidcFetch } : {}),
    });
    c.header("Cache-Control", "no-store");
    return c.json(
      {
        id: issued.credentialId,
        token: issued.token,
        expiresAt: issued.expiresAt,
        identityId: issued.identityId,
      },
      201,
    );
  });

  // ---- Invitations (ADR-0006: links an admin hands out, never emails).
  app.post("/v1/organizations/:org/invitations", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({ name: z.string().min(1).max(200), role: z.enum(["admin", "member"]) }),
      await c.req.json(),
    );
    const invite = await issueInviteGrant(
      ctx,
      { organizationId: org.id, role: body.role, name: body.name },
      principal.identity.id,
    );
    // The caller composes the browser URL: <dashboard-origin>/enroll#<token>.
    return c.json({ id: invite.id, token: invite.token, expiresAt: invite.expiresAt }, 201);
  });

  // Listing and revocation (capability invitations.manage) are authorized
  // like creation. Metadata only: no token, nothing derived from one.
  app.get("/v1/organizations/:org/invitations", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    const status = c.req.query("status") ?? "pending";
    if (status !== "pending" && status !== "all") {
      throw new DomainError("VALIDATION_FAILED", "status must be pending or all");
    }
    const limit = parseLimit(c.req.query("limit"));
    const cursor = c.req.query("cursor");
    const after = cursor === undefined ? null : decodeCursor(cursor);
    if (cursor !== undefined && after?.length !== 2) throw new DomainError("VALIDATION_FAILED", "Invalid cursor");
    const { rows, more } = await listInvitations(ctx, org.id, {
      status,
      limit,
      after: after as [string, string] | null,
    });
    const last = rows[rows.length - 1];
    return c.json({
      items: rows.map(serializeInvitation),
      nextCursor: more && last ? encodeCursor([last.cursor_time, last.id]) : null,
    });
  });

  app.delete("/v1/organizations/:org/invitations/:invitation", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "identity.manage", { organizationId: org.id }, { hideExistence: true });
    await revokeInvitation(ctx, org.id, routeParam(c, "invitation"), principal.identity.id);
    return c.body(null, 204);
  });

  // ---- Grants
  app.get("/v1/organizations/:org/grants", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.read", { organizationId: org.id }, { hideExistence: true });
    const res = await ctx.db.query(
      "SELECT id, organization_id, subject_identity_id, subject_group_id, scope, actions, role_id, created_at FROM grants WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY created_at, id",
      [org.id],
    );
    return c.json({
      items: (res.rows as Record<string, unknown>[]).map((r) => ({
        id: r.id,
        organizationId: r.organization_id,
        subjectIdentityId: r.subject_identity_id,
        subjectGroupId: r.subject_group_id,
        scope: typeof r.scope === "string" ? JSON.parse(r.scope) : r.scope,
        actions: r.actions,
        roleId: r.role_id,
        createdAt: iso(r.created_at as string),
      })),
      nextCursor: null,
    });
  });

  const grantScopeSchema = z.union([
    z.object({ kind: z.literal("organization") }),
    z.object({ kind: z.literal("project"), projectId: z.string() }),
    z.object({
      kind: z.literal("environments"),
      projectId: z.string(),
      selector: z.union([
        z.object({ kind: z.literal("environments"), environmentIds: z.array(z.string()).min(1) }),
        z.object({ kind: z.literal("tier"), tier: z.enum(TIERS) }),
      ]),
    }),
    z.object({ kind: z.literal("team"), teamId: z.string() }),
  ]);
  // A complete Grant declaration: subject is an identity OR a group;
  // permission is actions OR a role. Shared by create and replace.
  const grantBodySchema = z.object({
    subjectIdentityId: z.string().optional(),
    subjectGroupId: z.string().optional(),
    scope: grantScopeSchema,
    actions: z.array(z.string()).min(1).optional(),
    roleId: z.string().optional(),
  });
  const requireOneOfEach = (body: z.infer<typeof grantBodySchema>) => {
    if ((body.subjectIdentityId ? 1 : 0) + (body.subjectGroupId ? 1 : 0) !== 1) {
      throw new DomainError("VALIDATION_FAILED", "Provide exactly one of subjectIdentityId or subjectGroupId");
    }
    if ((body.actions ? 1 : 0) + (body.roleId ? 1 : 0) !== 1) {
      throw new DomainError("VALIDATION_FAILED", "Provide exactly one of actions or roleId");
    }
  };

  app.post("/v1/organizations/:org/grants", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(grantBodySchema, await c.req.json());
    requireOneOfEach(body);
    const id = newId("grant");
    await withTx(ctx.db, async (db) => {
      await db.query(
        `INSERT INTO grants (id, organization_id, subject_identity_id, subject_group_id, scope, actions, role_id, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          id,
          org.id,
          body.subjectIdentityId ?? null,
          body.subjectGroupId ?? null,
          JSON.stringify(body.scope),
          body.actions ?? null,
          body.roleId ?? null,
          principal.identity.id,
        ],
      );
      await recordAuditEvent(db, {
        eventType: "grant.created",
        decision: "info",
        actorIdentityId: principal.identity.id,
        organizationId: org.id,
        action: "policy.manage",
        resource: {
          grantId: id,
          ...(body.subjectIdentityId ? { subjectIdentityId: body.subjectIdentityId } : {}),
          ...(body.subjectGroupId ? { subjectGroupId: body.subjectGroupId } : {}),
        },
        metadata: body.roleId ? { roleId: body.roleId } : { actions: (body.actions ?? []).join(",") },
      });
    });
    return c.json(
      {
        id,
        organizationId: org.id,
        subjectIdentityId: body.subjectIdentityId ?? null,
        subjectGroupId: body.subjectGroupId ?? null,
        scope: body.scope,
        actions: body.actions ?? null,
        roleId: body.roleId ?? null,
        createdAt: new Date().toISOString(),
      },
      201,
    );
  });

  app.delete("/v1/organizations/:org/grants/:grant", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    await withTx(ctx.db, async (db) => {
      const res = await db.query(
        "UPDATE grants SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id",
        [c.req.param("grant"), org.id],
      );
      if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Grant not found");
      await recordAuditEvent(db, {
        eventType: "grant.revoked",
        decision: "info",
        actorIdentityId: principal.identity.id,
        organizationId: org.id,
        action: "policy.manage",
        resource: { grantId: c.req.param("grant") },
      });
    });
    return c.body(null, 204);
  });

  // Grant declarations are immutable (ADR-0029 §4/5): the only edit is an
  // atomic revoke-and-replace, one transaction, linked audit events. An
  // already-revoked original is VERSION_CONFLICT so concurrent replacements
  // can never create multiple successors.
  app.post("/v1/organizations/:org/grants/:grant/replace", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(grantBodySchema, await c.req.json());
    requireOneOfEach(body);
    const grantId = c.req.param("grant");
    const endpoint = `POST grants ${grantId} replace`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => {
      const newGrantId = newId("grant");
      await withTx(ctx.db, async (db) => {
        const existing = await db.query(
          "SELECT id, revoked_at FROM grants WHERE id = $1 AND organization_id = $2 FOR UPDATE",
          [grantId, org.id],
        );
        const row = existing.rows[0] as { id: string; revoked_at: string | null } | undefined;
        if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Grant not found");
        if (row.revoked_at) {
          throw new DomainError("VERSION_CONFLICT", "Grant is already revoked or replaced");
        }
        await db.query("UPDATE grants SET revoked_at = now() WHERE id = $1", [grantId]);
        await db.query(
          `INSERT INTO grants (id, organization_id, subject_identity_id, subject_group_id, scope, actions, role_id, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            newGrantId,
            org.id,
            body.subjectIdentityId ?? null,
            body.subjectGroupId ?? null,
            JSON.stringify(body.scope),
            body.actions ?? null,
            body.roleId ?? null,
            principal.identity.id,
          ],
        );
        await recordAuditEvent(db, {
          eventType: "grant.revoked",
          decision: "info",
          actorIdentityId: principal.identity.id,
          organizationId: org.id,
          action: "policy.manage",
          resource: { grantId },
          metadata: { replacedBy: newGrantId },
        });
        await recordAuditEvent(db, {
          eventType: "grant.created",
          decision: "info",
          actorIdentityId: principal.identity.id,
          organizationId: org.id,
          action: "policy.manage",
          resource: {
            grantId: newGrantId,
            ...(body.subjectIdentityId ? { subjectIdentityId: body.subjectIdentityId } : {}),
            ...(body.subjectGroupId ? { subjectGroupId: body.subjectGroupId } : {}),
          },
          metadata: {
            replaces: grantId,
            ...(body.roleId ? { roleId: body.roleId } : { actions: (body.actions ?? []).join(",") }),
          },
        });
      });
      return {
        status: 201,
        payload: {
          replacedGrantId: grantId,
          grant: {
            id: newGrantId,
            organizationId: org.id,
            subjectIdentityId: body.subjectIdentityId ?? null,
            subjectGroupId: body.subjectGroupId ?? null,
            scope: body.scope,
            actions: body.actions ?? null,
            roleId: body.roleId ?? null,
            createdAt: new Date().toISOString(),
          },
        },
      };
    });
    return c.json(payload as Record<string, unknown>, status as 201);
  });

  // ---- Roles, Groups, Teams (ADR-0028): reusable authorization constructs.
  // All gated by policy.read (list) / policy.manage (mutate), like Grants.
  const policyRead = async (c: Context) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.read", { organizationId: org.id }, { hideExistence: true });
    return { principal, org };
  };
  const policyManage = async (c: Context) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    return { principal, org };
  };

  app.get("/v1/organizations/:org/roles", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listRoles(ctx, org.id), nextCursor: null });
  });
  app.post("/v1/organizations/:org/roles", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(
      z.object({ name: z.string().min(1).max(200), actions: z.array(z.string()).min(1) }),
      await c.req.json(),
    );
    const role = await createRole(ctx, org.id, body as { name: string; actions: Action[] }, principal.identity.id);
    return c.json(role, 201);
  });
  app.patch("/v1/organizations/:org/roles/:role", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(
      z.object({
        expectedVersion: z.number().int().min(1),
        name: z.string().min(1).max(200).optional(),
        actions: z.array(z.string()).min(1).optional(),
      }),
      await c.req.json(),
    );
    const endpoint = `PATCH roles ${c.req.param("role")}`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => ({
      status: 200,
      payload: await updateRole(
        ctx,
        org.id,
        c.req.param("role"),
        body as { expectedVersion: number; name?: string; actions?: Action[] },
        principal.identity.id,
      ),
    }));
    return c.json(payload as Record<string, unknown>, status as 200);
  });
  app.delete("/v1/organizations/:org/roles/:role", async (c) => {
    const { principal, org } = await policyManage(c);
    await deleteRole(ctx, org.id, c.req.param("role"), principal.identity.id);
    return c.body(null, 204);
  });

  app.get("/v1/organizations/:org/groups", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listGroups(ctx, org.id, "group"), nextCursor: null });
  });
  app.post("/v1/organizations/:org/groups", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(z.object({ name: z.string().min(1).max(200) }), await c.req.json());
    const group = await createGroup(ctx, org.id, { name: body.name, kind: "group" }, principal.identity.id);
    return c.json(group, 201);
  });
  app.patch("/v1/organizations/:org/groups/:group", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(
      z.object({ expectedVersion: z.number().int().min(1), name: z.string().min(1).max(200).optional() }),
      await c.req.json(),
    );
    const endpoint = `PATCH groups ${c.req.param("group")}`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => ({
      status: 200,
      payload: await updateGroup(ctx, org.id, c.req.param("group"), "group", body, principal.identity.id),
    }));
    return c.json(payload as Record<string, unknown>, status as 200);
  });
  app.delete("/v1/organizations/:org/groups/:group", async (c) => {
    const { principal, org } = await policyManage(c);
    await deleteGroup(ctx, org.id, c.req.param("group"), principal.identity.id);
    return c.body(null, 204);
  });
  app.get("/v1/organizations/:org/groups/:group/members", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listGroupMembers(ctx, org.id, c.req.param("group")), nextCursor: null });
  });
  app.post("/v1/organizations/:org/groups/:group/members", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(z.object({ identityId: z.string() }), await c.req.json());
    await addGroupMember(ctx, org.id, c.req.param("group"), body.identityId, principal.identity.id);
    return c.body(null, 204);
  });
  app.delete("/v1/organizations/:org/groups/:group/members/:identity", async (c) => {
    const { principal, org } = await policyManage(c);
    await removeGroupMember(ctx, org.id, c.req.param("group"), c.req.param("identity"), principal.identity.id);
    return c.body(null, 204);
  });

  app.get("/v1/organizations/:org/teams", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listGroups(ctx, org.id, "team"), nextCursor: null });
  });
  app.post("/v1/organizations/:org/teams", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(z.object({ name: z.string().min(1).max(200) }), await c.req.json());
    const team = await createGroup(ctx, org.id, { name: body.name, kind: "team" }, principal.identity.id);
    return c.json(team, 201);
  });
  app.patch("/v1/organizations/:org/teams/:team", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(
      z.object({ expectedVersion: z.number().int().min(1), name: z.string().min(1).max(200).optional() }),
      await c.req.json(),
    );
    const endpoint = `PATCH teams ${c.req.param("team")}`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => ({
      status: 200,
      payload: await updateGroup(ctx, org.id, c.req.param("team"), "team", body, principal.identity.id),
    }));
    return c.json(payload as Record<string, unknown>, status as 200);
  });
  app.delete("/v1/organizations/:org/teams/:team", async (c) => {
    const { principal, org } = await policyManage(c);
    await deleteGroup(ctx, org.id, c.req.param("team"), principal.identity.id);
    return c.body(null, 204);
  });
  app.get("/v1/organizations/:org/teams/:team/members", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listGroupMembers(ctx, org.id, c.req.param("team")), nextCursor: null });
  });
  app.post("/v1/organizations/:org/teams/:team/members", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(z.object({ identityId: z.string() }), await c.req.json());
    await addGroupMember(ctx, org.id, c.req.param("team"), body.identityId, principal.identity.id);
    return c.body(null, 204);
  });
  app.delete("/v1/organizations/:org/teams/:team/members/:identity", async (c) => {
    const { principal, org } = await policyManage(c);
    await removeGroupMember(ctx, org.id, c.req.param("team"), c.req.param("identity"), principal.identity.id);
    return c.body(null, 204);
  });
  app.get("/v1/organizations/:org/teams/:team/projects", async (c) => {
    const { org } = await policyRead(c);
    return c.json({ items: await listTeamProjects(ctx, org.id, c.req.param("team")), nextCursor: null });
  });
  app.post("/v1/organizations/:org/teams/:team/projects", async (c) => {
    const { principal, org } = await policyManage(c);
    const body = parseBody(z.object({ projectId: z.string() }), await c.req.json());
    await addTeamProject(ctx, org.id, c.req.param("team"), body.projectId, principal.identity.id);
    return c.body(null, 204);
  });
  app.delete("/v1/organizations/:org/teams/:team/projects/:project", async (c) => {
    const { principal, org } = await policyManage(c);
    await removeTeamProject(ctx, org.id, c.req.param("team"), routeParam(c, "project"), principal.identity.id);
    return c.body(null, 204);
  });

  // ---- Tailnet Requirements (ADR-0014): restrictive policy objects.
  app.get("/v1/organizations/:org/requirements", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.read", { organizationId: org.id }, { hideExistence: true });
    const res = await ctx.db.query(
      "SELECT id, kind, target, config, created_at, version, updated_at FROM requirements WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY created_at, id",
      [org.id],
    );
    return c.json({
      items: (res.rows as Record<string, unknown>[]).map((r) => ({
        id: r.id,
        kind: r.kind,
        target: typeof r.target === "string" ? JSON.parse(r.target) : r.target,
        selector: typeof r.config === "string" ? JSON.parse(r.config) : r.config,
        createdAt: iso(r.created_at as string),
        version: r.version,
        updatedAt: r.updated_at ? iso(r.updated_at as string) : null,
      })),
      nextCursor: null,
    });
  });

  app.post("/v1/organizations/:org/requirements", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        kind: z.literal("tailnet"),
        target: z.union([
          z.object({ kind: z.literal("tier"), tier: z.enum(TIERS) }),
          z.object({ kind: z.literal("environments"), environmentIds: z.array(z.string()).min(1) }),
        ]),
        selector: z.object({
          tailnet: z.string().min(1),
          tags: z.array(z.string()).optional(),
          users: z.array(z.string()).optional(),
          nodes: z.array(z.string()).optional(),
        }),
      }),
      await c.req.json(),
    );
    if (!body.selector.tags?.length && !body.selector.users?.length && !body.selector.nodes?.length) {
      throw new DomainError("VALIDATION_FAILED", "Selector must name at least one tag, user, or node");
    }
    const id = newId("requirement");
    await withTx(ctx.db, async (db) => {
      await db.query(
        "INSERT INTO requirements (id, organization_id, kind, target, config, created_by) VALUES ($1,$2,'tailnet',$3,$4,$5)",
        [id, org.id, JSON.stringify(body.target), JSON.stringify(body.selector), principal.identity.id],
      );
      await recordAuditEvent(db, {
        eventType: "requirement.created",
        decision: "info",
        actorIdentityId: principal.identity.id,
        organizationId: org.id,
        action: "policy.manage",
        resource: { requirementId: id },
        metadata: { kind: "tailnet", tailnet: body.selector.tailnet },
      });
    });
    return c.json({ id, kind: "tailnet", target: body.target, selector: body.selector, version: 1, updatedAt: null }, 201);
  });

  // In-place Requirement update (ADR-0029): kind is immutable; loosening a
  // selector is exactly as audited as tightening one (old/new diff).
  app.patch("/v1/organizations/:org/requirements/:requirement", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        expectedVersion: z.number().int().min(1),
        target: z
          .union([
            z.object({ kind: z.literal("tier"), tier: z.enum(TIERS) }),
            z.object({ kind: z.literal("environments"), environmentIds: z.array(z.string()).min(1) }),
          ])
          .optional(),
        selector: z
          .object({
            tailnet: z.string().min(1),
            tags: z.array(z.string()).optional(),
            users: z.array(z.string()).optional(),
            nodes: z.array(z.string()).optional(),
          })
          .optional(),
      }),
      await c.req.json(),
    );
    if (
      body.selector &&
      !body.selector.tags?.length &&
      !body.selector.users?.length &&
      !body.selector.nodes?.length
    ) {
      throw new DomainError("VALIDATION_FAILED", "Selector must name at least one tag, user, or node");
    }
    const requirementId = c.req.param("requirement");
    const endpoint = `PATCH requirements ${requirementId}`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) =>
      withTx(ctx.db, async (db) => {
        const res = await db.query(
          "SELECT id, kind, target, config, created_at, version, updated_at FROM requirements WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE",
          [requirementId, org.id],
        );
        const row = res.rows[0] as Record<string, unknown> | undefined;
        if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Requirement not found");
        if (row.version !== body.expectedVersion) {
          throw new DomainError("VERSION_CONFLICT", "Requirement was modified concurrently; reload and retry");
        }
        const oldTarget = typeof row.target === "string" ? JSON.parse(row.target) : row.target;
        const oldSelector = typeof row.config === "string" ? JSON.parse(row.config) : row.config;
        const target = body.target ?? oldTarget;
        const selector = body.selector ?? oldSelector;
        const unchanged =
          JSON.stringify(target) === JSON.stringify(oldTarget) &&
          JSON.stringify(selector) === JSON.stringify(oldSelector);
        const serialized = (version: number, updatedAt: string | null) => ({
          id: requirementId,
          kind: row.kind,
          target,
          selector,
          createdAt: iso(row.created_at as string),
          version,
          updatedAt,
        });
        if (unchanged) {
          return {
            status: 200,
            payload: serialized(row.version as number, row.updated_at ? iso(row.updated_at as string) : null),
          };
        }
        const updated = await db.query(
          "UPDATE requirements SET target = $1, config = $2, version = version + 1, updated_at = now() WHERE id = $3 RETURNING version, updated_at",
          [JSON.stringify(target), JSON.stringify(selector), requirementId],
        );
        const out = updated.rows[0] as { version: number; updated_at: string };
        await recordAuditEvent(db, {
          eventType: "requirement.updated",
          decision: "info",
          actorIdentityId: principal.identity.id,
          organizationId: org.id,
          action: "policy.manage",
          resource: { requirementId },
          metadata: {
            oldTarget: JSON.stringify(oldTarget),
            newTarget: JSON.stringify(target),
            oldSelector: JSON.stringify(oldSelector),
            newSelector: JSON.stringify(selector),
            version: out.version,
          },
        });
        return { status: 200, payload: serialized(out.version, iso(out.updated_at)) };
      }),
    );
    return c.json(payload as Record<string, unknown>, status as 200);
  });

  app.delete("/v1/organizations/:org/requirements/:requirement", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "policy.manage", { organizationId: org.id }, { hideExistence: true });
    await withTx(ctx.db, async (db) => {
      const res = await db.query(
        "UPDATE requirements SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id",
        [c.req.param("requirement"), org.id],
      );
      if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Requirement not found");
      await recordAuditEvent(db, {
        eventType: "requirement.revoked",
        decision: "info",
        actorIdentityId: principal.identity.id,
        organizationId: org.id,
        action: "policy.manage",
        resource: { requirementId: c.req.param("requirement") },
      });
    });
    return c.body(null, 204);
  });

  // ---- Audit webhooks: an operational sink for the org's audit stream.
  // Registration is org-admin territory (the receiver will see audit data),
  // deliveries are signed so receivers can verify origin and reject replays,
  // and the append-only audit_events table stays authoritative (ADR-0016).
  const serializeWebhook = (w: WebhookRow) => ({
    id: w.id,
    url: w.url,
    eventTypes: w.event_types ?? null,
    createdAt: iso(w.created_at),
    failureCount: w.failure_count,
    lastAttemptAt: w.last_attempt_at ? iso(w.last_attempt_at) : null,
    lastStatus: w.last_status ?? null,
    version: w.version,
    updatedAt: w.updated_at ? iso(w.updated_at) : null,
  });

  app.post("/v1/organizations/:org/webhooks", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        url: z.string().min(1).max(2000),
        eventTypes: z.array(z.string().min(1).max(200)).min(1).max(100).optional(),
      }),
      await c.req.json(),
    );
    const { webhook, secret } = await createWebhook(ctx, org, body, principal.identity.id);
    c.header("Cache-Control", "no-store");
    return c.json({ ...serializeWebhook(webhook), secret }, 201);
  });

  app.get("/v1/organizations/:org/webhooks", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.manage", { organizationId: org.id }, { hideExistence: true });
    const hooks = await listWebhooks(ctx, org.id);
    return c.json({ items: hooks.map(serializeWebhook), nextCursor: null });
  });

  app.patch("/v1/organizations/:org/webhooks/:webhook", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({
        expectedVersion: z.number().int().min(1),
        url: z.string().min(1).max(2000).optional(),
        eventTypes: z.array(z.string().min(1).max(200)).min(1).max(100).nullable().optional(),
      }),
      await c.req.json(),
    );
    const endpoint = `PATCH webhooks ${c.req.param("webhook")}`;
    const { status, payload } = await withIdempotency(ctx, c, principal, endpoint, body, async (ctx) => ({
      status: 200,
      payload: serializeWebhook(
        await updateWebhook(ctx, org.id, c.req.param("webhook"), body, principal.identity.id),
      ),
    }));
    return c.json(payload as Record<string, unknown>, status as 200);
  });

  app.delete("/v1/organizations/:org/webhooks/:webhook", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "organization.manage", { organizationId: org.id }, { hideExistence: true });
    await revokeWebhook(ctx, org.id, c.req.param("webhook"), principal.identity.id);
    return c.body(null, 204);
  });

  // ---- Sync Targets (ADR-0031): opt-in integrations pushing an
  // Environment's Effective Configuration to external platforms. Lifecycle
  // is gated by config.sync.manage; anything that widens what a Target may
  // disclose additionally passes the write-time disclosure gate
  // (secret.reveal / config.value.read at decision time, provenance
  // recorded). A Connection alone discloses nothing.
  const syncEnabled = options.sync !== null && options.sync !== undefined ? options.sync : { adapters: null };
  const syncDisabled = options.sync === null;
  const assertSyncEnabled = () => {
    if (syncDisabled) {
      throw new DomainError(
        "PERMISSION_DENIED",
        "Outbound sync is disabled on this Installation; use the CLI mode (varlatch sync push)",
      );
    }
  };

  const serializeConnection = (r: PlatformConnectionRow & { target_count?: number }) => ({
    id: r.id,
    organizationId: r.organization_id,
    platform: r.platform,
    baseIdentity: r.base_identity,
    name: r.name,
    ...(r.target_count !== undefined ? { targetCount: r.target_count } : {}),
    createdAt: iso(r.created_at),
    version: r.version,
    updatedAt: r.updated_at ? iso(r.updated_at) : null,
    credentialExpiresAt: r.credential_expires_at ? iso(r.credential_expires_at) : null,
    credentialExpirySeenAt: r.credential_expiry_seen_at ? iso(r.credential_expiry_seen_at) : null,
    credentialKind: r.credential_kind,
    githubAppId: r.github_app_id,
    installationId: r.github_installation_id === null ? null : Number(r.github_installation_id),
  });

  const serializeTarget = (t: SyncTargetRow) => ({
    id: t.id,
    organizationId: t.organization_id,
    projectId: t.project_id,
    environmentId: t.environment_id,
    connectionId: t.connection_id,
    destination: t.destination,
    mapping: t.mapping,
    removeOrphans: t.remove_orphans,
    redeploy: t.redeploy,
    state: t.state,
    disabledReason: t.disabled_reason ?? null,
    failureCount: t.failure_count,
    needsSync: t.needs_sync,
    lastAttemptAt: t.last_attempt_at ? iso(t.last_attempt_at) : null,
    lastResult: t.last_result ?? null,
    createdAt: iso(t.created_at),
    version: t.version,
    updatedAt: t.updated_at ? iso(t.updated_at) : null,
  });

  const mappingSchema = z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("wildcard"),
      // Exact source names or trailing-* prefixes; validated in
      // normalizeMapping (shape only here, like explicit items).
      exclude: z.array(z.string().min(1).max(200)).max(200).optional(),
    }),
    z.object({
      kind: z.literal("explicit"),
      items: z
        .array(
          z.object({
            name: z.string().min(1).max(200),
            rename: z.string().min(1).max(200).optional(),
          }),
        )
        .min(1)
        .max(500),
    }),
  ]);

  /**
   * The write-time disclosure gate (ADR-0031 §2): evaluated per required
   * action on the Environment's scope, decision-time provenance captured
   * for the audit event. Runs AFTER config.sync.manage has been checked.
   */
  const syncDisclosureGate = async (
    c: Context,
    principal: Principal,
    org: OrgRow,
    project: ProjectRow,
    env: EnvironmentRow,
    mapping: SyncMapping,
  ): Promise<Record<string, unknown>> => {
    const contract = await activeContractOf(ctx, project);
    const actions = requiredDisclosureActions(mapping, (name) => sensitivityOf(contract, name));
    const authz: Record<string, unknown> = {};
    for (const action of actions) {
      const evaluation = await authorize(ctx, c, principal, action, envResource(org, project, env));
      authz[action] = {
        grantIds: evaluation.provenance.grantIds,
        ...(evaluation.provenance.applied ? { applied: evaluation.provenance.applied } : {}),
        requirements: evaluation.requirements,
      };
    }
    return authz;
  };

  app.get("/v1/organizations/:org/platform-connections", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const items = await listConnections(ctx, org.id);
    return c.json({ items: items.map(serializeConnection), nextCursor: null });
  });

  app.post("/v1/organizations/:org/platform-connections", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const raw = await c.req.json();
    // A Connection on an installation of the Organization's GitHub App
    // (ADR-0047 Decision 2): no credential, only the installation.
    if (typeof raw === "object" && raw !== null && (raw as { credentialKind?: unknown }).credentialKind === "github-app") {
      const appBody = parseBody(
        z.object({
          credentialKind: z.literal("github-app"),
          installationId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
          name: z.string().min(1).max(200),
        }),
        raw,
      );
      const connection = await createAppConnection(ctx, org, appBody, principal.identity.id, syncEnabled.adapters, options.syncFetch);
      c.header("Cache-Control", "no-store");
      return c.json(serializeConnection(connection), 201);
    }
    const body = parseBody(
      z.object({
        platform: z.string().min(1).max(50),
        baseIdentity: z.string().min(1).max(500),
        name: z.string().min(1).max(200),
        credential: z.string().min(1).max(10_000),
        credentialKind: z.literal("token").optional(),
      }),
      raw,
    );
    if (syncEnabled.adapters && !syncEnabled.adapters.includes(body.platform)) {
      throw new DomainError(
        "VALIDATION_FAILED",
        "This Installation does not allow the requested platform adapter",
      );
    }
    const connection = await createConnection(ctx, org, body, principal.identity.id);
    c.header("Cache-Control", "no-store");
    return c.json(serializeConnection(connection), 201);
  });

  // A Connection's stored credential, a replacement for it, or a new one: the
  // credential an access check or a destination listing runs with.
  const credentialInput = (body: {
    connectionId?: string | undefined;
    platform?: string | undefined;
    baseIdentity?: string | undefined;
    credential?: string | undefined;
  }): CredentialInput => {
    const { connectionId, platform, baseIdentity, credential } = body;
    if (connectionId !== undefined) {
      if (platform !== undefined || baseIdentity !== undefined) {
        throw new DomainError("VALIDATION_FAILED", "Name a Connection, or a platform and base identity, not both");
      }
      return { connectionId, credential };
    }
    if (platform !== undefined && baseIdentity !== undefined && credential !== undefined) {
      return { platform, baseIdentity, credential };
    }
    throw new DomainError("VALIDATION_FAILED", "Name a Connection, or a platform, base identity and credential");
  };
  const credentialFields = {
    connectionId: z.string().min(1).optional(),
    platform: z.string().min(1).max(50).optional(),
    baseIdentity: z.string().min(1).max(500).optional(),
    credential: z.string().min(1).max(10_000).optional(),
  };

  // A read-only access check before anything is saved (ADR-0031, amendment
  // 2026-10-09): a new credential, a replacement for a stored one, or the
  // stored one, against the base identity and optionally a destination.
  app.post("/v1/organizations/:org/platform-connections/check", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({ ...credentialFields, destination: z.record(z.string(), z.unknown()).optional() }),
      await c.req.json(),
    );
    const input: AccessCheckInput = { ...credentialInput(body), destination: body.destination };
    const result = await checkConnectionAccess(ctx, org, input, syncEnabled.adapters, principal.identity.id, options.syncFetch);
    c.header("Cache-Control", "no-store");
    return c.json(result);
  });

  // The destinations a credential can see, for the dashboard's pickers:
  // read-only, under the access check's rules.
  app.post("/v1/organizations/:org/platform-connections/destinations", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(z.object(credentialFields), await c.req.json());
    const listing = await listConnectionDestinations(
      ctx,
      org,
      credentialInput(body),
      syncEnabled.adapters,
      principal.identity.id,
      options.syncFetch,
    );
    c.header("Cache-Control", "no-store");
    return c.json(listing);
  });

  app.get("/v1/organizations/:org/platform-connections/:connection", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const connection = await getConnection(ctx, org.id, c.req.param("connection"));
    // The full dependency list, shown BEFORE credential replacement (§9):
    // an actor managing only development Targets learns here that this
    // Connection also feeds production.
    const targets = await listTargets(ctx, { organizationId: org.id, connectionId: connection.id });
    return c.json({ ...serializeConnection(connection), targets: targets.map(serializeTarget) });
  });

  app.post("/v1/organizations/:org/platform-connections/:connection/credential", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const body = parseBody(
      z.object({ credential: z.string().min(1).max(10_000), expectedVersion: z.number().int().min(1) }),
      await c.req.json(),
    );
    // Replacement is a new disclosure grant for every non-revoked
    // referencing Target at once, atomically (§2): each Target's write-time
    // gate must pass for THIS actor, or the whole replacement is refused.
    const connection = await replaceConnectionCredential(
      ctx,
      org,
      c.req.param("connection"),
      body,
      async (target) => {
        const project = await ctx.db.query("SELECT * FROM projects WHERE id = $1", [target.project_id]);
        const env = await ctx.db.query("SELECT * FROM environments WHERE id = $1", [target.environment_id]);
        const projectRow = project.rows[0] as ProjectRow | undefined;
        const envRow = env.rows[0] as EnvironmentRow | undefined;
        if (!projectRow || !envRow) return;
        try {
          await syncDisclosureGate(c, principal, org, projectRow, envRow, target.mapping);
        } catch (err) {
          if (err instanceof DomainError && err.code !== "INTERNAL") {
            throw new DomainError(
              "PERMISSION_DENIED",
              "Replacing this credential re-authorizes every referencing Sync Target; you lack disclosure authority for at least one",
              { targetId: target.id, environmentId: target.environment_id },
            );
          }
          throw err;
        }
      },
      principal.identity.id,
    );
    c.header("Cache-Control", "no-store");
    return c.json(serializeConnection(connection));
  });

  app.delete("/v1/organizations/:org/platform-connections/:connection", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    await revokeConnection(ctx, org, c.req.param("connection"), principal.identity.id);
    return c.body(null, 204);
  });

  // ---- GitHub App (ADR-0047): one per Organization, registered through
  // GitHub's manifest flow. GitHub sends the browser back to the dashboard,
  // which completes the registration with its own bearer.
  const serializeGitHubApp = (a: GitHubAppRow) => ({
    id: a.id,
    organizationId: a.organization_id,
    githubAppId: Number(a.github_app_id),
    slug: a.slug,
    clientId: a.client_id,
    owner: { login: a.owner_login, id: Number(a.owner_id), type: a.owner_type },
    htmlUrl: `${GITHUB_WEB}/apps/${a.slug}`,
    version: a.version,
    createdAt: iso(a.created_at),
    updatedAt: a.updated_at ? iso(a.updated_at) : null,
  });
  const assertGitHubAdapterAllowed = () => {
    assertSyncEnabled();
    if (syncEnabled.adapters && !syncEnabled.adapters.includes("github-actions")) {
      throw new DomainError("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter");
    }
  };
  const assertGitHubAppsAllowed = (): URL => {
    assertGitHubAdapterAllowed();
    const base = deviceSignInBase(options.publicUrl);
    if (!base) {
      throw new DomainError(
        "VALIDATION_FAILED",
        "Registering a GitHub App needs this Installation's public URL (VARLATCH_PUBLIC_URL) over HTTPS, or a loopback address in local development",
      );
    }
    return base;
  };

  app.get("/v1/organizations/:org/github-app", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    return c.json(serializeGitHubApp(await getGitHubApp(ctx, org.id)));
  });

  app.post("/v1/organizations/:org/github-app/registrations", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const base = assertGitHubAppsAllowed();
    const body = parseBody(
      z.object({
        account: z.object({
          login: z.string().min(1).max(39),
          type: z.enum(["organization", "user"]),
        }),
      }),
      await c.req.json(),
    );
    const started = await startRegistration(ctx, org, body.account, principal.identity.id, base);
    c.header("Cache-Control", "no-store");
    return c.json(started, 201);
  });

  app.post("/v1/organizations/:org/github-app/registrations/complete", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    assertGitHubAppsAllowed();
    const body = parseBody(
      z.object({ state: z.string().min(1).max(200), code: z.string().min(1).max(200) }),
      await c.req.json(),
    );
    const result = await completeRegistration(ctx, org, body, principal.identity.id, options.syncFetch);
    c.header("Cache-Control", "no-store");
    if (result.outcome === "registered") {
      return c.json({ outcome: "registered", app: serializeGitHubApp(result.app) }, 201);
    }
    return c.json(result);
  });

  app.post("/v1/organizations/:org/github-app/import", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    assertGitHubAdapterAllowed();
    const body = parseBody(
      z.object({
        appId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        privateKey: z.string().min(1).max(10_000),
      }),
      await c.req.json(),
    );
    const result = await importGitHubApp(ctx, org, body, principal.identity.id, options.syncFetch);
    c.header("Cache-Control", "no-store");
    if (result.outcome === "registered") {
      return c.json({ outcome: "registered", app: serializeGitHubApp(result.app) }, 201);
    }
    return c.json(result);
  });

  app.get("/v1/organizations/:org/github-app/installations", async (c) => {
    assertSyncEnabled();
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    assertGitHubAdapterAllowed();
    return c.json(await listAppInstallations(ctx, org, principal.identity.id, options.syncFetch));
  });

  app.get("/v1/organizations/:org/sync-targets", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "config.sync.manage", { organizationId: org.id }, { hideExistence: true });
    const items = await listTargets(ctx, { organizationId: org.id });
    return c.json({ items: items.map(serializeTarget), nextCursor: null });
  });

  const targetEnvScope = async (c: Context) => {
    const { org, project, env } = await envScope(ctx, c);
    const principal = c.get("principal") as Principal;
    await authorize(ctx, c, principal, "config.sync.manage", envResource(org, project, env), {
      hideExistence: true,
    });
    return { org, project, env, principal };
  };

  app.get(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets",
    async (c) => {
      const { org, env } = await targetEnvScope(c);
      const items = await listTargets(ctx, { organizationId: org.id, environmentId: env.id });
      return c.json({ items: items.map(serializeTarget), nextCursor: null });
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets",
    async (c) => {
      assertSyncEnabled();
      const { org, project, env, principal } = await targetEnvScope(c);
      const body = parseBody(
        z.object({
          connectionId: z.string().min(1),
          destination: z.record(z.string(), z.unknown()),
          mapping: mappingSchema,
          removeOrphans: z.boolean().optional(),
          redeploy: z.boolean().optional(),
        }),
        await c.req.json(),
      );
      const connection = await getConnection(ctx, org.id, body.connectionId);
      const contract = await activeContractOf(ctx, project);
      const mapping = normalizeMapping(connection.platform, body.mapping, (name) =>
        sensitivityOf(contract, name),
      );
      const authz = await syncDisclosureGate(c, principal, org, project, env, mapping);
      const target = await createTarget(
        ctx,
        org,
        project.id,
        env.id,
        {
          connectionId: connection.id,
          destination: body.destination,
          mapping,
          removeOrphans: body.removeOrphans ?? false,
          redeploy: body.redeploy ?? false,
        },
        authz,
        principal.identity.id,
      );
      return c.json(serializeTarget(target), 201);
    },
  );

  const targetScope = async (c: Context) => {
    const base = await targetEnvScope(c);
    const target = await getTarget(ctx, base.org.id, routeParam(c, "target"));
    if (target.environment_id !== base.env.id) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
    }
    return { ...base, target };
  };

  app.get(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target",
    async (c) => {
      const { target } = await targetScope(c);
      const names = await targetLedger(ctx, target.id);
      return c.json({
        ...serializeTarget(target),
        names: names.map((n) => ({
          name: n.dest_name,
          state: n.state,
          updatedAt: iso(n.updated_at),
          error: n.last_error ?? null,
        })),
      });
    },
  );

  app.patch(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target",
    async (c) => {
      assertSyncEnabled();
      const { org, project, env, principal, target } = await targetScope(c);
      const body = parseBody(
        z.object({
          expectedVersion: z.number().int().min(1),
          connectionId: z.string().min(1).optional(),
          destination: z.record(z.string(), z.unknown()).optional(),
          mapping: mappingSchema.optional(),
          removeOrphans: z.boolean().optional(),
          redeploy: z.boolean().optional(),
        }),
        await c.req.json(),
      );
      const connection = await getConnection(ctx, org.id, body.connectionId ?? target.connection_id);
      const contract = await activeContractOf(ctx, project);
      const mapping = body.mapping
        ? normalizeMapping(
            connection.platform,
            body.mapping,
            (name) => sensitivityOf(contract, name),
            target.mapping,
          )
        : target.mapping;
      // Destination changes and Connection re-points are new disclosure
      // grants and re-run the full gate (§2); so does any widening. A pure
      // narrowing or operational toggle needs only config.sync.manage.
      const needsGate =
        body.destination !== undefined ||
        body.connectionId !== undefined ||
        (body.mapping !== undefined && mappingWidens(target.mapping, mapping));
      const authz = needsGate
        ? await syncDisclosureGate(c, principal, org, project, env, mapping)
        : null;
      const updated = await updateTarget(
        ctx,
        org,
        target,
        {
          expectedVersion: body.expectedVersion,
          mapping: body.mapping !== undefined ? mapping : undefined,
          destination: body.destination,
          connectionId: body.connectionId,
          removeOrphans: body.removeOrphans,
          redeploy: body.redeploy,
        },
        authz,
        principal.identity.id,
      );
      return c.json(serializeTarget(updated));
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/push",
    async (c) => {
      const { org, target } = await targetScope(c);
      assertSyncEnabled();
      await requestPush(ctx, org, target.id);
      return c.json({ scheduled: true }, 202);
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/pause",
    async (c) => {
      const { org, target, principal } = await targetScope(c);
      const updated = await setTargetState(ctx, org, target.id, "pause", principal.identity.id);
      return c.json(serializeTarget(updated as SyncTargetRow));
    },
  );

  app.post(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/resume",
    async (c) => {
      assertSyncEnabled();
      const { org, target, principal } = await targetScope(c);
      const updated = await setTargetState(ctx, org, target.id, "resume", principal.identity.id);
      return c.json(serializeTarget(updated as SyncTargetRow));
    },
  );

  app.delete(
    "/v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target",
    async (c) => {
      const { org, target, principal } = await targetScope(c);
      await setTargetState(ctx, org, target.id, "revoke", principal.identity.id);
      return c.body(null, 204);
    },
  );

  // ---- Audit
  app.get("/v1/organizations/:org/audit-events", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "audit.read", { organizationId: org.id }, { hideExistence: true });
    const limit = Math.max(1, Math.min(Math.floor(Number(c.req.query("limit") ?? 100)) || 100, 500));
    const cursor = c.req.query("cursor");
    const decoded = cursor ? decodeCursor(cursor) : null;
    if (cursor && !decoded) throw new DomainError("VALIDATION_FAILED", "Invalid cursor");
    // Filters (capability audit.filters) only add conditions: the order,
    // and so every cursor, is the same with or without them.
    const filters = parseAuditFilters((name) => c.req.queries(name));
    const params: unknown[] = [org.id, limit + 1];
    const where = ["organization_id = $1"];
    if (decoded) {
      params.push(decoded[0], decoded[1]);
      where.push("(occurred_at, id) < ($3::timestamptz, $4)");
    }
    where.push(...auditFilterConditions(filters, params));
    const res = await ctx.db.query(
      `SELECT *, occurred_at::text AS cursor_time FROM audit_events WHERE ${where.join(" AND ")} ORDER BY occurred_at DESC, id DESC LIMIT $2`,
      params,
    );
    const rows = res.rows as Record<string, unknown>[];
    const page = rows.slice(0, limit);
    const nextCursor =
      rows.length > limit && page.length > 0
        ? encodeCursor([page[page.length - 1]?.cursor_time as string, page[page.length - 1]?.id as string])
        : null;
    // The credentials the page's events name, so a reader can tell a
    // person's dashboard from their CLI, or two machines sharing an
    // identity, without a lookup per event. A sidecar of this listing only:
    // events, the export, and webhooks carry the ID alone, and an ID with no
    // stored credential is simply absent. Metadata, never token material.
    const credentialIds = [...new Set(page.map((r) => r.credential_id).filter((id): id is string => typeof id === "string"))];
    const credentials =
      credentialIds.length === 0
        ? []
        : ((await ctx.db.query("SELECT id, name, kind, client FROM credentials WHERE id = ANY($1)", [credentialIds]))
            .rows as { id: string; name: string | null; kind: string; client: string | null }[]);
    return c.json({
      items: page.map(serializeAuditEvent),
      nextCursor,
      credentials: Object.fromEntries(
        credentials.map((r) => [r.id, { name: r.name ?? null, kind: r.kind, client: r.client ?? null }]),
      ),
    });
  });

  app.get("/v1/organizations/:org/audit-events/export", async (c) => {
    const principal = c.get("principal");
    const { org } = await scope(ctx, c);
    await authorize(ctx, c, principal, "audit.read", { organizationId: org.id }, { hideExistence: true });
    // Validated before the stream starts, so a bad filter is an ordinary error response.
    const filters = parseAuditFilters((name) => c.req.queries(name));
    const highWater = await ctx.db.query("SELECT COALESCE(max(event_order), 0)::text AS value FROM audit_events WHERE organization_id = $1", [org.id]);
    const upper = (highWater.rows[0] as { value: string }).value;
    let cursor = "0";
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        const params: unknown[] = [org.id, cursor, upper];
        const where = [
          "organization_id = $1 AND event_order > $2::bigint AND event_order <= $3::bigint",
          ...auditFilterConditions(filters, params),
        ];
        const batch = await ctx.db.query(
          `SELECT *, event_order::text AS position FROM audit_events WHERE ${where.join(" AND ")} ORDER BY event_order LIMIT 250`,
          params,
        );
        const rows = batch.rows as Record<string, unknown>[];
        if (rows.length === 0) { controller.close(); return; }
        cursor = rows[rows.length - 1]!.position as string;
        controller.enqueue(encoder.encode(rows.map(row => JSON.stringify(serializeAuditEvent(row)) + "\n").join("")));
      },
    });
    return new Response(stream, { headers: { "Content-Type": "application/x-ndjson", "Cache-Control": "no-store" } });
  });

  return app;
}
