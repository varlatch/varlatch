// SPDX-License-Identifier: Apache-2.0
import type {
  AuditEventFilters,
  InstallationBackups,
  ApiError,
  CapabilityExercise,
  CapabilitySummary,
  ConfigItemSearchResult,
  ContractRevision,
  CreatedIdentity,
  DeviceSignInLookup,
  DeviceSignInStarted,
  GrantReplacement,
  IssuedCliCredential,
  OwnCredential,
  Requirement,
  IssuedAgentCredential,
  IssuedCapability,
  EffectiveConfiguration,
  Environment,
  ErrorCode,
  Grant,
  GrantScope,
  Invitation,
  Group,
  Role,
  Meta,
  Organization,
  Profile,
  Project,
  Tier,
  ValidationReport,
  StateManifest,
  CallerView,
  DisclosurePurpose,
  StrictRetrieval,
  ValueVersion,
  ValueRotation,
  Webhook,
  CreatedWebhook,
  OidcBinding,
  IssuedOidcCredential,
  PlatformConnection,
  SyncLedgerName,
  SyncMappingInput,
  SyncPlatform,
  SyncTarget,
} from "@varlatch/protocol";

/** A response's media type for a diagnostic, without parameters. */
function contentType(res: Response): string {
  return res.headers.get("Content-Type")?.split(";")[0]?.trim() || "no content type";
}

export class VarlatchApiError extends Error {
  override name = "VarlatchApiError";
  readonly code: ErrorCode;
  readonly status: number;
  readonly requestId: string;
  readonly details: Record<string, unknown> | undefined;
  constructor(status: number, body: ApiError["error"]) {
    super(body.message);
    this.status = status;
    this.code = body.code;
    this.requestId = body.requestId;
    this.details = body.details;
  }
}

/**
 * A device sign-in request answered with a redirect (ADR-0043 device
 * sign-in transport rule). The device code is a bearer, so the body is
 * never resent to another location; `location` is where the server
 * pointed, for the message.
 */
export class DeviceSignInRedirectError extends Error {
  override name = "DeviceSignInRedirectError";
  constructor(readonly status: number, readonly location: string | null) {
    super(`The server answered ${status} with a redirect${location ? ` to ${location}` : ""}; device sign-in follows no redirect`);
  }
}

/** One poll of a device sign-in (POST /v1/auth/device/token). */
export type DeviceSignInPoll =
  | { state: "issued"; credential: IssuedCliCredential }
  | { state: "pending"; interval: number }
  | { state: "slow_down"; interval: number }
  | { state: "denied" }
  | { state: "expired" }
  | { state: "consumed"; credentialId: string | null };

export interface VarlatchClientOptions {
  server: string;
  /** Opaque Varlatch bearer credential; cookies never authenticate /v1. */
  token?: string;
  fetch?: typeof fetch;
  /**
   * How long to ride out 503 MAINTENANCE responses (restore and migration
   * windows, ADR-0036 D6) before surfacing them, honoring Retry-After (with
   * jitter) between attempts. The budget belongs to the client, not to each
   * call: a command that makes several calls waits at most this long across
   * one maintenance window. It starts at the first MAINTENANCE response and
   * resets once the server answers normally. Default 180000; 0 disables retry.
   */
  maintenanceRetryMs?: number;
  /** Called before each maintenance wait, e.g. to tell a user why nothing happens. */
  onMaintenance?: (wait: MaintenanceWait) => void;
  /**
   * A User-Agent header for every request, for clients that identify
   * themselves (the CLI sends `varlatch-cli/<version> (<platform>; <arch>)`,
   * which the server summarizes as a credential's client label). Browsers
   * may ignore it; omit it there.
   */
  userAgent?: string;
}

export interface MaintenanceWait {
  /** How long this wait lasts. */
  retryInMs: number;
  /** What remains of the client's maintenance budget after it. */
  remainingMs: number;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

export interface OrgIdentity {
  id: string;
  name: string;
  kind: "human" | "service" | "workload" | "ci" | "broker" | "agent";
  disabled: boolean;
  orgRole: "admin" | "member" | null;
  /**
   * Most recent successful authentication by any of the identity's
   * credentials, ~60s granularity (ADR-0034). Null when never seen.
   */
  lastSeenAt?: string | null;
  /** Better Auth account email for humans; null/absent for machines. */
  email?: string | null;
  /** Avatar image (data or https URL) for humans; null/absent for machines. */
  image?: string | null;
}

/** Credential metadata (ADR-0034 §2); never includes token material. */
export interface IdentityCredential {
  id: string;
  kind: "service" | "cli" | "browser" | "agent-run" | "oidc";
  name: string | null;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
  /**
   * Readable client summary, such as "Firefox on Linux"; null when unknown
   * or for kinds other than browser and cli, absent from older servers.
   */
  client?: string | null;
}

export type { AuditEventFilters, DeviceSignInLookup, DeviceSignInStarted, Invitation, OwnCredential, IssuedCliCredential, Profile } from "@varlatch/protocol";

const AUDIT_FILTERS = [
  "decision",
  "eventType",
  "actorIdentityId",
  "projectId",
  "environmentId",
  "item",
  "since",
  "until",
] as const satisfies readonly (keyof AuditEventFilters)[];

function setAuditFilters(params: URLSearchParams, filters: AuditEventFilters): void {
  for (const name of AUDIT_FILTERS) {
    const value = filters[name];
    if (value) params.set(name, value);
  }
}

export class VarlatchClient {
  readonly server: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly maintenanceRetryMs: number;
  private readonly onMaintenance: ((wait: MaintenanceWait) => void) | undefined;
  private readonly userAgent: string | undefined;
  /** End of the current maintenance budget; null while the server answers normally. */
  private maintenanceDeadline: number | null = null;

  constructor(options: VarlatchClientOptions) {
    this.server = options.server.replace(/\/+$/, "");
    this.token = options.token;
    this.maintenanceRetryMs = options.maintenanceRetryMs ?? 180_000;
    this.onMaintenance = options.onMaintenance;
    this.userAgent = options.userAgent;
    // Bind to globalThis: browsers throw "Illegal invocation" when window
    // fetch is called with a foreign `this`.
    this.fetchImpl = options.fetch ?? ((...args) => globalThis.fetch(...args));
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<T> {
    // Installation maintenance that must isolate (restore, schema migration)
    // rejects requests before processing them with a retryable 503
    // MAINTENANCE + Retry-After. Ride out the window here so every consumer
    // — CI, scripts, status bars — survives it without special handling.
    // Bounded, per client: a wedged installation still surfaces as
    // MAINTENANCE, just not instantly, and never as an auth failure.
    for (;;) {
      const res = await this.requestOnce(method, path, body, headers);
      if (res.status !== 503) {
        this.maintenanceDeadline = null;
        return this.finish<T>(res);
      }
      const parsed = await res
        .clone()
        .json()
        .catch(() => undefined);
      if ((parsed as ApiError | undefined)?.error?.code !== "MAINTENANCE") return this.finish<T>(res);
      const deadline = (this.maintenanceDeadline ??= Date.now() + this.maintenanceRetryMs);
      const remaining = deadline - Date.now();
      if (remaining <= 0) return this.finish<T>(res);
      const after = Number(res.headers.get("Retry-After"));
      const base = (Number.isFinite(after) && after >= 0 ? after : 5) * 1000;
      // ±20% jitter: clients released by one window don't return in lockstep.
      const retryInMs = Math.min(Math.round(base * (0.8 + 0.4 * Math.random())), remaining);
      this.onMaintenance?.({ retryInMs, remainingMs: remaining - retryInMs });
      await new Promise((r) => setTimeout(r, retryInMs));
    }
  }

  private async requestOnce(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return this.fetchImpl(`${this.server}${path}`, {
      method,
      headers: {
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(this.userAgent ? { "User-Agent": this.userAgent } : {}),
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...headers,
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  }

  private async finish<T>(res: Response): Promise<T> {
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    // A body that is not JSON (a reverse proxy's HTML error page, a captive
    // portal) keeps its HTTP status as a VarlatchApiError instead of
    // surfacing as a SyntaxError; its content is never echoed.
    let parsed: unknown;
    let json = true;
    try {
      parsed = text ? (JSON.parse(text) as unknown) : undefined;
    } catch {
      json = false;
    }
    const fallback = (message: string) =>
      new VarlatchApiError(res.status, {
        code: "INTERNAL",
        message,
        requestId: res.headers.get("X-Request-Id") ?? "unknown",
      });
    if (!res.ok) {
      const err = (parsed as ApiError | undefined)?.error;
      if (json && err) throw new VarlatchApiError(res.status, err);
      throw fallback(json ? `HTTP ${res.status}` : `HTTP ${res.status}; the response is not a Varlatch API error (${contentType(res)})`);
    }
    if (!json) throw fallback(`HTTP ${res.status}; the response is not JSON (${contentType(res)})`);
    return parsed as T;
  }

  meta(): Promise<Meta> {
    return this.request("GET", "/v1/meta");
  }

  listOrganizations(): Promise<Page<Organization>> {
    return this.request("GET", "/v1/organizations");
  }

  createOrganization(input: { name: string; slug: string }): Promise<Organization> {
    return this.request("POST", "/v1/organizations", input);
  }

  getOrganization(org: string): Promise<Organization> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}`);
  }

  /** Rename an organization's display name; its slug never changes (capability organizations.rename). */
  renameOrganization(org: string, name: string): Promise<Organization> {
    return this.request("PATCH", `/v1/organizations/${encodeURIComponent(org)}`, { name });
  }

  listProjects(org: string): Promise<Page<Project>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/projects`);
  }

  createProject(
    org: string,
    input: { name: string; slug: string; contractAuthority: "git" | "managed" },
  ): Promise<Project> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/projects`, input);
  }

  /** Rename a project's display name; its slug never changes (capability projects.rename). */
  renameProject(org: string, project: string, name: string): Promise<Project> {
    return this.request(
      "PATCH",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}`,
      { name },
    );
  }

  listEnvironments(org: string, project: string): Promise<Page<Environment>> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments`,
    );
  }

  createEnvironment(
    org: string,
    project: string,
    input: {
      name: string;
      tier?: Tier;
      kind?: "shared" | "personal" | "preview";
      parentEnvironmentId?: string;
      expiresAt?: string;
    },
  ): Promise<Environment> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments`,
      input,
    );
  }

  deleteEnvironment(org: string, project: string, environment: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}`,
    );
  }

  setValue(
    org: string,
    project: string,
    environment: string,
    item: string,
    input: { value: string; expectedVersionId?: string },
    opts: { idempotencyKey?: string } = {},
  ): Promise<ValueVersion> {
    return this.request(
      "PUT",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/values/${encodeURIComponent(item)}`,
      input,
      opts.idempotencyKey ? { "Idempotency-Key": opts.idempotencyKey } : {},
    );
  }

  deleteValue(org: string, project: string, environment: string, item: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/values/${encodeURIComponent(item)}`,
    );
  }

  /** Begin a dual-phase rotation (ADR-0027): new primary + retiring overlap. */
  beginRotation(
    org: string,
    project: string,
    environment: string,
    item: string,
    input: { value: string; expectedVersionId?: string; graceSeconds?: number },
  ): Promise<ValueRotation> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/values/${encodeURIComponent(item)}/rotations`,
      input,
    );
  }

  /** Complete a rotation early, dropping the retiring value. */
  completeRotation(
    org: string,
    project: string,
    environment: string,
    item: string,
  ): Promise<ValueRotation> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/values/${encodeURIComponent(item)}/rotations/complete`,
      {},
    );
  }

  effectiveConfiguration(
    org: string,
    project: string,
    environment: string,
    opts: { includeValues?: boolean } = {},
  ): Promise<EffectiveConfiguration> {
    const query = opts.includeValues ? "?include=values" : "";
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/effective-configuration${query}`,
    );
  }

  /**
   * Explicit Secret disclosure. `purpose` (capability
   * secrets.disclosure-purpose) is recorded in the audit events and changes
   * nothing else; a server without the capability ignores it.
   */
  discloseSecrets(
    org: string,
    project: string,
    environment: string,
    request: ({ items: string[] } | { scope: "all-authorized-secrets" }) & { purpose?: DisclosurePurpose },
  ): Promise<{
    items: {
      name: string;
      versionId: string;
      value: string;
      retiring?: { versionId: string; value: string };
    }[];
    withheld: string[];
    /** Present when the caller also holds config.metadata.read. */
    manifest?: StateManifest;
    stateDigest?: string;
    callerView?: CallerView;
  }> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/disclosures`,
      request,
    );
  }

  /**
   * Strict retrieval (capability retrieval.strict): every value this caller
   * may receive, the state manifest, the caller view, the Contract, and the
   * validation of exactly those values, from one snapshot, in one request.
   */
  strictRetrieval(
    org: string,
    project: string,
    environment: string,
    mode: "strict" | "preflight" = "strict",
  ): Promise<StrictRetrieval> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/retrievals`,
      { mode },
    );
  }

  applyChangeSet(
    org: string,
    project: string,
    environment: string,
    changes: (
      | { op: "set"; item: string; value: string; expectedVersionId?: string }
      | { op: "delete"; item: string; expectedVersionId?: string }
    )[],
    opts: { idempotencyKey?: string } = {},
  ): Promise<{ changeSetId: string; results: { item: string; op: "set" | "delete"; versionId: string | null }[] }> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/changes`,
      { changes },
      opts.idempotencyKey ? { "Idempotency-Key": opts.idempotencyKey } : {},
    );
  }

  validateEnvironment(org: string, project: string, environment: string): Promise<ValidationReport> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/validate`,
      {},
    );
  }

  getActiveContract(org: string, project: string): Promise<ContractRevision> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/contract`,
    );
  }

  /** One stored revision by ID, active or not (capability contracts.revision-by-id). */
  getContractRevision(org: string, project: string, revisionId: string): Promise<ContractRevision> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/contract/revisions/${encodeURIComponent(revisionId)}`,
    );
  }

  pushContractRevision(
    org: string,
    project: string,
    input: { contract: unknown; provenance?: Record<string, string> },
  ): Promise<ContractRevision> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/contract/revisions`,
      input,
    );
  }

  activateContractRevision(org: string, project: string, revisionId: string): Promise<ContractRevision> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/contract/revisions/${encodeURIComponent(revisionId)}/activate`,
      {},
    );
  }

  /** The token is returned once; `id` (servers with invitations.manage) is what list and revoke use. */
  createInvitation(
    org: string,
    input: { name: string; role: "admin" | "member" },
  ): Promise<{ id?: string; token: string; expiresAt: string }> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/invitations`, input);
  }

  /**
   * The organization's invitations, newest first (capability
   * invitations.manage): pending only unless `status` is "all". Metadata
   * only, never a token.
   */
  listInvitations(
    org: string,
    opts: { status?: "pending" | "all"; limit?: number; cursor?: string } = {},
  ): Promise<{ items: Invitation[]; nextCursor: string | null }> {
    const params = new URLSearchParams();
    if (opts.status) params.set("status", opts.status);
    if (opts.limit) params.set("limit", String(opts.limit));
    if (opts.cursor) params.set("cursor", opts.cursor);
    const query = params.size ? `?${params}` : "";
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/invitations${query}`);
  }

  /** Revoke a pending invitation; its token stops working at once (capability invitations.manage). */
  revokeInvitation(org: string, invitationId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/invitations/${encodeURIComponent(invitationId)}`,
    );
  }

  listRequirements(org: string): Promise<Page<Requirement>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/requirements`);
  }

  updateRequirement(
    org: string,
    requirementId: string,
    patch: {
      expectedVersion: number;
      target?: { kind: "tier"; tier: Tier } | { kind: "environments"; environmentIds: string[] };
      selector?: { tailnet: string; tags?: string[]; users?: string[]; nodes?: string[] };
    },
  ): Promise<Requirement> {
    return this.request(
      "PATCH",
      `/v1/organizations/${encodeURIComponent(org)}/requirements/${encodeURIComponent(requirementId)}`,
      patch,
    );
  }

  createTailnetRequirement(
    org: string,
    input: {
      target: { kind: "tier"; tier: Tier } | { kind: "environments"; environmentIds: string[] };
      selector: { tailnet: string; tags?: string[]; users?: string[]; nodes?: string[] };
    },
  ): Promise<{ id: string }> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/requirements`, {
      kind: "tailnet",
      ...input,
    });
  }

  deleteRequirement(org: string, requirementId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/requirements/${encodeURIComponent(requirementId)}`,
    );
  }

  createIdentity(
    org: string,
    input: {
      name: string;
      kind: "service" | "workload" | "ci" | "broker" | "agent";
      credentialTtlSeconds?: number;
      credentialMaxUses?: number;
    },
  ): Promise<CreatedIdentity> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/identities`, input);
  }

  issueCapability(
    org: string,
    project: string,
    environment: string,
    input: {
      agentIdentityId: string;
      items: string[];
      destinations: string[];
      /** Per item, 1 to 4 substitution targets (header:, query:, json:, form:). */
      targets: Record<string, string[]>;
      ttlSeconds: number;
      runId?: string;
      /** Agent-safe strict preflight: the state the preflight retrieval saw. */
      precondition?: {
        projectId: string;
        environmentId: string;
        stateDigest: string;
        stateDigests: StrictRetrieval["stateDigests"];
      };
    },
  ): Promise<IssuedCapability> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/capabilities`,
      input,
    );
  }

  listCapabilities(org: string, project: string, environment: string): Promise<Page<CapabilitySummary>> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/capabilities`,
    );
  }

  revokeCapability(org: string, project: string, environment: string, capabilityId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/capabilities/${encodeURIComponent(capabilityId)}`,
    );
  }

  exerciseCapability(
    org: string,
    project: string,
    environment: string,
    capabilityId: string,
    input: {
      capabilitySecret: string;
      destination: { host: string; port: number };
      /** Each substitution the Broker will make: an item and one of its recorded targets. */
      placements: { item: string; target: string }[];
    },
  ): Promise<CapabilityExercise> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/capabilities/${encodeURIComponent(capabilityId)}/exercises`,
      input,
    );
  }

  issueAgentCredential(
    org: string,
    identityId: string,
    input: { ttlSeconds: number; runId?: string },
  ): Promise<IssuedAgentCredential> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/credentials`,
      input,
    );
  }

  revokeAgentCredential(org: string, identityId: string, credentialId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/credentials/${encodeURIComponent(credentialId)}`,
    );
  }

  // ---- Machine identity lifecycle (ADR-0034; capability identity.lifecycle).

  listIdentityCredentials(org: string, identityId: string): Promise<Page<IdentityCredential>> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/credentials`,
    );
  }

  /** Revoke a service/oidc credential of an in-org machine identity (identity.manage). */
  revokeIdentityCredential(org: string, identityId: string, credentialId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/credentials/${encodeURIComponent(credentialId)}`,
    );
  }

  renameIdentity(org: string, identityId: string, name: string): Promise<{ id: string; name: string }> {
    return this.request(
      "PATCH",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}`,
      { name },
    );
  }

  /** Disables the identity and revokes all of its credentials transactionally. */
  retireIdentity(org: string, identityId: string): Promise<{ id: string; disabled: boolean }> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/retire`,
    );
  }

  /** Clears disabled only; the identity has zero working credentials afterwards. */
  reactivateIdentity(org: string, identityId: string): Promise<{ id: string; disabled: boolean }> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/reactivate`,
    );
  }

  createOidcBinding(
    org: string,
    identityId: string,
    input: { issuer: string; audience: string; subject: string; claims?: Record<string, string> },
  ): Promise<OidcBinding> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/oidc-bindings`,
      input,
    );
  }

  listOidcBindings(org: string, identityId: string): Promise<Page<OidcBinding>> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/oidc-bindings`,
    );
  }

  revokeOidcBinding(org: string, identityId: string, bindingId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/identities/${encodeURIComponent(identityId)}/oidc-bindings/${encodeURIComponent(bindingId)}`,
    );
  }

  /**
   * Trade the short-lived browser-handoff bearer (ADR-0024) for a
   * longer-lived CLI credential. The presenting bearer is revoked.
   */
  exchangeCliCredential(input: { ttlSeconds?: number; name?: string } = {}): Promise<IssuedCliCredential> {
    return this.request("POST", "/v1/me/credentials/cli", input);
  }

  /**
   * The CLI's device sign-in calls (capability auth.device). One request
   * each: no maintenance retry, and no redirect followed (the body carries
   * the device code, a bearer), so a redirect throws
   * DeviceSignInRedirectError. `signal` bounds the request.
   */
  private async deviceRequest(path: string, body: unknown, signal: AbortSignal | undefined): Promise<Response> {
    const res = await this.fetchImpl(`${this.server}${path}`, {
      method: "POST",
      headers: {
        ...(this.userAgent ? { "User-Agent": this.userAgent } : {}),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      redirect: "manual",
      ...(signal ? { signal } : {}),
    });
    // Browsers report a manual redirect as an opaque response (status 0).
    if ((res.status >= 300 && res.status < 400) || res.type === "opaqueredirect") {
      throw new DeviceSignInRedirectError(res.status, res.headers.get("Location"));
    }
    return res;
  }

  /** Start a device sign-in. Unauthenticated; keep `deviceCode` private. */
  async startDeviceSignIn(
    input: { ttlSeconds?: number; name?: string } = {},
    options: { signal?: AbortSignal } = {},
  ): Promise<DeviceSignInStarted> {
    return this.finish(await this.deviceRequest("/v1/auth/device", input, options.signal));
  }

  /** Poll a device sign-in once: its state, or the issued credential (exactly once). */
  async pollDeviceSignIn(deviceCode: string, options: { signal?: AbortSignal } = {}): Promise<DeviceSignInPoll> {
    const res = await this.deviceRequest("/v1/auth/device/token", { deviceCode }, options.signal);
    if (res.status === 201) return { state: "issued", credential: await this.finish<IssuedCliCredential>(res) };
    if (res.ok) {
      throw new VarlatchApiError(res.status, {
        code: "INTERNAL",
        message: `HTTP ${res.status}; not a device sign-in answer`,
        requestId: res.headers.get("X-Request-Id") ?? "unknown",
      });
    }
    try {
      return await this.finish<never>(res);
    } catch (err) {
      if (!(err instanceof VarlatchApiError)) throw err;
      const interval = Number(err.details?.interval);
      switch (err.code) {
        case "AUTHORIZATION_PENDING":
          return { state: "pending", interval: Number.isFinite(interval) && interval > 0 ? interval : 5 };
        case "SLOW_DOWN":
          return { state: "slow_down", interval: Number.isFinite(interval) && interval > 0 ? interval : 10 };
        case "ACCESS_DENIED":
          return { state: "denied" };
        case "EXPIRED":
          return { state: "expired" };
        case "CONSUMED":
          return { state: "consumed", credentialId: typeof err.details?.credentialId === "string" ? err.details.credentialId : null };
        default:
          throw err;
      }
    }
  }

  /** The dashboard's lookup of a typed code: the pending sign-in and a fresh approval challenge. */
  lookupDeviceSignIn(userCode: string): Promise<DeviceSignInLookup> {
    return this.request("POST", "/v1/auth/device/lookup", { userCode });
  }

  /** Approve (with a passkey assertion over the lookup's challenge) or deny a device sign-in. */
  decideDeviceSignIn(input: { userCode: string; decision: "approve" | "deny"; assertion?: unknown }): Promise<{ decision: "approved" | "denied" }> {
    return this.request("POST", "/v1/auth/device/approve", input);
  }

  /** Unauthenticated: the external OIDC token is the proof of identity. */
  exchangeOidcToken(input: { organization: string; token: string; ttlSeconds?: number }): Promise<IssuedOidcCredential> {
    return this.request("POST", "/v1/oidc/token", input);
  }

  createWebhook(
    org: string,
    input: { url: string; eventTypes?: string[] },
  ): Promise<CreatedWebhook> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/webhooks`, input);
  }

  listWebhooks(org: string): Promise<Page<Webhook>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/webhooks`);
  }

  updateWebhook(
    org: string,
    webhookId: string,
    patch: { expectedVersion: number; url?: string; eventTypes?: string[] | null },
  ): Promise<Webhook> {
    return this.request(
      "PATCH",
      `/v1/organizations/${encodeURIComponent(org)}/webhooks/${encodeURIComponent(webhookId)}`,
      patch,
    );
  }

  revokeWebhook(org: string, webhookId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/webhooks/${encodeURIComponent(webhookId)}`,
    );
  }

  // ---- Sync Targets (ADR-0031)

  private envPath(org: string, project: string, environment: string): string {
    return `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}`;
  }

  listPlatformConnections(org: string): Promise<Page<PlatformConnection>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/platform-connections`);
  }

  createPlatformConnection(
    org: string,
    input: { platform: SyncPlatform; baseIdentity: string; name: string; credential: string },
  ): Promise<PlatformConnection> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/platform-connections`, input);
  }

  getPlatformConnection(
    org: string,
    connectionId: string,
  ): Promise<PlatformConnection & { targets: SyncTarget[] }> {
    return this.request(
      "GET",
      `/v1/organizations/${encodeURIComponent(org)}/platform-connections/${encodeURIComponent(connectionId)}`,
    );
  }

  replacePlatformCredential(
    org: string,
    connectionId: string,
    input: { credential: string; expectedVersion: number },
  ): Promise<PlatformConnection> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/platform-connections/${encodeURIComponent(connectionId)}/credential`,
      input,
    );
  }

  revokePlatformConnection(org: string, connectionId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/platform-connections/${encodeURIComponent(connectionId)}`,
    );
  }

  listOrgSyncTargets(org: string): Promise<Page<SyncTarget>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/sync-targets`);
  }

  listSyncTargets(org: string, project: string, environment: string): Promise<Page<SyncTarget>> {
    return this.request("GET", `${this.envPath(org, project, environment)}/sync-targets`);
  }

  createSyncTarget(
    org: string,
    project: string,
    environment: string,
    input: {
      connectionId: string;
      destination: Record<string, unknown>;
      mapping: SyncMappingInput;
      removeOrphans?: boolean;
      redeploy?: boolean;
    },
  ): Promise<SyncTarget> {
    return this.request("POST", `${this.envPath(org, project, environment)}/sync-targets`, input);
  }

  getSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
  ): Promise<SyncTarget & { names: SyncLedgerName[] }> {
    return this.request(
      "GET",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}`,
    );
  }

  updateSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
    patch: {
      expectedVersion: number;
      connectionId?: string;
      destination?: Record<string, unknown>;
      mapping?: SyncMappingInput;
      removeOrphans?: boolean;
      redeploy?: boolean;
    },
  ): Promise<SyncTarget> {
    return this.request(
      "PATCH",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}`,
      patch,
    );
  }

  pushSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
  ): Promise<{ scheduled: boolean }> {
    return this.request(
      "POST",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}/push`,
    );
  }

  pauseSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
  ): Promise<SyncTarget> {
    return this.request(
      "POST",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}/pause`,
    );
  }

  resumeSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
  ): Promise<SyncTarget> {
    return this.request(
      "POST",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}/resume`,
    );
  }

  revokeSyncTarget(
    org: string,
    project: string,
    environment: string,
    targetId: string,
  ): Promise<void> {
    return this.request(
      "DELETE",
      `${this.envPath(org, project, environment)}/sync-targets/${encodeURIComponent(targetId)}`,
    );
  }

  listIdentities(org: string): Promise<Page<OrgIdentity>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/identities`);
  }

  listGrants(org: string): Promise<Page<Grant>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/grants`);
  }

  deleteGrant(org: string, grantId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/v1/organizations/${encodeURIComponent(org)}/grants/${encodeURIComponent(grantId)}`,
    );
  }

  getInstallationBackups(): Promise<InstallationBackups> {
    return this.request("GET", "/v1/installation/backups");
  }

  /** The caller's own profile (humans only; machines get RESOURCE_NOT_FOUND). */
  getMyProfile(): Promise<Profile> {
    return this.request("GET", "/v1/me/profile");
  }

  /** Update display name and/or avatar image (data:image/… or https URL, ≤100KB; null clears). */
  updateMyProfile(patch: { name?: string; image?: string | null }): Promise<Profile> {
    return this.request("PATCH", "/v1/me/profile", patch);
  }

  listMyCredentials(): Promise<Page<OwnCredential>> {
    return this.request("GET", "/v1/me/credentials");
  }

  revokeMyCredential(credentialId: string): Promise<void> {
    return this.request("DELETE", `/v1/me/credentials/${encodeURIComponent(credentialId)}`);
  }

  createGrant(
    org: string,
    input: {
      subjectIdentityId?: string;
      subjectGroupId?: string;
      scope: GrantScope;
      actions?: string[];
      roleId?: string;
    },
  ): Promise<Grant> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/grants`, input);
  }

  /**
   * Atomic revoke-and-replace (ADR-0029): Grant declarations are immutable,
   * so "editing" a Grant is one server operation that revokes the original
   * and creates the successor with linked audit events.
   */
  replaceGrant(
    org: string,
    grantId: string,
    declaration: {
      subjectIdentityId?: string;
      subjectGroupId?: string;
      scope: GrantScope;
      actions?: string[];
      roleId?: string;
    },
  ): Promise<GrantReplacement> {
    return this.request(
      "POST",
      `/v1/organizations/${encodeURIComponent(org)}/grants/${encodeURIComponent(grantId)}/replace`,
      declaration,
    );
  }

  /**
   * Cross-project Config Item name search (ADR-0030, capability
   * search.items): literal case-insensitive substring over item names the
   * caller may read metadata for. Never matches or returns Values.
   */
  searchConfigItems(
    org: string,
    opts: { q: string; limit?: number; cursor?: string },
  ): Promise<Page<ConfigItemSearchResult>> {
    const params = new URLSearchParams({ q: opts.q });
    if (opts.limit) params.set("limit", String(opts.limit));
    if (opts.cursor) params.set("cursor", opts.cursor);
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/config-items?${params}`);
  }

  // Roles, Groups, Teams (ADR-0028).
  listRoles(org: string): Promise<Page<Role>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/roles`);
  }
  createRole(org: string, input: { name: string; actions: string[] }): Promise<Role> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/roles`, input);
  }
  updateRole(
    org: string,
    roleId: string,
    patch: { expectedVersion: number; name?: string; actions?: string[] },
  ): Promise<Role> {
    return this.request("PATCH", `/v1/organizations/${encodeURIComponent(org)}/roles/${encodeURIComponent(roleId)}`, patch);
  }
  deleteRole(org: string, roleId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/roles/${encodeURIComponent(roleId)}`);
  }
  listGroups(org: string): Promise<Page<Group>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/groups`);
  }
  createGroup(org: string, input: { name: string }): Promise<Group> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/groups`, input);
  }
  updateGroup(org: string, groupId: string, patch: { expectedVersion: number; name?: string }): Promise<Group> {
    return this.request("PATCH", `/v1/organizations/${encodeURIComponent(org)}/groups/${encodeURIComponent(groupId)}`, patch);
  }
  deleteGroup(org: string, groupId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/groups/${encodeURIComponent(groupId)}`);
  }
  listGroupMembers(org: string, groupId: string): Promise<Page<{ identityId: string }>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/groups/${encodeURIComponent(groupId)}/members`);
  }
  addGroupMember(org: string, groupId: string, identityId: string): Promise<void> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/groups/${encodeURIComponent(groupId)}/members`, { identityId });
  }
  removeGroupMember(org: string, groupId: string, identityId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(identityId)}`);
  }
  listTeams(org: string): Promise<Page<Group>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/teams`);
  }
  createTeam(org: string, input: { name: string }): Promise<Group> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/teams`, input);
  }
  updateTeam(org: string, teamId: string, patch: { expectedVersion: number; name?: string }): Promise<Group> {
    return this.request("PATCH", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}`, patch);
  }
  deleteTeam(org: string, teamId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}`);
  }
  addTeamMember(org: string, teamId: string, identityId: string): Promise<void> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}/members`, { identityId });
  }
  removeTeamMember(org: string, teamId: string, identityId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(identityId)}`);
  }
  listTeamProjects(org: string, teamId: string): Promise<Page<{ projectId: string }>> {
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}/projects`);
  }
  addTeamProject(org: string, teamId: string, projectId: string): Promise<void> {
    return this.request("POST", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}/projects`, { projectId });
  }
  removeTeamProject(org: string, teamId: string, projectId: string): Promise<void> {
    return this.request("DELETE", `/v1/organizations/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamId)}/projects/${encodeURIComponent(projectId)}`);
  }

  /**
   * Security Audit Events, newest first. The filters (capability
   * audit.filters) are ANDed; pass the same ones with each cursor. A server
   * without the capability ignores them, so check /v1/meta first.
   */
  listAuditEvents(
    org: string,
    opts: { limit?: number; cursor?: string } & AuditEventFilters = {},
  ): Promise<Page<Record<string, unknown>>> {
    const params = new URLSearchParams();
    if (opts.limit) params.set("limit", String(opts.limit));
    if (opts.cursor) params.set("cursor", opts.cursor);
    setAuditFilters(params, opts);
    const query = params.size ? `?${params}` : "";
    return this.request("GET", `/v1/organizations/${encodeURIComponent(org)}/audit-events${query}`);
  }

  /** Every matching event as NDJSON, oldest first; same filters as {@link listAuditEvents}. */
  async exportAuditEventsNdjson(org: string, opts: AuditEventFilters = {}): Promise<string> {
    const params = new URLSearchParams();
    setAuditFilters(params, opts);
    const query = params.size ? `?${params}` : "";
    const res = await this.fetchImpl(
      `${this.server}/v1/organizations/${encodeURIComponent(org)}/audit-events/export${query}`,
      {
        headers: {
          ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
          ...(this.userAgent ? { "User-Agent": this.userAgent } : {}),
        },
      },
    );
    if (!res.ok) {
      const body = (await res.json().catch(() => undefined)) as ApiError | undefined;
      throw new VarlatchApiError(
        res.status,
        body?.error ?? { code: "INTERNAL", message: `HTTP ${res.status}`, requestId: "unknown" },
      );
    }
    return res.text();
  }
}
