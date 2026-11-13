// SPDX-License-Identifier: Apache-2.0
/**
 * Stable machine-readable error codes (ADR-0018 §10). Once /v1 is declared
 * stable these are public protocol values: never reuse a code for a different
 * meaning, only add.
 */
export const ERROR_CODES = [
  "AUTHENTICATION_REQUIRED",
  "INVALID_CREDENTIAL",
  "PERMISSION_DENIED",
  "RESOURCE_NOT_FOUND",
  "VALIDATION_FAILED",
  "VERSION_CONFLICT",
  "ROTATION_IN_PROGRESS",
  "IDEMPOTENCY_CONFLICT",
  "CONTRACT_INVALID",
  "CONTRACT_DRIFT",
  "CONTRACT_MAPPING_UNRESOLVED",
  "ENVIRONMENT_EXPIRED",
  "TAILNET_CONTEXT_REQUIRED",
  "TAILNET_CONTEXT_UNAVAILABLE",
  "RATE_LIMITED",
  "MAINTENANCE",
  "INTERNAL",
  "STATE_CHANGED",
  // Device-authorization sign-in (RFC 8628 §3.5): the CLI's poll answers.
  "AUTHORIZATION_PENDING",
  "SLOW_DOWN",
  "ACCESS_DENIED",
  "EXPIRED",
  "CONSUMED",
  // Organization deletion (ADR-0051): refused while frozen; gone after.
  "ORGANIZATION_DELETING",
  "ORGANIZATION_DELETED",
  // Step-up approvals (ADR-0054 Decision 3): the operation needs an
  // approval with a trusted passkey (details.approval); an approval sent
  // with an operation that cannot use it (details.reason).
  "STEP_UP_REQUIRED",
  "APPROVAL_INVALID",
  // Security Controls (ADR-0054 Decision 1): a mode this server does not
  // offer for that control (details: control, mode, availableModes).
  "CONTROL_MODE_UNAVAILABLE",
  // credential-lifetime at enforce (ADR-0054 Decision 5): a machine
  // credential asked for with a lifetime above the Organization's maximum
  // (details: control, requestedTtlSeconds, maxTtlSeconds). Nothing was
  // issued; ask again with a lifetime of at most maxTtlSeconds.
  "CREDENTIAL_LIFETIME_EXCEEDED",
  // The incident freeze (ADR-0055): refused while the Organization is
  // frozen (details: freezeId, frozenAt). Final for the request: do not retry.
  "ORGANIZATION_FROZEN",
  // passkey-verification (ADR-0054 Decision 7): this Organization needs a
  // sign-in by a trusted passkey that verified the person (details:
  // control, reason). Sign in again; retrying the same credential will not help.
  "PASSKEY_VERIFICATION_REQUIRED",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

/** The single public error envelope (ADR-0018 §10). */
export interface ApiError {
  error: {
    code: ErrorCode;
    message: string;
    requestId: string;
    details?: Record<string, unknown>;
  };
}

/** Stable server capability identifiers surfaced by GET /v1/meta (ADR-0018 §3). */
export const CAPABILITIES = [
  "contracts.push",
  "contracts.managed",
  "tailnet.constraints",
  "audit.ndjson",
  "values.changeset",
  "secrets.requested-disclosure",
  "secrets.disclosure-purpose",
  "environments.personal",
  "environments.preview",
  "capabilities.broker",
  "credentials.agent",
  "webhooks.audit",
  "values.references",
  "values.rotation",
  "auth.oidc",
  "access.update",
  "grants.replace",
  "search.items",
  "sync.targets",
  "installation.backups",
  "identity.lifecycle",
  "identity.credentials.issue",
  "retrieval.manifest",
  "retrieval.strict",
  "retrieval.preflight",
  "capabilities.targets",
  "contracts.revision-by-id",
  "projects.rename",
  "invitations.manage",
  "organizations.rename",
  "audit.filters",
  "auth.device",
  "audit.attribution",
  "environments.tailnet-required",
  "tailnet.browser-reads",
  "identity.whoami",
  "installation.release",
  "disclosure.purpose.export",
  "sync.pause-wait",
  "members.lifecycle",
  "projects.delete",
  "organizations.delete",
  "identity.reach",
  "security.credential-review",
  "account.passkeys",
  "security.controls",
  "security.report",
  "security.approval-keys",
  "organizations.permissions",
  "installation.outbound",
  // GET /cli/varlatch.cjs, /install.sh and /install.ps1 answer (ADR-0058 Decision 3).
  "cli.download",
  "security.refused-destinations",
  "organizations.incident-freeze",
  // An Organization's audit export to object storage (ADR-0056).
  "audit.storage-export",
  // Security Controls this server can enforce (ADR-0054 step 4), one per
  // control, unlocked by the release that builds its full guarantee.
  "security.enforce.requirement-protection",
  "security.enforce.credential-lifetime",
  "security.enforce.passkey-verification",
  "security.enforce.admin-step-up",
] as const;

export type Capability = (typeof CAPABILITIES)[number];
