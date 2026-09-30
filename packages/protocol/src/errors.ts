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
  "retrieval.manifest",
  "retrieval.strict",
  "retrieval.preflight",
  "capabilities.targets",
  "contracts.revision-by-id",
  "projects.rename",
] as const;

export type Capability = (typeof CAPABILITIES)[number];
