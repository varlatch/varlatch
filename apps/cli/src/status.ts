// SPDX-License-Identifier: Apache-2.0
import type { LocalState, ResolvedContext, StoredCredential } from "@varlatch/context";

/**
 * Session disclosure (ADR-0032). The status document is a versioned contract
 * consumed by external scripts (shell prompts, desktop widgets): offline by
 * default, probe strictly opt-in, and no secret material — connection
 * metadata only.
 */

export const STATUS_SCHEMA_VERSION = 1;

/** Warn when less than this fraction of the credential's lifetime remains.
    A fixed window would be wrong: CLI credentials are capped at 24h
    (ADR-0024), so any absolute threshold near that fires on every run. */
const WARN_LIFETIME_FRACTION = 0.2;

export type ProbeState = "valid" | "invalid" | "unreachable";

/**
 * What a valid probe resolved the credential to (ADR-0032 Decision 3), from
 * GET /v1/me; absent from servers without the identity.whoami capability.
 * Only in the JSON document: the human format is frozen (Decision 6).
 */
export interface ProbeIdentity {
  identity: { id: string; name: string; kind: string };
  organization: { id: string; slug: string; name: string } | null;
}

export interface ServerStatus {
  server: string;
  name: string | null;
  issuedAt: string | null;
  expiresAt: string | null;
  credentialId: string | null;
  expired: boolean | null;
  /** Inside the proportional warning window (less than 20% of the lifetime
      left) but not yet expired; null when issuedAt/expiresAt are missing. */
  expiring: boolean | null;
  probe?: { state: ProbeState; detail: string | null } & Partial<ProbeIdentity>;
}

export interface RepoStatus {
  server: string;
  organization: string;
  project: string;
  environment: string;
  environmentSource: string;
  repoRoot: string;
  tier: string | null;
  tierCachedAt: string | null;
}

export interface StatusDocument {
  version: typeof STATUS_SCHEMA_VERSION;
  servers: ServerStatus[];
  repo: RepoStatus | null;
}

export type ExpiryState = "ok" | "expiring" | "expired";

/** Single source of the proportional expiry rule, shared by the stderr
    warning and the status document. Null when the lifetime is unknowable:
    pre-ADR-0032 entries, garbage timestamps. */
export function expiryState(
  credential: StoredCredential | null,
  now: number = Date.now(),
): ExpiryState | null {
  if (!credential?.issuedAt || !credential.expiresAt) return null;
  const issued = Date.parse(credential.issuedAt);
  const expires = Date.parse(credential.expiresAt);
  if (Number.isNaN(issued) || Number.isNaN(expires) || expires <= issued) return null;
  if (now >= expires) return "expired";
  if (expires - now < (expires - issued) * WARN_LIFETIME_FRACTION) return "expiring";
  return "ok";
}

export function serverStatus(
  server: string,
  credential: StoredCredential,
  now: number = Date.now(),
): ServerStatus {
  const state = expiryState(credential, now);
  return {
    server,
    name: credential.name ?? null,
    issuedAt: credential.issuedAt ?? null,
    expiresAt: credential.expiresAt ?? null,
    credentialId: credential.credentialId ?? null,
    expired: credential.expiresAt ? Date.parse(credential.expiresAt) <= now : null,
    expiring: state === null ? null : state === "expiring",
  };
}

export function repoStatus(ctx: ResolvedContext, local: LocalState): RepoStatus {
  // The cached tier belongs to the locally selected environment only; a
  // flag/env-var override selects a different environment with an unknown tier.
  const tierApplies =
    local.selectedTier !== undefined && local.selectedEnvironment === ctx.environment;
  return {
    server: ctx.server,
    organization: ctx.organization,
    project: ctx.project,
    environment: ctx.environment,
    environmentSource: ctx.environmentSource,
    repoRoot: ctx.repoRoot,
    tier: tierApplies ? (local.selectedTier as string) : null,
    tierCachedAt: tierApplies ? (local.tierCachedAt ?? null) : null,
  };
}

/** Proportional expiry warning, or null when there is nothing to say.
    Needs both timestamps: pre-ADR-0032 entries stay silent. */
export function expiryWarning(
  server: string,
  credential: StoredCredential | null,
  now: number = Date.now(),
): string | null {
  const state = expiryState(credential, now);
  const expiresAt = credential?.expiresAt;
  if (state === "expired") {
    return `varlatch: credential for ${server} expired ${expiresAt} — run \`varlatch login --server ${server}\``;
  }
  if (state === "expiring") {
    return `varlatch: credential for ${server} expires ${expiresAt} — run \`varlatch login --server ${server}\` to renew`;
  }
  return null;
}

export function formatStatusHuman(doc: StatusDocument): string {
  const lines: string[] = [];
  if (doc.servers.length === 0) {
    lines.push("No stored credentials. Run: varlatch login --server <url>");
  }
  for (const s of doc.servers) {
    const bits = [
      s.expired === true ? "EXPIRED" : s.expiresAt ? `expires ${s.expiresAt}` : "no expiry recorded",
      ...(s.name ? [s.name] : []),
      ...(s.probe ? [`probe: ${s.probe.state}${s.probe.detail ? ` (${s.probe.detail})` : ""}`] : []),
    ];
    lines.push(`${s.server}  (${bits.join(", ")})`);
  }
  if (doc.repo) {
    lines.push("");
    lines.push(`Repo          ${doc.repo.repoRoot}`);
    lines.push(`Project       ${doc.repo.organization}/${doc.repo.project}`);
    lines.push(
      `Environment   ${doc.repo.environment} (${doc.repo.environmentSource}${doc.repo.tier ? `, tier ${doc.repo.tier}` : ""})`,
    );
  }
  return lines.join("\n");
}
