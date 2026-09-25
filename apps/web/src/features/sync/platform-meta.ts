// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SyncPlatform } from "@varlatch/protocol";

/**
 * Display metadata for sync platforms (ADR-0031 adapters). Field labels,
 * placeholders and help copy were previously inlined in ConnectionsPage and
 * IntegrationsPage; unknown adapters from a newer server fall back to the
 * raw platform id.
 */
export type PlatformMeta = {
  label: string;
  /** One line: what a Sync Target on this platform pushes to. */
  description: string;
  identityLabel: string;
  identityPlaceholder: string;
  identityNoun: string;
  credentialPlaceholder: string;
  credentialHelp: string;
};

export const PLATFORM_META: Record<SyncPlatform, PlatformMeta> = {
  "github-actions": {
    label: "GitHub Actions",
    description: "Pushes values as Actions secrets on a repository or repo environment.",
    identityLabel: "Owner",
    identityPlaceholder: "acme-org",
    identityNoun: "account",
    credentialPlaceholder: "Fine-grained PAT, secrets:write on the target repo only",
    credentialHelp: "Stored encrypted, never shown again. Scope it as narrowly as the platform allows.",
  },
  coolify: {
    label: "Coolify",
    description: "Writes values into an application's environment variables on a Coolify instance.",
    identityLabel: "Instance URL",
    identityPlaceholder: "https://coolify.example.com",
    identityNoun: "instance",
    credentialPlaceholder: "Coolify API token (instance-wide by design)",
    credentialHelp: "Stored encrypted, never shown again. Scope it as narrowly as the platform allows.",
  },
  convex: {
    label: "Convex",
    description: "Sets environment variables on one Convex deployment (cloud or self-hosted).",
    identityLabel: "Deployment URL",
    identityPlaceholder: "https://happy-animal-123.convex.cloud",
    identityNoun: "deployment",
    credentialPlaceholder: "Deploy key or admin key (per-deployment)",
    credentialHelp:
      "Convex Cloud uses a deployment deploy key (CONVEX_DEPLOY_KEY); a self-hosted backend uses its admin key (CONVEX_SELF_HOSTED_ADMIN_KEY) — both are scoped to one deployment. Stored encrypted, never shown again.",
  },
};

export function platformMeta(platform: SyncPlatform | (string & {})): PlatformMeta {
  return (
    PLATFORM_META[platform as SyncPlatform] ?? {
      label: platform,
      description: "Pushes values to this platform.",
      identityLabel: "Instance",
      identityPlaceholder: "",
      identityNoun: "instance",
      credentialPlaceholder: "Platform credential",
      credentialHelp: "Stored encrypted, never shown again.",
    }
  );
}
