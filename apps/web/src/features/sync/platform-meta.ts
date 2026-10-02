// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SyncPlatform } from "@varlatch/protocol";

/**
 * Display metadata for sync platforms: labels, field labels, placeholders and
 * help copy. Unknown adapters from a newer server fall back to the raw
 * platform id.
 */
export type PlatformMeta = {
  label: string;
  /** Short name for headings and "via …" lines. */
  shortLabel: string;
  /** One line: what a sync target on this platform pushes to. */
  description: string;
  identityLabel: string;
  identityPlaceholder: string;
  identityNoun: string;
  credentialLabel: string;
  credentialPlaceholder: string;
  credentialHelp: string;
};

export const PLATFORM_META: Record<SyncPlatform, PlatformMeta> = {
  "github-actions": {
    label: "GitHub Actions",
    shortLabel: "GitHub",
    description: "Actions secrets on a repository or one of its environments.",
    identityLabel: "Owner",
    identityPlaceholder: "acme-org",
    identityNoun: "account",
    credentialLabel: "Access token",
    credentialPlaceholder: "Fine-grained token with secrets write access",
    credentialHelp: "Scope it to the repositories you sync, with Secrets read and write only.",
  },
  coolify: {
    label: "Coolify",
    shortLabel: "Coolify",
    description: "Environment variables of an application on a Coolify instance.",
    identityLabel: "Instance URL",
    identityPlaceholder: "https://coolify.example.com",
    identityNoun: "instance",
    credentialLabel: "API token",
    credentialPlaceholder: "Coolify API token",
    credentialHelp: "Coolify tokens reach the whole instance; create one for Varlatch alone so you can revoke it on its own.",
  },
  convex: {
    label: "Convex",
    shortLabel: "Convex",
    description: "Environment variables of one Convex deployment, cloud or self-hosted.",
    identityLabel: "Deployment URL",
    identityPlaceholder: "https://happy-animal-123.convex.cloud",
    identityNoun: "deployment",
    credentialLabel: "Deploy or admin key",
    credentialPlaceholder: "Deploy key or admin key",
    credentialHelp:
      "Convex Cloud uses a deploy key (CONVEX_DEPLOY_KEY); a self-hosted backend uses its admin key (CONVEX_SELF_HOSTED_ADMIN_KEY). Both reach one deployment only.",
  },
};

export function platformMeta(platform: SyncPlatform | (string & {})): PlatformMeta {
  return (
    PLATFORM_META[platform as SyncPlatform] ?? {
      label: platform,
      shortLabel: platform,
      description: "Pushes values to this platform.",
      identityLabel: "Instance",
      identityPlaceholder: "",
      identityNoun: "instance",
      credentialLabel: "Credential",
      credentialPlaceholder: "Platform credential",
      credentialHelp: "Stored encrypted, never shown again.",
    }
  );
}
