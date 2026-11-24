// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import type { OrganizationPermissions, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { useCapability } from "../projects/hooks";
import { myPermissionsKey } from "../security-controls/keys";

/** Constants and hooks shared across the Access tabs. */

export const TIERS: Tier[] = ["development", "staging", "production"];

/** Presets compile to plain Grants; nothing in the policy model knows them. */
export const PRESETS: { key: string; label: string; hint: string; actions: string[] }[] = [
  {
    key: "read-config",
    label: "Read configuration",
    hint: "See projects, environments, contracts, and non-sensitive values",
    actions: [
      "organization.read",
      "project.read",
      "environment.read",
      "contract.read",
      "config.metadata.read",
      "config.value.read",
    ],
  },
  {
    key: "write-config",
    label: "Write configuration",
    hint: "Read configuration plus set/delete values and manage environments",
    actions: [
      "organization.read",
      "project.read",
      "environment.read",
      "contract.read",
      "config.metadata.read",
      "config.value.read",
      "config.value.write",
      "environment.manage",
    ],
  },
  {
    key: "use-secrets",
    label: "Use secrets (runtime)",
    hint: "Retrieve secret material for running software; no reveal in tooling",
    actions: [
      "organization.read",
      "project.read",
      "environment.read",
      "contract.read",
      "config.metadata.read",
      "config.value.read",
      "secret.use",
    ],
  },
  {
    key: "agent",
    label: "AI agent (broker-mediated)",
    hint: "Metadata and non-sensitive values; secret material only through broker-mediated use — never revealed",
    actions: ["config.metadata.read", "config.value.read", "secret.use"],
  },
  {
    key: "reveal-secrets",
    label: "Reveal secrets",
    hint: "Use secrets plus explicit, audited plaintext disclosure",
    actions: [
      "organization.read",
      "project.read",
      "environment.read",
      "contract.read",
      "config.metadata.read",
      "config.value.read",
      "secret.use",
      "secret.reveal",
    ],
  },
];

export const ALL_ACTIONS = [
  "organization.read",
  "organization.manage",
  "project.read",
  "project.manage",
  "environment.read",
  "environment.manage",
  "config.metadata.read",
  "config.value.read",
  "config.value.write",
  "contract.read",
  "contract.submit",
  "contract.activate",
  "secret.use",
  "capability.issue",
  "secret.reveal",
  "identity.read",
  "identity.manage",
  "policy.read",
  "policy.manage",
  "audit.read",
  "config.sync.manage",
];

/**
 * Whether the caller has an organization-wide permission, as the server
 * answers it (GET .../me/permissions). Three answers: "unknown" until the
 * server has said, after a failed check, and on a server that cannot be
 * asked; a control that needs the permission shows on "allowed" only.
 */
export function useOrganizationPermission(org: string, action: OrganizationPermissions["actions"][number]): "unknown" | "allowed" | "denied" {
  const { api } = useSession();
  const supported = useCapability("organizations.permissions");
  const permissions = useQuery({ queryKey: myPermissionsKey(org), queryFn: () => api.myOrganizationPermissions(org), enabled: supported });
  // isSuccess, not data: an answer kept from before a failed check is not one.
  if (!supported || !permissions.isSuccess) return "unknown";
  return permissions.data.actions.includes(action) ? "allowed" : "denied";
}

export function useIdentities(org: string | undefined) {
  const { api } = useSession();
  // No slug yet (the account pages before the organizations load): no
  // request, rather than GET /v1/organizations//identities.
  return useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org as string),
    enabled: Boolean(org),
  });
}
