// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import type { Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";

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
  "secret.reveal",
  "identity.read",
  "identity.manage",
  "policy.read",
  "policy.manage",
  "audit.read",
  "config.sync.manage",
];

export function useIdentities(org: string) {
  const { api } = useSession();
  return useQuery({ queryKey: ["identities", org], queryFn: () => api.listIdentities(org) });
}
