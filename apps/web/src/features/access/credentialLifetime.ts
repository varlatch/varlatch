// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import type { CredentialLifetimeConfig, SecurityControlList } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { useCapability } from "../projects/hooks";
import { durationWords } from "../security-controls/approval";
import { securityControlsKey } from "../security-controls/SecurityControlsCard";

/**
 * credential-lifetime as the machine-credential forms show it (ADR-0054):
 * while the Organization enforces it, a credential issued without a
 * lifetime gets the default, and one above the maximum is refused
 * (CREDENTIAL_LIFETIME_EXCEEDED). The server decides; the forms only say
 * so before asking, and keep a longer lifetime from being sent.
 */

/** The lifetimes of an enforced credential-lifetime; null when it is not enforced. */
export function enforcedLifetime(list: Pick<SecurityControlList, "items"> | undefined): CredentialLifetimeConfig | null {
  const control = list?.items.find((c) => c.control === "credential-lifetime");
  return control?.mode === "enforce" && control.config ? control.config : null;
}

/**
 * The Organization's enforced lifetimes, read with the Security page's
 * query (every member may read the controls); null when the control is
 * not enforced, or the server has no controls, or they cannot be read.
 */
export function useEnforcedLifetime(org: string): CredentialLifetimeConfig | null {
  const { api } = useSession();
  const supported = useCapability("security.controls");
  const controls = useQuery({
    queryKey: securityControlsKey(org),
    queryFn: () => api.listSecurityControls(org),
    enabled: supported,
    retry: false,
  });
  return enforcedLifetime(controls.data);
}

/** The hint under a lifetime field: what leaving it empty does here. */
export function lifetimeHint(enforced: CredentialLifetimeConfig | null): string {
  if (!enforced) return "Empty: no expiry, revocation only.";
  return `Empty: this organization's default, ${durationWords(enforced.defaultTtlSeconds)}. At most ${durationWords(enforced.maxTtlSeconds)} (${enforced.maxTtlSeconds} seconds).`;
}

/**
 * Why a lifetime field's value cannot be sent, or undefined when it can:
 * not whole seconds, or longer than the enforced maximum.
 */
export function lifetimeError(value: string, enforced: CredentialLifetimeConfig | null): string | undefined {
  if (value === "") return undefined;
  if (!/^[1-9][0-9]*$/.test(value)) return "Whole seconds, at least 1.";
  if (enforced && Number(value) > enforced.maxTtlSeconds) {
    return `This organization allows at most ${durationWords(enforced.maxTtlSeconds)} (${enforced.maxTtlSeconds} seconds).`;
  }
  return undefined;
}
