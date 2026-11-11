// SPDX-License-Identifier: Apache-2.0
import type { components } from "./generated/api.js";

/**
 * The outbound policy's refusals in words (ADR-0057 Decisions 6 and 8),
 * shared by varlatchd, the CLI and the dashboard so each says the same
 * thing. The wording names the class of address, never the address.
 */

export type OutboundRefusalReason = components["schemas"]["OutboundRefusalReason"];

export const OUTBOUND_REFUSAL_REASONS: readonly OutboundRefusalReason[] = [
  "private_address",
  "host_only_address",
  "never_address",
  "mixed_answers",
  "scheme",
  "port",
];

export const OUTBOUND_POLICY_DOCS = "https://docs.varlatch.com/reference/outbound-policy/";

/** The full sentence for a refusal, as a refused save or check says it. */
export const OUTBOUND_REFUSAL_MESSAGES: Record<OutboundRefusalReason, string> = {
  private_address:
    "This address is on a private network, which this installation does not let Organizations reach. The host operator can allow it with VARLATCH_OUTBOUND_ALLOW.",
  host_only_address: "This address is a loopback or link-local address, which Organizations cannot use.",
  never_address: "This address is unspecified, multicast or reserved, and can never be used.",
  mixed_answers: "This name has several addresses and one of them is not allowed.",
  scheme: "Plain http is allowed only to destinations the host operator allowed. Use https.",
  port: "The host operator allowed this destination on another port only. The host operator can allow this port with VARLATCH_OUTBOUND_ALLOW.",
};

/** A few words for a list: "private network address". */
export const OUTBOUND_REFUSAL_LABELS: Record<OutboundRefusalReason, string> = {
  private_address: "private network address",
  host_only_address: "loopback or link-local address",
  never_address: "reserved address",
  mixed_answers: "one of its addresses is not allowed",
  scheme: "plain http",
  port: "port not allowed",
};

/** For a stored refusal without a reason (a webhook's last_status). */
export const OUTBOUND_REFUSED_GENERIC =
  "This installation's outbound policy refuses this destination, so deliveries wait. The host operator can allow it with VARLATCH_OUTBOUND_ALLOW.";

/** The sentence for a refusal state on an item: its reason's, or the generic one. */
export function outboundRefusalText(reason: OutboundRefusalReason | "unknown"): string {
  return reason === "unknown" ? OUTBOUND_REFUSED_GENERIC : OUTBOUND_REFUSAL_MESSAGES[reason];
}

/** Where private destinations are allowed: on the host, never in Varlatch. */
export const OUTBOUND_HOST_NOTE =
  "Private destinations are allowed by the host operator, with VARLATCH_OUTBOUND_ALLOW on the host, not in Varlatch. " +
  "Nothing waiting is lost: it is delivered once the host operator allows the destination and restarts varlatchd.";

export function isOutboundRefusalReason(value: unknown): value is OutboundRefusalReason {
  return typeof value === "string" && (OUTBOUND_REFUSAL_REASONS as readonly string[]).includes(value);
}

/** The full sentence and the docs link. */
export function outboundRefusalMessage(reason: OutboundRefusalReason): string {
  return `${OUTBOUND_REFUSAL_MESSAGES[reason]} See ${OUTBOUND_POLICY_DOCS}`;
}

/**
 * A stored refusal state: a Sync Target's last_result (`outbound_refused:
 * <reason>`) or a webhook's last_status (`outbound_refused`, without a
 * reason). The reason, "unknown" when none is stored, or null when the text
 * is not a refusal.
 */
export function outboundRefusalOfStatus(text: string | null | undefined): OutboundRefusalReason | "unknown" | null {
  const match = /^outbound_refused(?::\s*([a-z_]+))?/.exec(text ?? "");
  if (!match) return null;
  return isOutboundRefusalReason(match[1]) ? match[1] : "unknown";
}
