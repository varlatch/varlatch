// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  OUTBOUND_HOST_NOTE as PROTOCOL_HOST_NOTE,
  OUTBOUND_POLICY_DOCS,
  OUTBOUND_REFUSAL_MESSAGES as PROTOCOL_REFUSAL_MESSAGES,
  OUTBOUND_REFUSAL_REASONS,
  OUTBOUND_REFUSED_GENERIC as PROTOCOL_REFUSED_GENERIC,
  type OutboundRefusalReason,
} from "@varlatch/protocol";

/**
 * Outbound policy refusal texts for the 0.50 dashboard.
 *
 * `@varlatch/protocol` keeps the TypeScript server's `VARLATCH_OUTBOUND_ALLOW`
 * wording because it is shared with that server and with Go's recorded
 * vectors. On `varlatchd` the setting is `outbound_allow` in `varlatchd.conf`,
 * so the dashboard rewrites the setting name here.
 */

function forVarlatchdConf(text: string): string {
  return text
    .replaceAll("VARLATCH_OUTBOUND_ALLOW on the host", "outbound_allow in varlatchd.conf on the host")
    .replaceAll("VARLATCH_OUTBOUND_ALLOW", "outbound_allow in varlatchd.conf");
}

export const OUTBOUND_REFUSAL_MESSAGES: Record<OutboundRefusalReason, string> = Object.fromEntries(
  OUTBOUND_REFUSAL_REASONS.map((reason) => [reason, forVarlatchdConf(PROTOCOL_REFUSAL_MESSAGES[reason])]),
) as Record<OutboundRefusalReason, string>;

export const OUTBOUND_REFUSED_GENERIC: string = forVarlatchdConf(PROTOCOL_REFUSED_GENERIC);

export const OUTBOUND_HOST_NOTE: string = forVarlatchdConf(PROTOCOL_HOST_NOTE);

export function outboundRefusalText(reason: OutboundRefusalReason | "unknown"): string {
  return reason === "unknown" ? OUTBOUND_REFUSED_GENERIC : OUTBOUND_REFUSAL_MESSAGES[reason];
}

export function outboundRefusalMessage(reason: OutboundRefusalReason): string {
  return `${OUTBOUND_REFUSAL_MESSAGES[reason]} See ${OUTBOUND_POLICY_DOCS}`;
}
