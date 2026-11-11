// SPDX-License-Identifier: AGPL-3.0-or-later
import { outboundRefusalOfStatus, outboundRefusalText, type Webhook } from "@varlatch/protocol";

/**
 * The last delivery of a webhook in words. A delivery this installation's
 * outbound policy refused (ADR-0057 Decision 7) is not a failure of the
 * receiver: the events wait, and go out once the host operator allows it.
 */
export function deliveryStatus(w: Pick<Webhook, "failureCount" | "lastStatus">): { tone: "ok" | "warn" | "error"; label: string; refusal?: string } {
  const refused = outboundRefusalOfStatus(w.lastStatus);
  if (refused) return { tone: "warn", label: "Refused by this installation", refusal: outboundRefusalText(refused) };
  if (w.failureCount > 0) return { tone: "error", label: `${w.failureCount} failing` };
  return { tone: "ok", label: w.lastStatus ?? "delivered" };
}
