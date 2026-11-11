// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { deliveryStatus } from "../src/features/audit/webhookStatus";

/** A webhook's last delivery in words, a refusal by the outbound policy included (ADR-0057 Decision 7). */
describe("deliveryStatus", () => {
  it("says a refused delivery is this installation's refusal, with the wording, not a failing receiver", () => {
    const s = deliveryStatus({ failureCount: 4, lastStatus: "outbound_refused" });
    expect(s).toMatchObject({ tone: "warn", label: "Refused by this installation" });
    expect(s.refusal).toContain("outbound policy refuses this destination");
    expect(s.refusal).toContain("VARLATCH_OUTBOUND_ALLOW");
  });

  it("keeps failures and deliveries as they were", () => {
    expect(deliveryStatus({ failureCount: 2, lastStatus: "500" })).toEqual({ tone: "error", label: "2 failing" });
    expect(deliveryStatus({ failureCount: 0, lastStatus: "200" })).toEqual({ tone: "ok", label: "200" });
    expect(deliveryStatus({ failureCount: 0, lastStatus: null })).toEqual({ tone: "ok", label: "delivered" });
  });
});
