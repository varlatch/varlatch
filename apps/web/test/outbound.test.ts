// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { OUTBOUND_REFUSAL_REASONS } from "@varlatch/protocol";
import {
  OUTBOUND_HOST_NOTE,
  OUTBOUND_REFUSAL_MESSAGES,
  OUTBOUND_REFUSED_GENERIC,
  outboundRefusalMessage,
  outboundRefusalText,
} from "../src/lib/outbound";

describe("dashboard outbound refusal texts", () => {
  it("never names VARLATCH_OUTBOUND_ALLOW in any helper text", () => {
    const texts = [
      OUTBOUND_HOST_NOTE,
      OUTBOUND_REFUSED_GENERIC,
      outboundRefusalText("unknown"),
      ...OUTBOUND_REFUSAL_REASONS.flatMap((reason) => [
        OUTBOUND_REFUSAL_MESSAGES[reason],
        outboundRefusalText(reason),
        outboundRefusalMessage(reason),
      ]),
    ];
    for (const text of texts) {
      expect(text).not.toContain("VARLATCH_OUTBOUND_ALLOW");
    }
  });

  it("names outbound_allow in varlatchd.conf where the host setting is mentioned", () => {
    expect(OUTBOUND_HOST_NOTE).toContain("outbound_allow in varlatchd.conf on the host");
    expect(OUTBOUND_REFUSED_GENERIC).toContain("outbound_allow in varlatchd.conf");
    expect(OUTBOUND_REFUSAL_MESSAGES.private_address).toContain("outbound_allow in varlatchd.conf");
    expect(OUTBOUND_REFUSAL_MESSAGES.port).toContain("outbound_allow in varlatchd.conf");
    expect(outboundRefusalMessage("private_address")).toContain("outbound_allow in varlatchd.conf");
  });
});
