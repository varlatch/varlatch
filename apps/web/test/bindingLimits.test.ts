// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { OidcBinding } from "@varlatch/protocol";
import { bindingLimits } from "../src/features/access/MachinesTab";

const binding = (over: Partial<OidcBinding>): OidcBinding => ({
  id: "oib_1",
  identityId: "idn_1",
  issuer: "https://issuer.example",
  audience: "varlatch",
  subject: "machine:m1",
  claims: null,
  createdAt: "2026-10-02T09:14:00Z",
  ...over,
});

describe("bindingLimits", () => {
  it("says nothing of a binding without limits", () => {
    expect(bindingLimits(binding({}))).toBe("");
  });
  it("says what a binding limits", () => {
    expect(bindingLimits(binding({ singleExchange: true }))).toBe("Each token exchanges once.");
    expect(bindingLimits(binding({ exerciseOnly: true, singleExchange: true }))).toBe("Uses capabilities, and nothing else; each token exchanges once.");
    expect(bindingLimits(binding({ exerciseOnly: true, singleExchange: true, runIdClaim: "job_id" }))).toBe(
      "Uses capabilities of the run in its job_id claim, and nothing else; each token exchanges once.",
    );
  });
});
