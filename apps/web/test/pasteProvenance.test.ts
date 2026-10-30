// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { savedPastedValue } from "../src/features/values/model";

/**
 * The checklist after pasted drafts are saved (ADR-0053) advises deleting
 * the source of the paste, so it shows only when a value was saved exactly
 * as pasted: never for a pasted draft reverted or edited before saving.
 */
describe("whether a save stored a pasted value", () => {
  const pasted = new Map([
    ["API_KEY", "pasted-value-1"],
    ["PORT", "3000"],
  ]);

  it("is true when a pasted value was saved as pasted", () => {
    expect(savedPastedValue(pasted, new Map([["API_KEY", { op: "set", value: "pasted-value-1" }]]))).toBe(true);
  });

  it("is false when the pasted drafts were reverted and something else was saved", () => {
    expect(savedPastedValue(pasted, new Map([["OTHER", { op: "set", value: "typed" }]]))).toBe(false);
  });

  it("is false when a pasted draft was edited, or turned into a delete, before saving", () => {
    expect(savedPastedValue(pasted, new Map([["API_KEY", { op: "set", value: "edited" }]]))).toBe(false);
    expect(savedPastedValue(pasted, new Map([["PORT", { op: "delete" }]]))).toBe(false);
  });

  it("is false when nothing was pasted or nothing saved in that environment", () => {
    expect(savedPastedValue(undefined, new Map([["API_KEY", { op: "set", value: "pasted-value-1" }]]))).toBe(false);
    expect(savedPastedValue(pasted, undefined)).toBe(false);
  });
});
