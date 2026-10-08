// SPDX-License-Identifier: Apache-2.0
import { describe, expect, expectTypeOf, it } from "vitest";
import { CAPABILITIES, ERROR_CODES, type ErrorCode } from "../src/errors.js";
import type { components } from "../src/generated/api.js";

describe("protocol consistency", () => {
  it("errors.ts codes and the OpenAPI ErrorCode enum are the same type", () => {
    // Compile-time: drift between the hand-written list and the spec fails here.
    expectTypeOf<ErrorCode>().toEqualTypeOf<components["schemas"]["ErrorCode"]>();
  });

  it("error codes are unique", () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });

  it("capabilities are unique and namespaced", () => {
    expect(new Set(CAPABILITIES).size).toBe(CAPABILITIES.length);
    for (const cap of CAPABILITIES) {
      expect(cap).toMatch(/^[a-z-]+(\.[a-z-]+)+$/);
    }
  });
});
