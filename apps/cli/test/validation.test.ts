// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { ValidationReport } from "@varlatch/protocol";
import { validationOutcome, VALIDATE_EXIT } from "../src/validation.js";

const base = {
  environmentId: "env_1",
  contractRevisionId: "rev_1",
  missing: [],
  invalid: [],
  notEvaluated: [],
} satisfies Partial<ValidationReport>;

describe("varlatch validate outcome", () => {
  it("valid and complete exits 0", () => {
    const out = validationOutcome("production", { ...base, valid: true, complete: true });
    expect(out).toEqual({ stdout: ["production: valid"], stderr: [], exitCode: VALIDATE_EXIT.valid });
  });

  it("invalid evaluated items exit 1 with their reasons", () => {
    const out = validationOutcome("production", {
      ...base,
      valid: false,
      complete: true,
      missing: ["DATABASE_URL"],
      invalid: [{ name: "PORT", reason: "must be a number" }],
    });
    expect(out.exitCode).toBe(VALIDATE_EXIT.invalid);
    expect(out.stderr).toEqual([
      "production: INVALID",
      "  missing: DATABASE_URL",
      "  invalid: PORT — must be a number",
    ]);
  });

  it("a partial evaluation is never reported as valid: exit 2, items named with the access they need", () => {
    const out = validationOutcome("production", {
      ...base,
      valid: false,
      complete: false,
      notEvaluated: [
        { name: "API_TOKEN", reason: "permission", requires: "secret.reveal" },
        { name: "STRIPE_KEY", reason: "requirement", requires: "secret.reveal" },
        { name: "LOG_LEVEL", reason: "permission", requires: "config.value.read" },
      ],
    });
    expect(out.exitCode).toBe(VALIDATE_EXIT.incomplete);
    expect(out.stdout).toEqual([]);
    expect(out.stderr[0]).toMatch(/^production: INCOMPLETE/);
    expect(out.stderr).toContain("  not evaluated: API_TOKEN (needs secret.reveal)");
    expect(out.stderr).toContain(
      "  not evaluated: STRIPE_KEY (needs secret.reveal; a Requirement (e.g. Tailnet Constraint) is not met)",
    );
    expect(out.stderr).toContain("  not evaluated: LOG_LEVEL (needs config.value.read)");
    expect(out.stderr.join("\n")).not.toMatch(/valid$/m);
  });

  it("invalid plus not evaluated is INVALID (exit 1) and still lists what was not evaluated", () => {
    const out = validationOutcome("production", {
      ...base,
      valid: false,
      complete: false,
      invalid: [{ name: "PORT", reason: "must be a number" }],
      notEvaluated: [{ name: "API_TOKEN", reason: "permission", requires: "secret.reveal" }],
    });
    expect(out.exitCode).toBe(VALIDATE_EXIT.invalid);
    expect(out.stderr[0]).toBe("production: INVALID (some items not evaluated)");
    expect(out.stderr).toContain("  not evaluated: API_TOKEN (needs secret.reveal)");
  });

  it("a server without the new fields is treated as a full evaluation", () => {
    const legacy = { environmentId: "e", contractRevisionId: null, valid: true, missing: [], invalid: [] };
    const out = validationOutcome("dev", legacy as unknown as ValidationReport);
    expect(out.exitCode).toBe(VALIDATE_EXIT.valid);
  });
});
