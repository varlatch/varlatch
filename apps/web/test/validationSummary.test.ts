// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { ValidationReport } from "@varlatch/protocol";
import { validationSummary } from "../src/features/projects/validationSummary";

const base = { environmentId: "e", contractRevisionId: "r", missing: [], invalid: [], notEvaluated: [], unresolved: [] };

describe("dashboard validation summary", () => {
  it("valid only when complete", () => {
    expect(validationSummary({ ...base, valid: true, complete: true })).toEqual({ state: "valid" });
  });

  it("a partial result with no failures is incomplete, never valid", () => {
    const report: ValidationReport = {
      ...base,
      valid: false,
      complete: false,
      notEvaluated: [{ name: "API_TOKEN", reason: "permission", requires: "secret.reveal" }],
    };
    expect(validationSummary(report)).toEqual({ state: "incomplete", notEvaluated: ["API_TOKEN"] });
  });

  it("failures among evaluated items are invalid, and not-evaluated items are listed separately", () => {
    const report: ValidationReport = {
      ...base,
      valid: false,
      complete: false,
      missing: ["DATABASE_URL"],
      invalid: [{ name: "PORT", reason: "must be a number" }],
      notEvaluated: [{ name: "API_TOKEN", reason: "requirement", requires: "secret.reveal" }],
    };
    expect(validationSummary(report)).toEqual({
      state: "invalid",
      failing: ["DATABASE_URL", "PORT"],
      notEvaluated: ["API_TOKEN"],
    });
  });

  it("an unresolved reference fails; one unresolved only for this caller's access is not evaluated", () => {
    const report: ValidationReport = {
      ...base,
      valid: false,
      complete: false,
      unresolved: [
        { name: "DATABASE_URL", reason: "authority" },
        { name: "LEAK", reason: "reference" },
      ],
    };
    expect(validationSummary(report)).toEqual({
      state: "invalid",
      failing: ["LEAK"],
      notEvaluated: ["DATABASE_URL"],
    });
    expect(
      validationSummary({ ...report, unresolved: [{ name: "DATABASE_URL", reason: "authority" }] }),
    ).toEqual({ state: "incomplete", notEvaluated: ["DATABASE_URL"] });
  });

  it("treats a report from an older server (no new fields) as complete", () => {
    const legacy = { environmentId: "e", contractRevisionId: null, valid: true, missing: [], invalid: [] };
    expect(validationSummary(legacy as unknown as ValidationReport)).toEqual({ state: "valid" });
  });
});
