// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ValidationReport } from "@varlatch/protocol";

/**
 * How the dashboard presents a validation report. Items the signed-in
 * identity may not read come back "not evaluated"; a partial evaluation is
 * never shown as valid, and its not-evaluated items never affect "invalid".
 */
export type ValidationSummary =
  | { state: "valid" }
  | { state: "invalid"; failing: string[]; notEvaluated: string[] }
  | { state: "incomplete"; notEvaluated: string[] };

export function validationSummary(report: ValidationReport): ValidationSummary {
  // Servers before this field existed evaluated everything.
  // An item unresolved only because of this caller's access counts as not
  // evaluated; any other unresolved reference is a failure.
  const unresolved = report.unresolved ?? [];
  const notEvaluated = [
    ...(report.notEvaluated ?? []).map((i) => i.name),
    ...unresolved.filter((u) => u.reason === "authority").map((u) => u.name),
  ];
  const complete = report.complete ?? notEvaluated.length === 0;
  const failing = [
    ...(report.missing ?? []),
    ...(report.invalid ?? []).map((i) => i.name),
    ...unresolved.filter((u) => u.reason === "reference").map((u) => u.name),
  ];
  if (report.valid && complete) return { state: "valid" };
  if (failing.length > 0) return { state: "invalid", failing, notEvaluated };
  return { state: "incomplete", notEvaluated };
}
