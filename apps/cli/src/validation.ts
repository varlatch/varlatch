// SPDX-License-Identifier: Apache-2.0
import type { ValidationReport } from "@varlatch/protocol";

/**
 * `varlatch validate` output. A partial evaluation (items this identity may
 * not read) is never presented as valid; it gets its own exit status so CI
 * can tell "invalid" from "could not check everything".
 */

export const VALIDATE_EXIT = { valid: 0, invalid: 1, incomplete: 2 } as const;

export interface ValidationOutcome {
  stdout: string[];
  stderr: string[];
  exitCode: number;
}

const REQUIRES_HINT: Record<string, string> = {
  "config.metadata.read": "needs config.metadata.read",
  "config.value.read": "needs config.value.read",
  "secret.reveal": "needs secret.reveal",
};

export function validationOutcome(environment: string, report: ValidationReport): ValidationOutcome {
  // Servers before this field existed evaluated everything.
  const notEvaluated = report.notEvaluated ?? [];
  const complete = report.complete ?? notEvaluated.length === 0;
  const missing = report.missing ?? [];
  const invalid = report.invalid ?? [];
  const unresolved = report.unresolved ?? [];

  if (report.valid && complete) {
    return { stdout: [`${environment}: valid`], stderr: [], exitCode: VALIDATE_EXIT.valid };
  }

  const failed =
    missing.length > 0 || invalid.length > 0 || unresolved.some((u) => u.reason === "reference");
  const stderr: string[] = [];
  stderr.push(
    failed
      ? `${environment}: INVALID${complete ? "" : " (some items not evaluated)"}`
      : `${environment}: INCOMPLETE: not every item could be evaluated with this identity's access`,
  );
  for (const name of missing) stderr.push(`  missing: ${name}`);
  for (const item of invalid) stderr.push(`  invalid: ${item.name} — ${item.reason}`);
  for (const item of unresolved) {
    stderr.push(
      item.reason === "authority"
        ? `  unresolved: ${item.name} (references non-sensitive values; needs config.value.read)`
        : `  unresolved: ${item.name} (a reference stays literal when delivered)`,
    );
  }
  for (const item of notEvaluated) {
    const why =
      item.reason === "requirement"
        ? `${REQUIRES_HINT[item.requires] ?? item.requires}; a Requirement (e.g. Tailnet Constraint) is not met`
        : (REQUIRES_HINT[item.requires] ?? item.requires);
    stderr.push(`  not evaluated: ${item.name} (${why})`);
  }
  return {
    stdout: [],
    stderr,
    exitCode: failed ? VALIDATE_EXIT.invalid : VALIDATE_EXIT.incomplete,
  };
}

/**
 * `varlatch validate --json`: the report's names and reasons, never a value,
 * with the result and the exit status the human form would give.
 */
export function validationDocument(environment: string, report: ValidationReport, exitCode: number): Record<string, unknown> {
  const result = exitCode === VALIDATE_EXIT.valid ? "valid" : exitCode === VALIDATE_EXIT.invalid ? "invalid" : "incomplete";
  const notEvaluated = report.notEvaluated ?? [];
  return {
    environment,
    result,
    complete: report.complete ?? notEvaluated.length === 0,
    missing: report.missing ?? [],
    invalid: report.invalid ?? [],
    unresolved: report.unresolved ?? [],
    notEvaluated,
    exitCode,
  };
}
