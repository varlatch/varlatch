// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { labelWithId, quoted } from "./approvallabels.js";
import type { ApprovalBinding } from "./approvals.js";

/**
 * admin-step-up for deletion (ADR-0054 Decision 5, step 4.9, amendment
 * B): what an approval binds for deleting a Project and for scheduling the
 * Organization's deletion, per the binding catalogue, and the summary its
 * approver reads. Neither request carries a secret. Both bind the query
 * `{}` (neither route reads one) and no expected version.
 *
 * - project.delete: target the Project (the route's slug resolved to its
 *   id); no body. Projects are unversioned and a deleted one never comes
 *   back, so the id pins it. The deletion is immediate (ADR-0051 Decision
 *   2): the approval is consumed in the deletion's own transaction.
 * - organization.delete: target the Organization; body `afterDays`, 1 to
 *   30, 7 when left out (a left-out field and its default bind the same).
 *   `run_after` is computed from it when the approved request commits: no
 *   timestamp is bound. An open deletion is refused before an approval is
 *   asked for. The approval adds to ADR-0051's checks and replaces none:
 *   the waiting period applies in full, and with more than one admin a
 *   different admin must still approve the scheduled deletion, with no
 *   step-up of their own.
 *
 * Summaries follow approvallabels.ts: the Project and the Organization are
 * named by their quoted name and bound id, a slug is quoted, and counts
 * are numbers.
 */

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** A live Project of the Organization, as its deletion's summary names it. */
export interface ProjectRef {
  id: string;
  slug: string;
  name: string;
  /** Its live environments, which the deletion ends with their values. */
  environments: number;
}

/** A live Project with its count of live environments, read without a lock; null when there is none. */
export async function readProjectForDeletion(db: Querier, organizationId: string, projectId: string): Promise<ProjectRef | null> {
  const row = (await db.query(
    `SELECT p.id, p.slug, p.name,
            (SELECT count(*)::int FROM environments e WHERE e.project_id = p.id AND e.deleted_at IS NULL) AS environments
     FROM projects p WHERE p.id = $1 AND p.organization_id = $2 AND p.deleted_at IS NULL`,
    [projectId, organizationId],
  )).rows[0] as { id: string; slug: string; name: string; environments: number } | undefined;
  return row ? { ...row, environments: Number(row.environments) } : null;
}

/** project.delete of a live Project. */
export function projectDeleteBinding(org: { id: string }, project: ProjectRef): ApprovalBinding {
  return {
    operation: "project.delete",
    organizationId: org.id,
    target: { projectId: project.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: {
      title:
        `Delete the project ${labelWithId(null, project.name, project.id)}, slug ${quoted(project.slug)}, now: ` +
        `${plural(project.environments, "environment")} and their values erased. This cannot be undone`,
      changes: [],
    },
  };
}

/** organization.delete: scheduling the Organization's deletion after `afterDays` days. */
export function organizationDeleteBinding(org: { id: string; name: string }, afterDays: number, admins: number): ApprovalBinding {
  return {
    operation: "organization.delete",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { afterDays },
    query: {},
    expectedVersion: null,
    summary: {
      title:
        `Schedule the deletion of organization ${labelWithId(null, org.name, org.id)} in ${plural(afterDays, "day")}` +
        (admins > 1 ? ". Another admin must approve it before it can run" : ""),
      changes: [{ field: "afterDays", from: null, to: plural(afterDays, "day"), loosens: false }],
    },
  };
}
