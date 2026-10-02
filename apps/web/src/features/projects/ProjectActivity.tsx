// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { AuditTimeline, NO_FILTERS, type AuditFilterState } from "../audit/AuditTimeline";
import { useProjectContext } from "./hooks";

/** Project Activity: the audit timeline scoped to this project. */
export function ProjectActivity() {
  const { org, project } = useProjectContext();
  const [filters, setFilters] = useState<AuditFilterState>(NO_FILTERS);
  return (
    <AuditTimeline
      org={org}
      filters={filters}
      onFiltersChange={setFilters}
      scope={{ projectId: project.id }}
      facets={["actor", "decision", "range"]}
      emptyHint="Changes, reads and denials in this project's environments show up here."
    />
  );
}
