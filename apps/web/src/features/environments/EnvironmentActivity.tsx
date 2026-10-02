// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { AuditTimeline, NO_FILTERS, type AuditFilterState } from "../audit/AuditTimeline";
import { useEnvironmentContext } from "../projects/hooks";

/** Environment Activity: the audit timeline scoped to this environment. */
export function EnvironmentActivity() {
  const { org, environment } = useEnvironmentContext();
  const [filters, setFilters] = useState<AuditFilterState>(NO_FILTERS);
  return (
    <AuditTimeline
      org={org}
      filters={filters}
      onFiltersChange={setFilters}
      scope={{ environmentId: environment.id }}
      facets={["actor", "decision", "range"]}
      emptyHint="Changes, reads, integrations and denials in this environment show up here."
    />
  );
}
