// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useConvexConnectionState } from "convex/react";
import { Download } from "lucide-react";
import { useMirrorInvalidation } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Status } from "../../components/ui";
import { PageHeader } from "../../components/PageHeader";
import { useToast } from "../../components/Toast";
import { useOrgName } from "../projects/hooks";
import { AuditTimeline, NO_FILTERS, rangeStart, serverFilters, useServerFiltering, type AuditFilterState } from "./AuditTimeline";
import { WebhooksSection } from "./WebhooksSection";

/**
 * Audit log: one timeline over the authoritative /v1 store. The reactive
 * Convex mirror only signals that new events exist, so the page refreshes
 * without polling ("Live"). Export downloads the same filters as NDJSON.
 */
export function AuditPage() {
  const { org } = useParams() as { org: string };
  const { api } = useSession();
  const toast = useToast();
  const orgName = useOrgName(org);
  const orgQuery = useQuery({ queryKey: ["org", org], queryFn: () => api.getOrganization(org) });
  useMirrorInvalidation(orgQuery.data?.id, "*", [["audit", org]]);
  const connection = useConvexConnectionState();
  const live = connection.isWebSocketConnected && Boolean(orgQuery.data);
  const server = useServerFiltering();

  const [params] = useSearchParams();
  const [filters, setFilters] = useState<AuditFilterState>(() => ({
    ...NO_FILTERS,
    actor: params.get("actor") ?? "",
    project: params.get("project") ?? "",
    decision: (["allow", "deny", "info"].includes(params.get("decision") ?? "") ? params.get("decision") : "") as AuditFilterState["decision"],
  }));
  const [exporting, setExporting] = useState(false);

  const exportNdjson = async () => {
    setExporting(true);
    try {
      const body = await api.exportAuditEventsNdjson(org, server ? serverFilters(filters, {}, rangeStart(filters.range)) : {});
      const url = URL.createObjectURL(new Blob([body], { type: "application/x-ndjson" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `varlatch-audit-${org}.ndjson`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error("Export failed", { description: err instanceof Error ? err.message : String(err) });
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Audit" }]}
        title="Audit log"
        actions={
          <>
            <span
              data-testid="audit-live"
              title={
                live
                  ? "New events appear as they are recorded."
                  : "Live updates are not connected; the log refreshes when you reload or filter."
              }
            >
              {live ? <Status tone="live">Live</Status> : <Status tone="muted">Not live</Status>}
            </span>
            <Button
              data-testid="audit-export"
              icon={<Download size={14} />}
              loading={exporting}
              onClick={() => void exportNdjson()}
              title={
                server
                  ? "Downloads every event matching the actor, project, decision and time filters."
                  : "Downloads every event; this server does not filter exports."
              }
            >
              Export NDJSON
            </Button>
          </>
        }
      />
      <AuditTimeline
        org={org}
        filters={filters}
        onFiltersChange={setFilters}
        emptyHint="Every sign-in, change, disclosure and denial in this organization is recorded here."
      />
      <WebhooksSection org={org} orgId={orgQuery.data?.id} className="mt-8" />
    </>
  );
}
