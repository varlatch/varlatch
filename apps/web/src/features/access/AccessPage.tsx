// SPDX-License-Identifier: AGPL-3.0-or-later
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { useOrgName } from "../projects/hooks";
import { HowAccessWorks } from "./HowAccessWorks";
import { MembersTab } from "./MembersTab";
import { MachinesTab } from "./MachinesTab";
import { RolesTab } from "./RolesTab";
import { GrantsTab } from "./GrantsTab";
import { AdvancedTab } from "./AdvancedTab";
import { useIdentities } from "./shared";

/**
 * Access: who exists (People, Machines), how to avoid repeating yourself
 * (Roles & teams), who may do what (Grants), and the mechanisms that only
 * narrow or observe (Advanced). Tabs live in `?tab=` so links can deep-link.
 */

const TABS = ["members", "machines", "roles", "grants", "advanced"] as const;
type TabKey = (typeof TABS)[number];

export function AccessPage() {
  const { org } = useParams() as { org: string };
  const [searchParams, setSearchParams] = useSearchParams();
  const raw = searchParams.get("tab");
  const tab: TabKey = (TABS as readonly string[]).includes(raw ?? "") ? (raw as TabKey) : "members";
  const orgName = useOrgName(org);
  const { api } = useSession();
  useOrgRealtime(
    org,
    ["identity", "invitation", "oidc_binding", "grant", "capability", "requirement", "credential", "role", "group", "team"],
    [
      ["identities", org],
      ["oidc-bindings", org],
      ["grants", org],
      ["capabilities", org],
      ["requirements", org],
      ["roles", org],
      ["groups", org],
      ["teams", org],
      ["invitations", org],
    ],
  );
  const identities = useIdentities(org);
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const people = identities.data?.items.filter((i) => i.kind === "human" && !i.disabled).length;
  const machines = identities.data?.items.filter((i) => i.kind !== "human" && !i.disabled).length;

  const select = (key: string) =>
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams();
        next.set("tab", key);
        // Builder preselection (?subject=) only applies to the tab it targets.
        if (key === "grants") for (const k of ["subject", "project"]) if (prev.get(k)) next.set(k, prev.get(k)!);
        return next;
      },
      { replace: true },
    );

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Access" }]}
        title="Access"
        subtitle="Default-deny. Everything anyone can do comes from grants: explicit ones, plus the built-in grants of a person's organization role."
      />
      <HowAccessWorks />
      <Tabs
        aria-label="Access sections"
        className="mb-6"
        active={tab}
        onSelect={select}
        items={[
          { key: "members", label: "People", ...(people !== undefined ? { count: people } : {}), "data-testid": "access-tab-members" },
          { key: "machines", label: "Machines", ...(machines !== undefined ? { count: machines } : {}), "data-testid": "access-tab-machines" },
          { key: "roles", label: "Roles & teams", "data-testid": "access-tab-roles" },
          { key: "grants", label: "Grants", ...(grants.data ? { count: grants.data.items.length } : {}), "data-testid": "access-tab-grants" },
          { key: "advanced", label: "Advanced", "data-testid": "access-tab-advanced" },
        ]}
      />
      <div role="tabpanel">
        {tab === "members" && <MembersTab org={org} onGrant={(id) => setSearchParams({ tab: "grants", subject: id })} />}
        {tab === "machines" && <MachinesTab org={org} onGrant={(id) => setSearchParams({ tab: "grants", subject: id })} />}
        {tab === "roles" && <RolesTab org={org} />}
        {tab === "grants" && <GrantsTab org={org} />}
        {tab === "advanced" && <AdvancedTab org={org} />}
      </div>
    </>
  );
}
