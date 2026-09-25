// SPDX-License-Identifier: AGPL-3.0-or-later
import { useParams, useSearchParams } from "react-router-dom";
import { useOrgRealtime } from "../../lib/realtime";
import { cn } from "../../components/ui";
import { HowAccessWorks } from "./HowAccessWorks";
import { MembersTab } from "./MembersTab";
import { MachinesTab } from "./MachinesTab";
import { RolesTab } from "./RolesTab";
import { GrantsTab } from "./GrantsTab";
import { AdvancedTab } from "./AdvancedTab";

/**
 * P3 Access, restructured as an internal tabbed page (`?tab=`; no router
 * routes). Default-deny made visible: Members and Machines answer "who
 * exists", Roles & teams keep grants tidy (ADR-0028), Grants are the single
 * source of permission (ADR-0015/0029), and Advanced holds the mechanisms
 * that only narrow or observe (ADR-0014 requirements, ADR-0022 capabilities).
 */

const TABS = [
  { key: "members", label: "Members", hint: "People in this organization" },
  { key: "machines", label: "Machines", hint: "Services, CI, brokers, agents + OIDC" },
  { key: "roles", label: "Roles & teams", hint: "Reusable bundles: roles, groups, teams" },
  { key: "grants", label: "Grants", hint: "Who may do what, where — the core" },
  { key: "advanced", label: "Advanced", hint: "Broker capabilities, tailnet requirements" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

export function AccessPage() {
  const { org } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const raw = searchParams.get("tab");
  const tab: TabKey = TABS.some((t) => t.key === raw) ? (raw as TabKey) : "members";
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
    ],
  );
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Access</h1>
        <p className="text-muted text-sm">
          Who exists, and what each of them may do. Everything is default-deny: identities convey
          no access by themselves — Grants do.
        </p>
      </div>
      <HowAccessWorks />
      <div role="tablist" aria-label="Access sections" className="flex flex-wrap gap-1 border-b border-bd">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            title={t.hint}
            data-testid={`access-tab-${t.key}`}
            onClick={() =>
              setSearchParams(
                (prev) => {
                  const next = new URLSearchParams(prev);
                  next.set("tab", t.key);
                  return next;
                },
                { replace: true },
              )
            }
            className={cn(
              "-mb-px cursor-pointer rounded-t-md border-b-2 px-3 py-2 text-sm transition-colors",
              tab === t.key
                ? "border-accent font-medium text-fg"
                : "border-transparent text-muted hover:text-fg hover:bg-raised",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" aria-label={TABS.find((t) => t.key === tab)!.label}>
        {tab === "members" && <MembersTab org={org as string} />}
        {tab === "machines" && <MachinesTab org={org as string} />}
        {tab === "roles" && <RolesTab org={org as string} />}
        {tab === "grants" && <GrantsTab org={org as string} />}
        {tab === "advanced" && <AdvancedTab org={org as string} />}
      </div>
    </div>
  );
}
