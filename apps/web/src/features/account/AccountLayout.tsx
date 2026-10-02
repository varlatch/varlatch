// SPDX-License-Identifier: AGPL-3.0-or-later
import { Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useSession } from "../../lib/session";
import { displayEmail } from "../../lib/identity";
import { useMeRealtime } from "../../lib/realtime";
import { Avatar, Badge } from "../../components/ui";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { useCurrentOrg } from "../../shell/Shell";
import { useOrgName } from "../projects/hooks";
import { useIdentities } from "../access/shared";

/** The signed-in person's own account: profile, passkeys, sessions. */
export function AccountLayout() {
  const { api, identityId } = useSession();
  const { pathname } = useLocation();
  const section = pathname.endsWith("/security") ? "Security" : pathname.endsWith("/sessions") ? "Sessions" : "Profile";
  const org = useCurrentOrg();
  const orgName = useOrgName(org);
  useMeRealtime(["credential"], [["me-credentials"]]);
  const profile = useQuery({ queryKey: ["me-profile"], queryFn: () => api.getMyProfile(), retry: false });
  const creds = useQuery({ queryKey: ["me-credentials"], queryFn: () => api.listMyCredentials() });
  const identities = useIdentities(org ?? "");
  const me = identities.data?.items.find((i) => i.id === identityId);
  const name = profile.data?.name ?? me?.name ?? "Your account";
  const email = displayEmail(profile.data?.email);
  const active = (creds.data?.items ?? []).filter((c) => !c.revokedAt && (!c.expiresAt || new Date(c.expiresAt).getTime() > Date.now())).length;

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: "Account", to: "/account" }, { label: section }]}
        title={
          <span className="flex items-center gap-4">
            <Avatar name={name} image={profile.data?.image ?? null} size="xl" />
            <span>
              <span className="block">{name}</span>
              <span className="mt-1 flex flex-wrap items-center gap-2 text-sm font-normal tracking-normal text-muted">
                {email && <span>{email}</span>}
                {me?.orgRole && orgName && (
                  <>
                    {email && <span aria-hidden="true">·</span>}
                    <span>
                      {me.orgRole} of {orgName}
                    </span>
                  </>
                )}
                {profile.isError && <Badge>machine identity</Badge>}
              </span>
            </span>
          </span>
        }
        tabs={
          <Tabs
            aria-label="Account sections"
            items={[
              { key: "profile", label: "Profile", to: "/account", end: true, "data-testid": "account-tab-profile" },
              { key: "security", label: "Security", to: "/account/security", "data-testid": "account-tab-security" },
              {
                key: "sessions",
                label: "Sessions",
                to: "/account/sessions",
                ...(creds.data ? { count: active } : {}),
                "data-testid": "account-tab-sessions",
              },
            ]}
          />
        }
      />
      <div className="max-w-4xl">
        <Outlet />
      </div>
    </>
  );
}
