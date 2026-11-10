// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, BookOpen, Fingerprint, KeyRound, ListChecks, ShieldCheck, ShieldOff, Wifi } from "lucide-react";
import type { SecurityControl } from "@varlatch/sdk";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Badge, EmptyState, SectionCard, Skeleton, cn } from "../../components/ui";
import { PageHeader } from "../../components/PageHeader";
import { errorMessage } from "../../shell/Shell";
import { useCapability, useOrgName } from "../projects/hooks";
import { useIdentities } from "../access/shared";
import { CONTROL_TEXT, SecurityControlsCard, controlReportKey, securityControlsKey } from "./SecurityControlsCard";
import { ApprovalKeysCard, approvalKeysKey } from "./ApprovalKeysCard";
import { CredentialsCard, credentialReviewKey } from "./CredentialsCard";
import { CHECKLIST, SECURITY_PAGE_DOCS } from "./checklist";

/**
 * The Organization's Security page (ADR-0054 Decision 11), next to
 * Settings: the controls with what each counts and would change, their
 * counts, the admins' approval keys, the credential review with expiry
 * warnings, the Tailnet Requirements, and a short checklist. It is where an
 * admin decides which controls to turn on. (The account's own passkeys live
 * on /account/security.)
 *
 * Every member reads the controls (organization.read). The counts and the
 * approval keys need organization.manage, the credential review
 * identity.manage, Requirements policy.read: all of which an admin holds.
 * They are asked for only for an admin, so a member's visit never collects
 * refusals, and a member sees a note instead of errors.
 */

const SECTIONS = [
  { id: "controls", label: "Controls", icon: ShieldCheck, admin: false },
  { id: "approval-keys", label: "Approval keys", icon: Fingerprint, admin: true },
  { id: "credentials", label: "Machine credentials", icon: KeyRound, admin: true },
  { id: "requirements", label: "Tailnet Requirements", icon: Wifi, admin: true },
  { id: "checklist", label: "Checklist", icon: ListChecks, admin: false },
] as const;

export function OrgSecurityPage() {
  const { org } = useParams() as { org: string };
  const { api, identityId } = useSession();
  const orgName = useOrgName(org);
  const supported = useCapability("security.controls");
  const hasReport = useCapability("security.report");
  const hasKeys = useCapability("security.approval-keys");
  const hasReview = useCapability("security.credential-review");
  useOrgRealtime(
    org,
    ["security_control", "membership", "identity", "credential", "requirement"],
    [securityControlsKey(org), controlReportKey(org), approvalKeysKey(org), credentialReviewKey(org), ["requirements", org], ["identities", org]],
  );
  const identities = useIdentities(org);
  const admin = (identities.data?.items ?? []).some((i) => i.id === identityId && i.orgRole === "admin" && !i.removedAt);
  const controls = useQuery({ queryKey: securityControlsKey(org), queryFn: () => api.listSecurityControls(org), enabled: supported });
  // The current hour is live: refresh while the page is open.
  const report = useQuery({
    queryKey: controlReportKey(org),
    queryFn: () => api.securityControlReport(org, { days: 30 }),
    enabled: supported && admin && hasReport,
    refetchInterval: 60_000,
  });
  const keys = useQuery({ queryKey: approvalKeysKey(org), queryFn: () => api.securityApprovalKeys(org), enabled: supported && admin && hasKeys });
  const review = useQuery({ queryKey: credentialReviewKey(org), queryFn: () => api.credentialReview(org), enabled: supported && admin && hasReview });
  const requirements = useQuery({ queryKey: ["requirements", org], queryFn: () => api.listRequirements(org), enabled: supported && admin });

  // The whole page waits for the controls and the person's role, so admin sections never pop in.
  const settled = !controls.isLoading && !identities.isLoading;
  const sections = SECTIONS.filter(
    (s) => (admin || !s.admin) && (s.id !== "approval-keys" || hasKeys) && (s.id !== "credentials" || hasReview),
  );
  const [active, setActive] = useState<string>("controls");
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const els = sections.map((s) => document.getElementById(`security-${s.id}`)).filter(Boolean) as HTMLElement[];
    const io = new IntersectionObserver(
      (entries) => {
        const top = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (top) setActive(top.target.id.replace("security-", ""));
      },
      { rootMargin: "-20% 0px -60% 0px" },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [settled, sections.length, keys.data, review.data, requirements.data]);

  const header = (
    <PageHeader
      breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Security" }]}
      title="Security"
      subtitle="Optional protections for this organization, and what to check. Every control is off unless an admin turns it on."
    />
  );

  if (!supported) {
    return (
      <>
        {header}
        <SectionCard title="Security controls" data-testid="security-unsupported">
          <EmptyState
            icon={<ShieldOff size={20} />}
            title="This server has no security controls yet"
            description="They arrive with a newer Varlatch release. Whoever runs this server can upgrade it."
          />
        </SectionCard>
      </>
    );
  }

  return (
    <>
      {header}
      <div className="grid gap-8 lg:grid-cols-[200px_1fr]">
        <nav className="hidden lg:block" aria-label="Security sections">
          <ul className="sticky top-6 space-y-0.5">
            {sections.map(({ id, label, icon: Icon }) => (
              <li key={id}>
                <a
                  href={`#security-${id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    document.getElementById(`security-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
                    setActive(id);
                  }}
                  className={cn(
                    "relative flex h-9 items-center gap-2.5 rounded-lg px-3 text-[14px] font-medium transition-colors",
                    active === id ? "bg-accent-dim text-fg" : "text-muted hover:bg-hover hover:text-fg",
                  )}
                >
                  {active === id && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-r bg-accent" aria-hidden="true" />}
                  <Icon size={16} className={active === id ? "text-accent" : undefined} />
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 space-y-6" data-testid="security-page" data-admin={admin ? "true" : "false"}>
          {!settled ? (
            <PageSkeleton />
          ) : controls.error ? (
            <SectionCard title="Controls" data-testid="security-controls-error">
              <p className="px-5 py-4 text-[13px] text-deny" role="alert">
                {errorMessage(controls.error)}
              </p>
            </SectionCard>
          ) : (
            <>
              <Overview items={controls.data?.items ?? []} />
              <SecurityControlsCard
                org={org}
                admin={admin}
                controls={controls.data}
                report={report.data ? { days: report.data.days, controls: report.data.controls } : null}
              />
              {admin ? (
                <>
                  <Part query={keys} enabled={hasKeys} title="Approval keys" id="approval-keys">
                    {(data) => <ApprovalKeysCard keys={data} />}
                  </Part>
                  <Part query={review} enabled={hasReview} title="Machine credentials" id="credentials">
                    {(data) => <CredentialsCard org={org} review={data} />}
                  </Part>
                  <Part query={requirements} enabled title="Tailnet Requirements" id="requirements">
                    {(data) => (
                      <RequirementsCard
                        org={org}
                        count={data.items.length}
                        protection={controls.data?.items.find((c) => c.control === "requirement-protection")?.mode ?? "off"}
                      />
                    )}
                  </Part>
                </>
              ) : (
                <p className="rounded-xl border border-bd bg-raised px-5 py-4 text-[13px] text-muted" data-testid="security-member-note">
                  An admin of this organization manages its security. Admins also see here what each control counted, their approval keys,
                  the machine credentials to review and the Tailnet Requirements.
                </p>
              )}
              <ChecklistCard />
            </>
          )}
        </div>
      </div>
    </>
  );
}

/** One line on top: which controls are on, if any. */
function Overview({ items }: { items: SecurityControl[] }) {
  const on = items.filter((c) => c.mode !== "off");
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-bd bg-raised px-5 py-3.5 text-[13px]" data-testid="security-overview">
      {on.length === 0 ? (
        <>
          <ShieldOff size={16} className="text-muted" aria-hidden="true" />
          <span>Every control is off, as it is by default. Nothing is counted, refused or changed.</span>
        </>
      ) : (
        <>
          <ShieldCheck size={16} className="text-accent" aria-hidden="true" />
          <span>Turned on:</span>
          {on.map((c) => (
            <Badge key={c.control} tone="accent">
              {CONTROL_TEXT[c.control].label}: {c.mode}
            </Badge>
          ))}
        </>
      )}
    </div>
  );
}

/**
 * An admin section: hidden when the server cannot give it or the person
 * may not read it (a refusal), a skeleton while it loads, an error in place
 * otherwise.
 */
function Part<T>({
  query,
  enabled,
  title,
  id,
  children,
}: {
  query: { data: T | undefined; error: unknown; isLoading: boolean };
  enabled: boolean;
  title: string;
  id: string;
  children: (data: T) => React.ReactNode;
}) {
  if (!enabled) return null;
  if (query.data !== undefined) return <>{children(query.data)}</>;
  if (query.error) {
    const status = (query.error as { status?: number }).status;
    if (status === 403 || status === 404) return null;
    return (
      <SectionCard id={`security-${id}`} title={title} className="scroll-mt-6">
        <p className="px-5 py-4 text-[13px] text-deny" role="alert" data-testid={`security-${id}-error`}>
          {errorMessage(query.error)}
        </p>
      </SectionCard>
    );
  }
  return <CardSkeleton title={title} id={id} />;
}

function RequirementsCard({ org, count, protection }: { org: string; count: number; protection: SecurityControl["mode"] }) {
  const editor = `/o/${org}/access?tab=advanced`;
  return (
    <SectionCard
      id="security-requirements"
      title="Tailnet Requirements"
      description="Requirements narrow where values can be read: only from devices on your tailnet that match. They never grant access."
      className="scroll-mt-6"
      data-testid="security-requirements"
      actions={
        <Link to={editor} className="inline-flex h-7 items-center rounded-md border border-bd px-2.5 text-xs font-medium text-fg hover:bg-hover" data-testid="security-requirements-link">
          Access, Advanced
        </Link>
      }
    >
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-4 text-[13px]">
        <span data-testid="security-requirements-count" data-count={count}>
          {count === 0 ? "No Tailnet Requirements yet." : `${count} Tailnet Requirement${count === 1 ? "" : "s"}.`}
        </span>
        <span className="flex items-center gap-2 text-muted">
          Requirement protection
          <Badge tone={protection === "off" ? "neutral" : "accent"}>{protection}</Badge>
        </span>
      </div>
      <p className="border-t border-bd px-5 py-2.5 text-xs text-muted">
        {count === 0
          ? "Reading values is governed by grants alone. Add one in Access, Advanced, for example so that production values are only read from devices tagged tag:prod."
          : "Requirement protection counts each edit or revocation without an approval; with enforce, changing one would need an approval with a trusted passkey."}
      </p>
    </SectionCard>
  );
}

function ChecklistCard() {
  return (
    <SectionCard
      id="security-checklist"
      title="Checklist"
      description="A few things worth doing, whatever the controls say. Each links to its page in the docs."
      className="scroll-mt-6"
      data-testid="security-checklist"
      actions={
        <a
          href={SECURITY_PAGE_DOCS}
          target="_blank"
          rel="noreferrer"
          className="inline-flex h-7 items-center gap-1 rounded-md border border-bd px-2.5 text-xs font-medium text-fg hover:bg-hover"
        >
          <BookOpen size={13} aria-hidden="true" />
          About this page
        </a>
      }
    >
      <ul>
        {CHECKLIST.map((item) => (
          <li key={item.id} className="border-b border-bd last:border-b-0" data-testid={`security-checklist-${item.id}`}>
            <a href={item.url} target="_blank" rel="noreferrer" className="group flex items-start justify-between gap-4 px-5 py-3 hover:bg-hover">
              <span className="min-w-0">
                <span className="block text-[14px] font-medium group-hover:text-accent">{item.title}</span>
                <span className="block text-[13px] text-muted">{item.why}</span>
              </span>
              <ArrowUpRight size={14} className="mt-1 shrink-0 text-muted group-hover:text-accent" aria-hidden="true" />
            </a>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function CardSkeleton({ title, id }: { title: string; id?: string }) {
  return (
    <SectionCard id={id ? `security-${id}` : undefined} title={title} className="scroll-mt-6" data-testid={id ? `security-${id}-loading` : undefined}>
      <div className="space-y-2.5 px-5 py-4">
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-4 w-3/5" />
      </div>
    </SectionCard>
  );
}

function PageSkeleton() {
  return (
    <div className="space-y-6" data-testid="security-loading">
      <Skeleton className="h-12 w-full rounded-xl" />
      <CardSkeleton title="Controls" />
      <CardSkeleton title="Approval keys" />
    </div>
  );
}
