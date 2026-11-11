// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import {
  VarlatchApiError,
  type CredentialLifetimeConfig,
  type SecurityControl,
  type SecurityControlChangeInput,
  type SecurityControlMode,
  type SecurityControlCounts,
  type SecurityControlName,
  type SecurityReportReason,
} from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { formatTime, timeAgo, useNow } from "../../lib/time";
import { Badge, Button, Callout, Input, SectionCard, Select, Skeleton } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { approvalOutcomeMessage, durationWords } from "./approval";

/**
 * The Organization's Security Controls (ADR-0054 Decisions 1, 2, 5 and 9),
 * the first section of the Security page. Every control is off unless an
 * admin changes it. Each one says what report mode counts and what enforce
 * would change, with its counts of the last 30 days for admins. Tightening
 * saves at once; loosening (a mode towards off, a lifetime that grows,
 * lifetimes cleared) needs the admin's approval with a trusted passkey,
 * which the session's approval dialog asks for. enforce is not available
 * yet: it is shown as coming in a later release, never as a broken choice.
 */

export const securityControlsKey = (org: string) => ["security-controls", org] as const;
export const controlReportKey = (org: string) => ["security-control-report", org] as const;

export const CONTROL_TEXT: Record<SecurityControlName, { label: string; report: string; enforce: string }> = {
  "requirement-protection": {
    label: "Requirement protection",
    report: "Counts each edit or revocation of a Tailnet Requirement made without an approval. Creating one is not counted: it only restricts.",
    enforce: "Editing or revoking a Tailnet Requirement would need an approval with a trusted passkey, so a stolen admin sign-in cannot remove one from off the tailnet.",
  },
  "admin-step-up": {
    label: "Admin step-up",
    report:
      "Counts each administrative change made without an approval: machine identities and credentials, grants, roles, groups and teams, admins and members, integrations, deletion, and .env export.",
    enforce: "Those changes would need an approval with a trusted passkey. A machine credential can never give one, so it would be refused.",
  },
  "passkey-verification": {
    label: "Passkey verification",
    report:
      "Counts requests by a person's dashboard or CLI sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face). Only requests that were allowed and succeeded count, and machine credentials never do. Access counts are best-effort: a busy server can drop some, so a count is a lower bound.",
    enforce: "Such sign-ins would be refused in this organization until the person signs in again with a trusted passkey and a PIN, fingerprint or face.",
  },
  "credential-lifetime": {
    label: "Credential lifetime",
    report:
      "Counts machine credentials issued without a lifetime (they would get the default) and with one above the maximum (they would be refused). OIDC and agent-run credentials are not counted.",
    enforce: "Machine credentials would get the default lifetime when none is given, and longer ones would be refused. Existing credentials never change.",
  },
};

/** Why a control counted an attempt, in words. */
export const REASON_TEXT: Record<SecurityReportReason, string> = {
  "no-approval": "no approval",
  "machine-credential": "machine credential",
  "no-evidence": "no sign-in evidence",
  "not-user-verified": "not verified",
  "untrusted-passkey": "unconfirmed passkey",
  "would-default": "would get the default",
  "would-refuse": "would be refused",
};

const MODE_LABEL: Record<SecurityControlMode, string> = { off: "Off", report: "Report", enforce: "Enforce" };
const MODE_RANK: Record<SecurityControlMode, number> = { off: 0, report: 1, enforce: 2 };

/** Whether a change weakens the control, field by field, as the server decides it. */
export function loosens(current: SecurityControl, next: { mode: SecurityControlMode; config: CredentialLifetimeConfig | null }): boolean {
  if (MODE_RANK[next.mode] < MODE_RANK[current.mode]) return true;
  const before = current.config;
  if (before && !next.config) return true;
  if (before && next.config) {
    return next.config.defaultTtlSeconds > before.defaultTtlSeconds || next.config.maxTtlSeconds > before.maxTtlSeconds;
  }
  return false;
}

/** The lifetimes typed, or why they cannot be saved. Both empty clears them. */
export function parseLifetimes(defaultTtl: string, maxTtl: string): { config: CredentialLifetimeConfig | null } | { error: string } {
  const d = defaultTtl.trim();
  const m = maxTtl.trim();
  if (d === "" && m === "") return { config: null };
  if (!/^\d+$/.test(d) || !/^\d+$/.test(m)) return { error: "Give both lifetimes in whole seconds, or leave both empty." };
  const config = { defaultTtlSeconds: Number(d), maxTtlSeconds: Number(m) };
  if (config.defaultTtlSeconds <= 0) return { error: "The default lifetime must be more than 0 seconds." };
  if (config.defaultTtlSeconds > config.maxTtlSeconds) return { error: "The default lifetime cannot be longer than the maximum." };
  return { config };
}

/** What the request sends: only what changed, and the version it was read at. */
export function changeInput(
  current: SecurityControl,
  next: { mode: SecurityControlMode; config: CredentialLifetimeConfig | null },
): SecurityControlChangeInput | null {
  const input: SecurityControlChangeInput = { expectedVersion: current.version };
  if (next.mode !== current.mode) input.mode = next.mode;
  const same =
    (current.config === null && next.config === null) ||
    (current.config !== null &&
      next.config !== null &&
      current.config.defaultTtlSeconds === next.config.defaultTtlSeconds &&
      current.config.maxTtlSeconds === next.config.maxTtlSeconds);
  if (!same) input.config = next.config;
  return input.mode === undefined && input.config === undefined ? null : input;
}

/** The message for a failed save. */
export function saveError(err: unknown): string {
  const approval = approvalOutcomeMessage(err);
  if (approval) return approval;
  if (err instanceof VarlatchApiError) {
    if (err.code === "VERSION_CONFLICT") return "Someone changed this control meanwhile. It was reloaded: check it and save again.";
    if (err.code === "CONTROL_MODE_UNAVAILABLE") return "Enforce is not available yet on this server. Use report to see what the control would do.";
  }
  return errorMessage(err);
}

/** The counts as the page loaded them: data, and whether loading or the last refresh failed. */
export interface ReportState {
  data: { days: number; controls: SecurityControlCounts[] } | null;
  error: unknown;
  loading: boolean;
  fetching: boolean;
  /** When the data was last loaded (ms since the epoch); 0 before. */
  updatedAt: number;
  retry: () => void;
}

/**
 * The controls section. `admin` decides whether the modes can be changed;
 * `report` is the counts' state, null when the caller cannot read them
 * (or the server has none).
 */
export function SecurityControlsCard({
  org,
  admin,
  controls,
  report,
}: {
  org: string;
  admin: boolean;
  controls: { items: SecurityControl[]; availableModes: SecurityControlMode[] } | undefined;
  report: ReportState | null;
}) {
  const available = controls?.availableModes ?? ["off", "report"];
  const enforceAvailable = available.includes("enforce");
  const data = report?.data ?? null;
  return (
    <SectionCard
      id="security-controls"
      title="Controls"
      description="Optional protections for this organization. Every control is off unless an admin turns it on."
      className="scroll-mt-6"
      data-testid="security-controls-section"
    >
      <div className="grid gap-x-6 gap-y-1.5 border-b border-bd px-5 py-3.5 text-[13px] sm:grid-cols-[auto_1fr]" data-testid="security-controls-explainer">
        <span className="font-medium">Off</span>
        <span className="text-muted">No effect. The default for every control.</span>
        <span className="font-medium">Report</span>
        <span className="text-muted">Counts what the control would have done, without refusing or changing anything.</span>
        <span className="font-medium">Enforce</span>
        <span className="text-muted" data-testid="security-controls-enforce-note">
          {enforceAvailable ? "The control applies." : "Coming in a later release. Report shows today what it would do."}
        </span>
      </div>
      {admin ? (
        <p className="border-b border-bd px-5 py-2.5 text-xs text-muted">
          Turning a control down or off, or making a lifetime longer, needs your approval with a trusted passkey.
        </p>
      ) : (
        <p className="border-b border-bd px-5 py-2.5 text-xs text-muted" data-testid="security-controls-member-note">
          An admin of this organization manages these controls.
        </p>
      )}
      {report && <ReportStatus report={report} />}
      {(controls?.items ?? []).map((c) => (
        <ControlRow
          key={`${c.control}-${c.version}`}
          org={org}
          control={c}
          admin={admin}
          available={available}
          counts={data ? (data.controls.find((r) => r.control === c.control) ?? null) : null}
          countsLoading={report !== null && data === null && report.loading}
          days={data?.days ?? 30}
        />
      ))}
    </SectionCard>
  );
}

/** Where the counts stand: loading, failed (with retry), or as of when, and whether the last refresh failed. */
export function ReportStatus({ report }: { report: ReportState }) {
  const now = useNow();
  const retry = (
    <Button size="sm" icon={<RefreshCw size={13} />} loading={report.fetching} onClick={report.retry} data-testid="security-report-retry">
      Retry
    </Button>
  );
  if (report.data === null && report.loading) {
    return (
      <p className="border-b border-bd px-5 py-2.5 text-xs text-muted" data-testid="security-report-status" data-state="loading">
        Loading what each control counted…
      </p>
    );
  }
  if (report.data === null && report.error) {
    return (
      <div className="border-b border-bd px-5 py-3" data-testid="security-report-status" data-state="failed">
        <Callout tone="danger" icon={<TriangleAlert size={16} />} role="alert" actions={retry} title="Could not load what each control counted">
          {errorMessage(report.error)}
        </Callout>
      </div>
    );
  }
  if (report.data === null) return null;
  const asOf = report.updatedAt ? `${formatTime(new Date(report.updatedAt).toISOString())} (${timeAgo(new Date(report.updatedAt).toISOString(), now)})` : "";
  if (report.error) {
    return (
      <div className="border-b border-bd px-5 py-3" data-testid="security-report-status" data-state="stale">
        <Callout tone="warn" icon={<TriangleAlert size={16} />} role="alert" actions={retry} title={`Counts as of ${asOf}; refreshing them failed`}>
          The counts below are not current. {errorMessage(report.error)}
        </Callout>
      </div>
    );
  }
  return (
    <p className="border-b border-bd px-5 py-2.5 text-xs text-muted" data-testid="security-report-status" data-state="current">
      Counts of the last {report.data.days} days, as of {asOf}. The current hour is live and refreshes every minute.
    </p>
  );
}

/** Beside passkey-verification's counts: access counts can be dropped. */
const BEST_EFFORT = " Access counts are best-effort: a busy server can drop some, so this is a lower bound.";

/** How many entries a control shows before "Show all". */
const ENTRIES_SHOWN = 5;

/** A control's counts: totals, then per operation, reason and who. */
export function ControlCounts({ control, counts, days }: { control: SecurityControl; counts: SecurityControlCounts; days: number }) {
  const now = useNow();
  const [all, setAll] = useState(false);
  const entries = all ? counts.entries : counts.entries.slice(0, ENTRIES_SHOWN);
  if (counts.total === 0) {
    return (
      <p className="mt-3 rounded-lg border border-bd bg-inset px-3 py-2 text-[13px] text-muted" data-testid={`security-control-counts-${control.control}`} data-total="0">
        {control.mode === "off"
          ? `Nothing counted in the last ${days} days. Set it to report to see what it would do.`
          : `Nothing counted in the last ${days} days.`}
        {control.control === "passkey-verification" && control.mode !== "off" && BEST_EFFORT}
      </p>
    );
  }
  return (
    <div className="mt-3 rounded-lg border border-bd" data-testid={`security-control-counts-${control.control}`} data-total={counts.total}>
      <p className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b border-bd bg-inset px-3 py-2 text-[13px]">
        <span>
          <span className="font-semibold tabular-nums">{counts.total}</span> counted in the last {days} days
        </span>
        <span className="text-muted" data-testid={`security-control-current-hour-${control.control}`}>
          {counts.currentHour} this hour
        </span>
      </p>
      {control.control === "passkey-verification" && (
        <p className="border-b border-bd px-3 py-1.5 text-xs text-muted" data-testid="security-control-best-effort">
          {BEST_EFFORT.trim()}
        </p>
      )}
      <table className="w-full text-[13px]">
        <thead>
          <tr className="text-left text-xs text-muted">
            <th className="px-3 py-1.5 font-medium">Operation</th>
            <th className="px-3 py-1.5 font-medium">Why</th>
            <th className="px-3 py-1.5 font-medium">Who</th>
            <th className="px-3 py-1.5 text-right font-medium">Count</th>
            <th className="hidden px-3 py-1.5 text-right font-medium sm:table-cell">Last</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={`${e.configVersion}-${e.operation}-${e.reason}-${e.actor.id}`} className="border-t border-bd" data-testid="security-control-entry">
              <td className="px-3 py-1.5 font-mono text-[12px]">{e.operation}</td>
              <td className="px-3 py-1.5 text-muted">{REASON_TEXT[e.reason] ?? e.reason}</td>
              <td className="px-3 py-1.5">
                {e.actor.name ?? e.actor.id}
                {e.actor.kind && e.actor.kind !== "human" && <span className="text-muted"> ({e.actor.kind})</span>}
              </td>
              <td className="px-3 py-1.5 text-right tabular-nums">{e.count}</td>
              <td className="hidden px-3 py-1.5 text-right text-muted sm:table-cell">{timeAgo(e.lastSeen, now)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {counts.entries.length > ENTRIES_SHOWN && (
        <button
          type="button"
          className="w-full cursor-pointer border-t border-bd px-3 py-1.5 text-left text-xs text-muted hover:text-fg"
          data-testid={`security-control-entries-toggle-${control.control}`}
          onClick={() => setAll((v) => !v)}
        >
          {all ? "Show fewer" : `Show all ${counts.entries.length}`}
        </button>
      )}
    </div>
  );
}

function ControlRow({
  org,
  control,
  admin,
  available,
  counts,
  countsLoading,
  days,
}: {
  org: string;
  control: SecurityControl;
  admin: boolean;
  available: readonly SecurityControlMode[];
  counts: SecurityControlCounts | null;
  countsLoading: boolean;
  days: number;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const now = useNow();
  const text = CONTROL_TEXT[control.control];
  const lifetime = control.control === "credential-lifetime";
  const [mode, setMode] = useState<SecurityControlMode>(control.mode);
  const [defaultTtl, setDefaultTtl] = useState(control.config ? String(control.config.defaultTtlSeconds) : "");
  const [maxTtl, setMaxTtl] = useState(control.config ? String(control.config.maxTtlSeconds) : "");
  const [error, setError] = useState<string | null>(null);
  const parsed = lifetime ? parseLifetimes(defaultTtl, maxTtl) : { config: control.config };
  const next = "config" in parsed ? { mode, config: parsed.config } : null;
  const input = next ? changeInput(control, next) : null;
  const weaker = next ? loosens(control, next) : false;
  const save = useMutation({
    mutationFn: (body: SecurityControlChangeInput) => api.changeSecurityControl(org, control.control, body),
    onSuccess: async (result) => {
      setError(null);
      await Promise.all([
        qc.invalidateQueries({ queryKey: securityControlsKey(org) }),
        qc.invalidateQueries({ queryKey: controlReportKey(org) }),
      ]);
      toast.success(`${text.label} saved`, {
        description: result.loosened ? "Approved with your passkey." : result.changed ? undefined : "Nothing was different.",
      });
    },
    onError: async (err) => {
      const message = saveError(err);
      setError(message);
      toast.error(`${text.label} not saved`, { description: message });
      if (err instanceof VarlatchApiError && err.code === "VERSION_CONFLICT") await qc.invalidateQueries({ queryKey: securityControlsKey(org) });
    },
  });
  const options = (["off", "report", "enforce"] as const).map((m) => ({
    value: m,
    label: MODE_LABEL[m],
    disabled: !available.includes(m),
    ...(available.includes(m) ? {} : { description: m === "enforce" ? "Coming in a later release" : "Not available yet" }),
  }));
  return (
    <div className="border-b border-bd px-5 py-4 last:border-b-0" data-testid={`security-control-${control.control}`} data-mode={control.mode}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-[14px] font-medium">
            {text.label}
            <Badge tone={control.mode === "off" ? "neutral" : "accent"} data-testid={`security-control-mode-${control.control}`}>
              {control.mode !== "off" && <ShieldCheck size={11} aria-hidden="true" />}
              {MODE_LABEL[control.mode]}
            </Badge>
          </p>
          <dl className="mt-1.5 space-y-1 text-[13px]">
            <div>
              <dt className="inline font-medium">Report counts: </dt>
              <dd className="inline text-muted" data-testid={`security-control-report-text-${control.control}`}>
                {text.report}
              </dd>
            </div>
            <div>
              <dt className="inline font-medium">Enforce would: </dt>
              <dd className="inline text-muted">
                {text.enforce}
                {!available.includes("enforce") && <span className="text-subtle"> (coming in a later release)</span>}
              </dd>
            </div>
          </dl>
          {lifetime && control.config && (
            <p className="mt-0.5 text-[13px] text-muted" data-testid="security-control-lifetimes">
              Default {durationWords(control.config.defaultTtlSeconds)}, at most {durationWords(control.config.maxTtlSeconds)}.
            </p>
          )}
          <p className="mt-0.5 text-xs text-muted">
            Version {control.version}
            {control.changedAt
              ? `, changed ${timeAgo(control.changedAt, now)}${control.changedBy ? ` by ${control.changedBy.name ?? control.changedBy.id}` : " by whoever runs this server"}`
              : ", never changed"}
          </p>
        </div>
        {admin && (
          <Select
            size="sm"
            value={mode}
            onChange={(v) => setMode(v as SecurityControlMode)}
            options={options}
            aria-label={`${text.label} mode`}
            data-testid={`security-control-select-${control.control}`}
          />
        )}
      </div>
      {counts && <ControlCounts control={control} counts={counts} days={days} />}
      {!counts && countsLoading && <Skeleton className="mt-3 h-9 w-full rounded-lg" />}
      {admin && lifetime && (
        <div className="mt-3 flex flex-wrap items-end gap-3 text-[13px]">
          <label className="space-y-1">
            <span className="block text-muted">Default lifetime (seconds)</span>
            <Input mono className="w-36" inputMode="numeric" value={defaultTtl} onChange={(e) => setDefaultTtl(e.target.value)} data-testid="security-control-default-ttl" />
          </label>
          <label className="space-y-1">
            <span className="block text-muted">Maximum lifetime (seconds)</span>
            <Input mono className="w-36" inputMode="numeric" value={maxTtl} onChange={(e) => setMaxTtl(e.target.value)} data-testid="security-control-max-ttl" />
          </label>
        </div>
      )}
      {admin && "error" in parsed && (
        <p className="mt-2 text-xs text-deny" data-testid="security-control-input-error">
          {parsed.error}
        </p>
      )}
      {admin && input && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            loading={save.isPending}
            onClick={() => save.mutate(input)}
            data-testid={`security-control-save-${control.control}`}
          >
            {weaker ? "Approve and save" : "Save"}
          </Button>
          {weaker && <span className="text-xs text-muted">This weakens the control: you approve it with a trusted passkey first.</span>}
        </div>
      )}
      {error && (
        <p className="mt-2 text-[13px] text-deny" role="alert" data-testid={`security-control-error-${control.control}`}>
          {error}
        </p>
      )}
    </div>
  );
}
