// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import {
  VarlatchApiError,
  type CredentialLifetimeConfig,
  type SecurityControl,
  type SecurityControlChangeInput,
  type SecurityControlMode,
  type SecurityControlName,
} from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { timeAgo, useNow } from "../../lib/time";
import { Badge, Button, Input, SectionCard, Select } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";
import { useIdentities } from "../access/shared";
import { approvalOutcomeMessage, durationWords } from "./approval";

/**
 * The Organization's Security Controls (ADR-0054 Decisions 1 and 2), in
 * Settings until the Security page arrives. Every control is off unless an
 * admin changes it. Tightening saves at once; loosening (a mode towards off,
 * a lifetime that grows, lifetimes cleared) needs the admin's approval with
 * a trusted passkey, which the session's approval dialog asks for. enforce
 * is not available yet.
 */

export const securityControlsKey = (org: string) => ["security-controls", org] as const;

export const CONTROL_TEXT: Record<SecurityControlName, { label: string; enforce: string }> = {
  "requirement-protection": {
    label: "Requirement protection",
    enforce: "Editing or revoking a Tailnet Requirement needs an approval.",
  },
  "admin-step-up": {
    label: "Admin step-up",
    enforce: "Administrative changes (machine identities, credentials, access, people, integrations, deletion, export) need an approval.",
  },
  "passkey-verification": {
    label: "Passkey verification",
    enforce: "People reach this organization only after signing in with a trusted passkey that verified them.",
  },
  "credential-lifetime": {
    label: "Credential lifetime",
    enforce: "Machine credentials get a default lifetime, and longer ones are refused.",
  },
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

export function SecurityControlsCard({ org }: { org: string }) {
  const { api, identityId } = useSession();
  const supported = useCapability("security.controls");
  const identities = useIdentities(org);
  const admin = (identities.data?.items ?? []).some((i) => i.id === identityId && i.orgRole === "admin" && !i.removedAt);
  const controls = useQuery({
    queryKey: securityControlsKey(org),
    queryFn: () => api.listSecurityControls(org),
    enabled: supported,
  });
  if (!supported) return null;
  const available = controls.data?.availableModes ?? ["off", "report"];
  return (
    <SectionCard
      id="settings-security"
      title="Security controls"
      description="Optional protections for this organization. Each one is off until an admin changes it."
      className="scroll-mt-6"
      data-testid="settings-security-controls"
    >
      <div className="space-y-1.5 border-b border-bd px-5 py-3.5 text-[13px] text-muted" data-testid="security-controls-explainer">
        <p>Report shows what a control would have done, without refusing or changing anything.</p>
        <p>Enforce, which applies a control, is not available yet.</p>
        <p>Turning a control down or off, or making a lifetime longer, needs your approval with a trusted passkey.</p>
      </div>
      {controls.error ? (
        <p className="px-5 py-4 text-[13px] text-deny" role="alert">
          {errorMessage(controls.error)}
        </p>
      ) : (
        (controls.data?.items ?? []).map((c) => (
          <ControlRow key={`${c.control}-${c.version}`} org={org} control={c} admin={admin} available={available} />
        ))
      )}
    </SectionCard>
  );
}

function ControlRow({
  org,
  control,
  admin,
  available,
}: {
  org: string;
  control: SecurityControl;
  admin: boolean;
  available: readonly SecurityControlMode[];
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
      await qc.invalidateQueries({ queryKey: securityControlsKey(org) });
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
    ...(available.includes(m) ? {} : { description: "Not available yet" }),
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
          <p className="mt-0.5 text-[13px] text-muted">With enforce: {text.enforce}</p>
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
