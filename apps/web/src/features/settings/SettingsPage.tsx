// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Check, Copy, Moon, Sun } from "lucide-react";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { applyTheme, initialTheme, type Theme } from "../../lib/theme";
import { Card, InfoTip, Mono, cn } from "../../components/ui";

/** Organization + installation facts; behavior settings live where they act. */

function CopyableMono({ value }: { value: string | undefined }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <span className="inline-flex items-center gap-1.5">
      <Mono>{value}</Mono>
      <button
        type="button"
        className="cursor-pointer text-muted hover:text-fg"
        aria-label={`Copy ${value}`}
        title="Copy to clipboard"
        onClick={() => {
          void navigator.clipboard.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? <Check size={12} className="text-allow" /> : <Copy size={12} />}
      </button>
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="text-muted w-28 shrink-0">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

export function SettingsPage() {
  const { org } = useParams();
  const { api } = useSession();
  useOrgRealtime(org, ["organization"], [["org", org]]);
  const orgQuery = useQuery({ queryKey: ["org", org], queryFn: () => api.getOrganization(org as string), enabled: !!org });
  const backups = useQuery({ queryKey: ["installation-backups"], queryFn: () => api.getInstallationBackups(), retry: false, refetchInterval: 60_000 });
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.meta() });
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    const onTheme = (e: Event) => setTheme((e as CustomEvent<Theme>).detail);
    window.addEventListener("varlatch:theme", onTheme);
    return () => window.removeEventListener("varlatch:theme", onTheme);
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">{org ? "Settings" : "Installation settings"}</h1>

      {org && <Card data-testid="settings-org">
        <h2 className="font-medium">Organization</h2>
        <p className="text-sm text-muted mb-3">
          Identity of this organization — the slug appears in URLs and CLI commands.
        </p>
        <dl className="text-sm space-y-1.5">
          <Row label="Name">{orgQuery.data?.name}</Row>
          <Row label="Slug"><CopyableMono value={orgQuery.data?.slug} /></Row>
          <Row label="ID"><CopyableMono value={orgQuery.data?.id} /></Row>
        </dl>
      </Card>}

      <Card data-testid="settings-server">
        <h2 className="font-medium">Server</h2>
        <p className="text-sm text-muted mb-3">
          Facts reported by this varlatchd installation; nothing here is editable from the
          dashboard.
        </p>
        <dl className="text-sm space-y-1.5">
          <Row label="Version"><Mono>{meta.data?.serverVersion}</Mono></Row>
          <Row label="API"><Mono>{meta.data ? `v${meta.data.apiMajor}` : null}</Mono></Row>
          <div className="flex gap-2">
            <dt className="text-muted w-28 shrink-0 flex items-center gap-1">
              Capabilities
              <InfoTip text="Optional features this server advertises. The dashboard and CLI feature-detect against this list, so an older or trimmed-down installation simply hides what it cannot do." />
            </dt>
            <dd className="flex flex-wrap gap-1.5">
              {meta.data?.capabilities?.map((c: string) => (
                <Mono key={c} className="rounded-full border border-bd bg-inset px-2 py-0.5 text-xs">
                  {c}
                </Mono>
              ))}
            </dd>
          </div>
        </dl>
      </Card>

      {backups.isError && !org && <p role="alert" className="text-deny">Backup status is unavailable. Installation Admin authority is required.</p>}
      {backups.data && <Card data-testid="settings-backups">
        <h2 className="font-medium">Installation backups</h2>
        <p className="text-sm text-muted mb-3">Managed by your Infrastructure Operator. Checks establish archive integrity, release compatibility, and a matching key; they do not replace a restore drill.</p>
        {backups.data.warnings.map(warning => <p role="alert" className="text-sm text-deny mb-2" key={warning}>{warning}</p>)}
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead><tr><th>Archive / created</th><th>Release / KEK versions</th><th>Verification</th><th>Destination</th></tr></thead>
            <tbody>{backups.data.archives.map(archive => <tr key={archive.archiveId} className="border-t border-bd">
              <td className="py-2"><Mono>{archive.archiveId}</Mono><div>{new Date(archive.createdAt).toLocaleString()}</div></td>
              <td>{archive.release} / {archive.requiredKeyVersions.join(", ")}</td>
              <td>{archive.verification ? <>
                <div>{archive.verification.integrity && archive.verification.compatibility && archive.verification.keyMatch ? "Checks passed" : "Checks failed"} against {archive.verification.targetRelease}</div>
                <div>{new Date(archive.verification.checkedAt).toLocaleString()}</div>
              </> : "Not verified"}</td>
              <td>{archive.delivery ? <>
                <div>Uploaded to {archive.delivery.destination} at {new Date(archive.delivery.uploadedAt).toLocaleString()}</div>
                <div>{archive.delivery.remoteVerification ? (archive.delivery.remoteVerification.integrity && archive.delivery.remoteVerification.compatibility && archive.delivery.remoteVerification.keyMatch ? "Remote retrieval checks passed" : "Remote retrieval checks failed") : "Remote retrieval not verified"}</div>
              </> : "No recorded delivery"}</td>
            </tr>)}</tbody>
          </table>
        </div>
        <p className="text-sm text-muted mt-3">Keep every required Root KEK version and the independent Backup Encryption Key while retaining its archives. Verification of a key does not establish separate off-host custody.</p>
      </Card>}

      <Card data-testid="settings-appearance">
        <h2 className="font-medium">Appearance</h2>
        <p className="text-sm text-muted mb-3">
          Stored in this browser only; every viewer picks their own theme.
        </p>
        <div className="flex gap-2" role="radiogroup" aria-label="Theme">
          {(
            [
              { value: "dark", label: "Dark", icon: Moon },
              { value: "light", label: "Light", icon: Sun },
            ] as const
          ).map(({ value, label, icon: Icon }) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={theme === value}
              data-testid={`theme-${value}`}
              onClick={() => {
                setTheme(value);
                applyTheme(value);
              }}
              className={cn(
                "inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm",
                theme === value
                  ? "border-accent bg-accent-dim/40 text-fg"
                  : "border-bd bg-inset text-muted hover:text-fg",
              )}
            >
              <Icon size={13} /> {label}
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}
