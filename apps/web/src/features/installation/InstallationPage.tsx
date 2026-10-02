// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Archive, CircleCheck, Clock, FileArchive, RotateCcw, Terminal, TriangleAlert } from "lucide-react";
import { useSession } from "../../lib/session";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Badge, Button, Callout, EmptyState, SectionCard, Status, table, cn } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { Dialog } from "../../components/Dialog";
import { PageHeader } from "../../components/PageHeader";
import { FullPageLoading } from "../../shell/AuthScreens";
import { archivePassed, backupHealth } from "./backupHealth";

/**
 * Installation backups, for Installation Admins. Archives are created and
 * restored by the operator on the host (the API is read-only by design), so
 * the actions here explain the commands instead of running them.
 */
export function InstallationPage() {
  const { api } = useSession();
  const now = useNow();
  const backups = useQuery({ queryKey: ["installation-backups"], queryFn: () => api.getInstallationBackups(), retry: false, refetchInterval: 60_000 });
  const [howTo, setHowTo] = useState<"create" | "restore" | null>(null);

  if (backups.isLoading) return <FullPageLoading />;
  const header = (
    <PageHeader
      breadcrumbs={[{ label: "Installation" }, { label: "Backups" }]}
      title="Backups"
      subtitle="Encrypted archives of this whole installation."
      actions={
        backups.data && (
          <>
            <Button variant="secondary" icon={<RotateCcw size={15} />} onClick={() => setHowTo("restore")}>
              Run a restore drill
            </Button>
            <Button variant="primary" icon={<Archive size={15} />} onClick={() => setHowTo("create")}>
              Create an archive
            </Button>
          </>
        )
      }
    />
  );
  if (backups.isError || !backups.data) {
    return (
      <>
        {header}
        <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Backup status is unavailable">
          Installation Admin authority is required to see this installation's backups.
        </Callout>
      </>
    );
  }
  const data = backups.data;
  const health = backupHealth(data, now);
  const verifiedCount = data.archives.filter(archivePassed).length;

  return (
    <>
      {header}
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat
          icon={health.latest ? <CircleCheck size={20} className={health.tone === "ok" ? "text-accent" : "text-warn"} /> : <TriangleAlert size={20} className="text-deny" />}
          label="Last archive"
          value={health.latest ? timeAgo(health.latest.createdAt, now) : "None yet"}
          hint={health.latest ? formatDateTime(health.latest.createdAt) : "Create the first archive on the host"}
        />
        <Stat
          icon={<CircleCheck size={20} className={health.verified && archivePassed(health.verified) ? "text-accent" : "text-muted"} />}
          label="Last verification"
          value={health.verified ? timeAgo(health.verified.verification!.checkedAt, now) : "Never"}
          hint={health.verified ? (archivePassed(health.verified) ? "All checks passed" : "Checks failed") : "Verify archives with --record"}
        />
        <Stat
          icon={<FileArchive size={20} className="text-muted" />}
          label="Archives on record"
          value={String(data.archives.length)}
          hint={`${verifiedCount} verified`}
        />
      </div>

      {data.warnings.length > 0 && (
        <div className="mt-6 space-y-2">
          {data.warnings.map((w) => (
            <Callout key={w} tone="warn" icon={<TriangleAlert size={17} />} role="alert">
              {w}
            </Callout>
          ))}
        </div>
      )}
      <Callout tone="neutral" icon={<Clock size={17} />} className="mt-6">
        Keep every required Root KEK version and the independent Backup Encryption Key for as long as you keep the
        archives that need them. Verifying a key here does not prove a separate off-host copy exists.
      </Callout>

      <SectionCard title="Archives" className="mt-6" bodyClassName={table.wrap} data-testid="settings-backups">
        {data.archives.length === 0 ? (
          <EmptyState icon={<Archive size={20} />} title="No archives yet" description="Run the create command on the host; archives appear here once recorded." />
        ) : (
          <table className={table.table}>
            <thead>
              <tr>
                <th className={table.th}>Created</th>
                <th className={table.th}>Archive</th>
                <th className={table.th}>Release</th>
                <th className={table.th}>Keys</th>
                <th className={table.th}>Verification</th>
                <th className={table.th}>Off-host copy</th>
              </tr>
            </thead>
            <tbody>
              {data.archives.map((a) => (
                <tr key={a.archiveId} className={cn(table.tr, table.trHover)}>
                  <td className={cn(table.td, "whitespace-nowrap")} title={formatDateTime(a.createdAt)}>
                    {timeAgo(a.createdAt, now)}
                  </td>
                  <td className={table.td}>
                    <Badge className="font-mono">{a.archiveId.slice(0, 8)}</Badge>
                  </td>
                  <td className={cn(table.td, "font-mono text-[13px]")}>{a.release}</td>
                  <td className={cn(table.td, "font-mono text-[13px] text-muted")}>{a.requiredKeyVersions.join(", ")}</td>
                  <td className={table.td}>
                    {a.verification ? (
                      <Status tone={archivePassed(a) ? "ok" : "error"}>
                        {archivePassed(a) ? "verified" : "checks failed"}
                        <span className="text-xs text-muted">{timeAgo(a.verification.checkedAt, now)}</span>
                      </Status>
                    ) : (
                      <Status tone="muted">not verified</Status>
                    )}
                  </td>
                  <td className={cn(table.td, "text-[13px]")}>
                    {a.delivery ? (
                      <span>
                        {a.delivery.destination}
                        <span className="block text-xs text-muted">
                          {a.delivery.remoteVerification
                            ? a.delivery.remoteVerification.integrity && a.delivery.remoteVerification.compatibility && a.delivery.remoteVerification.keyMatch
                              ? "retrieval checked"
                              : "retrieval check failed"
                            : "retrieval not checked"}
                        </span>
                      </span>
                    ) : (
                      <span className="text-muted">none recorded</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </SectionCard>
      <HowToDialog kind={howTo} onClose={() => setHowTo(null)} />
    </>
  );
}

function Stat({ icon, label, value, hint }: { icon: React.ReactNode; label: string; value: string; hint: string }) {
  return (
    <div className="flex items-start gap-4 rounded-xl border border-bd bg-raised px-5 py-4">
      <span className="mt-1">{icon}</span>
      <span>
        <span className="block text-[13px] text-muted">{label}</span>
        <span className="block text-[22px] font-semibold tracking-tight">{value}</span>
        <span className="block text-xs text-muted">{hint}</span>
      </span>
    </div>
  );
}

function HowToDialog({ kind, onClose }: { kind: "create" | "restore" | null; onClose: () => void }) {
  if (!kind) return null;
  const create = kind === "create";
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      icon={
        <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
          <Terminal size={17} />
        </span>
      }
      title={create ? "Create an archive" : "Run a restore drill"}
      description={
        create
          ? "Archives are made by the operator on the host, with the keys that never reach the dashboard. Run this where the installation's Compose project lives:"
          : "A drill restores the latest archive onto a fresh, isolated project and checks the restored installation. Run it on a separate host or project, never over the live one:"
      }
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="space-y-4">
        {create ? (
          <>
            <CodeBlock
              lines={[
                "varlatch admin backup create --dir /srv/varlatch \\",
                "  --bek-file /secure/operator/backup-key \\",
                "  --kek-file /secure/operator/root-kek-copy",
              ]}
            />
            <p className="text-[13px] text-muted">Then verify it and record the result, so this page shows it as verified:</p>
            <CodeBlock
              lines={[
                "varlatch admin backup verify --dir /srv/varlatch \\",
                "  --in /srv/varlatch/backups/ARCHIVE-ID.vltbak \\",
                "  --bek-file /secure/operator/backup-key \\",
                "  --kek-file /secure/operator/root-kek-copy --record",
              ]}
            />
          </>
        ) : (
          <CodeBlock
            lines={[
              "varlatch admin backup restore --dir /srv/varlatch-drill \\",
              "  --in /recovery/ARCHIVE-ID.vltbak \\",
              "  --bek-file /secure/operator/backup-key \\",
              "  --kek-file /secure/operator/root-kek-copy \\",
              "  --target-release /srv/varlatch-drill/varlatch-release.json",
            ]}
          />
        )}
        <p className="text-[13px] text-muted">
          The full procedure, including off-host destinations, is in the operations guide (<span className="font-mono">docs/operations/backup.md</span>).
        </p>
      </div>
    </Dialog>
  );
}
