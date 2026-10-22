// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { ArrowUpRight, Info, TriangleAlert } from "lucide-react";
import type { InstallationRelease } from "@varlatch/protocol";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Callout, SectionCard, Skeleton, Status } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { errorMessage } from "../../shell/Shell";
import { useInstallationRelease } from "./releaseNotice";
import {
  DEFAULT_RELEASE_REPO,
  DOCS_CHECK_URL,
  DOCS_COOLIFY_UPGRADE_URL,
  DOCS_UPGRADE_URL,
  checkLines,
  lastFailure,
  releaseSummary,
  upgradeLines,
} from "./releaseStatus";

/**
 * Releases, for Installation Admins (ADR-0049): the host's last look for a
 * newer release and how to upgrade on the host. Read-only by design: the
 * dashboard never upgrades Varlatch (ADR-0019).
 */
export function ReleaseTab({ admin, checking }: { admin: boolean; checking: boolean }) {
  const release = useInstallationRelease(admin);
  const now = useNow();
  if (checking || release.isLoading) return <Skeleton className="h-48" />;
  if (!admin) {
    return (
      <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Release status is unavailable" data-testid="release-error">
        Installation Admin authority is required to see this installation's release status.
      </Callout>
    );
  }
  if (release.isError || !release.data) {
    return (
      <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Release status is unavailable" data-testid="release-error">
        {release.error ? errorMessage(release.error) : "This server does not report release checks."}
      </Callout>
    );
  }
  return <ReleaseReport release={release.data} now={now} />;
}

export function ReleaseReport({ release, now }: { release: InstallationRelease; now: number }) {
  const summary = releaseSummary(release, now);
  const failure = lastFailure(release, now);
  const { latest } = release;
  const repo = latest?.repo ?? release.lastAttempt?.repo ?? DEFAULT_RELEASE_REPO;
  return (
    <div className="space-y-6">
      <SectionCard
        title="This installation"
        description="What the host last found, compared with the version this server runs."
        data-testid="release-status"
        actions={
          latest && (
            <span className="text-[13px] text-muted" data-testid="release-checked-at" title={formatDateTime(latest.checkedAt)}>
              Checked {timeAgo(latest.checkedAt, now)}
            </span>
          )
        }
      >
        <div className="border-b border-bd px-5 py-3">
          <span data-testid="release-summary" data-tone={summary.tone}>
            <Status tone={summary.tone}>{summary.headline}</Status>
          </span>
          <span className="mt-1 block text-[13px] text-muted">{summary.detail}</span>
        </div>
        <dl className="grid gap-x-8 gap-y-3 px-5 py-4 text-[14px] sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted">Running</dt>
          <dd className="font-mono text-[13px]" data-testid="release-running">{release.running}</dd>
          <dt className="text-muted">Latest release</dt>
          <dd data-testid="release-latest">
            {latest ? (
              <a href={latest.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-[13px] text-accent hover:underline">
                {latest.version}
                <ArrowUpRight size={13} />
              </a>
            ) : (
              <span className="text-muted">Unknown</span>
            )}
            {latest?.publishedAt && <span className="ml-2 text-xs text-muted">published {timeAgo(latest.publishedAt, now)}</span>}
          </dd>
          <dt className="text-muted">Checked in</dt>
          <dd className="font-mono text-[13px]" data-testid="release-repo">{repo}</dd>
        </dl>
        {failure && (
          <Callout tone="warn" icon={<TriangleAlert size={17} />} className="mx-5 mb-4" data-testid="release-failure">
            {failure}
            {latest ? " The result above is from the last check that succeeded." : ""}
          </Callout>
        )}
      </SectionCard>

      {latest && release.newer && (
        <SectionCard
          title="Upgrade on the host"
          description="Upgrading replaces the containers and needs the backup keys, so it runs on the host, never from the dashboard."
          data-testid="release-upgrade"
        >
          <div className="space-y-3 px-5 py-4 text-[13px]">
            {upgradeLines(latest) ? (
              <>
                <p className="text-muted">Where the installation's Compose project lives:</p>
                <CodeBlock lines={upgradeLines(latest)!} data-testid="release-upgrade-command" />
                <p className="text-muted">
                  It creates and verifies an encrypted archive first, and is complete only when the new release's checks pass.{" "}
                  <DocsLink href={DOCS_UPGRADE_URL}>Upgrading</DocsLink>
                </p>
              </>
            ) : (
              <p className="text-muted" data-testid="release-upgrade-elsewhere">
                The checked directory has no <code className="font-mono">varlatch-release.json</code>, so{" "}
                <code className="font-mono">varlatch upgrade</code> does not apply there. Upgrade as your deployment describes:{" "}
                <DocsLink href={DOCS_COOLIFY_UPGRADE_URL}>Coolify upgrades</DocsLink>
              </p>
            )}
          </div>
        </SectionCard>
      )}

      <SectionCard title="Checking for releases" description="The host checks GitHub; this server and your browser never do." data-testid="release-check-how">
        <div className="space-y-3 px-5 py-4 text-[13px]">
          <p className="text-muted">Run the check on the host, so this page stays current. Schedule it with the nightly backup, as its own step after it:</p>
          <CodeBlock lines={checkLines(repo)} data-testid="release-check-command" />
          <p className="text-muted">
            <DocsLink href={DOCS_CHECK_URL}>Newer releases in the dashboard</DocsLink>
          </p>
        </div>
      </SectionCard>

      <Callout tone="neutral" icon={<Info size={17} />}>
        Only the latest release receives fixes, security fixes included.
      </Callout>
    </div>
  );
}

function DocsLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
      {children}
      <ArrowUpRight size={13} />
    </a>
  );
}
