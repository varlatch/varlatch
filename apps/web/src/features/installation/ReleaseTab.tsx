// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { ArrowUpRight, Info, TriangleAlert } from "lucide-react";
import type { InstallationRelease, UpgradePreflightLine } from "@varlatch/protocol";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Callout, SectionCard, Skeleton, Status } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { errorMessage } from "../../shell/Shell";
import { useInstallationRelease } from "./releaseNotice";
import {
  DEFAULT_RELEASE_REPO,
  DOCS_CHECK_URL,
  DOCS_DIGEST_URL,
  DOCS_PREFLIGHT_URL,
  DOCS_SCHEDULE_URL,
  DOCS_UPGRADE_URL,
  checkLines,
  lastFailure,
  preflightDocs,
  preflightTone,
  releaseSummary,
  reportedDeployment,
  rollbackSentence,
  upgradeGuide,
  type UpgradeGuide,
} from "./releaseStatus";
import { DeploymentChoice, type Deployment } from "./deployment";
import { WebUpgrade } from "./WebUpgrade";

/**
 * Releases, for Installation Admins (ADR-0049, ADR-0065 phase 1): the host's
 * last look for a newer release, what it verified of it, the upgrade's
 * pre-flight checklist and the exact commands to run on the host; and, on a
 * systemd host whose helper is installed (phase 2), the button that asks the
 * host to upgrade, and how far it got. The dashboard never upgrades Varlatch
 * itself.
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
  return <ReleaseReport release={release.data} now={now} oneClick={<WebUpgrade release={release.data} />} />;
}

export function ReleaseReport({ release, now, oneClick }: { release: InstallationRelease; now: number; oneClick?: React.ReactNode }) {
  const summary = releaseSummary(release, now);
  const failure = lastFailure(release, now);
  const { latest } = release;
  const reported = reportedDeployment(release);
  const [chosen, setDeployment] = useState<Deployment>("host");
  const deployment = reported ?? chosen;
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

      {reported ? (
        <p className="text-[13px] text-muted" data-testid="release-deployment">
          varlatchd runs {reported === "host" ? "as a service (the systemd unit)" : "in a container (the image)"}.
        </p>
      ) : (
        <DeploymentChoice value={deployment} onChange={setDeployment} />
      )}

      {latest && release.newer && <UpgradeCard release={release} deployment={deployment} repo={repo} oneClick={oneClick} />}

      <SectionCard title="Checking for releases" description="The host checks GitHub; this server and your browser never do." data-testid="release-check-how">
        <div className="space-y-3 px-5 py-4 text-[13px]">
          <p className="text-muted">
            Run the check on the host, so this page stays current, and schedule it there once a day: it also verifies the newer release, as an
            upgrade would, for the checklist above.
          </p>
          <CodeBlock lines={checkLines(deployment)} data-testid="release-check-command" />
          <p className="flex flex-wrap gap-4 text-muted">
            <DocsLink href={DOCS_SCHEDULE_URL}>Scheduling the release check</DocsLink>
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

/**
 * The upgrade to the newer release (ADR-0065 Decision 8): the target and its
 * rollback-safety, the pre-flight checklist, the one click when it is
 * offered (oneClick, phase 2), and the exact commands for this installation.
 */
function UpgradeCard({ release, deployment, repo, oneClick }: { release: InstallationRelease; deployment: Deployment; repo: string; oneClick?: React.ReactNode }) {
  const latest = release.latest!;
  const rollback = rollbackSentence(release);
  const guide = upgradeGuide(release, deployment);
  return (
    <SectionCard
      title={`Upgrade to ${latest.version}`}
      description="Upgrading replaces varlatchd itself, so the host does it: from here when its helper is installed, or with the commands below."
      data-testid="release-upgrade"
    >
      <div className="space-y-4 px-5 py-4 text-[13px]">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <a href={latest.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
            Release notes of {latest.version}
            <ArrowUpRight size={13} />
          </a>
          <span data-testid="release-rollback" data-tone={rollback.tone}>
            <Status tone={rollback.tone}>{rollback.text}</Status>
          </span>
        </div>
        {release.preflight && <Preflight lines={release.preflight} />}
        {oneClick}
        {guide && <Guide guide={guide} repo={repo} />}
        <p className="text-muted">
          The upgrade verifies the release again, takes an encrypted snapshot first, and keeps the new release only when its checks pass.{" "}
          <DocsLink href={deployment === "host" ? DOCS_UPGRADE_URL : DOCS_DIGEST_URL}>{deployment === "host" ? "Upgrading" : "Upgrading by digest"}</DocsLink>
        </p>
      </div>
    </SectionCard>
  );
}

function Preflight({ lines }: { lines: UpgradePreflightLine[] }) {
  return (
    <div className="rounded-lg border border-bd" data-testid="release-preflight">
      <div className="flex items-center justify-between border-b border-bd px-4 py-2">
        <span className="font-medium">Before you upgrade</span>
        <DocsLink href={DOCS_PREFLIGHT_URL}>The pre-flight checklist</DocsLink>
      </div>
      <ul className="divide-y divide-bd">
        {lines.map((line) => {
          const docs = line.status === "pass" ? null : preflightDocs(line);
          return (
            <li key={line.id} className="space-y-1 px-4 py-2.5" data-testid={`preflight-${line.id}`} data-status={line.status}>
              <Status tone={preflightTone(line)}>
                <span className="text-fg">{line.title}</span>
                <span className="sr-only"> ({line.status})</span>
              </Status>
              <p className="pl-3.5 text-muted">{line.detail}</p>
              {line.remedy && (
                <p className="pl-3.5" data-testid={`preflight-${line.id}-remedy`}>
                  {line.remedy}.{docs && <> <DocsLink href={docs.href}>{docs.label}</DocsLink></>}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function Guide({ guide, repo }: { guide: UpgradeGuide; repo: string }) {
  return (
    <div className="space-y-4">
      {guide.oneAtATime && (
        <Callout tone="warn" icon={<TriangleAlert size={17} />} data-testid="release-one-at-a-time" title="Upgrade one release at a time">
          {guide.oneAtATime}{" "}
          <DocsLink href={`https://github.com/${repo}/releases`}>The releases in between</DocsLink>
        </Callout>
      )}
      {guide.sections.map((section) => (
        <div key={section.testId} className="space-y-2" data-testid={section.testId}>
          <p className="font-medium">{section.title}</p>
          <ol className="list-decimal space-y-2 pl-5">
            {section.steps.map((step, i) => (
              <li key={i} className="space-y-1.5">
                <span className="text-muted">{step.title}</span>
                {step.lines && <CodeBlock lines={step.lines} data-testid={section.testId === "release-guide-host" && i === section.steps.length - 1 ? "release-upgrade-command" : undefined} />}
                {step.note && <span className="block text-muted">{step.note}</span>}
              </li>
            ))}
          </ol>
        </div>
      ))}
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
