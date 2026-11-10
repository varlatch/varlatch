// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { CircleCheck } from "lucide-react";
import type { CredentialReview, ExpiringCredential, ReviewedCredential } from "@varlatch/sdk";
import { formatDate, formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Badge, EmptyState, SectionCard, Status, cn } from "../../components/ui";
import { credentialExpiry, expiryText, expiryTone, type CredentialExpiry } from "../sync/credentialExpiry";

export const credentialReviewKey = (org: string) => ["credential-review", org] as const;

const REASON_LABEL: Record<ReviewedCredential["reasons"][number], string> = {
  "never-used": "Never used",
  idle: "Idle",
  "no-expiry": "No expiry",
};

/** How many rows show before "Show all". */
const ROWS_SHOWN = 8;

type Row =
  | { kind: "expiry"; credential: ExpiringCredential }
  | { kind: "review"; credential: ReviewedCredential };

/** The server's word on soon or expired, with the days left counted here. */
export function serverExpiry(c: ExpiringCredential, now: number): CredentialExpiry | null {
  if (!c.expiresAt) return null;
  const computed = credentialExpiry(c.expiresAt, now, Number.POSITIVE_INFINITY);
  if (!computed) return null;
  return c.state === "expired" ? { state: "expired", days: 0, expiresAt: c.expiresAt } : { ...computed, state: "soon", days: Math.max(1, computed.days) };
}

/**
 * Machine credentials worth a look (ADR-0054 Decision 8): the credential
 * review (never used, idle for 30 days, no expiry) and the service
 * credentials that expire within 7 days or have expired. Reporting only:
 * acting on one happens in Access, Machines.
 */
export function CredentialsCard({ org, review }: { org: string; review: CredentialReview }) {
  const now = useNow();
  const [all, setAll] = useState(false);
  // Servers before 0.21.0 send no expiry warnings.
  const expiry = review.expiry as CredentialReview["expiry"] | undefined;
  const expiring = expiry?.items ?? [];
  const rows: Row[] = [
    ...expiring.map((credential) => ({ kind: "expiry" as const, credential })),
    ...review.items.map((credential) => ({ kind: "review" as const, credential })),
  ];
  const shown = all ? rows : rows.slice(0, ROWS_SHOWN);
  const machines = `/o/${org}/access?tab=machines`;
  const tiles: { label: string; value: number; tone?: "warn" | "error"; testid: string }[] = [
    { label: "Never used", value: review.summary.neverUsed, testid: "never-used" },
    { label: `Unused for ${review.idleDays} days`, value: review.summary.idle, testid: "idle" },
    { label: "No expiry", value: review.summary.noExpiry, testid: "no-expiry" },
    ...(expiry
      ? [
          { label: `Expire within ${expiry.warningDays} days`, value: expiry.summary.soon, tone: "warn" as const, testid: "expiring" },
          { label: "Expired", value: expiry.summary.expired, tone: "error" as const, testid: "expired" },
        ]
      : []),
  ];
  return (
    <SectionCard
      id="security-credentials"
      title="Machine credentials"
      description="Credentials of machine identities worth a look. Reporting only: nothing is revoked or retired automatically."
      className="scroll-mt-6"
      data-testid="security-credentials"
      actions={
        <Link to={machines} className="inline-flex h-7 items-center rounded-md border border-bd px-2.5 text-xs font-medium text-fg hover:bg-hover" data-testid="security-credentials-machines">
          Access, Machines
        </Link>
      }
    >
      <div className="grid grid-cols-2 gap-px border-b border-bd bg-bd sm:grid-cols-5" data-testid="security-credentials-summary">
        {tiles.map((t) => (
          <div key={t.testid} className="bg-raised px-4 py-3" data-testid={`credentials-tile-${t.testid}`} data-value={t.value}>
            <p
              className={cn(
                "text-[20px] font-semibold tabular-nums leading-tight",
                t.value > 0 && t.tone === "warn" && "text-warn",
                t.value > 0 && t.tone === "error" && "text-deny",
                t.value === 0 && "text-muted",
              )}
            >
              {t.value}
            </p>
            <p className="text-xs text-muted">{t.label}</p>
          </div>
        ))}
      </div>
      {rows.length === 0 ? (
        <EmptyState
          icon={<CircleCheck size={20} />}
          title="Nothing to review"
          description={`Each of the ${review.summary.reviewed} machine credentials was used in the last ${review.idleDays} days and has an expiry${expiry ? `, and none expires within ${expiry.warningDays} days` : ""}.`}
          className="py-8"
          data-testid="security-credentials-empty"
        />
      ) : (
        <ul>
          {shown.map((row) => {
            const c = row.credential;
            const exp = row.kind === "expiry" ? serverExpiry(row.credential, now) : null;
            return (
              <li
                key={`${row.kind}-${c.id}`}
                className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-b border-bd px-5 py-3 text-[13px] last:border-b-0"
                data-testid={`security-credential-${row.kind}-${c.id}`}
              >
                <div className="min-w-0">
                  <p>
                    <span className="font-medium">{c.name ?? "Unnamed credential"}</span>
                    <span className="text-muted">
                      {" "}
                      for {c.identity.name} ({c.identity.kind}
                      {c.identity.state !== "live" ? `, ${c.identity.state}` : ""})
                    </span>
                  </p>
                  <p className="text-xs text-muted">
                    Last used {c.lastUsedAt ? timeAgo(c.lastUsedAt, now) : "never"}
                    {row.kind === "review" && (c.expiresAt ? `, expires ${formatDate(c.expiresAt)}` : ", no expiry")}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {exp ? (
                    <span title={formatDateTime(exp.expiresAt)}>
                      <Status tone={expiryTone(exp)} className="text-xs">
                        {expiryText(exp, formatDate(exp.expiresAt), "Credential")}
                      </Status>
                    </span>
                  ) : (
                    row.kind === "review" &&
                    row.credential.reasons.map((r) => (
                      <Badge key={r} tone={r === "never-used" || r === "idle" ? "warn" : "neutral"}>
                        {REASON_LABEL[r]}
                      </Badge>
                    ))
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {rows.length > ROWS_SHOWN && (
        <button
          type="button"
          className="w-full cursor-pointer border-t border-bd px-5 py-2 text-left text-xs text-muted hover:text-fg"
          data-testid="security-credentials-toggle"
          onClick={() => setAll((v) => !v)}
        >
          {all ? "Show fewer" : `Show all ${rows.length}`}
        </button>
      )}
      <p className="border-t border-bd px-5 py-2.5 text-xs text-muted">
        To revoke a credential or issue a replacement, open the machine in{" "}
        <Link to={machines} className="text-accent hover:underline">
          Access, Machines
        </Link>
        .
      </p>
    </SectionCard>
  );
}
