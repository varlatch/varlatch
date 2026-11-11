// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Link } from "react-router-dom";
import { KeyRound, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ApprovalKeys } from "@varlatch/sdk";
import { timeAgo, useNow } from "../../lib/time";
import { Badge, Callout, Mono, SectionCard, Status } from "../../components/ui";

export const approvalKeysKey = (org: string) => ["security-approval-keys", org] as const;

/**
 * The admins' approval keys (ADR-0054 Decision 4): per admin, how many of
 * their passkeys are trusted and how many unconfirmed, by name. Only a
 * trusted passkey can approve; confirming is the person's own ceremony on
 * their account Security page, and recovery is the host operator's.
 */
export function ApprovalKeysCard({ keys }: { keys: ApprovalKeys }) {
  const now = useNow();
  return (
    <SectionCard
      id="security-approval-keys"
      title="Approval keys"
      description="Only a trusted passkey can approve turning a control down or off. A passkey added while signed in stays unconfirmed until its owner confirms it with a trusted one."
      className="scroll-mt-6"
      data-testid="security-approval-keys"
    >
      <ul>
        {keys.items.map((admin) => (
          <li
            key={admin.identity.id}
            className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2 border-b border-bd px-5 py-3.5 last:border-b-0"
            data-testid={`approval-keys-${admin.identity.id}`}
            data-trusted={admin.trusted}
          >
            <div className="min-w-0">
              <p className="text-[14px] font-medium">{admin.identity.name}</p>
              {admin.passkeys.length > 0 ? (
                <p className="mt-1 flex flex-wrap gap-1.5">
                  {admin.passkeys.map((p, i) => (
                    <Badge key={i} tone={p.trust === "trusted" ? "accent" : "neutral"} title={p.trust === "trusted" ? "Trusted" : "Unconfirmed"}>
                      {p.trust === "trusted" ? <ShieldCheck size={11} aria-hidden="true" /> : <KeyRound size={11} aria-hidden="true" />}
                      {p.name ?? "Unnamed passkey"}
                    </Badge>
                  ))}
                </p>
              ) : (
                <p className="mt-0.5 text-xs text-muted">No passkeys.</p>
              )}
              {admin.lastConfirmedAt && <p className="mt-1 text-xs text-muted">Last confirmed a passkey {timeAgo(admin.lastConfirmedAt, now)}.</p>}
            </div>
            <div className="text-right text-[13px]">
              {admin.trusted > 0 ? (
                <Status tone="ok">
                  {admin.trusted} trusted{admin.unconfirmed > 0 ? `, ${admin.unconfirmed} unconfirmed` : ""}
                </Status>
              ) : (
                <Status tone="warn">Cannot approve yet{admin.unconfirmed > 0 ? `: ${admin.unconfirmed} unconfirmed` : ""}</Status>
              )}
            </div>
          </li>
        ))}
      </ul>
      <div className="space-y-2 border-t border-bd px-5 py-3.5 text-[13px] text-muted">
        <p>
          To confirm a passkey, its owner opens{" "}
          <Link to="/account/security" className="text-accent hover:underline">
            Account, Security
          </Link>{" "}
          and confirms it with one of their trusted passkeys.
        </p>
        {keys.summary.withoutTrustedKey > 0 && (
          <Callout tone="warn" icon={<ShieldAlert size={16} />} data-testid="approval-keys-warning">
            {keys.summary.withoutTrustedKey === 1 ? "One admin has" : `${keys.summary.withoutTrustedKey} admins have`} no trusted passkey and cannot
            approve anything. Without any trusted passkey to confirm with, whoever runs the server can send a link that enrolls a trusted
            one: <Mono>varlatch admin reenroll --identity &lt;id&gt;</Mono>.
          </Callout>
        )}
      </div>
    </SectionCard>
  );
}
