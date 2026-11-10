// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { useSession } from "../../lib/session";
import { useNow } from "../../lib/time";
import { Callout, Spinner } from "../../components/ui";
import { BrandMark } from "../../shell/BrandMark";
import { CenteredCard } from "../../shell/AuthScreens";
import { ApprovalActions, ApprovalSummary, approvalProblem, useApprovalFlow } from "./approval";

/**
 * A step-up approval's page (ADR-0054 Decision 3), at the URL the CLI
 * prints: `varlatch security set` (or a coding agent running it) asked for
 * a change that needs the person's approval. The person, signed in here,
 * reads what the server says the change is and approves with a trusted
 * passkey, or denies. The CLI notices by itself and finishes the change.
 * Only the person who asked can see it.
 */

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);

export function ApprovalPage() {
  const { id } = useParams() as { id: string };
  const { api } = useSession();
  const now = useNow(1000);
  const loaded = useQuery({ queryKey: ["approval", id], queryFn: () => api.getApproval(id), retry: false, refetchOnWindowFocus: false });
  const flow = useApprovalFlow(api, loaded.data ?? null);

  if (location.protocol !== "https:" && !LOOPBACK.has(location.hostname)) {
    return (
      <Frame>
        <Callout tone="danger" icon={<ShieldAlert size={16} />} title="This page needs HTTPS">
          Approving here would send the approval over an unencrypted connection. Open this address with https://.
        </Callout>
      </Frame>
    );
  }

  if (loaded.isLoading) {
    return (
      <Frame>
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      </Frame>
    );
  }

  if (loaded.error || !flow.approval) {
    return (
      <Frame>
        <h1 className="text-[20px] font-semibold">Approval not available</h1>
        <p className="mt-3 text-[13px]" role="alert" data-testid="approval-load-error">
          {approvalProblem(loaded.error)}
        </p>
      </Frame>
    );
  }

  return (
    <Frame>
      <div data-testid="approval-page">
        <h1 className="mb-3 text-[20px] font-semibold">Approve this change?</h1>
        <ApprovalSummary approval={flow.approval} now={now} />
        <ApprovalActions flow={flow} now={now} />
        {flow.approval.state === "closed" && flow.approval.closeReason === "cancelled" && (
          <p className="mt-3 text-[13px] text-muted">The CLI is told the change was not approved.</p>
        )}
      </div>
    </Frame>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <CenteredCard testId="approval-frame">
      <div className="rounded-2xl border border-bd bg-raised px-8 pb-7 pt-8 shadow-pop">
        <div className="mb-5 flex justify-center">
          <BrandMark size={40} />
        </div>
        {children}
      </div>
    </CenteredCard>
  );
}
