// SPDX-License-Identifier: AGPL-3.0-or-later
import type React from "react";
import { CircleCheck, ShieldAlert } from "lucide-react";
import type { AccessCheck } from "@varlatch/protocol";
import { Callout, Spinner } from "../../components/ui";
import { formatDate } from "../../lib/time";
import { accessTitle, accessTone } from "./accessCheck";
import { credentialExpiry, expiryText } from "./credentialExpiry";

/** The outcome of an access check, or its progress; renders nothing before one runs. */
export function AccessCheckNotice({
  pending,
  check,
  error,
  actions,
  className,
}: {
  pending: boolean;
  check: AccessCheck | undefined;
  error: unknown;
  actions?: React.ReactNode;
  className?: string;
}) {
  if (pending) {
    return (
      <Callout tone="neutral" icon={<Spinner />} title="Checking access" className={className} data-testid="access-check" data-status="pending">
        Varlatch asks the platform with this credential. Nothing is saved or pushed.
      </Callout>
    );
  }
  if (error) {
    return (
      <Callout tone="warn" icon={<ShieldAlert size={16} />} title="The check did not run" className={className} data-testid="access-check" data-status="error">
        {error instanceof Error ? error.message : String(error)}
      </Callout>
    );
  }
  if (!check) return null;
  // GitHub says when a personal access token expires: a token that works
  // today but expires within days is worth replacing before it is saved.
  const expiry = credentialExpiry(check.credentialExpiresAt, Date.now());
  const expiresSoon = check.status === "ok" && expiry !== null && expiry.state !== "later";
  return (
    <Callout
      tone={expiresSoon ? "warn" : accessTone(check)}
      icon={check.status === "ok" && !expiresSoon ? <CircleCheck size={16} /> : <ShieldAlert size={16} />}
      title={expiresSoon ? `${accessTitle(check)}, but the token expires soon` : accessTitle(check)}
      actions={actions}
      className={className}
      data-testid="access-check"
      data-status={check.status}
    >
      {check.message}
      {expiry && (
        <span className="mt-1 block" data-testid="access-check-expiry">
          {expiryText(expiry, formatDate(expiry.expiresAt))}.
        </span>
      )}
    </Callout>
  );
}
