// SPDX-License-Identifier: AGPL-3.0-or-later
import type React from "react";
import { CircleCheck, ShieldAlert } from "lucide-react";
import type { AccessCheck } from "@varlatch/protocol";
import { Callout, Spinner } from "../../components/ui";
import { accessTitle, accessTone } from "./accessCheck";

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
  return (
    <Callout
      tone={accessTone(check)}
      icon={check.status === "ok" ? <CircleCheck size={16} /> : <ShieldAlert size={16} />}
      title={accessTitle(check)}
      actions={actions}
      className={className}
      data-testid="access-check"
      data-status={check.status}
    >
      {check.message}
    </Callout>
  );
}
