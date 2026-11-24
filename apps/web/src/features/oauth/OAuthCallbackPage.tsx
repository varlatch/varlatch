// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { OAuthAuthorizationOutcome } from "@varlatch/protocol";
import { Callout, Spinner } from "../../components/ui";
import { useSession } from "../../lib/session";
import { errorMessage } from "../../shell/Shell";
import { takeArrival, takeFromAddress } from "./arrival";
import { recall, type Pending } from "./model";

/**
 * Where a provider sends the browser back to (ADR-0062): the dashboard sends
 * the code on (arrival.ts took it out of the address), in the person's
 * session, for the connection it was begun for.
 * The server decides about all of it.
 */
export function OAuthCallbackPage() {
  const { api } = useSession();
  const [pending, setPending] = useState<Pending | null | undefined>(undefined);
  const [outcome, setOutcome] = useState<OAuthAuthorizationOutcome | null>(null);
  const [error, setError] = useState("");
  // Once per visit: the state is single-use.
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    takeFromAddress(); // where the page was come to without a load
    const answer = takeArrival();
    const p = answer?.state ? recall(answer.state) : null;
    setPending(p);
    if (!answer?.state || !p) return;
    const { state, code, error: said, iss, redirectUri } = answer;
    api
      .completeOAuthAuthorization(p.org, p.project, p.env, p.item, {
        state,
        redirectUri,
        ...(code !== undefined ? { code } : {}),
        ...(said !== undefined ? { error: said } : {}),
        ...(iss !== undefined ? { iss } : {}),
      })
      .then(setOutcome, (err) => setError(errorMessage(err)));
  }, [api]);

  const to = pending ? `/o/${encodeURIComponent(pending.org)}/p/${encodeURIComponent(pending.project)}/e/${encodeURIComponent(pending.env)}?item=${encodeURIComponent(pending.item)}` : "/";
  const back = (
    <Link className="link" to={to} data-testid="oauth-back">
      {pending ? `Back to ${pending.item}` : "To the dashboard"}
    </Link>
  );
  let body: React.ReactNode;
  if (pending === undefined) body = <Spinner />;
  else if (pending === null)
    body = (
      <Callout tone="neutral" title="Nothing to finish here" data-testid="oauth-callback" data-status="nothing" actions={back}>
        A provider sends you to this page after you connect an OAuth connection, once. Connect it from its item, in this tab.
      </Callout>
    );
  else if (error)
    body = (
      <Callout tone="danger" title={`${pending.item} is not connected`} data-testid="oauth-callback" data-status="error" actions={back}>
        {error}
      </Callout>
    );
  else if (!outcome)
    body = (
      <Callout tone="neutral" icon={<Spinner />} title={`Connecting ${pending.item}`} data-testid="oauth-callback" data-status="pending">
        Varlatch exchanges what the provider sent for its tokens.
      </Callout>
    );
  else if (outcome.outcome === "connected")
    body = (
      <Callout tone="success" title={`${pending.item} is connected`} data-testid="oauth-callback" data-status="connected" actions={back}>
        {outcome.connection?.account ? `It is ${outcome.connection.account.label}'s.` : "The provider does not say whose account it is."}
        {outcome.connection && outcome.connection.missingScopes.length > 0 && ` Not granted: ${outcome.connection.missingScopes.join(" ")}.`}
      </Callout>
    );
  else
    body = (
      <Callout tone={outcome.outcome === "refused" ? "danger" : "warn"} title={`${pending.item} is not connected`} data-testid="oauth-callback" data-status={outcome.reason} actions={back}>
        {outcome.message}
        {outcome.account && outcome.previousAccount && (
          <span className="mt-1 block">
            Connected before: {outcome.previousAccount.label}. Now: {outcome.account.label}.
          </span>
        )}
      </Callout>
    );
  return <div className="mx-auto max-w-2xl px-4 py-16">{body}</div>;
}
