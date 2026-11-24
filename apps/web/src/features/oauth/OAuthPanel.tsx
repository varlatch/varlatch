// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pause, Pencil, Play, RefreshCw, Unplug } from "lucide-react";
import type { OAuthConnection } from "@varlatch/protocol";
import { CopyButton } from "../../components/CodeBlock";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Callout, Skeleton, Status } from "../../components/ui";
import { useSession } from "../../lib/session";
import { formatDateTime, timeUntil, useNow } from "../../lib/time";
import { errorMessage } from "../../shell/Shell";
import { OAuthDialog } from "./OAuthDialog";
import { knownAccount, reasonText, remember, safeToOpen, statusOf } from "./model";

const DISCONNECTED: Record<string, string> = {
  revoked: "Its tokens are revoked at the provider.",
  "not-supported": "The provider has no endpoint to revoke tokens: withdraw the consent there to end them.",
  failed: "The provider did not revoke its tokens: withdraw the consent there to end them.",
  "nothing-to-revoke": "It held no tokens.",
  left: "Its tokens were left as they are at the provider.",
};

/** An OAuth connection's place in the item panel (ADR-0062): its state, connecting, pausing and disconnecting it. */
export function OAuthPanel({ org, project, env, item, own, onChanged }: { org: string; project: string; env: string; item: string; own: boolean; onChanged: () => void }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const now = useNow(30_000);
  const toast = useToast();
  const confirm = useConfirm();
  const [editing, setEditing] = useState(false);
  const queryKey = ["oauth-connection", org, project, env, item];
  const query = useQuery({ queryKey, queryFn: () => api.getOAuthConnection(org, project, env, item), enabled: own });
  const changed = async () => {
    await qc.invalidateQueries({ queryKey });
    onChanged();
  };
  const failed = (what: string) => (err: unknown) => toast.error(what, { description: errorMessage(err) });

  const connect = useMutation({
    mutationFn: async ({ c, another }: { c: OAuthConnection; another: boolean }) => {
      // Never by accident: another account is refused unless this was asked.
      if (
        another &&
        !(await confirm({
          title: `Connect ${item} to another account`,
          body: `It is ${knownAccount(c)}'s. What uses it will act for the account you connect next.`,
          confirmLabel: "Connect another account",
          tone: "danger",
        }))
      )
        return;
      const begun = await api.startOAuthAuthorization(org, project, env, item, another ? { confirmAccountChange: true } : {});
      if (!safeToOpen(begun.authorizationUrl)) throw new Error("The provider's address is not https.");
      remember(begun.state, { org, project, env, item });
      window.location.assign(begun.authorizationUrl);
    },
    onError: failed(`Could not connect ${item}`),
  });
  const refresh = useMutation({
    mutationFn: () => api.refreshOAuthConnection(org, project, env, item),
    onSuccess: async (r) => {
      if (r.refreshed) toast.success(`Refreshed ${item}`);
      else toast.error(`No new access token of ${item}`, { description: reasonText(r.reason ?? null) ?? undefined });
      await changed();
    },
    onError: failed(`Could not refresh ${item}`),
  });
  const pause = useMutation({
    mutationFn: (paused: boolean) => api.updateOAuthConnection(org, project, env, item, { paused }),
    onSuccess: changed,
    onError: failed(`Could not change ${item}`),
  });
  const disconnect = useMutation({
    mutationFn: () => api.disconnectOAuthConnection(org, project, env, item),
    onSuccess: async (r) => {
      toast.success(`Disconnected ${item}`, { description: DISCONNECTED[r.atProvider] });
      await changed();
    },
    onError: failed(`Could not disconnect ${item}`),
  });

  if (!own) return <p className="text-[13px] text-muted">An OAuth connection of the parent environment: it is connected there.</p>;
  if (query.isLoading) return <Skeleton className="h-24 w-full" />;
  if (!query.data) return <p className="text-[13px] text-muted">{errorMessage(query.error)}</p>;
  const c = query.data;
  const status = statusOf(c);
  const personal = c.grant === "authorization_code";
  const held = c.status !== "not_connected" && c.status !== "revoked" && c.status !== "needs_reconnect";
  const busy = connect.isPending || refresh.isPending || pause.isPending || disconnect.isPending;
  const why = reasonText(c.reason);
  return (
    <div className="space-y-3" data-testid="oauth-panel">
      <Status tone={status.tone}>
        <span data-testid="oauth-status">{status.label}</span>
      </Status>
      {why && (c.status === "failing" || c.status === "needs_reconnect") && (
        <Callout tone={c.status === "failing" ? "warn" : "danger"} data-testid="oauth-reason">
          {why}
          {c.retryAt && c.status === "failing" ? ` Tried again ${timeUntil(c.retryAt, now)}, when it is used.` : ""}
        </Callout>
      )}
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[13px]">
        <dt className="text-muted">Account</dt>
        <dd data-testid="oauth-account">{c.account?.label ?? (personal ? "Not known" : "The client's own")}</dd>
        <dt className="text-muted">Token endpoint</dt>
        <dd className="min-w-0 break-all font-mono text-[12.5px]">{c.provider.tokenEndpoint}</dd>
        <dt className="text-muted">Client ID</dt>
        <dd className="min-w-0 break-all font-mono text-[12.5px]">{c.clientId}</dd>
        <dt className="text-muted">Scopes</dt>
        <dd className="min-w-0 break-words font-mono text-[12.5px]">{(c.grantedScopes ?? c.scopes).join(" ") || "None"}</dd>
        <dt className="text-muted">Hosts</dt>
        <dd className="min-w-0 break-words font-mono text-[12.5px]">{c.hosts.join(" ") || <span className="font-sans text-muted">Wherever a Capability says</span>}</dd>
        {held && (
          <>
            <dt className="text-muted">Access token</dt>
            <dd>{c.accessTokenExpiresAt ? `Ends ${timeUntil(c.accessTokenExpiresAt, now)}` : "The provider does not say when it ends"}</dd>
            {personal && (
              <>
                <dt className="text-muted">Connected</dt>
                <dd>{c.connectedAt ? formatDateTime(c.connectedAt) : "Never"}</dd>
              </>
            )}
          </>
        )}
        {c.redirectUri && (
          <>
            <dt className="text-muted">Redirect URI</dt>
            <dd className="flex items-center gap-2">
              <span className="min-w-0 break-all font-mono text-[12.5px]">{c.redirectUri}</span>
              <CopyButton value={c.redirectUri} label="Copy the redirect URI" />
            </dd>
          </>
        )}
      </dl>
      {c.missingScopes.length > 0 && (
        <Callout tone="warn" data-testid="oauth-missing">
          The provider did not grant <span className="font-mono">{c.missingScopes.join(" ")}</span>.
        </Callout>
      )}
      {held && personal && !c.hasRefreshToken && (
        <Callout tone="warn">The provider gave no refresh token: it has to be connected again when its access token ends.</Callout>
      )}
      <p className="text-xs text-muted">A Capability that names this item gives its Broker the access token. The client secret and the refresh token are shown to nobody.</p>
      <div className="flex flex-wrap gap-2">
        {personal && (
          <Button size="sm" variant={held ? "secondary" : "primary"} data-testid="oauth-connect" loading={connect.isPending} disabled={busy || c.paused} onClick={() => connect.mutate({ c, another: false })}>
            {c.connectedAt ? "Connect again…" : "Connect…"}
          </Button>
        )}
        {personal && knownAccount(c) && (
          <Button size="sm" variant="ghost" data-testid="oauth-another" disabled={busy || c.paused} onClick={() => connect.mutate({ c, another: true })}>
            Another account…
          </Button>
        )}
        {(held || !personal) && (
          <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} data-testid="oauth-refresh" loading={refresh.isPending} disabled={busy || c.paused} onClick={() => refresh.mutate()}>
            {held ? "Refresh now" : "Get a token"}
          </Button>
        )}
        <Button size="sm" variant="ghost" icon={c.paused ? <Play size={13} /> : <Pause size={13} />} data-testid="oauth-pause" disabled={busy} onClick={() => pause.mutate(!c.paused)}>
          {c.paused ? "Resume" : "Pause"}
        </Button>
        <Button size="sm" variant="ghost" icon={<Pencil size={13} />} data-testid="oauth-edit" disabled={busy} onClick={() => setEditing(true)}>
          Change…
        </Button>
        {c.status !== "not_connected" && c.status !== "revoked" && (
          <Button
            size="sm"
            variant="ghost"
            className="text-muted hover:text-deny"
            icon={<Unplug size={13} />}
            data-testid="oauth-disconnect"
            loading={disconnect.isPending}
            disabled={busy}
            onClick={() =>
              void confirm({
                title: `Disconnect ${item}`,
                body: "Its tokens are revoked at the provider, where it can, and forgotten here. Many providers end everything this client has for this account, other connections included.",
                confirmLabel: "Disconnect",
                tone: "danger",
              }).then((ok) => ok && disconnect.mutate())
            }
          >
            Disconnect…
          </Button>
        )}
      </div>
      {editing && (
        <OAuthDialog
          open
          org={org}
          project={project}
          env={env}
          connection={c}
          exists={() => false}
          onClose={() => setEditing(false)}
          onSaved={async () => {
            setEditing(false);
            toast.success(`Changed ${item}`);
            await changed();
          }}
        />
      )}
    </div>
  );
}
