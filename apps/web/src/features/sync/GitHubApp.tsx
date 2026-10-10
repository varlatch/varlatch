// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, MoreHorizontal, Plus, Trash2 } from "lucide-react";
import { VarlatchApiError } from "@varlatch/sdk";
import type {
  AccessCheck,
  GitHubAccount,
  GitHubApp,
  GitHubAppInstallation,
  GitHubAppRegistrationStart,
  PlatformConnection,
  SyncTarget,
  Tier,
} from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Button, Callout, Field, Input, Menu, Segmented, Skeleton, Spinner, Textarea, TierDot, cn } from "../../components/ui";
import { PageHeader } from "../../components/PageHeader";
import { Dialog, useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { useOrgName } from "../projects/hooks";
import { AccessCheckNotice } from "./AccessCheckNotice";
import { PlatformTile } from "./TargetCard";
import type { EnvironmentRef } from "./useOrgEnvironments";

/**
 * The Organization's GitHub App: register it through GitHub's manifest
 * flow (or import one an owner registered), connect its installations, and
 * rotate or remove it. A Connection on an installation stores no token:
 * Varlatch issues a token for each use, limited to one repository and
 * valid for an hour.
 */

export const githubAppKey = (org: string) => ["github-app", org] as const;
const installationsKey = (org: string) => ["github-app-installations", org] as const;

/** The live App, or null when the Organization has none. */
export function useGitHubApp(org: string, enabled = true) {
  const { api } = useSession();
  return useQuery({
    queryKey: githubAppKey(org),
    enabled,
    queryFn: async () => {
      try {
        return await api.getGitHubApp(org);
      } catch (err) {
        if (err instanceof VarlatchApiError && err.code === "RESOURCE_NOT_FOUND") return null;
        throw err;
      }
    },
  });
}

/** Where the App's owner manages it on GitHub (keys under Credentials, deletion under Advanced). */
export function appSettingsUrl(app: Pick<GitHubApp, "slug" | "owner">): string {
  const slug = encodeURIComponent(app.slug);
  return app.owner.type === "organization"
    ? `https://github.com/organizations/${encodeURIComponent(app.owner.login)}/settings/apps/${slug}`
    : `https://github.com/settings/apps/${slug}`;
}

export const installUrl = (slug: string) => `https://github.com/apps/${encodeURIComponent(slug)}/installations/new`;

function ExternalAnchor({ href, children, testId }: { href: string; children: React.ReactNode; testId?: string }) {
  return (
    <a className="link inline-flex items-center gap-1" href={href} target="_blank" rel="noreferrer" data-testid={testId}>
      {children}
      <ExternalLink size={12} aria-hidden="true" />
    </a>
  );
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

// ---------------------------------------------------------------------------
// The panel on the Connections page

export function GitHubAppPanel({
  org,
  connections,
  targets,
  envs,
  onChanged,
  rotating,
  onRotate,
  onRotateDone,
}: {
  org: string;
  connections: PlatformConnection[];
  targets: SyncTarget[];
  envs: Map<string, EnvironmentRef>;
  onChanged: () => void;
  rotating: boolean;
  onRotate: () => void;
  onRotateDone: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const app = useGitHubApp(org);
  const [dialog, setDialog] = useState<"register" | "import" | "connect" | null>(null);
  const appConnections = connections.filter((c) => c.credentialKind === "github-app");
  const appTargets = targets.filter((t) => appConnections.some((c) => c.id === t.connectionId));
  const changed = () => {
    void qc.invalidateQueries({ queryKey: githubAppKey(org) });
    void qc.invalidateQueries({ queryKey: installationsKey(org) });
    onChanged();
  };
  const remove = useMutation({
    // The App confirmed, by its id: if another one replaced it meanwhile, the server refuses.
    mutationFn: (appId: string) => api.removeGitHubApp(org, appId),
    onSuccess: () => {
      changed();
      toast.success("GitHub App removed", { description: "It is still on GitHub. Delete it there too if you no longer need it." });
    },
    onError: (err) => {
      if (err instanceof VarlatchApiError && err.code === "STATE_CHANGED") {
        changed();
        toast.error("The GitHub App changed", { description: "Another App replaced it since you confirmed. Nothing was removed; check it and try again." });
        return;
      }
      toast.error("Could not remove the GitHub App", { description: errorText(err) });
    },
  });

  if (app.isLoading) return <Skeleton className="mb-6 h-28 rounded-xl" />;
  if (app.error) {
    return (
      <Callout tone="warn" className="mb-6" title="Could not load the GitHub App">
        {errorText(app.error)}
      </Callout>
    );
  }
  const current = app.data;

  const askRemove = async (a: GitHubApp) => {
    const ok = await confirm({
      title: `Remove the GitHub App ${a.slug}?`,
      tone: "danger",
      confirmLabel: "Remove App",
      description:
        "Varlatch deletes the App's key and revokes its connections. Values already pushed stay on GitHub. The App itself stays on GitHub: delete it there, under Advanced, if you no longer need it.",
      consequences:
        appConnections.length === 0
          ? [{ text: "No connection uses this App." }]
          : [
              { text: `${appConnections.length} connection${appConnections.length === 1 ? "" : "s"} revoked: ${appConnections.map((c) => c.name).join(", ")}` },
              { text: `${appTargets.length} integration${appTargets.length === 1 ? "" : "s"} stop pushing until pointed at another connection.` },
            ],
    });
    if (ok) remove.mutate(a.id);
  };

  return (
    <section className="mb-6 rounded-xl border border-bd bg-raised" data-testid="github-app-panel">
      <div className="flex flex-wrap items-start gap-3.5 px-5 py-4">
        <PlatformTile platform="github-actions" size="lg" />
        <div className="min-w-0 flex-1">
          <h2 className="text-[15px] font-semibold text-fg">GitHub App</h2>
          {current ? (
            <p className="mt-0.5 text-[13px] text-muted" data-testid="github-app-summary">
              <ExternalAnchor href={current.htmlUrl}>{current.slug}</ExternalAnchor> on{" "}
              <span className="font-mono">{current.owner.login}</span>
              {" · "}
              {appConnections.length === 0
                ? "no installation connected yet"
                : `${appConnections.length} installation${appConnections.length === 1 ? "" : "s"} connected`}
            </p>
          ) : (
            <p className="mt-0.5 max-w-2xl text-[13px] text-muted">
              Push to GitHub through your own GitHub App instead of a personal access token. Varlatch issues a token for each push,
              limited to one repository and valid for an hour, and nothing expires with a person.
            </p>
          )}
        </div>
        {current ? (
          <div className="flex items-center gap-2">
            <Button size="sm" icon={<Plus size={14} />} onClick={() => setDialog("connect")} data-testid="github-app-connect">
              Connect an installation
            </Button>
            <Menu
              data-testid="github-app-menu"
              label="GitHub App actions"
              buttonClassName="size-8 justify-center border border-bd"
              items={[
                { label: "Install on GitHub", icon: <ExternalLink size={14} />, onSelect: () => window.open(installUrl(current.slug), "_blank", "noreferrer") },
                { label: "Rotate key", icon: <KeyRound size={14} />, "data-testid": "github-app-rotate", onSelect: onRotate },
                {
                  label: "Remove App",
                  danger: true,
                  separatorBefore: true,
                  icon: <Trash2 size={14} />,
                  "data-testid": "github-app-remove",
                  onSelect: () => void askRemove(current),
                },
              ]}
            >
              <MoreHorizontal size={16} />
            </Menu>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="primary" onClick={() => setDialog("register")} data-testid="github-app-register">
              Register an App
            </Button>
            <Button size="sm" onClick={() => setDialog("import")} data-testid="github-app-import">
              Import an App
            </Button>
          </div>
        )}
      </div>
      {current && appConnections.length === 0 && (
        <p className="border-t border-bd px-5 py-3 text-[13px] text-muted">
          <ExternalAnchor href={installUrl(current.slug)}>Install the App on GitHub</ExternalAnchor>, choosing the repositories
          Varlatch should push to, then connect the installation here.
        </p>
      )}

      {dialog === "register" && <RegisterAppDialog org={org} onClose={() => setDialog(null)} />}
      {dialog === "import" && (
        <ImportAppDialog
          org={org}
          onClose={() => setDialog(null)}
          onImported={() => {
            setDialog(null);
            changed();
          }}
        />
      )}
      {dialog === "connect" && current && (
        <ConnectInstallationDialog
          org={org}
          app={current}
          connections={appConnections}
          onClose={() => setDialog(null)}
          onCreated={() => {
            setDialog(null);
            changed();
          }}
        />
      )}
      {rotating && current && (
        <RotateKeyDialog
          org={org}
          app={current}
          connections={appConnections}
          targets={appTargets}
          envs={envs}
          onClose={onRotateDone}
          onRotated={() => {
            onRotateDone();
            changed();
          }}
          onConflict={changed}
        />
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Registration: GitHub's manifest flow

export function RegisterAppDialog({ org, onClose }: { org: string; onClose: () => void }) {
  const { api } = useSession();
  const [type, setType] = useState<GitHubAccount["type"]>("organization");
  const [login, setLogin] = useState("");
  const [started, setStarted] = useState<GitHubAppRegistrationStart | null>(null);
  const form = useRef<HTMLFormElement | null>(null);
  const start = useMutation({
    mutationFn: () => api.startGitHubAppRegistration(org, { login: login.trim(), type }),
    onSuccess: setStarted,
  });
  // GitHub's manifest flow is a form the browser posts to github.com.
  useEffect(() => {
    if (started) form.current?.submit();
  }, [started]);
  const account = login.trim() || (type === "organization" ? "the organization" : "your account");

  return (
    <Dialog
      open
      onClose={onClose}
      title="Register a GitHub App"
      description="GitHub shows a form to create the App, filled in by Varlatch. Then it sends you back here."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={start.isPending || started !== null}
            disabled={login.trim() === ""}
            onClick={() => start.mutate()}
            data-testid="github-app-continue"
          >
            Continue to GitHub
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Create the App on">
          <Segmented
            value={type}
            onChange={setType}
            aria-label="Account type"
            options={[
              { value: "organization", label: "A GitHub organization", "data-testid": "github-app-type-organization" },
              { value: "user", label: "My personal account", "data-testid": "github-app-type-user" },
            ]}
          />
        </Field>
        <Field
          label={type === "organization" ? "Organization" : "Your GitHub username"}
          hint="The App can only be installed on the account it is created on."
        >
          <Input mono value={login} onChange={(e) => setLogin(e.target.value)} placeholder="acme-org" data-testid="github-app-login" />
        </Field>
        {type === "organization" && (
          <Callout tone="info" title="Only an owner can do this" data-testid="github-app-owner-note">
            Registering an App on {account} needs an owner of it, or a member allowed to manage its GitHub Apps. If GitHub says you
            don't have permission and offers to create the App for your own account, stop there: that App cannot work for {account}.
            Ask an owner to register it, or to register one and give you its App ID and key to import.
          </Callout>
        )}
        {start.error && (
          <Callout tone="danger" title="Could not start the registration">
            {errorText(start.error)}
          </Callout>
        )}
        {started && (
          <form ref={form} method="post" action={started.action} className="hidden" data-testid="github-app-manifest-form">
            <input type="hidden" name="manifest" value={JSON.stringify(started.manifest)} />
          </form>
        )}
      </div>
    </Dialog>
  );
}

/** Where GitHub sends the browser back: completes the registration with this session's bearer. */
export function GitHubAppCallbackPage() {
  const { org } = useParams() as { org: string };
  const { api } = useSession();
  const qc = useQueryClient();
  const orgName = useOrgName(org);
  const [params] = useSearchParams();
  const code = params.get("code");
  const state = params.get("state");
  const complete = useMutation({
    mutationFn: () => api.completeGitHubAppRegistration(org, { state: state!, code: code! }),
    onSuccess: (result) => {
      if (result.outcome === "registered") void qc.invalidateQueries({ queryKey: githubAppKey(org) });
    },
  });
  // A used or expired link: whether the Organization has its App decides
  // what to say. A refresh after a successful registration lands here too,
  // and must not send anyone to delete the App that works.
  const errorCode = complete.error instanceof VarlatchApiError ? complete.error.code : undefined;
  const needsAppCheck = errorCode === "CONSUMED" || errorCode === "EXPIRED";
  const current = useGitHubApp(org, needsAppCheck);
  // Once per visit: the state is single-use.
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current || !code || !state) return;
    ran.current = true;
    complete.mutate();
  }, [code, state, complete]);

  const back = (
    <Link className="link" to={`/o/${org}/connections`}>
      Back to Connections
    </Link>
  );
  const recovery = (
    <span className="mt-1 block" data-testid="github-app-recovery">
      If GitHub created the App, it is still there. Delete it under the account's Settings, Developer settings, GitHub Apps (
      <ExternalAnchor href="https://github.com/settings/apps">your Apps</ExternalAnchor>), then start again from Connections.
    </span>
  );

  let body: React.ReactNode;
  if (!code || !state) {
    body = (
      <Callout tone="neutral" title="Nothing to finish here" actions={back}>
        GitHub sends you to this page after you create a GitHub App. Start from Connections.
      </Callout>
    );
  } else if (complete.isPending || (!complete.data && !complete.error)) {
    body = (
      <Callout tone="neutral" icon={<Spinner />} title="Finishing the registration with GitHub" data-testid="github-app-callback" data-status="pending">
        Varlatch asks GitHub for the App it just created.
      </Callout>
    );
  } else if (complete.error && needsAppCheck) {
    const expired = errorCode === "EXPIRED";
    if (current.isLoading) {
      body = (
        <Callout tone="neutral" icon={<Spinner />} title="Checking this organization's GitHub App" data-testid="github-app-callback" data-status={errorCode} data-app="checking">
          {expired ? "This registration expired." : "This registration was already finished."} Varlatch checks whether the organization has its App.
        </Callout>
      );
    } else if (current.error) {
      body = (
        <Callout tone="warn" title="Could not check this organization's GitHub App" actions={back} data-testid="github-app-callback" data-status={errorCode} data-app="unknown">
          {expired ? "This registration expired." : "This registration was already finished."} Open Connections before deleting anything on GitHub: it
          shows whether this organization has its App.
        </Callout>
      );
    } else if (current.data) {
      const app = current.data;
      body = expired ? (
        <Callout tone="warn" title="This registration expired" actions={back} data-testid="github-app-callback" data-status={errorCode} data-app="present">
          GitHub's code lasts an hour. This organization's GitHub App is <span className="font-mono">{app.slug}</span>: keep it. If GitHub created
          another App during this attempt, you can delete that one on GitHub, not {app.slug}.
        </Callout>
      ) : (
        <Callout tone="success" title="This registration already finished" actions={back} data-testid="github-app-callback" data-status={errorCode} data-app="present">
          This organization's GitHub App is <span className="font-mono">{app.slug}</span>. If you have not yet,{" "}
          <ExternalAnchor href={installUrl(app.slug)} testId="github-app-install">install it on GitHub</ExternalAnchor>, then connect the installation
          from Connections.
        </Callout>
      );
    } else {
      body = (
        <Callout tone="danger" title="The registration did not finish" actions={back} data-testid="github-app-callback" data-status={errorCode} data-app="absent">
          {expired
            ? "This registration expired: GitHub's code lasts an hour, and this organization has no GitHub App."
            : "This registration was already used, but this organization has no GitHub App: the earlier attempt stopped partway."}
          {recovery}
        </Callout>
      );
    }
  } else if (complete.error) {
    body = (
      <Callout tone="danger" title="The registration did not finish" actions={back} data-testid="github-app-callback" data-status={errorCode ?? "error"}>
        {errorCode === "RESOURCE_NOT_FOUND"
          ? "No registration of yours in this organization matches this link. Start again from Connections."
          : errorText(complete.error)}
      </Callout>
    );
  } else {
    const result = complete.data!;
    if (result.outcome === "registered") {
      body = (
        <Callout
          tone="success"
          title={`GitHub App ${result.app.slug} registered`}
          actions={back}
          data-testid="github-app-callback"
          data-status="registered"
        >
          Next, <ExternalAnchor href={installUrl(result.app.slug)} testId="github-app-install">install it on GitHub</ExternalAnchor>, choosing
          the repositories Varlatch should push to. Then connect the installation from Connections.
        </Callout>
      );
    } else if (result.outcome === "refused") {
      body = (
        <Callout
          tone="danger"
          title={
            result.reason === "owner-mismatch"
              ? "GitHub created the App on another account"
              : result.reason === "organization-has-app"
                ? "This organization already has a GitHub App"
                : "Another organization uses this App"
          }
          actions={back}
          data-testid="github-app-callback"
          data-status={result.reason}
        >
          {result.message}{" "}
          <ExternalAnchor href={result.deleteUrl} testId="github-app-delete">
            Delete {result.app.slug} on GitHub
          </ExternalAnchor>
        </Callout>
      );
    } else if (result.retryable) {
      body = (
        <Callout
          tone="warn"
          title="GitHub could not be reached"
          data-testid="github-app-callback"
          data-status="retryable"
          actions={
            <Button size="sm" onClick={() => complete.mutate()} data-testid="github-app-retry">
              Try again
            </Button>
          }
        >
          {result.message}
        </Callout>
      );
    } else {
      body = (
        <Callout tone="danger" title="The registration did not finish" actions={back} data-testid="github-app-callback" data-status="failed">
          {result.message}
          {recovery}
        </Callout>
      );
    }
  }

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Connections", to: `/o/${org}/connections` }, { label: "GitHub App" }]}
        title="GitHub App"
      />
      {body}
    </>
  );
}

// ---------------------------------------------------------------------------
// Import, and the App's private key

/** The key, pasted or read from the .pem GitHub downloaded. */
function KeyField({ value, onChange, label }: { value: string; onChange: (pem: string) => void; label: string }) {
  return (
    <Field label={label} hint="The .pem file GitHub downloaded. Varlatch stores it encrypted and never shows it again.">
      <div className="space-y-2">
        <Textarea
          mono
          rows={5}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="-----BEGIN RSA PRIVATE KEY-----"
          className="w-full"
          data-testid="github-app-key"
        />
        <input
          type="file"
          accept=".pem,application/x-pem-file"
          className="text-xs text-muted"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void file.text().then(onChange);
          }}
        />
      </div>
    </Field>
  );
}

export function ImportAppDialog({ org, onClose, onImported }: { org: string; onClose: () => void; onImported: () => void }) {
  const { api } = useSession();
  const toast = useToast();
  const [appId, setAppId] = useState("");
  const [key, setKey] = useState("");
  const [failed, setFailed] = useState<AccessCheck | null>(null);
  const id = Number(appId.trim());
  const valid = Number.isSafeInteger(id) && id > 0 && key.trim() !== "";
  const run = useMutation({
    mutationFn: () => api.importGitHubApp(org, { appId: id, privateKey: key }),
    onSuccess: (result) => {
      if (result.outcome === "registered") {
        toast.success(`GitHub App ${result.app.slug} imported`);
        onImported();
      } else {
        const { outcome: _outcome, ...check } = result;
        setFailed(check);
      }
    },
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title="Import a GitHub App"
      description="An App an owner registered on GitHub: its App ID and a private key. Varlatch checks the pair with GitHub before keeping it."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={run.isPending} disabled={!valid} onClick={() => run.mutate()} data-testid="github-app-import-submit">
            Import App
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="App ID" hint="On the App's settings page on GitHub, under About.">
          <Input mono inputMode="numeric" value={appId} onChange={(e) => setAppId(e.target.value)} placeholder="5254113" data-testid="github-app-id" />
        </Field>
        <KeyField label="Private key" value={key} onChange={setKey} />
        <Callout tone="info" title="Give the App no more than it needs" data-testid="github-app-key-reach">
          Varlatch needs Secrets and Environments (read and write) and Metadata (read). It limits each token it issues to one use,
          but the key itself keeps everything the App holds.
        </Callout>
        {failed && <AccessCheckNotice pending={false} check={failed} error={undefined} />}
        {run.error && <AccessCheckNotice pending={false} check={undefined} error={run.error} />}
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Installations: a Connection per installation

export function ConnectInstallationDialog({
  org,
  app,
  connections,
  onClose,
  onCreated,
}: {
  org: string;
  app: GitHubApp;
  connections: PlatformConnection[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { api } = useSession();
  const toast = useToast();
  const listing = useQuery({ queryKey: installationsKey(org), queryFn: () => api.listGitHubAppInstallations(org) });
  const [chosen, setChosen] = useState<GitHubAppInstallation | null>(null);
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => api.createAppConnection(org, { installationId: chosen!.installationId, name: name.trim() || `GitHub (${chosen!.account.login})` }),
    onSuccess: (connection) => {
      toast.success(`${connection.name} connected`);
      onCreated();
    },
  });
  const connected = new Set(connections.map((c) => c.installationId));
  const items = listing.data?.items ?? [];

  return (
    <Dialog
      open
      onClose={onClose}
      title="Connect an installation"
      description={`Where ${app.slug} is installed on GitHub. A connection pushes only to the repositories the installation includes.`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={create.isPending} disabled={!chosen} onClick={() => create.mutate()} data-testid="github-app-connect-submit">
            Connect
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {listing.isLoading && (
          <Callout tone="neutral" icon={<Spinner />} title="Asking GitHub where the App is installed" />
        )}
        {listing.error && <AccessCheckNotice pending={false} check={undefined} error={listing.error} />}
        {listing.data && listing.data.check.status !== "ok" && <AccessCheckNotice pending={false} check={listing.data.check} error={undefined} />}
        {listing.data?.check.status === "ok" && items.length === 0 && (
          <Callout tone="neutral" title="The App is not installed anywhere yet">
            <ExternalAnchor href={installUrl(app.slug)}>Install it on GitHub</ExternalAnchor>, then come back.
          </Callout>
        )}
        <div className="space-y-2" role="radiogroup" aria-label="Installation" data-testid="github-app-installations">
          {items.map((i) => {
            const taken = connected.has(i.installationId);
            const disabled = i.suspended || taken;
            return (
              <button
                key={i.installationId}
                type="button"
                role="radio"
                aria-checked={chosen?.installationId === i.installationId}
                disabled={disabled}
                data-testid={`github-app-installation-${i.installationId}`}
                onClick={() => {
                  setChosen(i);
                  setName(`GitHub (${i.account.login})`);
                }}
                className={cn(
                  "flex w-full items-center justify-between gap-3 rounded-lg border px-3.5 py-2.5 text-left text-[13px]",
                  chosen?.installationId === i.installationId ? "border-accent bg-accent/[0.06]" : "border-bd hover:border-bd-strong",
                  disabled && "cursor-not-allowed opacity-60",
                )}
              >
                <span className="min-w-0">
                  <span className="block font-mono text-fg">{i.account.login}</span>
                  <span className="text-muted">
                    {i.account.type === "organization" ? "Organization" : "Personal account"} ·{" "}
                    {i.repositorySelection === "all" ? "all repositories" : "selected repositories"}
                  </span>
                </span>
                <span className="shrink-0 text-xs text-muted">{i.suspended ? "suspended on GitHub" : taken ? "connected" : ""}</span>
              </button>
            );
          })}
        </div>
        {listing.data?.truncated && <p className="text-xs text-muted">Showing the first 3,000 installations.</p>}
        {chosen && (
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} data-testid="github-app-connection-name" />
          </Field>
        )}
        <p className="text-xs text-muted">
          To change which repositories the App can reach, configure the installation on GitHub. If you are not an owner there, GitHub
          sends your change to an owner to approve, and the repository appears here once it is reachable.
        </p>
        {create.error && (
          <Callout tone="danger" title="Could not connect the installation">
            {errorText(create.error)}
          </Callout>
        )}
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Key rotation

export function RotateKeyDialog({
  org,
  app,
  connections,
  targets,
  envs,
  onClose,
  onRotated,
  onConflict,
}: {
  org: string;
  app: GitHubApp;
  connections: PlatformConnection[];
  targets: SyncTarget[];
  envs: Map<string, EnvironmentRef>;
  onClose: () => void;
  onRotated: () => void;
  /** Reload the App (and what it covers) after a version conflict. */
  onConflict?: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [key, setKey] = useState("");
  const [failed, setFailed] = useState<AccessCheck | null>(null);
  // The version GitHub's rotation was refused at: until the App is read
  // again with a newer one, asking again would only repeat the conflict.
  const [conflictedAt, setConflictedAt] = useState<number | null>(null);
  const stale = conflictedAt !== null && app.version <= conflictedAt;
  const reload = () => (onConflict ? onConflict() : void qc.invalidateQueries({ queryKey: githubAppKey(org) }));
  const settings = appSettingsUrl(app);
  const rotate = useMutation({
    // The request's own inputs: the App may be re-read while it is in flight.
    mutationFn: (input: { privateKey: string; expectedVersion: number }) => api.rotateGitHubAppKey(org, input),
    onError: (err, input) => {
      if (err instanceof VarlatchApiError && err.code === "VERSION_CONFLICT") {
        // The version this request was refused at, not the one shown now:
        // a newer one may already be loaded, and then nothing is stale.
        setConflictedAt(input.expectedVersion);
        reload();
      }
    },
    onSuccess: (result) => {
      if (result.outcome === "rotated") {
        toast.success("Key rotated", { description: "Now delete the old key on GitHub: the App's settings, Credentials, Key pairs." });
        onRotated();
      } else {
        const { outcome: _outcome, ...check } = result;
        setFailed(check);
      }
    },
  });
  const conflict = rotate.error instanceof VarlatchApiError && rotate.error.code === "VERSION_CONFLICT";
  const refusal = rotate.error && !conflict ? errorText(rotate.error) : null;

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Rotate the key of ${app.slug}`}
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={rotate.isPending}
            disabled={key.trim() === "" || stale}
            onClick={() => rotate.mutate({ privateKey: key, expectedVersion: app.version })}
            data-testid="github-app-rotate-submit"
          >
            Rotate key
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <ol className="list-decimal space-y-1 pl-5 text-[13px] text-fg/90" data-testid="github-app-rotate-steps">
          <li>
            On GitHub, open <ExternalAnchor href={settings}>the App's settings</ExternalAnchor>, then Credentials, Key pairs, New key. A
            .pem file downloads.
          </li>
          <li>Paste it below, or choose the file. Varlatch checks it with GitHub first.</li>
          <li>Once Varlatch confirms, delete the old key on the same page.</li>
        </ol>
        <KeyField label="New private key" value={key} onChange={setKey} />
        <Callout tone="info" title={`This re-authorizes ${targets.length} integration${targets.length === 1 ? "" : "s"}`} data-testid="github-app-rotate-scope">
          Every integration on the App's {connections.length} connection{connections.length === 1 ? "" : "s"} switches to the new key at
          once, paused and disabled ones included, so you need permission to send each one's values. If you lack it for one, nothing
          changes.
          {targets.length > 0 && (
            <span className="mt-2 block space-y-1">
              {targets.map((t) => {
                const ref = envs.get(t.environmentId);
                return (
                  <span key={t.id} className="flex items-center gap-2 font-mono text-xs">
                    {ref ? <TierDot tier={ref.environment.tier as Tier} /> : null}
                    {ref ? `${ref.project.slug} / ${ref.environment.name}` : "an environment"}
                  </span>
                );
              })}
            </span>
          )}
        </Callout>
        {failed && <AccessCheckNotice pending={false} check={failed} error={undefined} />}
        {conflictedAt !== null &&
          (stale ? (
            <Callout
              tone="warn"
              icon={<Spinner />}
              title="The App changed while this was open"
              data-testid="github-app-rotate-conflict"
              data-status="reloading"
              actions={
                <Button size="sm" onClick={reload}>
                  Reload
                </Button>
              }
            >
              Varlatch is reading it again. Nothing was rotated.
            </Callout>
          ) : (
            <Callout tone="info" title="The App changed while this was open" data-testid="github-app-rotate-conflict" data-status="reloaded">
              Varlatch read it again. Check the integrations above, then rotate the key again.
            </Callout>
          ))}
        {refusal && (
          <Callout tone="danger" title="The key was not rotated" data-testid="github-app-rotate-refused">
            {refusal}
          </Callout>
        )}
      </div>
    </Dialog>
  );
}
