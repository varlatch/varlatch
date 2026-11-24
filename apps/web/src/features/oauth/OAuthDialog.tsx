// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link2 } from "lucide-react";
import type { OAuthConnection } from "@varlatch/protocol";
import { CopyButton } from "../../components/CodeBlock";
import { Dialog } from "../../components/Dialog";
import { Button, Checkbox, Field, Input, Segmented, Select, Textarea } from "../../components/ui";
import { useSession } from "../../lib/session";
import { errorMessage } from "../../shell/Shell";
import { ITEM_NAME_PATTERN } from "../values/model";
import { PRESETS, emptyForm, endpointHostsOf, inputOf, providerOf, providerReady, redirectFor, unnamedHosts, type FormState, type Preset } from "./model";

/**
 * Make an OAuth connection (ADR-0062), or change what may be changed of one:
 * its client secret, scopes and hosts. Every host it goes to is shown before
 * the secret can be typed. It is sent once; nothing on the page keeps it, and
 * no answer holds it.
 */
export function OAuthDialog({
  open,
  org,
  project,
  env,
  connection,
  exists,
  onClose,
  onSaved,
}: {
  open: boolean;
  org: string;
  project: string;
  env: string;
  /** The connection to change; absent to make one. */
  connection?: OAuthConnection | undefined;
  exists: (name: string) => boolean;
  onClose: () => void;
  onSaved: (name: string) => Promise<void>;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const [f, setForm] = useState<FormState>(emptyForm);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [discovered, setDiscovered] = useState<string[] | null>(null);
  // Another provider: what was shown, confirmed and typed for this one goes.
  const set = (patch: Partial<FormState>) => {
    setForm((was) => ({ ...was, clientSecret: "", ...patch, confirmedHosts: [] }));
    setDiscovered(null);
  };
  useEffect(() => {
    setName("");
    setForm(connection ? { ...emptyForm, scopes: connection.scopes.join(" "), hosts: connection.hosts.join(" "), clientId: connection.clientId } : emptyForm);
    setError("");
    setDiscovered(null);
  }, [open, connection]);

  const list = useQuery({
    queryKey: ["oauth-connections", org, project, env],
    queryFn: () => api.listOAuthConnections(org, project, env),
    enabled: open && !connection,
  });
  const hosts = connection ? connection.provider.endpointHosts : endpointHostsOf(f, discovered);
  const others = connection ? [] : unnamedHosts(f, hosts);
  const named = others.every((h) => f.confirmedHosts.includes(h)) && (others.length === 0 || f.grant === "authorization_code");
  const redirect = redirectFor(f, list.data?.redirectBase, discovered);
  const taken = !connection && name !== "" && exists(name);
  const ready = connection
    ? !busy
    : ITEM_NAME_PATTERN.test(name) && !taken && providerReady(f) && hosts !== null && named && f.clientId.trim() !== "" && (f.grant === "authorization_code" || f.clientSecret !== "") && !busy;

  const submit = async () => {
    if (!ready) return;
    setBusy(true);
    setError("");
    try {
      if (connection) {
        const { scopes, hosts } = inputOf(f, connection.item);
        await api.updateOAuthConnection(org, project, env, connection.item, {
          ...(f.clientSecret ? { clientSecret: f.clientSecret } : {}),
          scopes,
          hosts,
          expectedVersionId: connection.versionId,
        });
        await onSaved(connection.item);
      } else {
        await api.createOAuthConnection(org, project, env, inputOf(f, name));
        await onSaved(name);
      }
      setForm(emptyForm);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const discover = async () => {
    setError("");
    setBusy(true);
    try {
      const found = await api.discoverOAuthProvider(org, project, env, { provider: providerOf({ ...f, clientSecret: "x", confirmedHosts: [] }), grant: f.grant });
      setDiscovered(found.provider.endpointHosts);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => !busy && onClose()}
      size="md"
      data-testid="oauth-dialog"
      icon={
        <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
          <Link2 size={16} />
        </span>
      }
      title={
        connection ? (
          <>
            Change <span className="font-mono">{connection.item}</span>
          </>
        ) : (
          "Add an OAuth connection"
        )
      }
      description={
        <span className="font-mono text-[12.5px]">
          {project} / {env}
        </span>
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="confirm-oauth" disabled={!ready} loading={busy} onClick={() => void submit()}>
            {connection ? "Save" : "Add"}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        {!connection && (
          <>
            <p className="text-[13px] text-muted">
              Access to somebody else's API, for Brokers. Varlatch keeps the client secret and the refresh token and gives out neither; a Broker gets
              an access token, refreshed when it has to be.
            </p>
            <Field label="Item" htmlFor="oauth-name">
              <Input
                id="oauth-name"
                data-testid="oauth-name"
                data-autofocus
                mono
                placeholder="MAIL_TOKEN"
                value={name}
                invalid={taken || (name !== "" && !ITEM_NAME_PATTERN.test(name))}
                title={taken ? `${name} already has a value in ${env}` : undefined}
                onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))}
              />
            </Field>
            <Field label="Provider" htmlFor="oauth-preset">
              <Select
                id="oauth-preset"
                data-testid="oauth-preset"
                value={f.preset}
                options={PRESETS.map((p) => ({ value: p.value, label: p.label }))}
                onChange={(v) => set({ preset: v as Preset, ...(v === "google" ? { grant: "authorization_code" as const } : {}) })}
              />
            </Field>
            {f.preset === "microsoft" && (
              <Field label="Tenant ID" htmlFor="oauth-tenant" hint="The directory (tenant) ID, a UUID. Sign-ins of other tenants are not accepted.">
                <Input id="oauth-tenant" data-testid="oauth-tenant" mono value={f.tenant} placeholder="00000000-0000-0000-0000-000000000000" onChange={(e) => set({ tenant: e.target.value })} />
              </Field>
            )}
            {f.preset === "generic" && (
              <>
                <Checkbox
                  checked={f.byEndpoints}
                  onChange={(byEndpoints) => set({ byEndpoints })}
                  label="It publishes no metadata: give its endpoints"
                  data-testid="oauth-by-endpoints"
                />
                {!f.byEndpoints ? (
                  <Field label="Issuer" htmlFor="oauth-issuer" hint="Its metadata names the endpoints. They are read now and stay as they are.">
                    <Input id="oauth-issuer" data-testid="oauth-issuer" mono value={f.issuer} placeholder="https://login.example.com" onChange={(e) => set({ issuer: e.target.value })} />
                  </Field>
                ) : (
                  <>
                    {f.grant === "authorization_code" && (
                      <Field label="Authorization endpoint" htmlFor="oauth-authorization">
                        <Input id="oauth-authorization" data-testid="oauth-authorization" mono value={f.authorizationEndpoint} placeholder="https://" onChange={(e) => set({ authorizationEndpoint: e.target.value })} />
                      </Field>
                    )}
                    <Field label="Token endpoint" htmlFor="oauth-token" hint="The client secret and the refresh token go here.">
                      <Input id="oauth-token" data-testid="oauth-token" mono value={f.tokenEndpoint} placeholder="https://" onChange={(e) => set({ tokenEndpoint: e.target.value })} />
                    </Field>
                    <Field label="Revocation endpoint" htmlFor="oauth-revocation" hint="Optional. Used to disconnect: the client secret and the tokens go here then.">
                      <Input id="oauth-revocation" data-testid="oauth-revocation" mono value={f.revocationEndpoint} placeholder="https://" onChange={(e) => set({ revocationEndpoint: e.target.value })} />
                    </Field>
                    {f.grant === "authorization_code" && (
                      <Field label="Userinfo endpoint" htmlFor="oauth-userinfo" hint="Optional. Says whose account it is, so another one does not go unnoticed. The access token goes here.">
                        <Input id="oauth-userinfo" data-testid="oauth-userinfo" mono value={f.userinfoEndpoint} placeholder="https://" onChange={(e) => set({ userinfoEndpoint: e.target.value })} />
                      </Field>
                    )}
                  </>
                )}
              </>
            )}
            {f.preset !== "google" && (
              <Segmented
                value={f.grant}
                onChange={(grant) => set({ grant })}
                options={[
                  { value: "authorization_code", label: "A person's account" },
                  { value: "client_credentials", label: "The client's own" },
                ]}
              />
            )}
            {f.grant === "authorization_code" && (
              <Field label="Redirect URI, to register at the provider">
                {redirect ? (
                  <span className="flex items-center gap-2">
                    <span data-testid="oauth-redirect" className="min-w-0 break-all font-mono text-[12.5px]">
                      {redirect}
                    </span>
                    <CopyButton value={redirect} label="Copy the redirect URI" />
                  </span>
                ) : list.data && !list.data.redirectBase ? (
                  <span className="text-xs text-deny">This installation has no public URL over HTTPS, so a provider cannot send a browser back to it.</span>
                ) : (
                  <span className="text-xs text-muted">Known once the provider's hosts are.</span>
                )}
              </Field>
            )}
            <Field label="Client ID" htmlFor="oauth-client">
              <Input id="oauth-client" data-testid="oauth-client" mono value={f.clientId} onChange={(e) => set({ clientId: e.target.value })} />
            </Field>
          </>
        )}
        <Field label="Where the client secret and the tokens go">
          {hosts ? (
            <ul className="space-y-0.5 font-mono text-[12.5px]" data-testid="oauth-endpoint-hosts">
              {hosts.map((h) => (
                <li key={h} className="min-w-0 break-all">
                  {h}
                </li>
              ))}
            </ul>
          ) : !connection && f.preset === "generic" && !f.byEndpoints ? (
            <Button size="sm" data-testid="oauth-discover" disabled={!providerReady(f) || busy} onClick={() => void discover()}>
              Ask the provider
            </Button>
          ) : (
            <span className="text-xs text-muted">Give the endpoints first.</span>
          )}
        </Field>
        {others.length > 0 &&
          (f.grant === "authorization_code" ? (
            <Checkbox
              checked={named}
              onChange={(yes) => setForm((was) => ({ ...was, confirmedHosts: yes ? others : [] }))}
              label={`${others.join(", ")} ${others.length === 1 ? "is" : "are"} this provider's own`}
              data-testid="oauth-confirm-hosts"
            />
          ) : (
            <p className="text-[13px] text-deny" data-testid="oauth-hosts-refused">
              The endpoints of a client's own connection are all on one host.
            </p>
          ))}
        <Field
          label="Client secret"
          htmlFor="oauth-secret"
          hint={connection ? "Leave empty to keep the one there is." : f.grant === "authorization_code" ? "Leave empty for a client without one." : undefined}
        >
          <Input
            id="oauth-secret"
            data-testid="oauth-secret"
            type="password"
            autoComplete="new-password"
            mono
            disabled={hosts === null || !named}
            value={f.clientSecret}
            onChange={(e) => setForm((was) => ({ ...was, clientSecret: e.target.value }))}
          />
        </Field>
        <Field
          label="Scopes"
          htmlFor="oauth-scopes"
          hint={connection ? "Asked for the next time it is connected." : f.preset === "generic" ? "With a refresh token among them, where the provider needs a scope for that." : "The provider's own for the account and for a refresh token are added."}
        >
          <Textarea id="oauth-scopes" data-testid="oauth-scopes" mono rows={2} className="w-full" value={f.scopes} onChange={(e) => setForm((was) => ({ ...was, scopes: e.target.value }))} />
        </Field>
        <Field label="Hosts the token may go to" htmlFor="oauth-hosts" hint="As a Capability's destinations: api.example.com, *.example.com. A Capability can only narrow them. Empty: wherever the Capability says.">
          <Textarea id="oauth-hosts" data-testid="oauth-hosts" mono rows={2} className="w-full" value={f.hosts} onChange={(e) => setForm((was) => ({ ...was, hosts: e.target.value }))} />
        </Field>
        {error && (
          <p className="text-[13px] text-deny" data-testid="oauth-error">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}
