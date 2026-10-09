// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { Download, Lock, ShieldAlert, Wifi } from "lucide-react";
import type { Environment, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { TAILNET_ONLY_GUIDANCE, isTailnetOnly } from "../../lib/tailnet";
import { Dialog } from "../../components/Dialog";
import { Button, Callout, Checkbox, Field, Select, Skeleton, TierDot } from "../../components/ui";
import { errorMessage } from "../../shell/Shell";
import { dotenvLine, plural, type ServerItem } from "./model";
import { SecretMask } from "./bits";

/**
 * `.env` in and out. Import fills drafts (never writes); export downloads
 * non-secret values, and Secrets only after an explicit, audited disclosure.
 */

export function ImportDialog({
  rows,
  environments,
  initialEnv,
  isSensitive,
  existing,
  onClose,
  onImport,
}: {
  rows: { name: string; value: string }[] | null;
  /** Target choices; omit the picker by passing one. */
  environments: Environment[];
  initialEnv: string;
  isSensitive: (env: string, name: string) => boolean;
  /** Whether env already has a value or draft for name. */
  existing: (env: string, name: string) => boolean;
  onClose: () => void;
  onImport: (env: string) => void;
}) {
  const [env, setEnv] = useState(initialEnv);
  useEffect(() => setEnv(initialEnv), [initialEnv, rows]);
  return (
    <Dialog
      open={rows !== null}
      onClose={onClose}
      size="md"
      data-testid="import-dialog"
      title={`Import ${plural(rows?.length ?? 0, "item")} as drafts`}
      description="Nothing is saved yet: the pasted values become unsaved changes you review before saving."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="confirm-import" onClick={() => onImport(env)}>
            Import as drafts
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {environments.length > 1 && (
          <Field label="Into environment">
            <Select
              className="w-64"
              data-testid="import-env"
              aria-label="Into environment"
              value={env}
              onChange={setEnv}
              options={environments.map((e) => ({ value: e.name, label: e.name, icon: <TierDot tier={e.tier as Tier} /> }))}
            />
          </Field>
        )}
        <ul className="max-h-80 divide-y divide-bd overflow-y-auto rounded-lg border border-bd">
          {(rows ?? []).map((r) => (
            <li key={r.name} className="flex items-center gap-3 px-3 py-2">
              <span className="w-56 shrink-0 truncate font-mono text-[13px]">{r.name}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-muted">
                {isSensitive(env, r.name) ? (
                  <span className="inline-flex items-center gap-1.5">
                    <Lock size={12} />
                    <SecretMask />
                  </span>
                ) : (
                  r.value || <span className="italic">(empty)</span>
                )}
              </span>
              {existing(env, r.name) && <span className="shrink-0 text-xs text-warn">replaces</span>}
            </li>
          ))}
        </ul>
      </div>
    </Dialog>
  );
}

export function ExportDialog({
  org,
  project,
  env,
  onClose,
}: {
  org: string;
  project: string;
  env: Environment | null;
  onClose: () => void;
}) {
  const { api } = useSession();
  const [items, setItems] = useState<ServerItem[] | null>(null);
  const [withheld, setWithheld] = useState<Set<string>>(new Set());
  const [includeSecrets, setIncludeSecrets] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // A Tailnet Requirement covers the environment: no value can be read here.
  const tailnetOnly = isTailnetOnly(env ?? undefined);

  useEffect(() => {
    if (!env || tailnetOnly) return;
    let live = true;
    setItems(null);
    setIncludeSecrets(false);
    setError("");
    api
      .effectiveConfiguration(org, project, env.name, { includeValues: true })
      .then((r) => {
        if (!live) return;
        setItems(r.items ?? []);
        setWithheld(new Set((r.callerView?.withheld ?? []).map((w) => w.name)));
      })
      .catch((err) => live && setError(errorMessage(err)));
    return () => {
      live = false;
    };
  }, [api, org, project, env, tailnetOnly]);

  const secrets = (items ?? []).filter((i) => i.sensitive);
  const plain = (items ?? []).filter((i) => !i.sensitive && !withheld.has(i.name) && i.value != null);

  const download = async () => {
    if (!env || !items) return;
    setBusy(true);
    setError("");
    try {
      let disclosed = new Map<string, string>();
      if (includeSecrets && secrets.length > 0) {
        const result = await api.discloseSecrets(org, project, env.name, { items: secrets.map((s) => s.name) });
        disclosed = new Map(result.items.map((i) => [i.name, i.value]));
      }
      const lines = [`# ${project} / ${env.name}, exported ${new Date().toISOString()}`];
      for (const item of [...items].sort((a, b) => a.name.localeCompare(b.name))) {
        if (item.sensitive) {
          const value = disclosed.get(item.name);
          lines.push(value !== undefined ? dotenvLine(item.name, value) : `# ${item.name}: secret, not exported`);
        } else if (withheld.has(item.name) || item.value == null) {
          lines.push(`# ${item.name}: not readable with your access`);
        } else {
          lines.push(dotenvLine(item.name, item.value));
        }
      }
      const blob = new Blob([`${lines.join("\n")}\n`], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${project}.${env.name.replace(/\//g, "-")}.env`;
      document.body.append(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={env !== null}
      onClose={() => !busy && onClose()}
      size="sm"
      data-testid="export-dialog"
      title={
        <>
          Export <span className="font-mono">{env?.name}</span> as .env
        </>
      }
      description="Downloads a file to this computer."
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={<Download size={14} />}
            data-testid="export-download"
            disabled={!items || tailnetOnly}
            loading={busy}
            onClick={() => void download()}
          >
            {includeSecrets ? "Reveal and download" : "Download"}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-[13px]">
        {tailnetOnly && (
          <Callout tone="info" icon={<Wifi size={15} />} data-testid="export-tailnet-only" title="Nothing to export here">
            {TAILNET_ONLY_GUIDANCE}
          </Callout>
        )}
        {!items && !error && !tailnetOnly && <Skeleton className="h-10 w-full" />}
        {items && (
          <p className="text-muted">
            <span className="text-fg">{plural(plain.length, "value")}</span> exported.{" "}
            {secrets.length > 0 && !includeSecrets && <>{plural(secrets.length, "secret")} left out. </>}
            {withheld.size > 0 && <>{plural(withheld.size, "value")} not readable with your access.</>}
          </p>
        )}
        {items && secrets.length > 0 && (
          <Checkbox
            data-testid="export-include-secrets"
            checked={includeSecrets}
            onChange={setIncludeSecrets}
            label={`Include ${plural(secrets.length, "secret")}`}
            description="An audited disclosure, like revealing them on screen."
          />
        )}
        {includeSecrets && (
          <Callout tone="warn" icon={<ShieldAlert size={15} />} title="This is an audited disclosure">
            The secret values are revealed to this browser and written into the file. The disclosure is recorded in the
            audit log; deleting the file does not undo it.
          </Callout>
        )}
        {error && <p className="text-deny">{error}</p>}
      </div>
    </Dialog>
  );
}
