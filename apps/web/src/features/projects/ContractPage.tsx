// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ContractRevision, Environment } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, InfoTip, Input, Mono, Select, cn } from "../../components/ui";

/** Hover help for the item-type dropdown: `title` on each option plus an
    InfoTip echoing the selected type's meaning. */
const TYPE_HELP: Record<string, string> = {
  string: "Any text value; no validation beyond presence.",
  number: "Must be an integer or decimal written in digits, e.g. -12 or 3.5 (no exponent, no leading +).",
  boolean: "Must be true or false in any case, or 1/0.",
  url: "Must be an absolute URL including its scheme, e.g. https://…",
  email: "Must look like an email address.",
  enum: "Must be one of a fixed set of allowed values.",
};

/**
 * P4 Contract tab (design R2): the Contract is always visible; who may write
 * it depends on the project's contract authority. Git-authority projects get
 * a read-only view ("edit in your repository, push with the CLI"); managed
 * projects get the editor, where publishing pushes and activates a new
 * revision. The Varlock mapping (varlock env name -> Environment) is editable
 * for both.
 */

type Item = {
  name: string;
  required: { kind: string; selector?: { kind: string; tier?: string } };
  sensitive: boolean;
  type: string;
  defaultValue?: string;
  description?: string;
  enumValues?: string[];
  example?: string;
};

function describeRequired(r: Item["required"]): string {
  if (r.kind === "always") return "always";
  if (r.kind === "never") return "optional";
  return r.selector?.kind === "tier" ? `tier ${r.selector.tier}` : "selected environments";
}

export function ContractPage() {
  const { org, project } = useParams();
  useOrgRealtime(
    org,
    ["contract", "project", "environment"],
    [
      ["project", org, project],
      ["contract", org, project],
      ["varlock-mapping", org, project],
      ["environments", org, project],
    ],
  );
  const { api } = useSession();
  const qc = useQueryClient();
  const projectQuery = useQuery({
    queryKey: ["project", org, project],
    queryFn: async () =>
      (await api.listProjects(org as string)).items.find((p) => p.slug === project),
  });
  const contract = useQuery({
    queryKey: ["contract", org, project],
    queryFn: () => api.getActiveContract(org as string, project as string),
    retry: false,
  });

  const managed = projectQuery.data?.contractAuthority === "managed";
  const items = ((contract.data?.contract as { items?: Item[] } | undefined)?.items ?? []) as Item[];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">
          <Link to={`/o/${org}/p/${project}`} className="text-muted hover:text-fg">
            {project}
          </Link>{" "}
          / contract
        </h1>
        {projectQuery.data && (
          <span className="text-sm text-muted" data-testid="contract-authority">
            authority: <Mono>{projectQuery.data.contractAuthority}</Mono>
          </span>
        )}
      </div>
      {projectQuery.data && (
        <p className="text-sm text-muted">
          {managed
            ? "Managed authority: edit and publish the contract right here — Varlatch is the source of truth."
            : (
              <>
                Git authority: the schema lives in your repository as <Mono>.env.schema</Mono> and
                is pushed with <Mono>varlatch contract push</Mono> — the repo is the source of
                truth, so this view is read-only.
              </>
            )}
        </p>
      )}

      {contract.isError && (
        <Card>
          <p className="text-sm text-muted">
            No active Contract yet.{" "}
            {managed ? "Add items below and publish." : (
              <>Define it in your repository and push: <Mono className="text-accent">varlatch contract push</Mono></>
            )}
          </p>
        </Card>
      )}

      {contract.data && (
        <Card className="p-0 overflow-hidden">
          <div className="px-3 py-2 border-b border-bd flex items-center justify-between text-xs text-muted">
            <span>
              Active revision <Mono>{contract.data.id}</Mono>
            </span>
            <Mono>{contract.data.contentHash}</Mono>
          </div>
          <table className="w-full text-sm" data-testid="contract-items">
            <thead>
              <tr className="text-left text-muted border-b border-bd">
                <th className="px-3 py-2 font-medium">Item</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Required</th>
                <th className="px-3 py-2 font-medium">Secret</th>
                <th className="px-3 py-2 font-medium">Default</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.name} data-contract-item={i.name} className="border-b border-bd/50">
                  <td className="px-3 py-1.5">
                    <Mono>{i.name}</Mono>
                    {i.description && <p className="text-xs text-muted">{i.description}</p>}
                  </td>
                  <td className="px-3 py-1.5 text-muted">{i.type}</td>
                  <td className="px-3 py-1.5 text-muted">{describeRequired(i.required)}</td>
                  <td className={cn("px-3 py-1.5", i.sensitive ? "text-tier-production" : "text-muted")}>
                    {i.sensitive ? "secret" : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    <Mono className="text-muted">{i.defaultValue ?? "—"}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {managed ? (
        <ManagedEditor
          org={org as string}
          project={project as string}
          items={items}
          onPublished={() => void qc.invalidateQueries({ queryKey: ["contract", org, project] })}
        />
      ) : (
        <p className="text-muted text-sm">
          This project's Contract lives in git. Edit <Mono>.env.schema</Mono> in the repository
          and push with <Mono>varlatch contract push</Mono>; the dashboard view is read-only by
          design.
        </p>
      )}

      <VarlockMapping org={org as string} project={project as string} />
    </div>
  );
}

function ManagedEditor({
  org,
  project,
  items,
  onPublished,
}: {
  org: string;
  project: string;
  items: Item[];
  onPublished: () => void;
}) {
  const { api } = useSession();
  const [draft, setDraft] = useState<Item[] | null>(null);
  const working = draft ?? items;
  const [name, setName] = useState("");
  const [type, setType] = useState("string");
  const [sensitive, setSensitive] = useState(false);
  const [requiredKind, setRequiredKind] = useState<"always" | "never">("always");
  const [defaultValue, setDefaultValue] = useState("");

  const publish = useMutation({
    mutationFn: async () => {
      const revision = (await api.pushContractRevision(org, project, {
        contract: { schemaVersion: 1, items: working },
      })) as ContractRevision;
      await api.activateContractRevision(org, project, revision.id);
    },
    onSuccess: () => {
      setDraft(null);
      onPublished();
    },
  });

  const addItem = () => {
    const item: Item = {
      name,
      type,
      sensitive,
      required: { kind: requiredKind },
      ...(defaultValue ? { defaultValue } : {}),
    };
    setDraft([...working.filter((i) => i.name !== name), item].sort((a, b) => (a.name < b.name ? -1 : 1)));
    setName("");
    setDefaultValue("");
  };

  return (
    <Card data-testid="managed-editor">
      <h2 className="font-medium mb-2">Edit contract</h2>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Input
          data-testid="contract-item-name"
          placeholder="NEW_ITEM"
          value={name}
          onChange={(e) => setName(e.target.value.toUpperCase())}
        />
        <Select
          value={type}
          onChange={(v) => setType(v)}
          options={Object.keys(TYPE_HELP).map((t) => ({ value: t, label: t }))}
        />
        <InfoTip text={`${type}: ${TYPE_HELP[type]}`} />
        <Select
          value={requiredKind}
          onChange={(v) => setRequiredKind(v as "always" | "never")}
          options={[
            {
              value: "always",
              label: "required",
              description: "Environments fail validation without this item.",
            },
            {
              value: "never",
              label: "optional",
              description: "May be omitted; validation still checks the type when present.",
            },
          ]}
        />
        <label className="text-sm flex items-center gap-1.5">
          <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} />
          secret
          <InfoTip text="Secret items are write-only in the UI and disclosed only via the audited retrieval path. Uncontracted items default to secret." />
        </label>
        <Input placeholder="default (optional)" value={defaultValue} onChange={(e) => setDefaultValue(e.target.value)} />
        <Button data-testid="contract-add-item" disabled={!/^[A-Z][A-Z0-9_]*$/.test(name)} onClick={addItem}>
          Add / replace item
        </Button>
      </div>
      {draft && (
        <div className="flex items-center gap-2 mb-1">
          <p className="text-sm text-muted flex-1">
            Draft has {draft.length} item(s); publishing creates and activates a new revision.
          </p>
          <Button variant="ghost" onClick={() => setDraft(null)}>Discard</Button>
          <Button data-testid="contract-publish" disabled={publish.isPending} onClick={() => publish.mutate()}>
            Publish revision
          </Button>
        </div>
      )}
      {draft && (
        <p className="text-xs text-muted font-mono" data-testid="contract-draft-names">
          {draft.map((i) => i.name).join(", ")}
        </p>
      )}
      {publish.error && <p className="text-deny text-sm">{String(publish.error)}</p>}
    </Card>
  );
}

function VarlockMapping({ org, project }: { org: string; project: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const mapping = useQuery({
    queryKey: ["varlock-mapping", org, project],
    queryFn: () => api.getVarlockMapping(org, project),
  });
  const envs = useQuery({
    queryKey: ["environments", org, project],
    queryFn: () => api.listEnvironments(org, project),
  });
  const [varlockName, setVarlockName] = useState("");
  const [envId, setEnvId] = useState("");
  const set = useMutation({
    mutationFn: () => api.setVarlockMapping(org, project, varlockName, envId),
    onSuccess: () => {
      setVarlockName("");
      void qc.invalidateQueries({ queryKey: ["varlock-mapping", org, project] });
    },
  });
  const envName = (id: string) =>
    (envs.data?.items as Environment[] | undefined)?.find((e) => e.id === id)?.name ?? id;

  return (
    <Card data-testid="varlock-mapping">
      <h2 className="font-medium mb-1">Varlock mapping</h2>
      <p className="text-muted text-sm mb-2">
        Maps varlock environment names used by tooling onto Varlatch Environments.
      </p>
      <div className="flex gap-2 items-center mb-2">
        <Input
          data-testid="varlock-name"
          placeholder="varlock env name"
          value={varlockName}
          onChange={(e) => setVarlockName(e.target.value)}
        />
        <span className="text-muted text-sm">→</span>
        <Select
          data-testid="varlock-env"
          value={envId}
          onChange={(v) => setEnvId(v)}
          options={[
            { value: "", label: "Choose environment…" },
            ...((envs.data?.items as Environment[] | undefined)?.map((e) => ({
              value: e.id,
              label: e.name,
            })) ?? []),
          ]}
        />
        <Button data-testid="varlock-set" disabled={!varlockName || !envId || set.isPending} onClick={() => set.mutate()}>
          Map
        </Button>
      </div>
      {set.error && <p className="text-deny text-sm mb-1">{String(set.error)}</p>}
      {mapping.data && Object.keys(mapping.data.mapping).length === 0 && (
        <p className="text-muted text-sm">No mappings yet.</p>
      )}
      {mapping.data &&
        Object.entries(mapping.data.mapping).map(([k, v]) => (
          <div key={k} data-varlock={k} className="flex gap-2 items-center border-t border-bd py-1.5 text-sm">
            <Mono>{k}</Mono>
            <span className="text-muted">→</span>
            <span>{envName(v)}</span>
          </div>
        ))}
    </Card>
  );
}
