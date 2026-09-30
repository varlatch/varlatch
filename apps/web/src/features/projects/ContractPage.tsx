// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ContractRevision } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, InfoTip, Input, Mono, Select, cn } from "../../components/ui";
import {
  canMoveRules,
  movedContract,
  moveConsequences,
  newestSemanticsVersion,
  reviewMove,
  revisionSemanticsVersion,
  semanticsSteps,
  typeOffer,
} from "./semanticsMove";

/** Hover help for the item-type dropdown: `title` on each option plus an
    InfoTip echoing the selected type's meaning. */
const TYPE_HELP: Record<string, string> = {
  string: "Any text value; no validation beyond presence.",
  number: "A number written in digits, e.g. -12 or 3.5 (no exponent, no leading +). From semantics version 2, at most 2^53 - 1 in magnitude.",
  integer: "A whole number written in digits, e.g. -12 or 3000: an optional minus sign and digits only (no decimal point, exponent, or leading +), at most 2^53 - 1 in magnitude. Needs semantics version 3.",
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
 * revision.
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
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.meta() });

  const managed = projectQuery.data?.contractAuthority === "managed";
  const items = ((contract.data?.contract as { items?: Item[] } | undefined)?.items ?? []) as Item[];
  const newest = newestSemanticsVersion(meta.data?.semanticsVersions);
  const activeVersion = contract.data ? revisionSemanticsVersion(contract.data) : undefined;
  // Edits keep the active revision's version; a project's first revision
  // gets the newest one.
  const editorVersion = contract.data ? activeVersion : contract.isError && meta.data ? newest : undefined;
  const refresh = () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["contract", org, project] }),
      qc.invalidateQueries({ queryKey: ["project", org, project] }),
    ]);

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
            ? "Managed authority: edit and publish the contract right here. Varlatch is the source of truth."
            : (
              <>
                Git authority: the schema lives in your repository as <Mono>.env.schema</Mono> and
                is pushed with <Mono>varlatch contract push</Mono>. The repository is the source of
                truth, so this view is read-only, except for moving to the newest rules.
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
            <span className="flex items-center gap-1">
              Active revision <Mono>{contract.data.id}</Mono>
              <span className="ml-2" data-testid="semantics-version">
                Semantics version {activeVersion}
              </span>
              <InfoTip text="The validation rules this revision is evaluated with. Edits keep the version. To change it, move to the newest rules here or push with --semantics latest." />
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

      {contract.data && projectQuery.data && activeVersion !== undefined && canMoveRules(activeVersion, newest) && (
        <MoveRules
          org={org as string}
          project={project as string}
          active={contract.data}
          newest={newest}
          authority={projectQuery.data.contractAuthority}
          onActivated={refresh}
        />
      )}

      {managed ? (
        <ManagedEditor
          org={org as string}
          project={project as string}
          items={items}
          version={editorVersion}
          newest={newest}
          onPublished={refresh}
        />
      ) : (
        <p className="text-muted text-sm">
          This project's Contract lives in git. Edit <Mono>.env.schema</Mono> in the repository
          and push with <Mono>varlatch contract push</Mono>; the dashboard view is read-only by
          design.
        </p>
      )}
    </div>
  );
}

function ManagedEditor({
  org,
  project,
  items,
  version,
  newest,
  onPublished,
}: {
  org: string;
  project: string;
  items: Item[];
  /** The version a published revision gets: edits keep the active one's. */
  version: number | undefined;
  newest: number;
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
  const typeOptions = Object.keys(TYPE_HELP).map((t) => {
    const offer = typeOffer(t, version, newest);
    return offer.enabled
      ? { value: t, label: t }
      : { value: t, label: t, disabled: true, description: offer.reason };
  });
  const integerOffer = typeOffer("integer", version, newest);

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
          data-testid="contract-item-type"
          value={type}
          onChange={(v) => setType(v)}
          options={typeOptions}
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
        <Button
          data-testid="contract-add-item"
          disabled={!/^[A-Z][A-Z0-9_]*$/.test(name) || !typeOffer(type, version, newest).enabled}
          onClick={addItem}
        >
          Add / replace item
        </Button>
      </div>
      {!integerOffer.enabled && version !== undefined && (
        <p className="text-xs text-muted mb-2" data-testid="integer-unavailable">
          integer: {integerOffer.reason}
        </p>
      )}
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

/** Plain text with `backticked` commands rendered as code. */
function WithCode({ text }: { text: string }) {
  return (
    <>
      {text.split("`").map((part, i) => (i % 2 === 1 ? <Mono key={i}>{part}</Mono> : part))}
    </>
  );
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Move to the newest rules: push the active Contract unchanged except for
 * its semantics version, review what the server stored, and activate only on
 * an explicit confirmation. Available for git and managed projects alike.
 */
function MoveRules({
  org,
  project,
  active,
  newest,
  authority,
  onActivated,
}: {
  org: string;
  project: string;
  active: ContractRevision;
  newest: number;
  authority: "git" | "managed";
  /** Resolves once the page shows the newly active revision. */
  onActivated: () => Promise<unknown>;
}) {
  const { api } = useSession();
  const [review, setReview] = useState<{ base: ContractRevision; pushed: ContractRevision } | null>(null);
  const [cancelled, setCancelled] = useState<string | null>(null);
  const from = revisionSemanticsVersion(active);

  const push = useMutation({
    mutationFn: () =>
      api.pushContractRevision(org, project, { contract: movedContract(active.contract, newest) }),
    onSuccess: (pushed) => {
      setCancelled(null);
      setReview({ base: active, pushed });
    },
  });
  const activate = useMutation({
    mutationFn: async (revisionId: string) => {
      await api.activateContractRevision(org, project, revisionId);
      await onActivated();
    },
    onSuccess: () => setReview(null),
  });

  const result = review ? reviewMove(review.base, review.pushed, newest) : null;
  const stale = review !== null && review.base.id !== active.id;

  return (
    <Card className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm flex-1">
          This Contract uses semantics version {from}. Version {newest} is the newest this server
          supports; moving changes the version and nothing else.
        </p>
        {!review && (
          <Button data-testid="move-rules" disabled={push.isPending} onClick={() => push.mutate()}>
            Move to the newest rules (version {newest})
          </Button>
        )}
      </div>
      {push.error && <p className="text-deny text-sm">Could not push the revision: {errorText(push.error)}</p>}
      {cancelled && (
        <p className="text-xs text-muted">
          Cancelled. Revision <Mono>{cancelled}</Mono> stays stored but inactive; nothing changed.
        </p>
      )}

      {review && result && (
        <div className="border-t border-bd pt-2 space-y-2 text-sm" data-testid="move-rules-review">
          <p>
            Pushed revision <Mono>{review.pushed.id}</Mono>. It is not active yet.
          </p>
          <div>
            <h3 className="font-medium">Changes</h3>
            <ul className="list-disc pl-5" data-testid="move-rules-diff">
              {result.versionChange && (
                <li>
                  Semantics version {result.versionChange.from} → {result.versionChange.to}
                </li>
              )}
              {result.otherChanges.map((c) => (
                <li key={c} className="text-deny">{c}</li>
              ))}
            </ul>
          </div>
          {!result.activatable && (
            <p className="text-deny" data-testid="move-rules-refused">
              The stored revision differs from the active Contract in more than the semantics
              version, so it cannot be activated from here.
            </p>
          )}
          <div>
            <h3 className="font-medium">What the newer rules change</h3>
            <ul className="list-disc pl-5">
              {semanticsSteps(from, newest).map((s) => (
                <li key={s.version}>
                  Version {s.version}: {s.change}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="font-medium">After activation</h3>
            <ul className="list-disc pl-5">
              {moveConsequences(from, newest, authority).map((c) => (
                <li key={c}>
                  <WithCode text={c} />
                </li>
              ))}
            </ul>
          </div>
          {stale && (
            <p className="text-deny">The active revision changed since this review. Cancel and start again.</p>
          )}
          <div className="flex items-center gap-2">
            <p className="text-xs text-muted flex-1">
              Nothing changes until you activate. Cancel leaves the pushed revision stored but
              inactive.
            </p>
            <Button
              variant="ghost"
              onClick={() => {
                setCancelled(review.pushed.id);
                setReview(null);
                activate.reset();
              }}
            >
              Cancel
            </Button>
            <Button
              data-testid="move-rules-activate"
              disabled={!result.activatable || stale || activate.isPending}
              onClick={() => activate.mutate(review.pushed.id)}
            >
              Activate version {newest} rules
            </Button>
          </div>
          {activate.error && (
            <p className="text-deny">Could not activate the revision: {errorText(activate.error)}</p>
          )}
        </div>
      )}
    </Card>
  );
}
