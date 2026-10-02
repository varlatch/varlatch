// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FileCode2, GitBranch, Lock } from "lucide-react";
import type { ContractRevision, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { InlineCommand } from "../../components/CodeBlock";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { EmptyState, Mono, Skeleton, TierDot, cn, table } from "../../components/ui";
import { keys, useMeta, useProjectContext } from "./hooks";
import { ContractRevisions } from "./ContractRevisions";
import { RulesCard } from "./MoveRules";
import { ManagedContractEditor } from "./ManagedContractEditor";
import type { ContractItem, Requiredness } from "./contractDraft";
import { newestSemanticsVersion, revisionSemanticsVersion } from "./semanticsMove";

/**
 * Contract tab. Who writes the contract depends on the project's authority:
 * git projects read it here and push it from the repository; managed
 * projects edit it here as a draft and publish a revision. Both can move to
 * the newest validation rules.
 */
export function ContractPage() {
  const { org, project } = useProjectContext();
  const { api } = useSession();
  const qc = useQueryClient();
  const contract = useQuery({
    queryKey: keys.contract(org, project.slug),
    queryFn: () => api.getActiveContract(org, project.slug),
    retry: false,
  });
  const meta = useMeta();
  const newest = newestSemanticsVersion(meta.data?.semanticsVersions);
  const managed = project.contractAuthority === "managed";
  const active = contract.data;
  const items = ((active?.contract as { items?: ContractItem[] } | undefined)?.items ?? []) as ContractItem[];

  const refresh = () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: keys.contract(org, project.slug) }),
      qc.invalidateQueries({ queryKey: keys.projects(org) }),
      qc.invalidateQueries({ queryKey: ["audit", org] }),
    ]);

  if (contract.isLoading || (managed && !meta.data)) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-14 w-full rounded-xl" />
        <Skeleton className="h-72 w-full rounded-xl" />
      </div>
    );
  }

  const side = active && (
    <>
      <ContractRevisions org={org} projectId={project.id} active={active} />
      <RulesCard
        org={org}
        project={project.slug}
        active={active}
        newest={newest}
        authority={project.contractAuthority}
        onActivated={refresh}
      />
    </>
  );

  if (managed) {
    // Edits keep the active revision's version; a first revision gets the newest.
    const version = active ? revisionSemanticsVersion(active) : contract.isError && meta.data ? newest : undefined;
    return (
      <div className="space-y-4 pb-24">
        <ManagedContractEditor
          org={org}
          project={project.slug}
          active={active}
          items={items}
          version={version}
          newest={newest}
          onPublished={refresh}
        />
        {side && <div className="grid items-start gap-4 lg:grid-cols-2">{side}</div>}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <GitBanner active={active} />
      {!active ? (
        <div className="rounded-xl border border-dashed border-bd">
          <EmptyState
            icon={<FileCode2 size={20} />}
            title="No contract yet"
            description="Describe the items this project needs in your repository's schema file, then push it."
            actions={<InlineCommand command="varlatch contract push" />}
          />
        </div>
      ) : (
        <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
          <ContractTable items={items} />
          <div className="space-y-4">{side}</div>
        </div>
      )}
    </div>
  );
}

function GitBanner({ active }: { active: ContractRevision | undefined }) {
  const schemaPath = (active?.provenance as { schemaPath?: string } | undefined)?.schemaPath ?? ".env.schema";
  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-info/25 bg-info/[0.05] px-4 py-3 text-sm"
      data-testid="contract-authority"
      data-authority="git"
    >
      <GitBranch size={17} className="shrink-0 text-info" />
      <span className="text-fg/90">
        This contract lives in your repository as <Mono className="text-fg">{schemaPath}</Mono>. Edit it there and push:
      </span>
      <InlineCommand command="varlatch contract push" />
    </div>
  );
}

export function RequiredText({ required }: { required: Requiredness }) {
  if (required.kind === "always") return <span className="text-fg/90">always</span>;
  if (required.kind === "never") return <span className="text-muted">optional</span>;
  if (required.selector.kind === "tier") {
    return (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-bd bg-inset px-2 py-0.5 text-xs text-fg">
        <TierDot tier={required.selector.tier as Tier} />
        {required.selector.tier} only
      </span>
    );
  }
  return <span className="text-fg/90">selected environments</span>;
}

/** Read-only contract (git authority): filterable, one row per item. */
function ContractTable({ items }: { items: ContractItem[] }) {
  const [filter, setFilter] = useState("");
  const shown = useMemo(
    () => items.filter((i) => matchesFilter(filter, i.name, i.description, i.type, ...(i.enumValues ?? []))),
    [items, filter],
  );
  return (
    <section className="overflow-hidden rounded-xl border border-bd bg-raised">
      <header className="flex flex-wrap items-center gap-3 border-b border-bd px-5 py-3">
        <h2 className="text-[15px] font-semibold">
          Contract <span className="font-normal text-muted">· {items.length} item{items.length === 1 ? "" : "s"}</span>
        </h2>
        <FilterInput
          value={filter}
          onChange={setFilter}
          placeholder="Filter items…"
          className="ml-auto w-full max-w-xs"
          aria-label="Filter contract items"
          {...(filter ? { shown: shown.length, total: items.length } : {})}
        />
      </header>
      <div className={table.wrap}>
        <table className={table.table} data-testid="contract-items">
          <thead>
            <tr>
              <th className={table.th}>Item</th>
              <th className={table.th}>Type</th>
              <th className={table.th}>Required</th>
              <th className={cn(table.th, "text-center")}>Secret</th>
              <th className={table.th}>Default</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((i) => (
              <tr key={i.name} data-contract-item={i.name} className={cn(table.tr, table.trHover)}>
                <td className="px-4 py-2.5 align-top">
                  <p className="font-mono text-[13px] font-medium text-fg">
                    <Highlight text={i.name} needle={filter} />
                  </p>
                  {i.description && <p className="mt-0.5 text-[13px] text-muted">{i.description}</p>}
                  {i.type === "enum" && (i.enumValues ?? []).length > 0 && (
                    <p className="mt-1.5 flex flex-wrap gap-1">
                      {i.enumValues!.map((v) => (
                        <span key={v} className="rounded border border-bd bg-inset px-1.5 py-px font-mono text-[11px] text-muted">
                          {v}
                        </span>
                      ))}
                    </p>
                  )}
                </td>
                <td className="px-4 py-2.5 align-top">
                  <span className="inline-block rounded-md border border-bd bg-inset px-1.5 py-0.5 font-mono text-xs text-fg">{i.type}</span>
                </td>
                <td className="px-4 py-2.5 align-top text-[13px]">
                  <RequiredText required={i.required} />
                </td>
                <td className="px-4 py-2.5 text-center align-top">
                  {i.sensitive ? (
                    <Lock size={15} className="inline text-fg/80" aria-label="secret" />
                  ) : (
                    <span className="text-subtle" aria-label="not secret">
                      –
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 align-top">
                  {i.defaultValue !== undefined ? (
                    <span className="inline-block max-w-40 truncate rounded-md border border-bd bg-inset px-1.5 py-0.5 font-mono text-xs text-fg">
                      {i.defaultValue}
                    </span>
                  ) : (
                    <span className="text-subtle">–</span>
                  )}
                </td>
              </tr>
            ))}
            {shown.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-[13px] text-muted">
                  No item matches <Mono className="text-fg">{filter}</Mono>.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
