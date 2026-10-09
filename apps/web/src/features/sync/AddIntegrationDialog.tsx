// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, Lock, Plus, ShieldAlert } from "lucide-react";
import type { PlatformConnection, SyncMappingInput, SyncPlatform } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Dialog } from "../../components/Dialog";
import { Button, Callout, Checkbox, Field, Input, Mono, Segmented, Select, cn } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { keys } from "../projects/hooks";
import { AccessCheckNotice } from "./AccessCheckNotice";
import { DestinationPicker } from "./DestinationPicker";
import { useBoundCheck } from "./useBoundCheck";
import { CredentialHint } from "./CredentialHint";
import { fixStep } from "./accessCheck";
import { platformMeta } from "./platform-meta";
import { hostOf } from "./status";
import { PlatformTile } from "./TargetCard";

/**
 * Add an integration in four steps: connection, destination, items, and a
 * review that says in plain words what leaves Varlatch and where. Creating
 * one is a standing, audited disclosure; nothing is on by default. The
 * review checks, read-only, that the credential reaches the destination,
 * so a wrong token or name shows up here rather than on the first push.
 */

const STEPS = ["Connection", "Destination", "Items", "Review"] as const;
const GITHUB_REPO = /^[A-Za-z0-9._-]{1,100}$/;
const COOLIFY_UUID = /^[A-Za-z0-9][A-Za-z0-9-]{2,63}$/;

type Item = { name: string; sensitive: boolean };

function excluded(patterns: string[], name: string): boolean {
  return patterns.some((p) => (p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p));
}

export function AddIntegrationDialog({
  open,
  onClose,
  onCreated,
  org,
  project,
  envName,
  adapters,
  connections,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
  org: string;
  project: string;
  envName: string;
  adapters: SyncPlatform[];
  connections: PlatformConnection[];
}) {
  const { api } = useSession();
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [connectionId, setConnectionId] = useState(connections.length === 0 ? "__new" : "");
  const [platform, setPlatform] = useState<SyncPlatform | null>(null);
  const [baseIdentity, setBaseIdentity] = useState("");
  const [connectionName, setConnectionName] = useState("");
  const [credential, setCredential] = useState("");
  const [repo, setRepo] = useState("");
  const [ghEnvironment, setGhEnvironment] = useState("");
  const [appUuid, setAppUuid] = useState("");
  // Coolify per-target options (adapter-owned, never part of the identity).
  const [buildTime, setBuildTime] = useState<"" | "true" | "false">("");
  const [deployAction, setDeployAction] = useState<"deploy" | "restart">("deploy");
  const [redeploy, setRedeploy] = useState(false);
  const [mappingMode, setMappingMode] = useState<"wildcard" | "explicit">("wildcard");
  const [excludeText, setExcludeText] = useState("");
  const [picked, setPicked] = useState<Record<string, { on: boolean; rename: string }>>({});
  const [removeOrphans, setRemoveOrphans] = useState(false);
  const [showAll, setShowAll] = useState(false);

  const isNew = connectionId === "__new";
  const selected = connections.find((c) => c.id === connectionId);
  const effectivePlatform: SyncPlatform | null = isNew ? platform : (selected?.platform ?? null);
  const meta = effectivePlatform ? platformMeta(effectivePlatform) : null;
  const owner = isNew ? baseIdentity.trim() : (selected?.baseIdentity ?? "");

  // Items of this environment (names and secrecy only), plus contract items
  // without a value yet: both can be mapped.
  const effective = useQuery({
    queryKey: keys.effectiveMeta(org, project, envName),
    queryFn: () => api.effectiveConfiguration(org, project, envName),
    enabled: open,
  });
  const contract = useQuery({
    queryKey: keys.contract(org, project),
    queryFn: () => api.getActiveContract(org, project),
    enabled: open,
    retry: false,
  });
  const items: Item[] = useMemo(() => {
    const map = new Map<string, Item>();
    for (const i of effective.data?.items ?? []) map.set(i.name, { name: i.name, sensitive: i.sensitive });
    const contractItems = ((contract.data?.contract as { items?: { name: string; sensitive: boolean }[] } | undefined)?.items ?? []);
    for (const i of contractItems) if (!map.has(i.name)) map.set(i.name, { name: i.name, sensitive: i.sensitive });
    return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [effective.data, contract.data]);
  const withValue = new Set((effective.data?.items ?? []).map((i) => i.name));

  const excludes = excludeText
    .split(/[\n,]/)
    .map((e) => e.trim())
    .filter(Boolean);
  const explicitItems = items
    .filter((i) => picked[i.name]?.on)
    .map((i) => ({ name: i.name, ...(picked[i.name]?.rename.trim() ? { rename: picked[i.name]!.rename.trim() } : {}) }));
  const mapping: SyncMappingInput =
    mappingMode === "wildcard"
      ? { kind: "wildcard", ...(excludes.length ? { exclude: excludes } : {}) }
      : { kind: "explicit", items: explicitItems };
  const pushed: Item[] =
    mappingMode === "wildcard"
      ? items.filter((i) => withValue.has(i.name) && !excluded(excludes, i.name))
      : items.filter((i) => picked[i.name]?.on);
  const secrets = pushed.filter((i) => i.sensitive).length;

  const destination =
    effectivePlatform === "github-actions"
      ? { repo: repo.trim(), ...(ghEnvironment.trim() ? { environment: ghEnvironment.trim() } : {}) }
      : effectivePlatform === "coolify"
        ? {
            applicationUuid: appUuid.trim(),
            ...(buildTime ? { buildTime } : {}),
            ...(redeploy && deployAction === "restart" ? { deployAction } : {}),
          }
        : // Convex: the connection's deployment is the destination.
          {};

  const repoError =
    repo.includes("/") ? "Enter the repository name only; the owner comes from the connection." : repo && !GITHUB_REPO.test(repo.trim()) ? "Letters, digits, dots, dashes and underscores only." : null;
  const appError = appUuid && !COOLIFY_UUID.test(appUuid.trim()) ? "That does not look like a Coolify application UUID." : null;

  const stepValid = [
    isNew ? Boolean(platform && baseIdentity.trim() && connectionName.trim() && credential) : Boolean(selected),
    effectivePlatform === "github-actions"
      ? Boolean(repo.trim()) && !repoError
      : effectivePlatform === "coolify"
        ? Boolean(appUuid.trim()) && !appError
        : effectivePlatform !== null,
    mappingMode === "wildcard" || explicitItems.length > 0,
    true,
  ];

  // The destinations the chosen connection can see, for the Destination
  // step's picker: listed on arrival, again when the connection changes, and
  // bound like the access check, so a slow listing for another connection
  // never fills this one's list.
  const listable = effectivePlatform === "github-actions" || effectivePlatform === "coolify";
  const listInput = isNew ? { platform: platform as SyncPlatform, baseIdentity: baseIdentity.trim(), credential } : { connectionId };
  const destinations = useBoundCheck(listInput, (checked) => api.listPlatformDestinations(org, checked));
  const listKey = JSON.stringify(listInput);
  const runListing = destinations.run;
  useEffect(() => {
    if (step === 1 && listable && !destinations.settled && !destinations.pending) runListing();
  }, [step, listable, listKey, destinations.settled, destinations.pending, runListing]);
  // Another connection, platform, or base identity is another account or
  // instance: a destination picked for the previous one does not carry over.
  const clearDestination = () => {
    setRepo("");
    setGhEnvironment("");
    setAppUuid("");
  };
  const chooseConnection = (id: string) => {
    if (id !== connectionId) clearDestination();
    setConnectionId(id);
  };

  const pickedAppName = destinations.result?.items.find((o) => o.destination.applicationUuid === appUuid.trim())?.label;
  const destLabel =
    effectivePlatform === "github-actions"
      ? `${owner ? `${owner}/` : ""}${repo.trim()}`
      : effectivePlatform === "coolify"
        ? pickedAppName
          ? `${pickedAppName} (${appUuid.trim()})`
          : appUuid.trim()
        : hostOf(owner);

  // Read-only, nothing saved: a new credential is checked as typed, an
  // existing connection with its stored one. The outcome is bound to these
  // inputs, and Create waits for it: an integration is never created while
  // its check is still out.
  const access = useBoundCheck(
    isNew
      ? { platform: platform as SyncPlatform, baseIdentity: baseIdentity.trim(), credential, destination }
      : { connectionId, destination },
    (checked) => api.checkPlatformAccess(org, checked),
  );
  const checkAccess = access.run;
  useEffect(() => {
    // Every arrival at the review checks again: earlier steps may have changed.
    if (step === STEPS.length - 1) checkAccess();
  }, [step, checkAccess]);
  const fix = access.result ? fixStep(access.result) : null;

  const accessFailed = Boolean((access.result && access.result.status !== "ok") || access.error);

  const create = useMutation({
    mutationFn: async () => {
      let cid = connectionId;
      if (isNew) {
        const created = await api.createPlatformConnection(org, {
          platform: platform as SyncPlatform,
          baseIdentity: baseIdentity.trim(),
          name: connectionName.trim(),
          credential,
        });
        cid = created.id;
        setConnectionId(created.id);
      }
      await api.createSyncTarget(org, project, envName, {
        connectionId: cid,
        destination,
        mapping,
        removeOrphans,
        // Convex has no redeploy; a toggle left from another platform must not travel.
        redeploy: effectivePlatform === "convex" ? false : redeploy,
      });
    },
    onSuccess: () => {
      toast.success("Integration created", { description: `The first push to ${destLabel} starts in a moment.` });
      onCreated();
    },
    onError: (err) => toast.error("Could not create the integration", { description: err instanceof Error ? err.message : String(err) }),
  });

  const next = () => {
    if (stepValid[step]) setStep((s) => Math.min(STEPS.length - 1, s + 1));
  };

  const stepSummary = [
    isNew
      ? platform
        ? `New ${platformMeta(platform).shortLabel} connection`
        : undefined
      : selected
        ? `${platformMeta(selected.platform).shortLabel} (${selected.name})`
        : undefined,
    stepValid[1] ? `${destLabel}${ghEnvironment.trim() && effectivePlatform === "github-actions" ? ` · ${ghEnvironment.trim()}` : ""}` : undefined,
    stepValid[2]
      ? mappingMode === "wildcard"
        ? excludes.length
          ? `All except ${excludes.join(", ")}`
          : "All items"
        : `${explicitItems.length} item${explicitItems.length === 1 ? "" : "s"}`
      : undefined,
  ];

  const shown = showAll ? pushed : pushed.slice(0, 6);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add integration"
      size="lg"
      data-testid="add-integration-dialog"
      className="max-w-[860px]"
    >
      <div className="-mx-6 -mb-2 -mt-4 flex min-h-[460px] border-t border-bd max-sm:flex-col">
        <ol className="w-56 shrink-0 space-y-1 border-r border-bd px-4 py-5 max-sm:w-full max-sm:border-b max-sm:border-r-0">
          {STEPS.map((label, i) => {
            const done = i < step;
            const current = i === step;
            const reachable = i <= step || stepValid.slice(0, i).every(Boolean);
            return (
              <li key={label} className="relative">
                {i < STEPS.length - 1 && (
                  <span aria-hidden="true" className="absolute left-[15px] top-9 h-[calc(100%-1.75rem)] w-px bg-bd max-sm:hidden" />
                )}
                <button
                  type="button"
                  disabled={!reachable}
                  onClick={() => setStep(i)}
                  data-testid={`wizard-step-${i + 1}`}
                  aria-current={current ? "step" : undefined}
                  className={cn(
                    "flex w-full cursor-pointer items-start gap-3 rounded-lg px-0 py-1.5 text-left disabled:cursor-not-allowed",
                  )}
                >
                  <span
                    className={cn(
                      "flex size-[31px] shrink-0 items-center justify-center rounded-full border text-[13px] font-semibold",
                      current ? "border-accent bg-accent text-accent-fg" : done ? "border-bd-strong text-fg" : "border-bd text-muted",
                    )}
                  >
                    {i + 1}
                  </span>
                  <span className="min-w-0 pt-1">
                    <span className={cn("flex items-center gap-1.5 text-sm font-medium", current || done ? "text-fg" : "text-muted")}>
                      {label}
                      {done && <Check size={14} className="text-accent" />}
                    </span>
                    {done && stepSummary[i] && <span className="mt-0.5 block truncate text-xs text-muted">{stepSummary[i]}</span>}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>

        <div className="flex min-w-0 flex-1 flex-col px-7 py-6">
          <div className="min-h-0 flex-1 space-y-5">
            {step === 0 && (
              <>
                <StepTitle title="Which account should Varlatch push with?" hint="A connection holds one platform credential. Several integrations can share it." />
                <div className="grid gap-2" role="radiogroup" aria-label="Connection">
                  {connections.map((c) => (
                    <ChoiceCard
                      key={c.id}
                      selected={connectionId === c.id}
                      onSelect={() => chooseConnection(c.id)}
                      testId={`connection-option-${c.id}`}
                      icon={<PlatformTile platform={c.platform} size="sm" />}
                      title={c.name}
                      subtitle={
                        <>
                          {platformMeta(c.platform).label} · <Mono>{c.baseIdentity}</Mono>
                        </>
                      }
                    />
                  ))}
                  <ChoiceCard
                    selected={isNew}
                    onSelect={() => chooseConnection("__new")}
                    testId="connection-option-new"
                    icon={
                      <span className="flex size-8 items-center justify-center rounded-lg border border-dashed border-bd-strong text-muted">
                        <Plus size={15} />
                      </span>
                    }
                    title="New connection"
                    subtitle="Add a platform credential now"
                  />
                </div>
                {isNew && (
                  <div className="space-y-4 rounded-xl border border-bd bg-inset/40 p-4">
                    <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Platform">
                      {adapters.map((a) => (
                        <button
                          key={a}
                          type="button"
                          role="radio"
                          aria-checked={platform === a}
                          data-testid={`platform-card-${a}`}
                          onClick={() => {
                            if (a !== platform) clearDestination();
                            setPlatform(a);
                          }}
                          className={cn(
                            "flex cursor-pointer items-center gap-2.5 rounded-lg border bg-raised px-3 py-2.5 text-left text-sm font-medium transition-colors",
                            platform === a ? "border-accent ring-2 ring-accent/20" : "border-bd hover:border-bd-strong",
                          )}
                        >
                          <PlatformTile platform={a} size="sm" />
                          {platformMeta(a).shortLabel}
                        </button>
                      ))}
                    </div>
                    {platform && meta && (
                      <div className="grid gap-4 sm:grid-cols-2">
                        <Field label={meta.identityLabel} hint={`Fixed once created: another ${meta.identityNoun} is another connection.`}>
                          <Input
                            data-testid="base-identity"
                            mono
                            className="w-full"
                            placeholder={meta.identityPlaceholder}
                            value={baseIdentity}
                            onChange={(e) => {
                              // Another account or instance: a destination picked for the
                              // previous one does not carry over.
                              if (e.target.value.trim().toLowerCase() !== baseIdentity.trim().toLowerCase()) clearDestination();
                              setBaseIdentity(e.target.value);
                            }}
                          />
                        </Field>
                        <Field label="Name" hint="How this connection shows up in Varlatch.">
                          <Input
                            data-testid="connection-name"
                            className="w-full"
                            placeholder={`${meta.shortLabel} production`}
                            value={connectionName}
                            onChange={(e) => setConnectionName(e.target.value)}
                          />
                        </Field>
                        <Field label={meta.credentialLabel} hint={<CredentialHint platform={platform} />} className="sm:col-span-2">
                          <Input
                            data-testid="connection-credential"
                            mono
                            type="password"
                            autoComplete="off"
                            className="w-full"
                            placeholder={meta.credentialPlaceholder}
                            value={credential}
                            onChange={(e) => setCredential(e.target.value)}
                          />
                        </Field>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}

            {step === 1 && meta && (
              <>
                <StepTitle title={`Where in ${meta.shortLabel}?`} hint={meta.description} />
                {effectivePlatform === "github-actions" && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Repository" error={repoError} hint={owner ? `In ${owner}.` : undefined}>
                      <Input
                        data-testid="dest-repo"
                        mono
                        className="w-full"
                        placeholder="api"
                        value={repo}
                        invalid={Boolean(repoError)}
                        onChange={(e) => setRepo(e.target.value)}
                      />
                    </Field>
                    <Field label="GitHub environment" hint="Optional. Empty writes repository secrets.">
                      <Input
                        data-testid="dest-gh-environment"
                        mono
                        className="w-full"
                        placeholder={envName}
                        value={ghEnvironment}
                        onChange={(e) => setGhEnvironment(e.target.value)}
                      />
                    </Field>
                  </div>
                )}
                {effectivePlatform === "github-actions" && (
                  <DestinationPicker
                    noun={{ one: "repository", many: "repositories" }}
                    value={repo}
                    valueOf={(o) => o.destination.repo ?? ""}
                    listing={destinations}
                    onPick={(o) => setRepo(o.destination.repo ?? "")}
                    onRetry={() => runListing()}
                  />
                )}
                {effectivePlatform === "coolify" && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Application UUID" error={appError} hint="Pick it below, or paste it from the application's URL in Coolify.">
                      <Input
                        data-testid="dest-app"
                        mono
                        className="w-full"
                        placeholder="k4s8w0c0o4kw"
                        value={appUuid}
                        invalid={Boolean(appError)}
                        onChange={(e) => setAppUuid(e.target.value)}
                      />
                    </Field>
                    <Field
                      label="Build time"
                      hint="Values baked into a build (VITE_*, NEXT_PUBLIC_*) need it. Build-time values end up in image layers."
                    >
                      <Select
                        data-testid="dest-build-time"
                        className="w-full"
                        value={buildTime}
                        onChange={(v) => setBuildTime(v as "" | "true" | "false")}
                        options={[
                          { value: "", label: "Coolify default" },
                          { value: "true", label: "Available at build time" },
                          { value: "false", label: "Runtime only" },
                        ]}
                      />
                    </Field>
                  </div>
                )}
                {effectivePlatform === "coolify" && (
                  <DestinationPicker
                    noun={{ one: "application", many: "applications" }}
                    value={appUuid}
                    valueOf={(o) => o.destination.applicationUuid ?? ""}
                    listing={destinations}
                    onPick={(o) => setAppUuid(o.destination.applicationUuid ?? "")}
                    onRetry={() => runListing()}
                  />
                )}
                {effectivePlatform === "convex" && (
                  <Callout tone="neutral" data-testid="dest-convex">
                    The connection's deployment <Mono className="text-fg">{hostOf(owner)}</Mono> is the destination. Nothing else to set.
                  </Callout>
                )}
                {effectivePlatform === "convex" ? (
                  <p className="text-[13px] text-muted">Convex functions pick up new values at once; there is no redeploy.</p>
                ) : (
                  <div className="space-y-3">
                    <Checkbox
                      data-testid="redeploy"
                      checked={redeploy}
                      onChange={setRedeploy}
                      label="Redeploy after changes"
                      description="Where the platform supports it. A failed redeploy shows on the integration; the values still land."
                    />
                    {effectivePlatform === "coolify" && redeploy && (
                      <Select
                        data-testid="dest-deploy-action"
                        className="ml-6.5 w-80"
                        value={deployAction}
                        onChange={(v) => setDeployAction(v as "deploy" | "restart")}
                        options={[
                          { value: "deploy", label: "Deploy", description: "Forced rebuild; re-bakes build-time values." },
                          { value: "restart", label: "Restart only", description: "Runtime values, no rebuild." },
                        ]}
                      />
                    )}
                  </div>
                )}
              </>
            )}

            {step === 2 && (
              <>
                <StepTitle title="Which items?" hint="Choose everything, with exceptions, or an explicit list. Secrets are included only when you say so." />
                <Segmented
                  aria-label="Items to push"
                  value={mappingMode}
                  onChange={setMappingMode}
                  options={[
                    { value: "wildcard", label: "All items", "data-testid": "mapping-mode-wildcard" },
                    { value: "explicit", label: "Explicit list", "data-testid": "mapping-mode-explicit" },
                  ]}
                />
                {mappingMode === "wildcard" ? (
                  <div className="space-y-3">
                    <p className="text-[13px] text-muted">Every current item with a value, and every item added later, except:</p>
                    <Input
                      data-testid="mapping-exclude"
                      mono
                      className="w-full"
                      placeholder="CONVEX_*, INTERNAL_KEY"
                      value={excludeText}
                      onChange={(e) => setExcludeText(e.target.value)}
                    />
                    <p className="text-xs text-muted">Exact names or prefixes ending in *, separated by commas.</p>
                    {excludes.length > 0 && (
                      <p className="text-xs text-muted">
                        Excluded now:{" "}
                        {items.filter((i) => excluded(excludes, i.name)).map((i) => i.name).join(", ") || "nothing yet"}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="max-h-72 overflow-y-auto rounded-xl border border-bd" data-testid="mapping-items">
                    {items.length === 0 && <p className="p-4 text-[13px] text-muted">This environment has no items yet.</p>}
                    {items.map((i) => {
                      const p = picked[i.name] ?? { on: false, rename: "" };
                      return (
                        <div key={i.name} className="flex items-center gap-3 border-b border-bd px-3 py-2 last:border-b-0">
                          <input
                            type="checkbox"
                            data-testid={`mapping-item-${i.name}`}
                            aria-label={`Push ${i.name}`}
                            checked={p.on}
                            onChange={(e) => setPicked({ ...picked, [i.name]: { ...p, on: e.target.checked } })}
                            className="size-4 cursor-pointer accent-[var(--accent)]"
                          />
                          <span className="flex min-w-0 flex-1 items-center gap-1.5">
                            {i.sensitive && <Lock size={12} className="shrink-0 text-tier-production" aria-label="secret" />}
                            <Mono className="truncate">{i.name}</Mono>
                            {!withValue.has(i.name) && <span className="text-xs text-subtle">no value yet</span>}
                          </span>
                          {p.on && (
                            <Input
                              mono
                              aria-label={`Destination name for ${i.name}`}
                              className="h-7 w-44 text-xs"
                              placeholder="same name"
                              value={p.rename}
                              onChange={(e) => setPicked({ ...picked, [i.name]: { ...p, rename: e.target.value.toUpperCase() } })}
                            />
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}

            {step === 3 && meta && (
              <div data-testid="integration-review" className="space-y-4">
                <h3 className="text-lg font-semibold">Review what leaves Varlatch</h3>
                <p className="text-[15px] leading-relaxed text-fg/90">
                  Push {pushed.length} value{pushed.length === 1 ? "" : "s"}
                  {secrets > 0 && ` (${secrets} secret${secrets === 1 ? "" : "s"})`} from <Chip>{project}</Chip> / <Chip>{envName}</Chip> to{" "}
                  {meta.label} <Chip>{destLabel}</Chip>
                  {effectivePlatform === "github-actions" && ghEnvironment.trim() && (
                    <>
                      , environment <Chip>{ghEnvironment.trim()}</Chip>
                    </>
                  )}
                  {mappingMode === "wildcard" ? ", and every item added later." : "."}
                </p>
                <AccessCheckNotice
                  pending={!access.settled}
                  check={access.result}
                  error={access.error}
                  actions={
                    accessFailed ? (
                      <>
                        {fix !== null && (
                          <Button size="sm" variant="secondary" data-testid="access-fix" onClick={() => setStep(fix)}>
                            {fix === 0 ? "Change connection" : "Change destination"}
                          </Button>
                        )}
                        {/* A token's permissions can change on the platform without a new token. */}
                        <Button size="sm" variant="ghost" data-testid="access-retry" onClick={() => checkAccess()}>
                          Check again
                        </Button>
                      </>
                    ) : undefined
                  }
                />
                {pushed.length > 0 && (
                  <div className="rounded-xl border border-bd bg-inset/40 px-3 py-2">
                    <ul className="divide-y divide-bd">
                      {shown.map((i) => (
                        <li key={i.name} className="flex items-center gap-2.5 py-1.5">
                          <span className="flex w-4 justify-center">
                            {i.sensitive && <Lock size={13} className="text-tier-production" aria-label="secret" />}
                          </span>
                          <Mono>{i.name}</Mono>
                          {mappingMode === "explicit" && picked[i.name]?.rename.trim() && (
                            <span className="text-xs text-muted">
                              as <Mono>{picked[i.name]!.rename.trim()}</Mono>
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                    {pushed.length > 6 && (
                      <button type="button" className="cursor-pointer py-1.5 pl-6.5 text-xs text-muted hover:text-fg" onClick={() => setShowAll((v) => !v)}>
                        {showAll ? "Show fewer" : `+ ${pushed.length - 6} more`}
                      </button>
                    )}
                  </div>
                )}
                <Callout tone="warn" icon={<ShieldAlert size={16} />}>
                  Once pushed, a value's protection is {meta.shortLabel}'s. Revoking this integration stops future pushes; it does not delete
                  values already there. Every push is audited before values leave.
                </Callout>
                <Checkbox
                  data-testid="remove-orphans"
                  checked={removeOrphans}
                  onChange={setRemoveOrphans}
                  label="Remove destination names that leave this environment"
                />
              </div>
            )}
          </div>

          <div className="mt-6 flex items-center justify-end gap-2">
            {step > 0 && (
              <Button variant="secondary" data-testid="wizard-back" onClick={() => setStep((s) => s - 1)}>
                Back
              </Button>
            )}
            {step < STEPS.length - 1 ? (
              <Button variant="primary" data-testid="wizard-next" disabled={!stepValid[step]} onClick={next}>
                Continue
              </Button>
            ) : (
              <Button
                variant="primary"
                data-testid="confirm-integration"
                disabled={!access.settled}
                loading={create.isPending}
                onClick={() => create.mutate()}
              >
                {accessFailed ? "Create anyway" : "Create integration"}
              </Button>
            )}
          </div>
        </div>
      </div>
    </Dialog>
  );
}

function StepTitle({ title, hint }: { title: string; hint?: string }) {
  return (
    <div>
      <h3 className="text-lg font-semibold">{title}</h3>
      {hint && <p className="mt-1 text-[13px] text-muted">{hint}</p>}
    </div>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return <span className="whitespace-nowrap rounded-md border border-bd bg-inset px-1.5 py-0.5 font-mono text-[13px] text-fg">{children}</span>;
}

function ChoiceCard({
  selected,
  onSelect,
  icon,
  title,
  subtitle,
  testId,
}: {
  selected: boolean;
  onSelect: () => void;
  icon: React.ReactNode;
  title: React.ReactNode;
  subtitle: React.ReactNode;
  testId?: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      data-testid={testId}
      onClick={onSelect}
      className={cn(
        "flex w-full cursor-pointer items-center gap-3 rounded-lg border bg-raised px-3 py-2.5 text-left transition-colors",
        selected ? "border-accent ring-2 ring-accent/20" : "border-bd hover:border-bd-strong",
      )}
    >
      {icon}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-fg">{title}</span>
        <span className="block truncate text-xs text-muted">{subtitle}</span>
      </span>
      <span className={cn("flex size-4 shrink-0 items-center justify-center rounded-full border", selected ? "border-accent bg-accent" : "border-bd-strong")}>
        {selected && <span className="size-1.5 rounded-full bg-accent-fg" />}
      </span>
    </button>
  );
}
