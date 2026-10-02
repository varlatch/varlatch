// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { GitBranch, Pencil, Plus, X } from "lucide-react";
import type { Project, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Field, IconButton, Input, Select, TierDot, cn } from "../../components/ui";
import { errorMessage, slugify } from "../../shell/Shell";
import { keys } from "./hooks";

const TIERS: Tier[] = ["development", "staging", "production"];
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const ENV_NAME = /^[a-z0-9][a-z0-9._-]{0,62}$/;

type CustomEnv = { key: number; name: string; tier: Tier };
let customKey = 1;

/**
 * New project: name (the slug follows it until edited), where the contract
 * lives, and the environments to create with it. Creates the project, then
 * each environment in order; a failure part-way keeps the dialog open and
 * a second submit creates only what is still missing.
 */
export function NewProjectDialog({
  org,
  open,
  onClose,
  onCreated,
}: {
  org: string;
  open: boolean;
  onClose: () => void;
  /** Called after everything was created; defaults to opening the project. */
  onCreated?: ((project: Project) => void) | undefined;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [authority, setAuthority] = useState<"git" | "managed">("git");
  const [standard, setStandard] = useState<Record<Tier, boolean>>({ development: true, staging: true, production: true });
  const [custom, setCustom] = useState<CustomEnv[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<React.ReactNode>(null);
  // After a partial failure: the project and environments already created.
  const [created, setCreated] = useState<{ project: Project; envs: string[] } | null>(null);

  useEffect(() => {
    if (open) return;
    setName("");
    setSlug("");
    setSlugTouched(false);
    setAuthority("git");
    setStandard({ development: true, staging: true, production: true });
    setCustom([]);
    setError(null);
    setCreated(null);
  }, [open]);

  const effectiveSlug = slugTouched ? slug : slugify(name);
  const slugError = effectiveSlug && !SLUG.test(effectiveSlug)
    ? "Lowercase letters, digits and dashes, starting with a letter or digit."
    : null;
  const envs: { name: string; tier: Tier }[] = [
    ...TIERS.filter((t) => standard[t]).map((t) => ({ name: t, tier: t })),
    ...custom.filter((c) => c.name.trim()).map((c) => ({ name: c.name.trim(), tier: c.tier })),
  ];
  const envNameError = (c: CustomEnv): string | null => {
    const n = c.name.trim();
    if (!n) return null;
    if (!ENV_NAME.test(n)) return "Lowercase letters, digits, dots, dashes and underscores.";
    if (envs.filter((e) => e.name === n).length > 1) return "Already in the list.";
    return null;
  };
  const invalid = !effectiveSlug || !!slugError || custom.some((c) => envNameError(c) !== null);

  const submit = async () => {
    if (invalid || busy) return;
    setBusy(true);
    setError(null);
    let project = created?.project ?? null;
    const done = new Set(created?.envs ?? []);
    try {
      if (!project) {
        project = await api.createProject(org, {
          slug: effectiveSlug,
          name: name.trim() || effectiveSlug,
          contractAuthority: authority,
        });
        setCreated({ project, envs: [] });
        await qc.invalidateQueries({ queryKey: keys.projects(org) });
      }
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
      return;
    }
    for (const env of envs) {
      if (done.has(env.name)) continue;
      try {
        await api.createEnvironment(org, project.slug, { name: env.name, tier: env.tier });
        done.add(env.name);
        setCreated({ project, envs: [...done] });
      } catch (err) {
        await qc.invalidateQueries({ queryKey: keys.environments(org, project.slug) });
        setError(
          <>
            Created <span className="font-mono">{project.slug}</span>, but <span className="font-mono">{env.name}</span>{" "}
            could not be created: {errorMessage(err)}. Create again to retry the missing environments.
          </>,
        );
        setBusy(false);
        return;
      }
    }
    await qc.invalidateQueries({ queryKey: keys.environments(org, project.slug) });
    setBusy(false);
    toast.success(<>Created <span className="font-mono">{project.slug}</span></>, {
      description: done.size > 0 ? `With ${[...done].join(", ")}.` : "Add environments when you need them.",
    });
    onClose();
    if (onCreated) onCreated(project);
    else navigate(`/o/${org}/p/${project.slug}`);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      dismissable={!busy}
      title="New project"
      data-testid="new-project-dialog"
      footer={
        <>
          <p className="mr-auto text-[13px] text-muted">You can change environments later.</p>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="create-project" loading={busy} disabled={invalid} onClick={() => void submit()}>
            {created ? "Create again" : "Create project"}
            <span aria-hidden="true" className="ml-0.5 rounded border border-current/25 px-1 font-mono text-[11px] leading-4 opacity-70">
              ↵
            </span>
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Name" htmlFor="new-project-name">
          <Input
            id="new-project-name"
            data-autofocus
            data-testid="new-project-name"
            className="w-full"
            value={name}
            placeholder="Payments service"
            disabled={!!created}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field
          label="Slug"
          htmlFor="new-project-slug"
          error={slugError}
          hint={slugTouched ? "Used in URLs and the CLI. It cannot be changed later." : "Used in URLs and the CLI · filled in from the name"}
        >
          <Input
            id="new-project-slug"
            data-testid="new-project-slug"
            mono
            className="w-full"
            value={effectiveSlug}
            placeholder="payments-service"
            invalid={!!slugError}
            disabled={!!created}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value.toLowerCase());
            }}
          />
        </Field>

        <fieldset disabled={!!created}>
          <legend className="mb-2 text-[13px] font-medium text-fg">Where does the contract live?</legend>
          <div role="radiogroup" aria-label="Contract location" className="grid gap-3 sm:grid-cols-2">
            <AuthorityCard
              selected={authority === "git"}
              onSelect={() => setAuthority("git")}
              icon={<GitBranch size={18} />}
              title="In git"
              testId="contract-authority-git"
            >
              Schema in your repo as <span className="font-mono text-[12px]">.env.schema</span>, pushed with the CLI.
              Reviewed with your code.
            </AuthorityCard>
            <AuthorityCard
              selected={authority === "managed"}
              onSelect={() => setAuthority("managed")}
              icon={<Pencil size={17} />}
              title="In Varlatch"
              testId="contract-authority-managed"
            >
              Edit and publish the contract here. Good for apps without a repo.
            </AuthorityCard>
          </div>
        </fieldset>

        <fieldset>
          <legend className="mb-2 text-[13px] font-medium text-fg">Environments</legend>
          <div className="flex flex-wrap gap-2">
            {TIERS.map((t) => (
              <EnvToggle
                key={t}
                tier={t}
                on={standard[t]}
                onToggle={() => setStandard((s) => ({ ...s, [t]: !s[t] }))}
              />
            ))}
            <button
              type="button"
              data-testid="new-project-add-custom"
              onClick={() => setCustom((c) => [...c, { key: customKey++, name: "", tier: "development" }])}
              className="inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border border-dashed border-bd-strong px-2.5 text-[13px] text-muted transition-colors hover:border-accent/60 hover:text-fg"
            >
              <Plus size={14} />
              Custom
            </button>
          </div>
          {custom.length > 0 && (
            <ul className="mt-3 space-y-2">
              {custom.map((c, i) => {
                const err = envNameError(c);
                return (
                  <li key={c.key}>
                    <div className="flex items-center gap-2">
                      <Input
                        mono
                        aria-label={`Custom environment ${i + 1} name`}
                        data-testid="new-project-custom-name"
                        className="min-w-0 flex-1"
                        placeholder="qa"
                        value={c.name}
                        invalid={!!err}
                        autoFocus
                        onChange={(e) =>
                          setCustom((all) => all.map((x) => (x.key === c.key ? { ...x, name: e.target.value.toLowerCase() } : x)))
                        }
                      />
                      <Select
                        aria-label={`Custom environment ${i + 1} tier`}
                        className="w-40"
                        value={c.tier}
                        onChange={(v) => setCustom((all) => all.map((x) => (x.key === c.key ? { ...x, tier: v as Tier } : x)))}
                        options={TIERS.map((t) => ({ value: t, label: t, icon: <TierDot tier={t} /> }))}
                      />
                      <IconButton
                        label="Remove this environment"
                        onClick={() => setCustom((all) => all.filter((x) => x.key !== c.key))}
                      >
                        <X size={15} />
                      </IconButton>
                    </div>
                    {err && <p className="mt-1 text-xs text-deny">{err}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </fieldset>

        {error && (
          <p role="alert" className="rounded-lg border border-deny/40 bg-deny/[0.07] px-3 py-2 text-[13px] text-fg" data-testid="new-project-error">
            {error}
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function AuthorityCard({
  selected,
  onSelect,
  icon,
  title,
  children,
  testId,
}: {
  selected: boolean;
  onSelect: () => void;
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  testId: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      data-testid={testId}
      onClick={onSelect}
      className={cn(
        "relative flex cursor-pointer flex-col items-start rounded-xl border p-4 text-left transition-colors disabled:cursor-not-allowed",
        selected ? "border-accent bg-accent/[0.06] ring-1 ring-accent/40" : "border-bd bg-inset/40 hover:border-bd-strong hover:bg-hover/50",
      )}
    >
      <span className={cn("mb-2.5", selected ? "text-accent" : "text-muted")}>{icon}</span>
      <span className="text-[14px] font-semibold text-fg">{title}</span>
      <span className="mt-1 text-[13px] leading-relaxed text-muted">{children}</span>
      <span
        aria-hidden="true"
        className={cn(
          "absolute right-3.5 top-3.5 flex size-4 items-center justify-center rounded-full border",
          selected ? "border-accent" : "border-bd-strong",
        )}
      >
        {selected && <span className="size-2 rounded-full bg-accent" />}
      </span>
    </button>
  );
}

const KNOB: Record<Tier, string> = {
  development: "bg-tier-development",
  staging: "bg-tier-staging",
  production: "bg-tier-production",
};

function EnvToggle({ tier, on, onToggle }: { tier: Tier; on: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      data-testid={`new-project-env-${tier}`}
      onClick={onToggle}
      className={cn(
        "inline-flex h-9 cursor-pointer items-center gap-2 rounded-lg border px-2.5 text-[13px] transition-colors",
        on ? "border-bd-strong bg-raised text-fg" : "border-bd bg-transparent text-muted hover:text-fg",
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "relative inline-flex h-4 w-7 items-center rounded-full border transition-colors",
          on ? "border-bd-strong bg-inset" : "border-bd bg-inset",
        )}
      >
        <span
          className={cn(
            "absolute size-3 rounded-full transition-all",
            on ? cn("left-[13px]", KNOB[tier]) : "left-[1px] bg-subtle",
          )}
        />
      </span>
      <span>{tier}</span>
    </button>
  );
}
