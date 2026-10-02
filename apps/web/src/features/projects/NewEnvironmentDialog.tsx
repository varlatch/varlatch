// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Environment, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Dialog } from "../../components/Dialog";
import { Button, Field, Input, Segmented, Select, TierDot } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { keys } from "./hooks";

const TIERS: Tier[] = ["development", "staging", "production"];

/**
 * Creates a shared root environment, or a personal/preview environment
 * derived from an existing root (one level only).
 */
export function NewEnvironmentDialog({
  org,
  project,
  environments,
  open,
  onClose,
  onCreated,
}: {
  org: string;
  project: string;
  environments: Environment[];
  open: boolean;
  onClose: () => void;
  onCreated?: ((env: Environment) => void) | undefined;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const roots = environments.filter((e) => !e.parentEnvironmentId);
  const [name, setName] = useState("");
  const [tier, setTier] = useState<Tier>("development");
  const [kind, setKind] = useState<"shared" | "personal" | "preview">("shared");
  const [parentId, setParentId] = useState(roots[0]?.id ?? "");
  const derived = kind !== "shared";
  const parent = roots.find((e) => e.id === parentId);
  // Derived environments are named parent/suffix (e.g. development/alex).
  const fullName = derived && parent ? `${parent.name}/${name}` : name;
  const validName = /^[a-z0-9][a-z0-9._-]{0,62}$/.test(name);
  const create = useMutation({
    mutationFn: () =>
      api.createEnvironment(org, project, {
        name: fullName,
        ...(derived ? { kind, parentEnvironmentId: parentId } : { tier }),
      }),
    onSuccess: async (env) => {
      await qc.invalidateQueries({ queryKey: keys.environments(org, project) });
      toast.success(`Created ${env.name}`, { description: `${project} / ${env.name}` });
      setName("");
      onCreated?.(env);
      onClose();
    },
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title="New environment"
      description={`Environments of ${project} share its contract and hold their own values.`}
      data-testid="new-environment-dialog"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            data-testid="create-environment"
            loading={create.isPending}
            disabled={!validName || (derived && !parentId)}
            onClick={() => create.mutate()}
          >
            Create environment
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (validName && (!derived || parentId)) create.mutate();
        }}
      >
        <Field
          label="Name"
          hint={
            derived
              ? `Created as ${parent?.name ?? "parent"}/${name || "name"}. Lowercase letters, digits, dots, dashes and underscores.`
              : "Lowercase letters, digits, dots, dashes and underscores."
          }
        >
          <div className="flex items-center">
            {derived && parent && (
              <span className="flex h-8 items-center rounded-l-md border border-r-0 border-bd bg-hover px-2.5 font-mono text-[13px] text-muted">
                {parent.name}/
              </span>
            )}
            <Input
              data-autofocus
              data-testid="new-environment-name"
              mono
              className={derived && parent ? "w-full rounded-l-none" : "w-full"}
              value={name}
              placeholder={derived ? "alex" : "staging"}
              onChange={(e) => setName(e.target.value.toLowerCase())}
            />
          </div>
        </Field>
        <Field label="Kind">
          <Segmented
            value={kind}
            onChange={setKind}
            aria-label="Environment kind"
            options={[
              { value: "shared", label: "Shared" },
              { value: "personal", label: "Personal" },
              { value: "preview", label: "Preview" },
            ]}
          />
        </Field>
        {derived ? (
          <Field label="Derived from" hint="Inherits the parent's values and tier; its own values override them.">
            <Select
              className="w-full"
              value={parentId}
              onChange={setParentId}
              aria-label="Parent environment"
              options={roots.map((e) => ({
                value: e.id,
                label: e.name,
                icon: <TierDot tier={e.tier as Tier} />,
              }))}
            />
          </Field>
        ) : (
          <Field label="Tier" hint="Production-tier saves always ask for an explicit acknowledgement.">
            <Select
              className="w-full"
              data-testid="new-environment-tier"
              value={tier}
              onChange={(v) => setTier(v as Tier)}
              aria-label="Environment tier"
              options={TIERS.map((t) => ({ value: t, label: t, icon: <TierDot tier={t} /> }))}
            />
          </Field>
        )}
        {create.error && <p className="text-sm text-deny">{errorMessage(create.error)}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
