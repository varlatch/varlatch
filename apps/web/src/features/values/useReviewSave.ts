// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Environment } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { useToast } from "../../components/Toast";
import { buildChanges, draftKind, listNames, plural, storedText, type ServerItem } from "./model";
import type { useDrafts } from "./useDrafts";
import type { ReviewGroup, ReviewRow } from "./ReviewDialog";

/**
 * Draft -> review -> save. Opening the review freezes what it shows: the
 * server data keeps refreshing live, and reading it at save time would let
 * a change made elsewhere during the review be overwritten without a
 * conflict. Each environment is one atomic change set, saved in order; the
 * first failure stops the run and the report says exactly what was written.
 */
export function useReviewSave({
  org,
  project,
  environments,
  drafts,
  serverOf,
  sensitiveOf,
  targetsOf,
  onSaved,
}: {
  org: string;
  project: string;
  /** Save order (tier order). */
  environments: Environment[];
  drafts: ReturnType<typeof useDrafts>;
  serverOf: (env: string) => Map<string, ServerItem> | undefined;
  sensitiveOf: (env: string, item: string) => boolean;
  /** Labels of the integrations that will push these items. */
  targetsOf: (env: Environment, items: string[]) => string[];
  onSaved?: ((envs: string[]) => void) | undefined;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [snapshot, setSnapshot] = useState<Map<string, Map<string, ServerItem>> | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflicts, setConflicts] = useState<Set<string>>(() => new Set());

  const openReview = useCallback(() => {
    const current = drafts.ref.current;
    if (current.size === 0) return;
    const snap = new Map<string, Map<string, ServerItem>>();
    for (const env of current.keys()) snap.set(env, new Map(serverOf(env) ?? []));
    setSnapshot(snap);
  }, [drafts.ref, serverOf]);

  const closeReview = useCallback(() => setSnapshot(null), []);

  const groups: ReviewGroup[] = [];
  if (snapshot) {
    for (const env of environments) {
      const forEnv = drafts.drafts.get(env.name);
      if (!forEnv?.size) continue;
      const reviewed = snapshot.get(env.name) ?? serverOf(env.name) ?? new Map<string, ServerItem>();
      const rows: ReviewRow[] = [...forEnv.entries()].map(([name, draft]) => {
        const server = reviewed.get(name);
        const sensitive = sensitiveOf(env.name, name);
        const kind = draftKind(draft, server);
        const old = server && !sensitive ? storedText(server) : null;
        return {
          name,
          op: kind === "deleted" ? "delete" : kind === "edited" ? "change" : "add",
          sensitive,
          oldText: old,
          newText: draft.op === "set" ? draft.value : undefined,
        };
      });
      groups.push({ env, rows, targets: targetsOf(env, [...forEnv.keys()]) });
    }
  }

  const invalidate = useCallback(async () => {
    await qc.invalidateQueries({ queryKey: ["effective-values", org, project] });
    await qc.invalidateQueries({ queryKey: ["effective-meta", org, project] });
  }, [qc, org, project]);

  const save = useCallback(async () => {
    if (!snapshot) return;
    setSaving(true);
    setError(null);
    setConflicts(new Set());
    const order = environments.filter((e) => drafts.ref.current.get(e.name)?.size);
    const saved: { env: string; count: number }[] = [];
    let failure: string | null = null;
    let failedAt = -1;
    for (const [index, env] of order.entries()) {
      const forEnv = drafts.ref.current.get(env.name);
      if (!forEnv?.size) continue;
      const reviewed = snapshot.get(env.name) ?? new Map<string, ServerItem>();
      try {
        await api.applyChangeSet(org, project, env.name, buildChanges(forEnv, reviewed), {
          idempotencyKey: crypto.randomUUID(),
        });
        saved.push({ env: env.name, count: forEnv.size });
        drafts.clearEnv(env.name);
      } catch (err) {
        failedAt = index;
        if (err instanceof VarlatchApiError && err.code === "VERSION_CONFLICT") {
          const items = ((err.details?.conflicts as { item: string }[] | undefined) ?? []).map((c) => c.item);
          setConflicts(new Set(items.map((i) => `${env.name}\u0000${i}`)));
          failure =
            `Changed since review in ${env.name}: ${items.join(", ") || "one or more items"}. ` +
            `Nothing was written to ${env.name}; your drafts are kept and the current values are shown.`;
        } else {
          const message = err instanceof VarlatchApiError ? err.message : String(err);
          failure = `Could not save ${env.name}: ${message}. Nothing was written to ${env.name}; your drafts are kept.`;
        }
        break;
      }
    }
    await invalidate();
    setSaving(false);
    setSnapshot(null);
    if (saved.length > 0) onSaved?.(saved.map((s) => s.env));
    const total = saved.reduce((n, s) => n + s.count, 0);
    const savedText = saved.map((s) => `${s.env} (${plural(s.count, "change")})`);
    if (failure) {
      const skipped = order.slice(failedAt + 1).map((e) => e.name);
      const parts = [
        saved.length > 0 ? `Saved ${listNames(savedText)}.` : "",
        failure,
        skipped.length > 0 ? `Not attempted: ${listNames(skipped)} (drafts kept).` : "",
      ].filter(Boolean);
      setError(parts.join(" "));
      toast.error(saved.length > 0 ? "Some changes were not saved" : "Changes not saved", {
        description: parts.join(" "),
      });
    } else {
      toast.success(
        `Saved ${plural(total, "change")}`,
        { description: saved.length === 1 ? `${project} / ${saved[0]!.env}` : `${project}: ${listNames(saved.map((s) => s.env))}` },
      );
    }
  }, [snapshot, environments, drafts, api, org, project, invalidate, onSaved, toast]);

  return {
    reviewOpen: snapshot !== null,
    openReview,
    closeReview,
    save,
    saving,
    groups,
    error,
    clearError: () => setError(null),
    conflicts,
  };
}
