// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQueryClient } from "@tanstack/react-query";
import type { Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { keys } from "./hooks";

/**
 * What deleting a project does and does not reach (ADR-0051 Decisions 2
 * and 10), in the confirmation's words.
 */
export const PROJECT_DELETION_CONSEQUENCES = [
  "Every value of its environments, current and past, is erased from this installation's database at once. There is no undo.",
  "Its environments, Sync Targets and Capabilities stop working, and Teams lose their link to it.",
  "Values already pushed to platforms stay there, and copies people revealed or downloaded stay wherever they are: rotate them at their provider.",
  "Backups taken before now keep the values until their retention removes them.",
  "The audit log keeps the project's events. Its slug can be used again for a new, empty project.",
];

/**
 * Deleting a project: confirmed by typing its slug, then the caches that
 * name it are dropped. `onDeleted` runs first, so a page showing the
 * project can leave before its queries go.
 */
export function useDeleteProject(org: string) {
  const { api } = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const qc = useQueryClient();
  return async (project: Pick<Project, "slug">, onDeleted?: () => void): Promise<boolean> => {
    const ok = await confirm({
      title: `Delete project ${project.slug}?`,
      consequences: PROJECT_DELETION_CONSEQUENCES.map((text) => ({ text })),
      confirmLabel: "Delete project",
      tone: "danger",
      typeToConfirm: project.slug,
    });
    if (!ok) return false;
    try {
      const deleted = await api.deleteProject(org, project.slug);
      onDeleted?.();
      qc.removeQueries({ predicate: (q) => q.queryKey[1] === org && q.queryKey[2] === project.slug });
      await Promise.all([
        qc.invalidateQueries({ queryKey: keys.projects(org) }),
        qc.invalidateQueries({ queryKey: keys.orgSyncTargets(org) }),
      ]);
      toast.success(`Project ${project.slug} deleted`, {
        description: `Erased ${deleted.versionsErased} value versions in ${deleted.environments} environments.`,
      });
      return true;
    } catch (err) {
      toast.error("Could not delete the project", { description: errorMessage(err) });
      return false;
    }
  };
}
