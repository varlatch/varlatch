// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from "react";
import { useBlocker } from "react-router-dom";
import { useConfirm } from "../../components/Dialog";
import type { Draft } from "./model";

/**
 * Unsaved changes per environment per item. Memory only: drafts may hold
 * typed Secrets, so they never reach storage, URLs or the query cache. They
 * survive an in-place re-authentication and disappear with the screen.
 */
export type DraftMap = Map<string, Map<string, Draft>>;

export function useDrafts() {
  const [drafts, setDrafts] = useState<DraftMap>(() => new Map());
  const ref = useRef(drafts);
  ref.current = drafts;

  const setDraft = useCallback((env: string, item: string, draft: Draft | null) => {
    setDrafts((prev) => {
      const next = new Map(prev);
      const forEnv = new Map(next.get(env) ?? []);
      if (draft === null) forEnv.delete(item);
      else forEnv.set(item, draft);
      if (forEnv.size === 0) next.delete(env);
      else next.set(env, forEnv);
      return next;
    });
  }, []);

  const clearEnv = useCallback((env: string) => {
    setDrafts((prev) => {
      if (!prev.has(env)) return prev;
      const next = new Map(prev);
      next.delete(env);
      return next;
    });
  }, []);

  const get = useCallback((env: string, item: string) => drafts.get(env)?.get(item), [drafts]);
  const count = [...drafts.values()].reduce((n, m) => n + m.size, 0);

  return { drafts, ref, setDrafts, setDraft, clearEnv, get, count };
}

/**
 * Unsaved-changes protection: leaving the page asks first (in-app dialog),
 * closing the tab warns. Moves within the same page (query changes) pass.
 */
export function useUnsavedGuard(dirty: boolean, what: string) {
  const confirm = useConfirm();
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);
  const blocker = useBlocker(
    useCallback(
      ({ currentLocation, nextLocation }: { currentLocation: { pathname: string }; nextLocation: { pathname: string } }) =>
        dirty && currentLocation.pathname !== nextLocation.pathname,
      [dirty],
    ),
  );
  const asking = useRef(false);
  useEffect(() => {
    if (blocker.state !== "blocked" || asking.current) return;
    asking.current = true;
    void confirm({
      title: "Discard unsaved changes?",
      description: `${what} Leaving this page discards them.`,
      tone: "danger",
      confirmLabel: "Discard changes",
      cancelLabel: "Keep editing",
    }).then((ok) => {
      asking.current = false;
      if (ok) blocker.proceed();
      else blocker.reset();
    });
  }, [blocker, confirm, what]);
}
