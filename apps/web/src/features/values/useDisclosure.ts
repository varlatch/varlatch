// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "../../lib/session";

/**
 * Server-disclosed Secret plaintext, held in component memory only: never
 * the React Query cache, a URL or storage. Every reveal is the explicit,
 * audited disclosure call with a requested set (or the deliberate "all"
 * scope). Values re-mask after five minutes, on re-authentication and when
 * the screen goes away. Re-masking is a display feature, not revocation.
 */

const REMASK_MS = 5 * 60 * 1000;

export type Disclosed = { value: string; retiring?: string | undefined };

export function useDisclosure(org: string, project: string) {
  const { api, authEpoch } = useSession();
  const [values, setValues] = useState<Map<string, Map<string, Disclosed>>>(() => new Map());
  // Disclosed but hidden again locally (the eye toggles without a new disclosure).
  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const timer = useRef<number | undefined>(undefined);

  const maskAll = useCallback(() => {
    window.clearTimeout(timer.current);
    setValues(new Map());
    setHidden(new Set());
  }, []);

  useEffect(() => maskAll(), [authEpoch, org, project, maskAll]);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const reveal = useCallback(
    async (env: string, request: string[] | "all") => {
      const result = await api.discloseSecrets(
        org,
        project,
        env,
        request === "all" ? { scope: "all-authorized-secrets" } : { items: request },
      );
      setValues((prev) => {
        const next = new Map(prev);
        const forEnv = new Map(next.get(env) ?? []);
        for (const item of result.items) {
          forEnv.set(item.name, { value: item.value, retiring: item.retiring?.value });
        }
        next.set(env, forEnv);
        return next;
      });
      setHidden((prev) => {
        const next = new Set(prev);
        for (const item of result.items) next.delete(`${env}\u0000${item.name}`);
        return next;
      });
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(maskAll, REMASK_MS);
      return { disclosed: result.items.map((i) => i.name), withheld: result.withheld };
    },
    [api, org, project, maskAll],
  );

  /** Plaintext currently shown for env/item, if revealed and not hidden again. */
  const shown = useCallback(
    (env: string, item: string): Disclosed | undefined =>
      hidden.has(`${env}\u0000${item}`) ? undefined : values.get(env)?.get(item),
    [values, hidden],
  );

  const isDisclosed = useCallback((env: string, item: string) => values.get(env)?.has(item) ?? false, [values]);

  /** Hide or show an already disclosed value locally; no new disclosure. */
  const toggleLocal = useCallback((env: string, item: string) => {
    setHidden((prev) => {
      const key = `${env}\u0000${item}`;
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const maskEnv = useCallback((env: string) => {
    setValues((prev) => {
      if (!prev.has(env)) return prev;
      const next = new Map(prev);
      next.delete(env);
      return next;
    });
  }, []);

  const revealedEnvs = [...values.entries()].filter(([, m]) => m.size > 0).map(([env]) => env);
  const count = [...values.values()].reduce((n, m) => n + m.size, 0);

  return { reveal, shown, isDisclosed, toggleLocal, maskAll, maskEnv, revealedEnvs, count };
}

export type DisclosureApi = ReturnType<typeof useDisclosure>;
