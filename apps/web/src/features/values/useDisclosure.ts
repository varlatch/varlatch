// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "../../lib/session";
import { DisclosureDiscardedError, TailnetOnlyError, isTailnetDenial } from "../../lib/tailnet";

/**
 * Server-disclosed Secret plaintext, held in component memory only: never
 * the React Query cache, a URL or storage. Every reveal is the explicit,
 * audited disclosure call with a requested set (or the deliberate "all"
 * scope). Values re-mask after five minutes, on re-authentication and when
 * the screen goes away. Re-masking is a display feature, not revocation.
 *
 * `restricted` names the environments a Tailnet Requirement now covers.
 * Their plaintext stops showing in the same render the restriction appears,
 * is dropped from memory right after, and a disclosure still in flight for
 * one is discarded when it lands. Every cleanup (a restriction, a tailnet
 * denial, masking) bumps a generation, so a disclosure started before it
 * stays discarded even if the restriction has been lifted by the time it
 * lands. Display cleanup only: plaintext already delivered to this browser
 * is not revoked.
 */

const REMASK_MS = 5 * 60 * 1000;
const NONE: ReadonlySet<string> = new Set();

export type Disclosed = { value: string; retiring?: string | undefined };

export function useDisclosure(org: string, project: string, restricted: ReadonlySet<string> = NONE) {
  const { api, authEpoch } = useSession();
  const [values, setValues] = useState<Map<string, Map<string, Disclosed>>>(() => new Map());
  // Disclosed but hidden again locally (the eye toggles without a new disclosure).
  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const timer = useRef<number | undefined>(undefined);
  // Read when a disclosure lands, which may be renders after it started.
  const restrictedNow = useRef(restricted);
  restrictedNow.current = restricted;
  // Cleanup generations: one for everything, one per environment.
  const epoch = useRef(0);
  const generations = useRef(new Map<string, number>());
  const generationOf = (env: string) => `${epoch.current}:${generations.current.get(env) ?? 0}`;

  const maskAll = useCallback(() => {
    epoch.current++;
    window.clearTimeout(timer.current);
    setValues(new Map());
    setHidden(new Set());
  }, []);

  const maskEnv = useCallback((env: string) => {
    generations.current.set(env, (generations.current.get(env) ?? 0) + 1);
    setValues((prev) => {
      if (!prev.has(env)) return prev;
      const next = new Map(prev);
      next.delete(env);
      return next;
    });
    setHidden((prev) => {
      const next = new Set([...prev].filter((key) => !key.startsWith(`${env}\u0000`)));
      return next.size === prev.size ? prev : next;
    });
  }, []);

  useEffect(() => maskAll(), [authEpoch, org, project, maskAll]);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const restrictedKey = [...restricted].sort().join("\u0000");
  useEffect(() => {
    for (const env of restrictedNow.current) maskEnv(env);
  }, [restrictedKey, maskEnv]);

  const reveal = useCallback(
    async (env: string, request: string[] | "all") => {
      if (restrictedNow.current.has(env)) throw new TailnetOnlyError();
      const started = generationOf(env);
      let result;
      try {
        result = await api.discloseSecrets(
          org,
          project,
          env,
          request === "all" ? { scope: "all-authorized-secrets" } : { items: request },
        );
      } catch (err) {
        // A Requirement this page did not know about yet.
        if (isTailnetDenial(err)) maskEnv(env);
        throw err;
      }
      // A Requirement that appeared while the disclosure was in flight, or
      // any cleanup since it started, even one whose cause is gone again.
      if (restrictedNow.current.has(env)) throw new TailnetOnlyError();
      if (generationOf(env) !== started) throw new DisclosureDiscardedError();
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
    [api, org, project, maskAll, maskEnv],
  );

  /** Plaintext currently shown for env/item, if revealed, not hidden again, and not restricted since. */
  const shown = useCallback(
    (env: string, item: string): Disclosed | undefined =>
      restricted.has(env) || hidden.has(`${env}\u0000${item}`) ? undefined : values.get(env)?.get(item),
    [values, hidden, restricted],
  );

  const isDisclosed = useCallback(
    (env: string, item: string) => !restricted.has(env) && (values.get(env)?.has(item) ?? false),
    [values, restricted],
  );

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

  const live = [...values.entries()].filter(([env, m]) => m.size > 0 && !restricted.has(env));
  const revealedEnvs = live.map(([env]) => env);
  const count = live.reduce((n, [, m]) => n + m.size, 0);

  return { reveal, shown, isDisclosed, toggleLocal, maskAll, maskEnv, revealedEnvs, count };
}

export type DisclosureApi = ReturnType<typeof useDisclosure>;
