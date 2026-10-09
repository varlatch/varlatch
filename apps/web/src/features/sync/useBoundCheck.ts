// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useLayoutEffect, useRef, useState } from "react";

type Outcome<R> =
  | { key: string; status: "pending" }
  | { key: string; status: "done"; result: R }
  | { key: string; status: "error"; error: unknown };

/**
 * An access check bound to the inputs it checked. Its outcome counts only
 * while the inputs are exactly those, and only for the latest attempt: a
 * check that completes after an edit, after the dialog closed, or after a
 * newer check started (of the same inputs too) is dropped, and its
 * continuation never runs. The continuation receives the checked inputs, so
 * a dialog saves what was checked, never what the fields hold by then.
 */
export function useBoundCheck<I, R>(input: I, check: (input: I) => Promise<R>) {
  const key = JSON.stringify(input);
  // What a completion compares against: the committed inputs, or null once
  // the dialog is gone.
  const live = useRef<{ key: string | null; input: I; check: (input: I) => Promise<R> }>({ key, input, check });
  useLayoutEffect(() => {
    live.current = { key, input, check };
  });
  useLayoutEffect(
    () => () => {
      live.current = { ...live.current, key: null };
    },
    [],
  );
  // Same inputs do not make an older attempt current: a newer check may
  // see a revoked token or a changed permission.
  const attempts = useRef(0);
  const [outcome, setOutcome] = useState<Outcome<R> | null>(null);

  const run = useCallback((then?: (result: R, checked: I) => void) => {
    const { key: checkedKey, input: checked, check: fn } = live.current;
    if (checkedKey === null) return;
    const attempt = ++attempts.current;
    const fresh = () => attempts.current === attempt && live.current.key === checkedKey;
    setOutcome({ key: checkedKey, status: "pending" });
    fn(checked).then(
      (result) => {
        if (!fresh()) return;
        setOutcome({ key: checkedKey, status: "done", result });
        then?.(result, checked);
      },
      (error: unknown) => {
        if (fresh()) setOutcome({ key: checkedKey, status: "error", error });
      },
    );
  }, []);

  const mine = outcome?.key === key ? outcome : null;
  return {
    run,
    pending: mine?.status === "pending",
    result: mine?.status === "done" ? mine.result : undefined,
    error: mine?.status === "error" ? mine.error : undefined,
    /** A check of exactly the current inputs finished, with a result or an error. */
    settled: mine !== null && mine.status !== "pending",
  };
}
