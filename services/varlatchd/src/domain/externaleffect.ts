// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from "node:async_hooks";
import type { AuditEventInput } from "../audit/events.js";
import { DomainError } from "./errors.js";

/**
 * The lifetime of a protected external effect (liveness.ts
 * withExternalEffect, ADR-0054 Decision 7): what the effect's transaction
 * shares with the outbound calls it makes.
 *
 * - A deadline: an AbortSignal that fires `deadlineMs` after the effect
 *   began. Every outbound call of the effect goes through guardEffectFetch:
 *   none starts once the signal fired, and one in flight is aborted. The
 *   transaction's own idle cap (`idleMs`, PostgreSQL's
 *   idle_in_transaction_session_timeout) is set above the deadline, so the
 *   Organization lock is still held whenever a call can start: no call
 *   outlives the protection. When the deadline fired, the effect fails
 *   and its transaction rolls back.
 * - Outbound refusal records written during the effect (net/outbound.ts
 *   recordRefusal): kept in the transaction, in their place in the audit
 *   order, and written again after the transaction when it rolled back, so
 *   a refused destination is recorded as it was before the effect had a
 *   transaction.
 */
export const EXTERNAL_EFFECT_LIMITS = {
  /** From the effect's start to the last moment an outbound call may start. */
  deadlineMs: 90_000,
  /** PostgreSQL's idle cap for the effect's transaction: above the deadline. */
  idleMs: 120_000,
};

export interface ExternalEffect {
  readonly signal: AbortSignal;
  /** Outbound refusal events written in the effect's transaction. */
  readonly refusals: AuditEventInput[];
}

const storage = new AsyncLocalStorage<ExternalEffect>();

/** Run `fn`, and everything it awaits, as this effect. */
export function runExternalEffect<T>(effect: ExternalEffect, fn: () => Promise<T>): Promise<T> {
  return storage.run(effect, fn);
}

/** The external effect this async flow runs in, if any. */
export function currentExternalEffect(): ExternalEffect | undefined {
  return storage.getStore();
}

/** An external effect stopped at its deadline: nothing it began is kept. */
export function externalEffectDeadline(): DomainError {
  return new DomainError(
    "STATE_CHANGED",
    `The call outside Varlatch took longer than ${Math.round(EXTERNAL_EFFECT_LIMITS.deadlineMs / 1000)} seconds, so it was stopped and nothing was changed. Try again.`,
    { retryable: true, reason: "external-effect-deadline" },
  );
}

/**
 * A fetch bound to the current effect's lifetime: it refuses to start a
 * call once the deadline fired, and aborts a call in flight when it fires.
 * Outside an effect it is `fetchImpl` unchanged.
 */
export function guardEffectFetch(fetchImpl: typeof fetch): typeof fetch {
  const guarded = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const effect = currentExternalEffect();
    if (!effect) return fetchImpl(input, init);
    if (effect.signal.aborted) throw externalEffectDeadline();
    const signal = init?.signal ? AbortSignal.any([init.signal, effect.signal]) : effect.signal;
    return fetchImpl(input, { ...init, signal });
  }) as typeof fetch;
  // The outbound policy's purpose, for the callers that read it.
  const purpose = (fetchImpl as { outboundPurpose?: unknown }).outboundPurpose;
  if (purpose !== undefined) Object.defineProperty(guarded, "outboundPurpose", { value: purpose });
  return guarded;
}

/** Notes an outbound refusal event written in the current effect's transaction. */
export function noteEffectRefusal(event: AuditEventInput): void {
  currentExternalEffect()?.refusals.push(event);
}
