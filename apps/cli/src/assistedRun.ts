// SPDX-License-Identifier: Apache-2.0
import type { ConfigurationContract } from "@varlatch/contract";
import { formsOf, MIN_LENGTH, type SecretEntry } from "@varlatch/matcher";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * `varlatch run` in assisted mode (ADR-0043 Decision 4, amending ADR-0038
 * Decision 10): output redaction is the default, the redaction set also
 * holds inherited values under known Secret names, and a value the matcher
 * cannot register stops the run before the command starts.
 *
 * Coverage limits, stated rather than hidden: a secret under a name Varlatch
 * does not know, a transformation the matcher does not recognise (ADR-0038
 * Decision 12), and a command that deliberately encodes a value all pass
 * through.
 */

/**
 * The assisted redaction set: the Secrets delivered in this run, plus the
 * value of each known Secret name that the command inherits unchanged from
 * this process's environment (a withheld Secret, or a Contract Secret with
 * no stored value). Inherited values are already local, so nothing is
 * fetched to build the filter. Empty values carry nothing to mask.
 */
export function assistedRedactionSet(
  delivered: SecretEntry[],
  childEnv: NodeJS.ProcessEnv,
  parent: NodeJS.ProcessEnv,
  knownSecretNames: Iterable<string>,
): SecretEntry[] {
  const set = delivered.filter((e) => e.value.length > 0);
  const covered = new Set(set.map((e) => e.item));
  for (const name of new Set(knownSecretNames)) {
    if (covered.has(name)) continue;
    const inherited = parent[name];
    if (!inherited || childEnv[name] !== inherited) continue;
    set.push({ item: name, value: inherited });
    covered.add(name);
  }
  return set;
}

/** Items whose value is too short for the matcher to register (ADR-0039 Decision 17), sorted. */
export function unmaskableItems(set: SecretEntry[]): string[] {
  return [...new Set(set.filter((e) => formsOf(e.value).length === 0).map((e) => e.item))].sort();
}

export interface AssistedPlan {
  /** What the redactor is registered with. */
  entries: SecretEntry[];
  /** Short values the operator allowed to pass unmasked. */
  allowed: string[];
  /** Short values nobody allowed: the run must not start. */
  refused: string[];
  /** --allow-unmasked names that are not short Secrets in this run. */
  unusedAllowances: string[];
}

export function planAssistedRedaction(set: SecretEntry[], allowUnmasked: string[]): AssistedPlan {
  const short = unmaskableItems(set);
  const allow = new Set(allowUnmasked);
  return {
    entries: set,
    allowed: short.filter((n) => allow.has(n)),
    refused: short.filter((n) => !allow.has(n)),
    unusedAllowances: [...allow].filter((n) => !short.includes(n)).sort(),
  };
}

/**
 * What a remedy command needs to act on the same run from a new shell:
 * `target` holds the context options (the resolved environment, and an
 * overridden server), `runOptions` the run's own options to repeat in a
 * retry (`--strict`, the allowances already given).
 */
export interface RemedyContext {
  target: string;
  runOptions?: string[];
}

/**
 * Why an assisted run did not start: names and remedies, never a value.
 * The remedies are the human's, as commands for their own terminal (an
 * agent evaluation saw an agent run a printed remedy itself). Every command
 * names the run's environment: without it, a remedy for a production
 * refusal would replace or show the default environment's value.
 * Every remedy changes or exposes the human's configuration, so each is
 * theirs to approve, for the named item only: an agent reports and waits
 * (ADR-0043; the agent evaluation saw an agent regenerate other items).
 */
export function unmaskableRefusal(items: string[], how: RemedyContext): string[] {
  const first = items[0] as string;
  // The human's commands, for their own terminal: no --assisted (assisted mode refuses the override).
  const retry = ["varlatch run", how.target, ...(how.runOptions ?? []), `--allow-unmasked ${first} -- <command>`].join(" ");
  return [
    `varlatch: ${items.length === 1 ? "this Secret is" : "these Secrets are"} shorter than ${MIN_LENGTH} bytes, so ` +
      `${items.length === 1 ? "its value" : "their values"} cannot be masked in the command's output: ${items.join(", ")}`,
    `  Stop and ask the human. Each choice is theirs, for ${items.length === 1 ? first : "each named item"} only, made in their own terminal:`,
    `  - replace the value with a longer one, which overwrites the current value: varlatch values set ${first} ${how.target} --generate hex:32`,
    `  - if it is not a secret, correct its sensitivity in the Contract`,
    `  - show it unmasked in one run, every other Secret still masked: ${retry}`,
    "  An agent reports this and waits: it runs none of these itself, and approval for one item does not cover another.",
    "Nothing was started.",
  ];
}

/**
 * The run's verdict on its plan: false (after naming the items and the
 * remedies) when a short value nobody allowed would pass unmasked.
 */
export function assistedGate(plan: AssistedPlan, log: (line: string) => void, how: RemedyContext): boolean {
  if (plan.unusedAllowances.length > 0) {
    log(
      `varlatch: --allow-unmasked names ${plan.unusedAllowances.join(", ")}, which ${plan.unusedAllowances.length === 1 ? "is" : "are"} ` +
        `not a Secret shorter than ${MIN_LENGTH} bytes in this run; ignored`,
    );
  }
  if (plan.refused.length > 0) {
    const runOptions = [...(how.runOptions ?? []), ...plan.allowed.map((name) => `--allow-unmasked ${name}`)];
    for (const line of unmaskableRefusal(plan.refused, { ...how, runOptions })) log(line);
    return false;
  }
  return true;
}

export interface ContractReader {
  getActiveContract(org: string, project: string): Promise<{ contract?: unknown }>;
}

/**
 * Every name a default run knows as a Secret: stored as one in the
 * Environment (withheld ones included), or sensitive in the active
 * Contract. Reading the Contract needs contract.read; without it only the
 * stored names are known, and the run says so.
 */
export async function knownSecretNames(
  api: ContractReader,
  where: { organization: string; project: string },
  effective: EffectiveConfiguration,
  log: (line: string) => void,
): Promise<string[]> {
  const names = new Set((effective.items ?? []).filter((i) => i.sensitive).map((i) => i.name));
  // A server that reports its manifest says whether a Contract is active.
  if (!effective.manifest || effective.manifest.contract) {
    try {
      const revision = await api.getActiveContract(where.organization, where.project);
      const contract = revision.contract as ConfigurationContract | undefined;
      for (const item of contract?.items ?? []) if (item.sensitive) names.add(item.name);
    } catch (err) {
      if (!(err instanceof VarlatchApiError) || (err.status !== 404 && err.status !== 403)) throw err;
      if (err.status === 403) {
        log("varlatch: cannot read the Contract (403); inherited values are masked only under names stored as Secrets");
      }
    }
  }
  return [...names].sort();
}
