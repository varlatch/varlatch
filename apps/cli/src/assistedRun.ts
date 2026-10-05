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
 * through. So does a Secret the command does not get from the run (withheld,
 * or left out with `--omit`) when the command obtains it some other way:
 * the run never fetches a value only to mask it.
 */

/**
 * The assisted redaction set: the Secrets delivered in this run, plus the
 * value of each known Secret name that the command inherits unchanged from
 * this process's environment (a withheld Secret, or a Contract Secret with
 * no stored value). Only what the command actually holds counts: a value
 * not in `childEnv` (an item left out with `--omit`) is neither delivered
 * nor inherited, so it cannot stop the run. Inherited values are already
 * local, so nothing is fetched to build the filter. Empty values carry
 * nothing to mask.
 */
export function assistedRedactionSet(
  delivered: SecretEntry[],
  childEnv: NodeJS.ProcessEnv,
  parent: NodeJS.ProcessEnv,
  knownSecretNames: Iterable<string>,
): SecretEntry[] {
  const set = delivered.filter((e) => e.value.length > 0 && childEnv[e.item] === e.value);
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
 * retry (`--strict`, `--omit`, the allowances already given). `assisted`
 * is false for the human's override outside assisted mode, whose retry
 * keeps its allowances and so cannot run with `--assisted`.
 */
export interface RemedyContext {
  target: string;
  runOptions?: string[];
  assisted?: boolean;
}

/**
 * Why an assisted run did not start: names and remedies, never a value.
 * The first remedy needs nobody's approval: when the command does not need
 * the item, `--omit` leaves it out, so the command never holds a value
 * that would pass unmasked. Otherwise the agent stops and asks; each other
 * remedy is the human's decision, for the named item and environment only
 * (an agent evaluation saw an agent regenerate items nobody named). After
 * that approval, a safe remedy is printed as the agent's own command, with
 * --assisted (an evaluation saw an agent copy a human-only command into its
 * own shell, outside assisted mode). Showing a Secret unmasked stays the
 * human's alone, in their own terminal. Every command names the run's
 * environment and an overridden server: without them, a remedy for a
 * production refusal would act on the default environment.
 */
export function unmaskableRefusal(items: string[], how: RemedyContext): string[] {
  const first = items[0] as string;
  const several = items.length > 1;
  // The Contract is the server's: an overridden server must reach every contract command, or they change another server's.
  const server = /(?:^|\s)--server (\S+)/.exec(how.target)?.[1];
  // The same run without the items: the agent's own command, unless this is the human's override.
  const omit = [
    how.assisted === false ? "varlatch run" : "varlatch --assisted run",
    how.target,
    ...(how.runOptions ?? []),
    ...items.map((name) => `--omit ${name}`),
    "-- <command>",
  ].join(" ");
  // The human's override, for their own terminal: no --assisted (assisted mode refuses it).
  const retry = ["varlatch run", how.target, ...(how.runOptions ?? []), `--allow-unmasked ${first} -- <command>`].join(" ");
  return [
    `varlatch: ${several ? "these Secrets are" : "this Secret is"} shorter than ${MIN_LENGTH} bytes, so ` +
      `${several ? "their values" : "its value"} cannot be masked in the command's output: ${items.join(", ")}`,
    `  If the command does not need ${several ? "them" : first}, rerun with ${items.map((name) => `--omit ${name}`).join(" ")}: ` +
      `the command then does not get ${several ? "them" : "it"}, and no approval is needed` +
      (several ? " (leave out only the ones it does not need)" : "") +
      ":",
    `      ${omit}`,
    `  If it needs ${several ? "one" : "it"}, stop and ask the human what to do about ${several ? "each item it needs" : first}. Approval for one item or action never covers another.`,
    `  - Only if they approve replacing ${first} with a new random value (it overwrites the current one):`,
    `      varlatch --assisted values set ${first} ${how.target} --replace ${first} --generate hex:32` + (several ? "   (each item needs its own approval)" : ""),
    `    A credential a provider issued is never generated: the human enters it, in their own terminal: varlatch values set ${first} ${how.target}`,
    `  - Only if they approve marking ${first} as not secret (a Contract change, for the whole project): varlatch --assisted agents guide contract` +
      (server ? ` (add --server ${server} to every contract command)` : ""),
    `  - Showing it unmasked is the human's alone, in their own terminal (assisted mode refuses it; every other Secret stays masked):`,
    `      ${retry}`,
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
