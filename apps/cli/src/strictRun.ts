// SPDX-License-Identifier: Apache-2.0
import {
  RESERVED_ITEM_NAMES,
  SEMANTICS_VERSIONS,
  UnsupportedSemanticsVersionError,
  semanticsFor,
  type ConfigurationContract,
  type ContractItem,
  type ContractSemantics,
  type Tier,
} from "@varlatch/contract";
import type { SecretEntry } from "@varlatch/matcher";
import type { StrictRetrieval } from "@varlatch/protocol";
import { RUN_CONTEXT } from "./inject.js";
import { deliveredSecrets } from "./redact.js";

/**
 * `varlatch run --strict`: resolve the exact environment the child would
 * receive from one strict retrieval, validate it against that retrieval's
 * Contract Revision, and start the child only if nothing is wrong.
 *
 * For each Contract item the source is decided in this order, first match
 * wins:
 *
 * | Server status             | Parent environment      | Outcome                          |
 * | delivered, expanded       | any                     | delivered value (overrides)      |
 * | delivered, unexpanded ref | any                     | violation: unresolved reference  |
 * | withheld                  | set, name allowed       | inherited value                  |
 * | withheld                  | set, not allowed        | violation: withheld              |
 * | withheld                  | unset                   | violation if required, else absent |
 * | not stored                | set, name allowed       | inherited value                  |
 * | not stored                | set, not allowed        | violation: inherited             |
 * | not stored                | unset, default exists   | the Contract default             |
 * | not stored                | unset, no default       | violation if required, else absent |
 *
 * A default never stands in for a withheld value, and every value the child
 * will receive (delivered, inherited, or default) is validated exactly as it
 * will be received. Items outside the Contract are delivered as usual.
 */

export const STRICT_EXIT = 78; // EX_CONFIG
export const RUN_CONTEXT_MAX_BYTES = 64 * 1024;

export type ViolationKind =
  | "contract"
  | "semantics"
  | "reserved"
  | "unresolved-reference"
  | "withheld"
  | "inherited"
  | "missing"
  | "invalid"
  | "context"
  | "not-evaluated"
  | "agent-unauthorized"
  | "omitted";

export interface Violation {
  /** The Contract item, or "(contract)" / "(run context)" for global problems. */
  name: string;
  kind: ViolationKind;
  /** Never contains a value. */
  reason: string;
}

export type ServerStatus = "delivered" | "withheld" | "notStored";
export type Delivery = "varlatch" | "inherited" | "default" | "absent";

/** `VARLATCH_RUN_CONTEXT`: names and identifiers only, never values. */
export interface RunContext {
  v: 1;
  /** strict: from `varlatch run --strict`; exported: from a default run with `--export-context`. */
  mode: "strict" | "exported";
  contractRevisionId: string;
  contractHash: string;
  semanticsVersion: number;
  environment: { rootId: string; tier: Tier };
  items: Record<string, { server: ServerStatus; delivery: Delivery }>;
}

/**
 * Agent-safe strict startup: the retrieval is a preflight (no Secret values;
 * verdicts for an operator with secret.reveal), and each stored Secret
 * reaches the Agent as a Placeholder. `agent` is the Broker issuance's
 * per-item report, once issuance has run.
 */
export interface AgentSafeFacts {
  agent: Map<string, { present: boolean; authorized: boolean; reason?: "permission" | "requirement" }> | null;
  /** `--omit`: stored Secrets left out of the run and removed from the Agent's environment. */
  omitted?: ReadonlySet<string>;
}

export interface StrictPlan {
  /** The exact environment the child receives; meaningful only without violations. */
  env: NodeJS.ProcessEnv;
  /** Agent-safe only: stored Secrets that reach the Agent as Placeholders. */
  mediated: string[];
  violations: Violation[];
  context: RunContext | null;
  /** Delivered items that are not in the Contract, delivered as usual. */
  outsideContract: number;
}

export class UsageError extends Error {
  override name = "UsageError";
}

/**
 * `--allow-inherited` names must be Contract items: a typo is an error, never
 * ignored. In an agent-safe run it may not name a Secret, which would put
 * plaintext into the Agent's environment.
 */
export function checkAllowances(
  contract: ConfigurationContract,
  allowInherited: Iterable<string>,
  opts: { agentSafe?: boolean } = {},
): void {
  const byName = new Map(contract.items.map((i) => [i.name, i]));
  const names = [...new Set(allowInherited)];
  const unknown = names.filter((n) => !byName.has(n));
  if (unknown.length > 0) {
    throw new UsageError(`--allow-inherited names must be Contract items; not in the Contract: ${unknown.sort().join(", ")}`);
  }
  const secrets = names.filter((n) => byName.get(n)?.sensitive);
  if (opts.agentSafe && secrets.length > 0) {
    throw new UsageError(
      `--allow-inherited cannot name a Secret in an agent-safe run, which would put plaintext into the Agent's environment: ${secrets.sort().join(", ")}`,
    );
  }
}

function withheldReason(withheld: StrictRetrieval["callerView"]["withheld"][number]): string {
  return withheld.reason === "requirement"
    ? `withheld by the server: a Requirement (such as a Tailnet Constraint) for ${withheld.requires} is not met`
    : `withheld by the server: this identity needs ${withheld.requires}`;
}

export function planStrictRun(
  retrieval: StrictRetrieval,
  parent: NodeJS.ProcessEnv,
  allowInherited: ReadonlySet<string>,
  agentSafe?: AgentSafeFacts,
): StrictPlan {
  const violations: Violation[] = [];
  const mediated: string[] = [];
  const env: NodeJS.ProcessEnv = { ...parent };
  // Reserved launcher metadata: never inherited from an outer run.
  delete env[RUN_CONTEXT];
  const plan = (context: RunContext | null, outsideContract = 0): StrictPlan => ({
    env,
    mediated,
    violations,
    context,
    outsideContract,
  });

  const revision = retrieval.manifest.contract;
  if (!revision) {
    violations.push({ name: "(contract)", kind: "contract", reason: "no active Contract: strict startup needs one" });
    return plan(null);
  }
  const contract = retrieval.contract as unknown as ConfigurationContract | null;
  if (!contract) {
    violations.push({
      name: "(contract)",
      kind: "contract",
      reason: "the active Contract is not readable by this identity: it needs contract.read",
    });
    return plan(null);
  }
  let semantics: ContractSemantics;
  try {
    semantics = semanticsFor(revision.semanticsVersion);
  } catch (err) {
    if (!(err instanceof UnsupportedSemanticsVersionError)) throw err;
    violations.push({
      name: "(contract)",
      kind: "semantics",
      reason: `Contract semantics version ${revision.semanticsVersion} is not supported by this CLI (supported: ${SEMANTICS_VERSIONS.join(", ")}); upgrade the CLI`,
    });
    return plan(null);
  }

  for (const reserved of RESERVED_ITEM_NAMES) {
    if (retrieval.manifest.items.some((i) => i.name === reserved) || contract.items.some((i) => i.name === reserved)) {
      violations.push({
        name: reserved,
        kind: "reserved",
        reason: "this name is reserved for launcher metadata; rename the stored item",
      });
    }
  }

  const envCtx = { rootId: retrieval.manifest.environment.rootId, tier: retrieval.manifest.environment.tier };
  const items = new Map(retrieval.items.map((i) => [i.name, i]));
  const withheld = new Map(retrieval.callerView.withheld.map((w) => [w.name, w]));
  const unexpanded = new Map(retrieval.callerView.unexpanded.map((u) => [u.name, u.references]));
  const contracted = new Map(contract.items.map((i) => [i.name, i]));

  // Items outside the Contract are delivered as a default run delivers them
  // (in an agent-safe run, a stored Secret as a Placeholder).
  let outsideContract = 0;
  const omitted = agentSafe?.omitted ?? new Set<string>();
  for (const item of retrieval.items) {
    if (contracted.has(item.name) || RESERVED_ITEM_NAMES.includes(item.name)) continue;
    if (agentSafe && item.sensitive && omitted.has(item.name)) {
      delete env[item.name];
    } else if (agentSafe && item.sensitive) {
      mediated.push(item.name);
      outsideContract++;
    } else if (item.value !== null) {
      env[item.name] = item.value;
      outsideContract++;
    }
  }
  // The server's verdicts matter only for Secrets in an agent-safe run, the
  // one case where the CLI cannot see the value it would validate.
  const verdicts = {
    invalid: new Map((retrieval.validation?.invalid ?? []).map((v) => [v.name, v.reason])),
    unresolved: new Set((retrieval.validation?.unresolved ?? []).map((v) => v.name)),
    notEvaluated: new Map((retrieval.validation?.notEvaluated ?? []).map((v) => [v.name, v])),
  };

  const contextItems: RunContext["items"] = {};
  const validate = (item: ContractItem, value: string, source: string) => {
    const problem = semantics.validate(item, value);
    if (problem) violations.push({ name: item.name, kind: "invalid", reason: `${source} ${problem}` });
  };

  for (const item of contract.items) {
    if (RESERVED_ITEM_NAMES.includes(item.name)) continue;
    if (agentSafe && item.sensitive) {
      contextItems[item.name] = planAgentSecret(item, semantics.requiredApplies(item, envCtx));
      continue;
    }
    const got = items.get(item.name);
    const denied = withheld.get(item.name);
    const server: ServerStatus = !got ? "notStored" : denied || got.value === null ? "withheld" : "delivered";
    const inherited = parent[item.name];
    const allowed = allowInherited.has(item.name);
    const required = semantics.requiredApplies(item, envCtx);
    let delivery: Delivery = "absent";

    if (server === "delivered") {
      const references = unexpanded.get(item.name);
      if (references) {
        violations.push({
          name: item.name,
          kind: "unresolved-reference",
          reason: `a reference stays literal when delivered to this identity: ${references.join(", ")}`,
        });
      } else {
        const value = got?.value as string;
        env[item.name] = value;
        delivery = "varlatch";
        validate(item, value, "the delivered value");
      }
    } else if (inherited !== undefined) {
      if (allowed) {
        delivery = "inherited";
        validate(item, inherited, "the inherited value");
      } else {
        violations.push(
          server === "withheld"
            ? {
                name: item.name,
                kind: "withheld",
                reason: `${withheldReason(denied ?? { name: item.name, reason: "permission", requires: item.sensitive ? "secret.reveal" : "config.value.read" })}; the parent environment sets it, which --allow-inherited ${item.name} would accept`,
              }
            : {
                name: item.name,
                kind: "inherited",
                reason: `not stored in Varlatch and set only in the parent environment; accept it with --allow-inherited ${item.name}`,
              },
        );
      }
    } else if (server === "withheld") {
      // A default never replaces a withheld value: the real value exists.
      if (required) {
        violations.push({
          name: item.name,
          kind: "withheld",
          reason: withheldReason(denied ?? { name: item.name, reason: "permission", requires: item.sensitive ? "secret.reveal" : "config.value.read" }),
        });
      }
    } else if (item.defaultValue !== undefined) {
      env[item.name] = item.defaultValue;
      delivery = "default";
      validate(item, item.defaultValue, "the Contract default");
    } else if (required) {
      violations.push({ name: item.name, kind: "missing", reason: "required in this environment and not stored" });
    }
    contextItems[item.name] = { server, delivery };
  }

  /**
   * A Contract Secret in an agent-safe run. Stored: it reaches the Agent as a
   * Placeholder, but only if the operator's verdict is valid and the Agent
   * is authorized at issuance. Not stored: a parent value would put
   * plaintext into the Agent's environment, so it is a violation.
   */
  function planAgentSecret(item: ContractItem, required: boolean): RunContext["items"][string] {
    if (items.has(item.name) && omitted.has(item.name)) {
      delete env[item.name];
      if (required) {
        violations.push({ name: item.name, kind: "omitted", reason: "required in this environment, and --omit leaves it out of the run" });
      }
      return { server: "delivered", delivery: "absent" };
    }
    if (!items.has(item.name)) {
      if (parent[item.name] !== undefined) {
        violations.push({
          name: item.name,
          kind: "inherited",
          reason: "a Secret set only in the parent environment would reach the Agent as plaintext; store it in Varlatch",
        });
        return { server: "notStored", delivery: "absent" };
      }
      if (item.defaultValue !== undefined) {
        env[item.name] = item.defaultValue;
        validate(item, item.defaultValue, "the Contract default");
        return { server: "notStored", delivery: "default" };
      }
      if (required) violations.push({ name: item.name, kind: "missing", reason: "required in this environment and not stored" });
      return { server: "notStored", delivery: "absent" };
    }
    const notEvaluated = verdicts.notEvaluated.get(item.name);
    const invalid = verdicts.invalid.get(item.name);
    if (notEvaluated) {
      violations.push({
        name: item.name,
        kind: "not-evaluated",
        reason:
          notEvaluated.reason === "requirement"
            ? "validating Secrets needs secret.reveal, and a Requirement (such as a Tailnet Constraint) is not met"
            : "validating Secrets in an agent-safe strict run needs secret.reveal for the operator",
      });
    } else if (invalid) {
      violations.push({ name: item.name, kind: "invalid", reason: `the stored value ${invalid}` });
    } else if (verdicts.unresolved.has(item.name)) {
      violations.push({
        name: item.name,
        kind: "unresolved-reference",
        reason: "a reference stays literal for the operator",
      });
    }
    const agent = agentSafe?.agent?.get(item.name);
    if (agent && !agent.present) {
      violations.push({ name: item.name, kind: "missing", reason: "no longer stored when the Capability was issued" });
    } else if (agent && !agent.authorized) {
      violations.push({
        name: item.name,
        kind: "agent-unauthorized",
        reason:
          agent.reason === "requirement"
            ? "the Agent's secret.use Requirement (such as a Tailnet Constraint) is not met at issuance"
            : "the Agent lacks secret.use here",
      });
    }
    mediated.push(item.name);
    return { server: "delivered", delivery: "varlatch" };
  }

  const context: RunContext = {
    v: 1,
    mode: "strict",
    contractRevisionId: revision.revisionId,
    contractHash: revision.contentHash,
    semanticsVersion: revision.semanticsVersion,
    environment: envCtx,
    items: contextItems,
  };
  const encoded = encodeRunContext(context);
  if (encoded === null) {
    violations.push({
      name: "(run context)",
      kind: "context",
      reason: `the run context would exceed ${RUN_CONTEXT_MAX_BYTES} bytes; it is never truncated`,
    });
  } else {
    env[RUN_CONTEXT] = encoded;
  }
  return plan(context, outsideContract);
}

/** The run context as the child receives it, or null when it would exceed the bound: never truncated. */
export function encodeRunContext(context: RunContext): string | null {
  const encoded = JSON.stringify(context);
  return Buffer.byteLength(encoded, "utf8") > RUN_CONTEXT_MAX_BYTES ? null : encoded;
}

/** Every violation at once: names, classes, and reasons, never values. */
export function formatViolations(violations: Violation[]): string[] {
  return [
    `varlatch: strict startup found ${violations.length} violation(s); the command was not started:`,
    ...violations.map((v) => `  ${v.name}: ${v.kind}: ${v.reason}`),
  ];
}

/** The client surface strict startup needs. */
export interface StrictClient {
  meta(): Promise<{ serverVersion: string; capabilities: string[] }>;
  strictRetrieval(org: string, project: string, environment: string): Promise<StrictRetrieval>;
}

export interface StrictRunOptions {
  organization: string;
  project: string;
  environment: string;
  allowInherited: string[];
  parent: NodeJS.ProcessEnv;
  /**
   * Starts the child with exactly this environment; returns its exit code.
   * `secrets` are the sensitive values Varlatch delivered in it (for `--redact`).
   */
  start: (env: NodeJS.ProcessEnv, secrets: SecretEntry[]) => Promise<number>;
  log: (line: string) => void;
}

function retryable(err: unknown): boolean {
  const status = (err as { status?: unknown }).status;
  // A server-side failure (an audit commit or a decryption) or a lost
  // connection: nothing was returned, so one retry is safe.
  return typeof status === "number" ? status >= 500 : err instanceof TypeError;
}

/** Retry once on a server-side failure or a lost connection; nothing was returned. */
export async function retryOnce<T>(request: () => Promise<T>): Promise<T> {
  try {
    return await request();
  } catch (err) {
    if (!retryable(err)) throw err;
    return request();
  }
}

export async function runStrict(api: StrictClient, opts: StrictRunOptions): Promise<number> {
  const meta = await api.meta();
  if (!meta.capabilities.includes("retrieval.strict")) {
    opts.log(
      `varlatch: --strict needs strict retrieval, which this server (${meta.serverVersion}) does not offer; it needs Varlatch 0.11.0 or later. Strict startup never falls back to a default run.`,
    );
    return STRICT_EXIT;
  }
  const retrieval = await retryOnce(() => api.strictRetrieval(opts.organization, opts.project, opts.environment));
  if (retrieval.contract) checkAllowances(retrieval.contract as unknown as ConfigurationContract, opts.allowInherited);
  const plan = planStrictRun(retrieval, opts.parent, new Set(opts.allowInherited));
  if (plan.violations.length > 0) {
    for (const line of formatViolations(plan.violations)) opts.log(line);
    return STRICT_EXIT;
  }
  if (plan.outsideContract > 0) {
    opts.log(`varlatch: ${plan.outsideContract} delivered item(s) are not in the Contract; delivered as usual`);
  }
  return opts.start(plan.env, deliveredSecrets(retrieval.items, plan.env));
}
