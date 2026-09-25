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
import type { StrictRetrieval } from "@varlatch/protocol";
import { RUN_CONTEXT } from "./inject.js";

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
const RUN_CONTEXT_MAX_BYTES = 64 * 1024;

export type ViolationKind =
  | "contract"
  | "semantics"
  | "reserved"
  | "unresolved-reference"
  | "withheld"
  | "inherited"
  | "missing"
  | "invalid"
  | "context";

export interface Violation {
  /** The Contract item, or "(contract)" / "(run context)" for global problems. */
  name: string;
  kind: ViolationKind;
  /** Never contains a value. */
  reason: string;
}

export type ServerStatus = "delivered" | "withheld" | "notStored";
export type Delivery = "varlatch" | "inherited" | "default" | "absent";

export interface RunContext {
  v: 1;
  mode: "strict";
  contractRevisionId: string;
  contractHash: string;
  semanticsVersion: number;
  environment: { rootId: string; tier: Tier };
  items: Record<string, { server: ServerStatus; delivery: Delivery }>;
}

export interface StrictPlan {
  /** The exact environment the child receives; meaningful only without violations. */
  env: NodeJS.ProcessEnv;
  violations: Violation[];
  context: RunContext | null;
  /** Delivered items that are not in the Contract, delivered as usual. */
  outsideContract: number;
}

export class UsageError extends Error {
  override name = "UsageError";
}

/** `--allow-inherited` names must be Contract items: a typo is an error, never ignored. */
export function checkAllowances(contract: ConfigurationContract, allowInherited: Iterable<string>): void {
  const names = new Set(contract.items.map((i) => i.name));
  const unknown = [...allowInherited].filter((n) => !names.has(n));
  if (unknown.length > 0) {
    throw new UsageError(
      `--allow-inherited names must be Contract items; not in the Contract: ${[...new Set(unknown)].sort().join(", ")}`,
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
): StrictPlan {
  const violations: Violation[] = [];
  const env: NodeJS.ProcessEnv = { ...parent };
  // Reserved launcher metadata: never inherited from an outer run.
  delete env[RUN_CONTEXT];
  const plan = (context: RunContext | null, outsideContract = 0): StrictPlan => ({
    env,
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

  // Items outside the Contract are delivered as a default run delivers them.
  let outsideContract = 0;
  for (const item of retrieval.items) {
    if (contracted.has(item.name) || RESERVED_ITEM_NAMES.includes(item.name)) continue;
    if (item.value !== null) {
      env[item.name] = item.value;
      outsideContract++;
    }
  }

  const contextItems: RunContext["items"] = {};
  const validate = (item: ContractItem, value: string, source: string) => {
    const problem = semantics.validate(item, value);
    if (problem) violations.push({ name: item.name, kind: "invalid", reason: `${source} ${problem}` });
  };

  for (const item of contract.items) {
    if (RESERVED_ITEM_NAMES.includes(item.name)) continue;
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

  const context: RunContext = {
    v: 1,
    mode: "strict",
    contractRevisionId: revision.revisionId,
    contractHash: revision.contentHash,
    semanticsVersion: revision.semanticsVersion,
    environment: envCtx,
    items: contextItems,
  };
  const encoded = JSON.stringify(context);
  if (Buffer.byteLength(encoded, "utf8") > RUN_CONTEXT_MAX_BYTES) {
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
  /** Starts the child with exactly this environment; returns its exit code. */
  start: (env: NodeJS.ProcessEnv) => Promise<number>;
  log: (line: string) => void;
}

function retryable(err: unknown): boolean {
  const status = (err as { status?: unknown }).status;
  // A server-side failure (an audit commit or a decryption) or a lost
  // connection: nothing was returned, so one retry is safe.
  return typeof status === "number" ? status >= 500 : err instanceof TypeError;
}

export async function runStrict(api: StrictClient, opts: StrictRunOptions): Promise<number> {
  const meta = await api.meta();
  if (!meta.capabilities.includes("retrieval.strict")) {
    opts.log(
      `varlatch: --strict needs strict retrieval, which this server (${meta.serverVersion}) does not offer; it needs Varlatch 0.11.0 or later. Strict startup never falls back to a default run.`,
    );
    return STRICT_EXIT;
  }
  let retrieval: StrictRetrieval;
  try {
    retrieval = await api.strictRetrieval(opts.organization, opts.project, opts.environment);
  } catch (err) {
    if (!retryable(err)) throw err;
    retrieval = await api.strictRetrieval(opts.organization, opts.project, opts.environment);
  }
  if (retrieval.contract) checkAllowances(retrieval.contract as unknown as ConfigurationContract, opts.allowInherited);
  const plan = planStrictRun(retrieval, opts.parent, new Set(opts.allowInherited));
  if (plan.violations.length > 0) {
    for (const line of formatViolations(plan.violations)) opts.log(line);
    return STRICT_EXIT;
  }
  if (plan.outsideContract > 0) {
    opts.log(`varlatch: ${plan.outsideContract} delivered item(s) are not in the Contract; delivered as usual`);
  }
  return opts.start(plan.env);
}
