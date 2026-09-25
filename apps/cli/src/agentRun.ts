// SPDX-License-Identifier: Apache-2.0
import { maintenanceNotice } from "./maintenance.js";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ResolvedContext } from "@varlatch/context";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { generatePlaceholder, startBroker } from "./broker.js";
import type { ConfigurationContract } from "@varlatch/contract";
import { RUN_CONTEXT, runChild } from "./inject.js";
import {
  STRICT_EXIT,
  checkAllowances,
  formatViolations,
  planStrictRun,
  retryOnce,
  type Violation,
} from "./strictRun.js";

/**
 * `varlatch run --agent-safe` (ADR-0022 §8): the trusted parent resolves
 * configuration and spawns the Agent child with non-sensitive values,
 * Placeholders for Secrets, and proxy configuration — no reusable Varlatch
 * credential. The Broker credential never enters the child's environment.
 */

export const BROKER_CREDENTIAL_ENV = "VARLATCH_BROKER_CREDENTIAL";

export interface AgentRunOptions {
  agent: string;
  brokerCredentialFile?: string | undefined;
  allowHosts: string[];
  strict: boolean;
  ttlSeconds: number;
  /**
   * ADR-0023 (foreseen by ADR-0022 §8): explicit opt-in that gives the child
   * a short-lived, read-only agent-run credential for direct metadata access.
   * Never the default.
   */
  metadataCredential: boolean;
}

export function buildAgentEnv(
  base: NodeJS.ProcessEnv,
  effective: EffectiveConfiguration,
  placeholdersByItem: Map<string, string>,
  proxyUrl: string,
  agentCredential?: { server: string; token: string },
): NodeJS.ProcessEnv {
  const env = { ...base };
  // The Broker credential is the parent's secret, never the child's — and
  // neither is the parent's own bearer (VARLATCH_TOKEN).
  delete env[BROKER_CREDENTIAL_ENV];
  delete env.VARLATCH_TOKEN;
  delete env[RUN_CONTEXT];
  if (agentCredential) {
    env.VARLATCH_SERVER = agentCredential.server;
    env.VARLATCH_TOKEN = agentCredential.token;
  }
  for (const item of effective.items ?? []) {
    if (item.name === RUN_CONTEXT) continue;
    const placeholder = placeholdersByItem.get(item.name);
    if (placeholder !== undefined) env[item.name] = placeholder;
    else if (item.value !== null && item.value !== undefined) env[item.name] = item.value;
  }
  env.HTTP_PROXY = proxyUrl;
  env.HTTPS_PROXY = proxyUrl;
  env.http_proxy = proxyUrl;
  env.https_proxy = proxyUrl;
  return env;
}

function loadBrokerCredential(opts: AgentRunOptions): string {
  if (opts.brokerCredentialFile) {
    return readFileSync(opts.brokerCredentialFile, "utf8").trim();
  }
  const fromEnv = process.env[BROKER_CREDENTIAL_ENV];
  if (fromEnv) return fromEnv.trim();
  throw new Error(
    `Agent-safe runs need a Broker credential: pass --broker-credential-file <path> or set ${BROKER_CREDENTIAL_ENV}`,
  );
}

export async function runAgentSafe(
  ctx: ResolvedContext,
  api: VarlatchClient,
  opts: AgentRunOptions,
  command: string,
  commandArgs: string[],
): Promise<number> {
  const effective = await api.effectiveConfiguration(ctx.organization, ctx.project, ctx.environment, {
    includeValues: true,
  });
  const secretItems = (effective.items ?? []).filter((i) => i.sensitive).map((i) => i.name);

  const agent = await findAgent(api, ctx, opts.agent);
  const runId = `run_${randomBytes(8).toString("hex")}`;
  const mintAgentCredential = (brokerApi: VarlatchClient) => mintFor(brokerApi, ctx, agent.id, runId, opts.ttlSeconds);

  if (secretItems.length === 0) {
    // Nothing to mediate: run with non-sensitive values and no broker.
    console.error("varlatch: no Secrets in this environment; running without a broker");
    const minted = opts.metadataCredential
      ? await mintAgentCredential(new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts) }))
      : undefined;
    const env = buildAgentEnv(process.env, effective, new Map(), "", minted?.credential);
    delete env.HTTP_PROXY;
    delete env.HTTPS_PROXY;
    delete env.http_proxy;
    delete env.https_proxy;
    try {
      return await runChild(command, commandArgs, env);
    } finally {
      await minted?.revoke();
    }
  }

  if (opts.allowHosts.length === 0) {
    throw new Error(
      `This environment has ${secretItems.length} Secret(s); agent-safe runs need at least one --allow-host <host[:port]> destination`,
    );
  }

  const brokerApi = new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts) });
  const cap = await brokerApi.issueCapability(ctx.organization, ctx.project, ctx.environment, {
    agentIdentityId: agent.id,
    items: secretItems,
    destinations: opts.allowHosts,
    ttlSeconds: opts.ttlSeconds,
    runId,
  });
  if (cap.preflight === "agent-lacks-secret-use") {
    console.error(
      `varlatch: warning — agent "${opts.agent}" currently has no secret.use Grant here; exercises will be denied until one is granted`,
    );
  }

  return runMediated({
    ctx,
    opts,
    brokerApi,
    cap,
    secretItems,
    runId,
    command,
    commandArgs,
    mint: opts.metadataCredential ? () => mintAgentCredential(brokerApi) : undefined,
    childEnv: (placeholdersByItem, proxyUrl, credential) =>
      buildAgentEnv(process.env, effective, placeholdersByItem, proxyUrl, credential),
  });
}

interface Minted {
  credential: { server: string; token: string };
  revoke: () => Promise<void>;
}

/**
 * Placeholders for `secretItems`, a Broker exercising the Capability, the
 * child with the environment `childEnv` builds, and teardown: the Broker
 * closes, a minted metadata credential and the Capability are revoked.
 */
async function runMediated(run: {
  ctx: ResolvedContext;
  opts: AgentRunOptions;
  brokerApi: VarlatchClient;
  cap: { id: string; secret: string; destinations: string[] };
  secretItems: string[];
  runId: string;
  command: string;
  commandArgs: string[];
  mint: (() => Promise<Minted>) | undefined;
  childEnv: (
    placeholdersByItem: Map<string, string>,
    proxyUrl: string,
    credential: Minted["credential"] | undefined,
  ) => NodeJS.ProcessEnv;
}): Promise<number> {
  const { ctx, opts, brokerApi, cap, secretItems, runId } = run;
  const placeholdersByItem = new Map<string, string>();
  const placeholders = new Map<string, string>();
  for (const name of secretItems) {
    const token = generatePlaceholder();
    placeholdersByItem.set(name, token);
    placeholders.set(token, name);
  }

  // An agent's request is waiting on each exercise: during isolating
  // maintenance give up quickly and let the broker answer 503 + Retry-After.
  const exerciseApi = new VarlatchClient({ server: ctx.server, token: loadBrokerCredential(opts), maintenanceRetryMs: 15_000 });
  const broker = await startBroker({
    placeholders,
    destinations: cap.destinations,
    strict: opts.strict,
    exercise: async (destination) => {
      const result = await exerciseApi.exerciseCapability(
        ctx.organization,
        ctx.project,
        ctx.environment,
        cap.id,
        { capabilitySecret: cap.secret, destination },
      );
      return new Map(result.items.map((i) => [i.name, i.value]));
    },
  });

  const minted = run.mint ? await run.mint() : undefined;

  console.error(
    `varlatch: agent-safe run ${runId} — ${secretItems.length} Secret(s) as placeholders, ` +
      `broker on 127.0.0.1:${broker.port}, destinations: ${cap.destinations.join(", ")}` +
      (minted ? ", metadata credential issued" : ""),
  );

  try {
    return await runChild(run.command, run.commandArgs, run.childEnv(placeholdersByItem, broker.proxyUrl, minted?.credential));
  } finally {
    await broker.close();
    await minted?.revoke();
    await revokeQuietly(brokerApi, ctx, cap.id);
  }
}

/** Best-effort revoke; the Capability's TTL is the fail-safe. */
async function revokeQuietly(brokerApi: VarlatchClient, ctx: ResolvedContext, capabilityId: string): Promise<void> {
  await brokerApi
    .revokeCapability(ctx.organization, ctx.project, ctx.environment, capabilityId)
    .catch((err: unknown) => {
      if (!(err instanceof VarlatchApiError)) throw err;
    });
}

async function findAgent(api: VarlatchClient, ctx: ResolvedContext, name: string): Promise<{ id: string }> {
  const identities = await api.listIdentities(ctx.organization);
  const agent = identities.items.find((i) => i.kind === "agent" && (i.name === name || i.id === name));
  if (!agent) {
    throw new Error(
      `No agent identity "${name}" in ${ctx.organization}. Create one with the dashboard or the identities API (kind "agent").`,
    );
  }
  return agent;
}

/**
 * Metadata-credential mode (ADR-0023): the broker mints a short-lived,
 * read-only agent-run credential so the child can read configuration
 * metadata directly. Explicit opt-in; revoked on exit, TTL as fail-safe.
 */
async function mintFor(
  brokerApi: VarlatchClient,
  ctx: ResolvedContext,
  agentId: string,
  runId: string,
  ttlSeconds: number,
): Promise<Minted> {
  const issued = await brokerApi.issueAgentCredential(ctx.organization, agentId, {
    ttlSeconds: Math.min(ttlSeconds, 3600),
    runId,
  });
  return {
    credential: { server: ctx.server, token: issued.token },
    revoke: () =>
      brokerApi
        .revokeAgentCredential(ctx.organization, agentId, issued.id)
        .then(() => undefined)
        .catch((err: unknown) => {
          if (!(err instanceof VarlatchApiError)) throw err;
        }),
  };
}

/**
 * The Agent's environment from a strict plan: the plan's values, defaults,
 * allowed inherited values, and run context; Placeholders for Secrets; the
 * proxy; and no Broker credential or operator bearer.
 */
function agentEnvFrom(
  base: NodeJS.ProcessEnv,
  placeholdersByItem: Map<string, string>,
  proxyUrl: string,
  credential: Minted["credential"] | undefined,
): NodeJS.ProcessEnv {
  const env = { ...base };
  delete env[BROKER_CREDENTIAL_ENV];
  delete env.VARLATCH_TOKEN;
  if (credential) {
    env.VARLATCH_SERVER = credential.server;
    env.VARLATCH_TOKEN = credential.token;
  }
  for (const [name, placeholder] of placeholdersByItem) env[name] = placeholder;
  if (proxyUrl) {
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.http_proxy = proxyUrl;
    env.https_proxy = proxyUrl;
  }
  return env;
}

/**
 * `varlatch run --agent-safe --strict` (ADR-0038 Decision 7): the operator's
 * preflight retrieval (non-sensitive values, a verdict per Secret when the
 * operator holds secret.reveal, never a Secret value), then the Broker's
 * issuance bound to that state by a precondition. A changed state retries
 * both once. The Agent starts only if the strict plan has no violation;
 * every exercise still evaluates authorization and resolves references or
 * denies.
 */
export async function runAgentSafeStrict(
  ctx: ResolvedContext,
  api: VarlatchClient,
  opts: AgentRunOptions & { allowInherited: string[] },
  command: string,
  commandArgs: string[],
): Promise<number> {
  const log = (line: string) => console.error(line);
  const meta = await api.meta();
  if (!meta.capabilities.includes("retrieval.preflight")) {
    log(
      `varlatch: --agent-safe --strict needs the agent-safe preflight, which this server (${meta.serverVersion}) does not offer; it needs Varlatch 0.11.0 or later. Nothing was started.`,
    );
    return STRICT_EXIT;
  }
  const agent = await findAgent(api, ctx, opts.agent);
  const runId = `run_${randomBytes(8).toString("hex")}`;
  const allow = new Set(opts.allowInherited);
  const brokerApi = new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts) });
  const mint = opts.metadataCredential ? () => mintFor(brokerApi, ctx, agent.id, runId, opts.ttlSeconds) : undefined;
  const refuse = (violations: Violation[]) => {
    for (const line of formatViolations(violations)) log(line);
    return STRICT_EXIT;
  };

  for (let attempt = 0; ; attempt++) {
    const retrieval = await retryOnce(() =>
      api.strictRetrieval(ctx.organization, ctx.project, ctx.environment, "preflight"),
    );
    if (retrieval.contract) {
      checkAllowances(retrieval.contract as unknown as ConfigurationContract, opts.allowInherited, { agentSafe: true });
    }
    const preliminary = planStrictRun(retrieval, process.env, allow, { agent: null });
    const global = preliminary.violations.some((v) => v.kind === "contract" || v.kind === "semantics");
    if (global) return refuse(preliminary.violations);

    if (preliminary.mediated.length === 0) {
      // Nothing to mediate: no broker, no Capability.
      if (preliminary.violations.length > 0) return refuse(preliminary.violations);
      const minted = mint ? await mint() : undefined;
      try {
        return await runChild(command, commandArgs, agentEnvFrom(preliminary.env, new Map(), "", minted?.credential));
      } finally {
        await minted?.revoke();
      }
    }
    if (opts.allowHosts.length === 0) {
      throw new Error(
        `This environment has ${preliminary.mediated.length} Secret(s); agent-safe runs need at least one --allow-host <host[:port]> destination`,
      );
    }

    let cap: Awaited<ReturnType<VarlatchClient["issueCapability"]>>;
    try {
      cap = await brokerApi.issueCapability(ctx.organization, ctx.project, ctx.environment, {
        agentIdentityId: agent.id,
        items: preliminary.mediated,
        destinations: opts.allowHosts,
        ttlSeconds: opts.ttlSeconds,
        runId,
        precondition: {
          projectId: retrieval.manifest.projectId,
          environmentId: retrieval.manifest.environment.id,
          stateDigest: retrieval.stateDigest,
          stateDigests: retrieval.stateDigests,
        },
      });
    } catch (err) {
      if (!(err instanceof VarlatchApiError) || err.code !== "STATE_CHANGED") throw err;
      if (attempt === 0) continue;
      const categories = ((err.details?.categories as string[] | undefined) ?? []).join(", ");
      log(`varlatch: the configuration changed during the preflight twice (${categories}); the command was not started`);
      return STRICT_EXIT;
    }

    const agentFacts = new Map((cap.preflightItems ?? []).map((i) => [i.name, i]));
    const plan = planStrictRun(retrieval, process.env, allow, { agent: agentFacts });
    if (plan.violations.length > 0) {
      await revokeQuietly(brokerApi, ctx, cap.id);
      return refuse(plan.violations);
    }
    if (plan.outsideContract > 0) {
      log(`varlatch: ${plan.outsideContract} delivered item(s) are not in the Contract; delivered as usual`);
    }
    return runMediated({
      ctx,
      opts,
      brokerApi,
      cap,
      secretItems: plan.mediated,
      runId,
      command,
      commandArgs,
      mint,
      childEnv: (placeholdersByItem, proxyUrl, credential) => agentEnvFrom(plan.env, placeholdersByItem, proxyUrl, credential),
    });
  }
}
