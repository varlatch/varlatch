// SPDX-License-Identifier: Apache-2.0
import { maintenanceNotice } from "./maintenance.js";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ResolvedContext } from "@varlatch/context";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { generatePlaceholder, startBroker } from "./broker.js";
import { runChild } from "./inject.js";

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
  if (agentCredential) {
    env.VARLATCH_SERVER = agentCredential.server;
    env.VARLATCH_TOKEN = agentCredential.token;
  }
  for (const item of effective.items ?? []) {
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

  const identities = await api.listIdentities(ctx.organization);
  const agent = identities.items.find(
    (i) => i.kind === "agent" && (i.name === opts.agent || i.id === opts.agent),
  );
  if (!agent) {
    throw new Error(
      `No agent identity "${opts.agent}" in ${ctx.organization}. Create one with the dashboard or the identities API (kind "agent").`,
    );
  }

  const runId = `run_${randomBytes(8).toString("hex")}`;

  // Metadata-credential mode (ADR-0023): the broker mints a short-lived,
  // read-only agent-run credential so the child can read configuration
  // metadata directly. Explicit opt-in; revoked on exit, TTL as fail-safe.
  const mintAgentCredential = async (brokerApi: VarlatchClient) => {
    const issued = await brokerApi.issueAgentCredential(ctx.organization, agent.id, {
      ttlSeconds: Math.min(opts.ttlSeconds, 3600),
      runId,
    });
    return {
      credential: { server: ctx.server, token: issued.token },
      revoke: () =>
        brokerApi
          .revokeAgentCredential(ctx.organization, agent.id, issued.id)
          .catch((err: unknown) => {
            if (!(err instanceof VarlatchApiError)) throw err;
          }),
    };
  };

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

  const minted = opts.metadataCredential ? await mintAgentCredential(brokerApi) : undefined;

  console.error(
    `varlatch: agent-safe run ${runId} — ${secretItems.length} Secret(s) as placeholders, ` +
      `broker on 127.0.0.1:${broker.port}, destinations: ${cap.destinations.join(", ")}` +
      (minted ? ", metadata credential issued" : ""),
  );

  try {
    return await runChild(
      command,
      commandArgs,
      buildAgentEnv(process.env, effective, placeholdersByItem, broker.proxyUrl, minted?.credential),
    );
  } finally {
    await broker.close();
    await minted?.revoke();
    // Best-effort revoke; the Capability's TTL is the fail-safe.
    await brokerApi
      .revokeCapability(ctx.organization, ctx.project, ctx.environment, cap.id)
      .catch((err: unknown) => {
        if (!(err instanceof VarlatchApiError)) throw err;
      });
  }
}
