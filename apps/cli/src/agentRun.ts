// SPDX-License-Identifier: Apache-2.0
import { maintenanceNotice } from "./maintenance.js";
import { cliUserAgent } from "./userAgent.js";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AGENT_RUN_ENV, type ResolvedContext } from "@varlatch/context";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
import { canonicalTargets, type EffectiveConfiguration } from "@varlatch/protocol";
import { TUNNELS_PATH, generatePlaceholder, sameTargets, startBroker, type BrokerEvent } from "./broker.js";
import type { ConfigurationContract } from "@varlatch/contract";
import { RUN_CONTEXT, runChild } from "./inject.js";
import {
  STRICT_EXIT,
  UsageError,
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

/**
 * What isolates an Agent Run from the operator's credential store (ADR-0043
 * Decision 5): a fresh, empty configuration directory of its own, and the
 * run's identifier. A CLI started with VARLATCH_AGENT_RUN set never reads
 * the default store, so a `varlatch` command the Agent starts cannot fall
 * back to the operator's credential by accident. Same-OS-user access stays
 * out of scope (ADR-0022 Decision 16).
 */
export interface AgentIsolation {
  VARLATCH_CONFIG_DIR: string;
  [AGENT_RUN_ENV]: string;
}

/**
 * Run `start` with a per-run configuration directory, created private
 * (mode 0700) and removed when `start` settles, whatever its outcome.
 */
export async function withAgentIsolation<T>(runId: string, start: (isolation: AgentIsolation) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-agent-run-"));
  try {
    return await start({ VARLATCH_CONFIG_DIR: dir, [AGENT_RUN_ENV]: runId });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Start the Agent with its environment plus the run's isolation. */
function startAgent(runId: string, command: string, commandArgs: string[], env: NodeJS.ProcessEnv): Promise<number> {
  return withAgentIsolation(runId, (isolation) => runChild(command, commandArgs, { ...env, ...isolation }));
}

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
  /** `--target NAME=kind:location`, by item (ADR-0039 Decision 6). */
  targets: Record<string, string[]>;
  /** `--omit NAME`: stored Secrets left out of the run entirely. */
  omit: string[];
}

/** The minimum server for agent-safe runs: it records targets and reports the active Contract. */
const TARGETS_SERVER = "0.11.0";

/**
 * Every stored Secret is either targeted or omitted; a flag naming anything
 * else is a typo, never ignored. Returns the Secrets the run mediates and
 * their targets.
 */
export function checkTargetFlags(
  storedSecrets: string[],
  opts: Pick<AgentRunOptions, "targets" | "omit">,
): { mediated: string[]; targets: Record<string, string[]> } {
  const stored = new Set(storedSecrets);
  const omitted = new Set(opts.omit);
  const named = [...new Set([...Object.keys(opts.targets), ...omitted])];
  const unknown = named.filter((n) => !stored.has(n)).sort();
  if (unknown.length > 0) {
    throw new UsageError(`--target and --omit must name Secrets stored in this environment; not stored here: ${unknown.join(", ")}`);
  }
  const both = Object.keys(opts.targets).filter((n) => omitted.has(n)).sort();
  if (both.length > 0) throw new UsageError(`an item cannot be both targeted and omitted: ${both.join(", ")}`);
  const untargeted = [...stored].filter((n) => !omitted.has(n) && !opts.targets[n]).sort();
  if (untargeted.length > 0) {
    throw new UsageError(
      untargeted
        .map(
          (n) =>
            `${n} has no substitution target: add --target ${n}=header:authorization\n` +
            `          (or query:, json:, form:), or --omit ${n} to leave it out of this run`,
        )
        .join("\nvarlatch: "),
    );
  }
  const mediated = [...stored].filter((n) => !omitted.has(n)).sort();
  return { mediated, targets: Object.fromEntries(mediated.map((n) => [n, opts.targets[n]!])) };
}

/** Refuse a server that cannot record targets; never fall back to substituting anywhere. */
export async function requireTargetsServer(api: VarlatchClient): Promise<void> {
  const meta = await api.meta();
  if (!meta.capabilities.includes("capabilities.targets")) {
    throw new Error(
      `varlatch: agent-safe runs need Varlatch ${TARGETS_SERVER} or later on the server, which records substitution targets; ` +
        `this server is ${meta.serverVersion}. Nothing was started.`,
    );
  }
}

/**
 * The Contract's Secret names, so inherited copies can be stripped (ADR-0039
 * Decision 10). With an active Contract the run needs contract.read: it
 * never proceeds with stripping it could not complete.
 */
export async function contractSecrets(api: VarlatchClient, ctx: ResolvedContext, effective: EffectiveConfiguration): Promise<string[]> {
  if (!effective.manifest) {
    throw new Error(`varlatch: agent-safe runs need Varlatch ${TARGETS_SERVER} or later on the server. Nothing was started.`);
  }
  if (!effective.manifest.contract) return [];
  try {
    const revision = await api.getActiveContract(ctx.organization, ctx.project);
    const contract = revision.contract as unknown as ConfigurationContract | undefined;
    return (contract?.items ?? []).filter((i) => i.sensitive).map((i) => i.name);
  } catch (err) {
    if (!(err instanceof VarlatchApiError) || (err.status !== 403 && err.status !== 404)) throw err;
    throw new Error(
      "varlatch: this environment has an active Contract, and an agent-safe run needs contract.read to know which " +
        "inherited names are Secrets and remove them from the Agent's environment. Nothing was started.",
    );
  }
}

export function buildAgentEnv(
  base: NodeJS.ProcessEnv,
  effective: EffectiveConfiguration,
  placeholdersByItem: Map<string, string>,
  proxyUrl: string,
  agentCredential?: { server: string; token: string },
  strip: Iterable<string> = [],
): NodeJS.ProcessEnv {
  const env = { ...base };
  // The Broker credential is the parent's secret, never the child's — and
  // neither is the parent's own bearer (VARLATCH_TOKEN).
  delete env[BROKER_CREDENTIAL_ENV];
  delete env.VARLATCH_TOKEN;
  delete env[RUN_CONTEXT];
  // Stored and Contract Secrets inherited from the operator's shell never
  // reach the Agent; the ones the run carries come back as Placeholders.
  for (const name of strip) delete env[name];
  if (agentCredential) {
    env.VARLATCH_SERVER = agentCredential.server;
    env.VARLATCH_TOKEN = agentCredential.token;
  }
  for (const item of effective.items ?? []) {
    if (item.name === RUN_CONTEXT) continue;
    const placeholder = placeholdersByItem.get(item.name);
    if (placeholder !== undefined) env[item.name] = placeholder;
    else if (item.sensitive) delete env[item.name];
    else if (item.value !== null && item.value !== undefined) env[item.name] = item.value;
  }
  if (proxyUrl) setProxy(env, proxyUrl);
  return env;
}

/** A Placeholder, as the Broker issues them for the run's Secrets. */
const PLACEHOLDER_VALUE = /^vlch_ph_v1_[0-9a-f]{32}$/;

/**
 * The names in an Agent's environment that hold Placeholders: only these
 * are safe to show. Names only, never values. The environment also holds
 * the run's credentials and inherited variables that are not Placeholders.
 */
export function placeholderNames(env: NodeJS.ProcessEnv): string[] {
  return Object.entries(env)
    .filter(([, value]) => typeof value === "string" && PLACEHOLDER_VALUE.test(value))
    .map(([name]) => name)
    .sort();
}

/**
 * The run's own credentials in an Agent's environment, masked in the output
 * of a nested `varlatch run`: the agent-run credential (VARLATCH_TOKEN, with
 * --agent-metadata) and the Broker's proxy credential in the proxy URLs.
 */
export function agentRunCredentials(env: NodeJS.ProcessEnv): { item: string; value: string }[] {
  const out: { item: string; value: string }[] = [];
  if (env.VARLATCH_TOKEN) out.push({ item: "VARLATCH_TOKEN", value: env.VARLATCH_TOKEN });
  for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]) {
    const url = env[name];
    if (!url) continue;
    try {
      const password = decodeURIComponent(new URL(url).password);
      if (password && !out.some((e) => e.value === password)) out.push({ item: name, value: password });
    } catch {
      // Not a URL: nothing of the run's to mask.
    }
  }
  return out;
}

/**
 * The tunnels the run's Broker refused so far, by destination: a nested
 * `varlatch run` reads them before and after its command, to say what curl
 * does not. Undefined when the proxy is not the run's Broker or it does not
 * answer: the note is a hint, never a reason to fail the command.
 */
/** The counts are a few hundred bytes; the address comes from the Agent's environment. */
const TUNNELS_RESPONSE_LIMIT = 64 * 1024;

export async function refusedTunnels(env: NodeJS.ProcessEnv): Promise<Map<string, number> | undefined> {
  let proxy: URL;
  try {
    proxy = new URL(env.HTTPS_PROXY ?? env.https_proxy ?? "");
  } catch {
    return undefined;
  }
  if (proxy.hostname !== "127.0.0.1" || proxy.username !== "vlt" || !proxy.port) return undefined;
  const auth = Buffer.from(`vlt:${decodeURIComponent(proxy.password)}`).toString("base64");
  return new Promise((resolve) => {
    // A fresh agent: never Node's environment proxy, which is the Broker itself.
    const req = http.get(
      { host: "127.0.0.1", port: Number(proxy.port), path: TUNNELS_PATH, agent: false, timeout: 2000, headers: { "Proxy-Authorization": `Basic ${auth}` } },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          body += chunk;
          if (body.length > TUNNELS_RESPONSE_LIMIT) {
            res.destroy();
            resolve(undefined);
          }
        });
        res.on("error", () => resolve(undefined));
        res.on("end", () => {
          try {
            const { tunnels } = JSON.parse(body) as { tunnels?: { destination: string; count: number }[] };
            resolve(res.statusCode === 200 && Array.isArray(tunnels) ? new Map(tunnels.map((t) => [t.destination, t.count])) : undefined);
          } catch {
            resolve(undefined);
          }
        });
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(undefined));
  });
}

/**
 * What a nested `varlatch run` adds after its command when the Broker
 * refused a tunnel meanwhile (ADR-0043 agent evaluations, runs 8 and 10: an
 * Agent read curl's "CONNECT tunnel failed, response 502" as the API being
 * down). Destinations and a Placeholder name only, never a value.
 */
export function tunnelNote(
  before: Map<string, number> | undefined,
  after: Map<string, number> | undefined,
  placeholders: string[],
): string | undefined {
  if (!before || !after) return undefined;
  const refused = [...after].filter(([destination, n]) => n > (before.get(destination) ?? 0)).map(([destination]) => destination).sort();
  if (refused.length === 0) return undefined;
  const first = refused[0]!;
  const colon = first.lastIndexOf(":");
  const host = first.slice(0, colon).includes(":") ? `[${first.slice(0, colon)}]` : first.slice(0, colon);
  const port = first.slice(colon + 1);
  const url = `https://${host}${port === "443" ? "" : `:${port}`}/...`;
  return (
    `varlatch: while this command ran, the Broker refused an HTTPS tunnel to ${refused.join(", ")}. ` +
    "curl, fetch, and most SDKs open one, and agent-safe runs refuse it: the request never left this machine, " +
    "so this is not a network failure. Send the request with varlatch request instead, for example:\n" +
    `  varlatch --assisted request -H "Authorization: Bearer $${placeholders[0] ?? "API_KEY"}" ${url}`
  );
}

function setProxy(env: NodeJS.ProcessEnv, proxyUrl: string): void {
  env.HTTP_PROXY = proxyUrl;
  env.HTTPS_PROXY = proxyUrl;
  env.http_proxy = proxyUrl;
  env.https_proxy = proxyUrl;
  // Node's fetch (and, from Node 24, its http module) honours the proxy
  // variables only with this set (ADR-0039 Decision 11).
  env.NODE_USE_ENV_PROXY = "1";
  // With it set, Node would also proxy a request addressed to the Broker
  // itself and reject the absolute-URI form substitution needs.
  const removed = everyHostExemptions(env);
  Object.assign(env, agentNoProxy(env, new URL(proxyUrl).host));
  if (removed.length > 0) removedExemptions.set(env, removed);
}

/** What setProxy removed from an Agent's environment, for the run to name. */
const removedExemptions = new WeakMap<NodeJS.ProcessEnv, string[]>();

/** The inherited no-proxy entries removed from this Agent's environment, as `SPELLING=entry`. */
export function removedNoProxyEntries(env: NodeJS.ProcessEnv): string[] {
  return removedExemptions.get(env) ?? [];
}

/**
 * A no-proxy entry that exempts every destination, or every destination on
 * one port: `*`, `*:<port>`, or an address range with a /0 prefix
 * (`0.0.0.0/0`, `::/0`). Clients disagree about where in the list `*`
 * counts: curl, Python, and Node before 26.11 honour it only as the whole
 * value, Node from 26.11 (undici 8.11) anywhere in the list. Removing such
 * an entry is the only way it exempts nothing for every client.
 */
export function exemptsEveryHost(entry: string): boolean {
  const e = entry.trim().toLowerCase();
  return /^\*(:\d+)?$/.test(e) || /^\[?[0-9a-f.:]+\]?\/0$/.test(e);
}

function noProxyEntries(value: string | undefined): string[] {
  return (value ?? "").split(",").map((e) => e.trim()).filter(Boolean);
}

function everyHostExemptions(base: NodeJS.ProcessEnv): string[] {
  return (["NO_PROXY", "no_proxy"] as const).flatMap((spelling) =>
    noProxyEntries(base[spelling]).filter(exemptsEveryHost).map((entry) => `${spelling}=${entry}`),
  );
}

/**
 * The Agent's NO_PROXY and no_proxy: each spelling keeps the entries it
 * inherited, except one that exempts every host (see exemptsEveryHost),
 * and gains exactly the Broker's own address; a spelling that was unset
 * becomes that address alone. Clients disagree about which spelling wins
 * when both are set (Node 26 reads no_proxy first), so this is the only
 * rule under which, whatever spelling a client reads, the run adds no
 * exemption but the Broker's address. It can narrow an inherited exemption
 * (a client that fell back to the other spelling no longer sees it), never
 * widen one. Other inherited entries still bypass the Broker for clients
 * that read their spelling: a stated limit, even with --agent-network
 * strict.
 */
export function agentNoProxy(base: NodeJS.ProcessEnv, broker: string): { NO_PROXY: string; no_proxy: string } {
  const withBroker = (value: string | undefined) =>
    [...new Set([...noProxyEntries(value).filter((e) => !exemptsEveryHost(e)), broker])].join(",");
  return { NO_PROXY: withBroker(base.NO_PROXY), no_proxy: withBroker(base.no_proxy) };
}

/** Name the inherited Secrets a run removed, never their values. */
function reportStripped(base: NodeJS.ProcessEnv, names: Iterable<string>, carried: Set<string>): void {
  const stripped = [...new Set(names)].filter((n) => base[n] !== undefined && !carried.has(n)).sort();
  if (stripped.length > 0) {
    console.error(`varlatch: removed Secrets inherited from this shell from the Agent's environment: ${stripped.join(", ")}`);
  }
}

/** Issue with targets, and refuse unless varlatchd recorded exactly those. */
export async function issueWithTargets(
  brokerApi: VarlatchClient,
  ctx: ResolvedContext,
  input: Parameters<VarlatchClient["issueCapability"]>[3],
): Promise<Awaited<ReturnType<VarlatchClient["issueCapability"]>>> {
  const cap = await brokerApi.issueCapability(ctx.organization, ctx.project, ctx.environment, input);
  if (!cap.targets || !sameTargets(cap.targets, canonicalTargets(input.items, input.targets))) {
    await revokeQuietly(brokerApi, ctx, cap.id);
    throw new Error("varlatch: the server recorded different substitution targets than this run requested. Nothing was started.");
  }
  return cap;
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
  await requireTargetsServer(api);
  const effective = await api.effectiveConfiguration(ctx.organization, ctx.project, ctx.environment, {
    includeValues: true,
  });
  const storedSecrets = (effective.items ?? []).filter((i) => i.sensitive && i.name !== RUN_CONTEXT).map((i) => i.name);
  const { mediated: secretItems, targets } = checkTargetFlags(storedSecrets, opts);
  const strip = [...storedSecrets, ...(await contractSecrets(api, ctx, effective))];
  reportStripped(process.env, strip, new Set(secretItems));

  const agent = await findAgent(api, ctx, opts.agent);
  const runId = `run_${randomBytes(8).toString("hex")}`;
  const mintAgentCredential = (brokerApi: VarlatchClient) => mintFor(brokerApi, ctx, agent.id, runId, opts.ttlSeconds);

  if (secretItems.length === 0) {
    // Nothing to mediate: run with non-sensitive values and no broker.
    console.error("varlatch: no Secrets to mediate in this run; running without a broker");
    const minted = opts.metadataCredential
      ? await mintAgentCredential(new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts), userAgent: cliUserAgent() }))
      : undefined;
    const env = buildAgentEnv(process.env, effective, new Map(), "", minted?.credential, strip);
    delete env.HTTP_PROXY;
    delete env.HTTPS_PROXY;
    delete env.http_proxy;
    delete env.https_proxy;
    try {
      return await startAgent(runId, command, commandArgs, env);
    } finally {
      await minted?.revoke();
    }
  }

  if (opts.allowHosts.length === 0) {
    throw new Error(
      `This environment has ${secretItems.length} Secret(s); agent-safe runs need at least one --allow-host <host[:port]> destination`,
    );
  }

  const brokerApi = new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts), userAgent: cliUserAgent() });
  const cap = await issueWithTargets(brokerApi, ctx, {
    agentIdentityId: agent.id,
    items: secretItems,
    destinations: opts.allowHosts,
    targets,
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
      buildAgentEnv(process.env, effective, placeholdersByItem, proxyUrl, credential, strip),
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
  cap: { id: string; secret: string; destinations: string[]; targets: Record<string, string[]> };
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
  const exerciseApi = new VarlatchClient({ server: ctx.server, token: loadBrokerCredential(opts), maintenanceRetryMs: 15_000, userAgent: cliUserAgent() });
  const diagnostics = brokerDiagnostics();
  const broker = await startBroker({
    placeholders,
    destinations: cap.destinations,
    targets: cap.targets,
    strict: opts.strict,
    report: diagnostics.report,
    exercise: async (destination, placements) => {
      const result = await exerciseApi.exerciseCapability(
        ctx.organization,
        ctx.project,
        ctx.environment,
        cap.id,
        { capabilitySecret: cap.secret, destination, placements },
      );
      return {
        values: new Map(result.items.map((i) => [i.name, i.value])),
        retiring: new Map(result.items.flatMap((i) => (i.retiring ? [[i.name, i.retiring.value] as const] : []))),
        targets: result.targets,
        withheld: result.withheld,
      };
    },
  });

  const minted = run.mint ? await run.mint() : undefined;

  console.error(
    `varlatch: agent-safe run ${runId} — ${secretItems.length} Secret(s) as placeholders, ` +
      `broker on 127.0.0.1:${broker.port}, destinations: ${cap.destinations.join(", ")}` +
      (minted ? ", metadata credential issued" : ""),
  );

  try {
    const env = run.childEnv(placeholdersByItem, broker.proxyUrl, minted?.credential);
    const removed = removedNoProxyEntries(env);
    if (removed.length > 0) {
      console.error(
        `varlatch: removed inherited no-proxy entries that would send the Agent's requests around the Broker: ${removed.join(", ")}`,
      );
    }
    return await startAgent(runId, run.command, run.commandArgs, env);
  } finally {
    await broker.close();
    diagnostics.summarize();
    await minted?.revoke();
    await revokeQuietly(brokerApi, ctx, cap.id);
  }
}

/**
 * The run's Broker diagnostics (ADR-0039 Decisions 14 and 23): each blocked
 * or failed request and aborted response as it happens, each stray
 * Placeholder and unscrubbable Secret once, and counts by rule and by
 * scrubbed item at the end. Names, rules, and locations only, never a value.
 */
function brokerDiagnostics(): { report: (event: BrokerEvent) => void; summarize: () => void } {
  const counts = new Map<string, number>();
  const scrubbed = new Map<string, number>();
  const once = new Set<string>();
  const say = (key: string, line: string) => {
    if (once.has(key)) return;
    once.add(key);
    console.error(line);
  };
  return {
    report: (event) => {
      switch (event.kind) {
        case "stray":
          say(
            `stray ${event.item} ${event.surface}`,
            `varlatch-broker: ${event.item} placeholder forwarded unchanged in the ${event.surface}, which is not a target`,
          );
          return;
        case "scrubbed":
          scrubbed.set(event.item, (scrubbed.get(event.item) ?? 0) + event.count);
          return;
        case "unscrubbable":
          say(
            `short ${event.item}`,
            `varlatch-broker: ${event.item} is shorter than 8 bytes and is not scrubbed from responses`,
          );
          return;
        case "incomplete-prefix":
          console.error(
            `varlatch-broker: a response ended in the first ${event.length} bytes of ${event.item}, relayed unchanged (only complete values are scrubbed)`,
          );
          return;
        case "aborted":
          console.error(`varlatch-broker: aborted a response: ${event.reason}`);
          return;
        case "tunnel":
          counts.set("tunnel", (counts.get("tunnel") ?? 0) + 1);
          say(
            `tunnel ${event.destination}`,
            `varlatch-broker: refused an HTTPS tunnel to ${event.destination} (curl, fetch, and most SDKs open one); a request that uses a Secret goes through varlatch request`,
          );
          return;
        case "blocked":
        case "failed":
          counts.set(event.rule, (counts.get(event.rule) ?? 0) + 1);
          console.error(
            event.kind === "blocked"
              ? `varlatch-broker: blocked a request (${event.status}): ${event.message}`
              : `varlatch-broker: dropped a request after exercise (502): ${event.message}`,
          );
      }
    },
    summarize: () => {
      if (counts.size > 0) {
        const byRule = [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([rule, n]) => `${rule} ${n}`);
        console.error(`varlatch: the broker refused ${[...counts.values()].reduce((a, b) => a + b, 0)} request(s): ${byRule.join(", ")}`);
      }
      if (scrubbed.size > 0) {
        const byItem = [...scrubbed].sort(([a], [b]) => a.localeCompare(b)).map(([item, n]) => `${item} ${n}`);
        console.error(`varlatch: the broker replaced Secrets reflected in responses: ${byItem.join(", ")}`);
      }
    },
  };
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
  if (proxyUrl) setProxy(env, proxyUrl);
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
  if (!meta.capabilities.includes("retrieval.preflight") || !meta.capabilities.includes("capabilities.targets")) {
    log(
      `varlatch: --agent-safe --strict needs the agent-safe preflight and substitution targets, which this server (${meta.serverVersion}) does not offer; it needs Varlatch ${TARGETS_SERVER} or later. Nothing was started.`,
    );
    return STRICT_EXIT;
  }
  const agent = await findAgent(api, ctx, opts.agent);
  const runId = `run_${randomBytes(8).toString("hex")}`;
  const allow = new Set(opts.allowInherited);
  const brokerApi = new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token: loadBrokerCredential(opts), userAgent: cliUserAgent() });
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
    const storedSecrets = retrieval.items.filter((i) => i.sensitive && i.name !== RUN_CONTEXT).map((i) => i.name);
    const { targets } = checkTargetFlags(storedSecrets, opts);
    const omitted = new Set(opts.omit);
    const preliminary = planStrictRun(retrieval, process.env, allow, { agent: null }, omitted);
    const global = preliminary.violations.some((v) => v.kind === "contract" || v.kind === "semantics");
    if (global) return refuse(preliminary.violations);

    if (preliminary.mediated.length === 0) {
      // Nothing to mediate: no broker, no Capability.
      if (preliminary.violations.length > 0) return refuse(preliminary.violations);
      const minted = mint ? await mint() : undefined;
      try {
        return await startAgent(runId, command, commandArgs, agentEnvFrom(preliminary.env, new Map(), "", minted?.credential));
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
      cap = await issueWithTargets(brokerApi, ctx, {
        agentIdentityId: agent.id,
        items: preliminary.mediated,
        destinations: opts.allowHosts,
        targets: Object.fromEntries(preliminary.mediated.map((n) => [n, targets[n]!])),
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
    const plan = planStrictRun(retrieval, process.env, allow, { agent: agentFacts }, omitted);
    if (plan.violations.length > 0) {
      await revokeQuietly(brokerApi, ctx, cap.id);
      return refuse(plan.violations);
    }
    if (plan.outsideContract > 0) {
      log(`varlatch: ${plan.outsideContract} delivered item(s) are not in the Contract; delivered as usual`);
    }
    reportStripped(process.env, storedSecrets, new Set(plan.mediated));
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
