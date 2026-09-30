#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { maintenanceNotice } from "./maintenance.js";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ContextError,
  REPO_CONFIG_FILE,
  agentRunOf,
  deleteCredential,
  findRepoRoot,
  listCredentials,
  loadCredential,
  loadLocalState,
  loadToken,
  resolveContext,
  saveCredential,
  saveLocalState,
  type LocalState,
  type ResolvedContext,
} from "@varlatch/context";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
import { TargetError, formatTarget, parseTarget } from "@varlatch/protocol";
import { EnvSchemaParseError, parseEnvSchema, resolveDraft, UnknownEnvironmentNameError } from "@varlatch/env-schema";
import { RUN_CONTEXT, buildEnv, runChild, withheldItems } from "./inject.js";
import { deliveredSecrets, redactRefusal } from "./redact.js";
import { resolveAssisted, takeAssistedOption, type AssistedMode } from "./assisted.js";
import { assistedGate, assistedRedactionSet, knownSecretNames, planAssistedRedaction } from "./assistedRun.js";
import { STRICT_EXIT } from "./strictRun.js";
import {
  SecretInputError,
  describeGenerated,
  generateValue,
  isWellFormedText,
  parseValueSource,
  promptHidden,
  readAll,
  readValueFile,
  valueFromBytes,
  type GenerateSpec,
} from "./secretInput.js";
import { validationOutcome } from "./validation.js";
import { obtainOidcIdToken } from "./oidcLogin.js";
import { replacedCredential, revokeStoredCredential } from "./revoke.js";
import {
  STATUS_SCHEMA_VERSION,
  expiryWarning,
  formatStatusHuman,
  repoStatus,
  serverStatus,
  type ProbeState,
  type ServerStatus,
  type StatusDocument,
} from "./status.js";

/**
 * The varlatch CLI. Deliberately thin over @varlatch/sdk and
 * @varlatch/context; it uses the same stable /v1 surface as any third-party
 * client (ADR-0018 §7) and never prints secret Values except where the
 * command's purpose is disclosure.
 */

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

/** Positional at `i`, or undefined when that slot is a flag (or a flag's
    value) rather than a positional — `project create web --org acme` must not
    read "--org" as the display name. */
function positional(args: string[], i: number): string | undefined {
  const value = args[i];
  if (value === undefined || value.startsWith("-")) return undefined;
  const previous = args[i - 1];
  if (previous !== undefined && previous.startsWith("-")) return undefined;
  return value;
}

function flags(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === name && args[i + 1] !== undefined) values.push(args[i + 1] as string);
  }
  return values;
}

/**
 * `--target NAME=kind:location`, repeatable (ADR-0039 Decision 6). Targets
 * come only from the operator's command line, never from the repository.
 */
function targetFlags(args: string[]): Record<string, string[]> {
  const targets: Record<string, string[]> = {};
  for (const raw of flags(args, "--target")) {
    const eq = raw.indexOf("=");
    const name = eq < 0 ? "" : raw.slice(0, eq);
    if (!name) fail(`--target expects NAME=kind:location (for example API_KEY=header:authorization), got "${raw}"`);
    try {
      (targets[name] ??= []).push(formatTarget(parseTarget(raw.slice(eq + 1))));
    } catch (err) {
      if (!(err instanceof TargetError)) throw err;
      fail(`--target ${raw}: ${err.message}`);
    }
  }
  return targets;
}

function context(args: string[]): ResolvedContext {
  const opts: Parameters<typeof resolveContext>[0] = { cwd: process.cwd() };
  const environment = flag(args, "--environment") ?? flag(args, "-e");
  if (environment) opts.environment = environment;
  const server = flag(args, "--server");
  if (server) opts.server = server;
  return resolveContext(opts);
}

/** ADR-0032: stderr only, and always before any child process spawns —
    consumer scripts parse `varlatch run` stdout. Silent for VARLATCH_TOKEN
    (CI credentials are short-lived by design). */
function warnIfExpiring(server: string): void {
  if (process.env.VARLATCH_TOKEN) return;
  const warning = expiryWarning(server, loadCredential(server));
  if (warning) console.error(warning);
}

function client(ctx: ResolvedContext): VarlatchClient {
  const token = loadToken(ctx.server);
  const agentRun = agentRunOf();
  if (!token && agentRun) {
    // ADR-0043 Decision 5: never the operator's stored credential.
    fail(
      `Not authenticated to ${ctx.server}: this command runs inside agent-safe run ${agentRun}, which gives the ` +
        "Agent no Varlatch credential and never uses the operator's.\nFor read access to configuration metadata, " +
        "the operator relaunches the run with --agent-metadata.",
    );
  }
  if (!token) {
    fail(
      `Not authenticated to ${ctx.server}.\nRun: varlatch login --server ${ctx.server} --token <credential>`,
    );
  }
  warnIfExpiring(ctx.server);
  return new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token });
}

async function probeServer(
  server: string,
  token: string,
): Promise<{ state: ProbeState; detail: string | null }> {
  try {
    const api = new VarlatchClient({ onMaintenance: maintenanceNotice, server, token });
    await api.meta();
    // Verifies the credential AND identifies it: OwnCredential.current marks
    // the one authenticating this request, so a probe can backfill store
    // metadata that pre-ADR-0032 logins never recorded.
    const credentials = await api.listMyCredentials();
    const current = credentials.items.find((c) => c.current);
    const stored = loadCredential(server);
    if (current && stored?.token === token) {
      const backfilled = {
        ...stored,
        ...(current.expiresAt ? { expiresAt: current.expiresAt } : {}),
        credentialId: current.id,
        ...(current.name ? { name: current.name } : {}),
        issuedAt: stored.issuedAt ?? current.createdAt,
      };
      if (JSON.stringify(backfilled) !== JSON.stringify(stored)) saveCredential(server, backfilled);
    }
    return { state: "valid", detail: null };
  } catch (err) {
    if (err instanceof VarlatchApiError) return { state: "invalid", detail: err.code };
    return { state: "unreachable", detail: err instanceof Error ? err.message : String(err) };
  }
}

async function browserLogin(server: string): Promise<string> {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  return new Promise((resolve, reject) => {
    const httpServer = createServer((req, res) => {
      const origin = new URL(server).origin;
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      // Chrome Local Network Access: page -> loopback requires this on the
      // preflight or the fetch fails with a bare "Failed to fetch".
      res.setHeader("Access-Control-Allow-Private-Network", "true");
      if (req.method === "OPTIONS") return res.writeHead(204).end();
      if (req.method !== "POST") return res.writeHead(405).end();
      let body = "";
      req.on("data", (chunk: Buffer) => (body += chunk.toString()));
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{}");
        try {
          const { token } = JSON.parse(body) as { token?: string };
          if (!token) throw new Error("no token in callback");
          httpServer.close();
          clearTimeout(timer);
          resolve(token);
        } catch (err) {
          httpServer.close();
          clearTimeout(timer);
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });
    const timer = setTimeout(() => {
      httpServer.close();
      reject(new Error("Browser login timed out after 5 minutes"));
    }, 5 * 60 * 1000);
    httpServer.listen(0, "127.0.0.1", () => {
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      const url = `${server.replace(/\/+$/, "")}/enroll?callback=${encodeURIComponent(`http://127.0.0.1:${port}/`)}`;
      console.log("Complete passkey sign-in in your browser:");
      console.log(`  ${url}`);
      spawn(process.platform === "darwin" ? "open" : "xdg-open", [url], {
        stdio: "ignore",
        detached: true,
      }).on("error", () => {/* headless: user opens manually */});
    });
  });
}

/**
 * Whether `item` is a Secret by the active Contract: items outside it, and
 * every item of a project without one, are (ADR-0012). A caller that cannot
 * read the Contract treats the item as a Secret, the safe classification.
 */
async function sensitiveItem(api: VarlatchClient, ctx: ResolvedContext, item: string): Promise<boolean> {
  try {
    const revision = await api.getActiveContract(ctx.organization, ctx.project);
    const contract = revision.contract as unknown as { items?: { name: string; sensitive: boolean }[] };
    return contract.items?.find((i) => i.name === item)?.sensitive ?? true;
  } catch (err) {
    if (err instanceof VarlatchApiError && (err.status === 404 || err.status === 403)) return true;
    throw err;
  }
}

/**
 * The value for `values set` or `values rotate` (ADR-0043 Decision 2), from
 * the one source given. In assisted mode a Secret's value is never taken
 * from the command line, and there is no prompt: a coding agent cannot type
 * into one, and the human uses their own terminal instead.
 */
async function obtainValue(
  sub: "set" | "rotate",
  item: string,
  args: string[],
  mode: AssistedMode,
  sensitive: () => Promise<boolean>,
): Promise<{ value: string; generated?: GenerateSpec }> {
  const safeForms = [
    "  Store it without putting the value in a command:",
    `    varlatch --assisted values ${sub} ${item} --generate hex:32       a new random value`,
    `    varlatch --assisted values ${sub} ${item} --from-file <path>      from a file`,
    `    <command> | varlatch --assisted values ${sub} ${item} --stdin     from another command's output`,
    `  Or ask the human to run \`varlatch values ${sub} ${item}\` in their own terminal (a hidden prompt), or to use the dashboard.`,
  ].join("\n");
  try {
    const source = parseValueSource(args);
    switch (source.kind) {
      case "argument":
        if (mode.on && (await sensitive())) {
          fail(
            `varlatch: ${item} is a Secret, and in assisted mode a Secret's value is never taken from the command line. ` +
              `Nothing was stored.\n${safeForms}`,
          );
        }
        return { value: source.value };
      case "stdin":
        if (process.stdin.isTTY) {
          fail(`varlatch: --stdin reads a pipe or a file, and standard input is a terminal. For a hidden prompt, leave the value out: varlatch values ${sub} ${item}`);
        }
        return { value: valueFromBytes(await readAll(process.stdin), "standard input") };
      case "file":
        return { value: readValueFile(source.path) };
      case "generate":
        return { value: generateValue(source.spec), generated: source.spec };
      case "prompt":
        if (mode.on) fail(`varlatch: no value given for ${item}, and assisted mode never prompts. Nothing was stored.\n${safeForms}`);
        if (!process.stdin.isTTY) {
          fail(
            `varlatch: no value given for ${item}. Pass --stdin, --from-file <path>, or --generate <spec>, ` +
              "or run the command in a terminal for a hidden prompt.",
          );
        }
        return { value: await promptHidden(`Value for ${item} (input hidden): `) };
    }
  } catch (err) {
    if (err instanceof SecretInputError) fail(`varlatch: ${err.message}`);
    throw err;
  }
}

async function main(): Promise<void> {
  // The global --assisted option (ADR-0043 Decision 3): taken from the CLI's
  // own arguments, never from a command's after `--`.
  const taken = takeAssistedOption(process.argv.slice(2));
  const [command, ...args] = taken.argv;
  const assisted = resolveAssisted(taken.given, process.env);
  try {
    switch (command) {
      case "login": {
        const server = flag(args, "--server") ?? fail("Usage: varlatch login --server <url> [--token <credential>|--oidc]");
        let token = flag(args, "--token");
        // Issuance metadata (ADR-0032): stored so expiry is knowable offline.
        // Explicit --token has none — its entry stays metadata-free.
        let issuedMeta: { id: string; expiresAt: string } | undefined;
        if (!token && has(args, "--oidc")) {
          // CI federation (capability auth.oidc): exchange the platform's
          // OIDC ID token for a short-lived credential; nothing stored in
          // the pipeline's secrets at all.
          const organization = flag(args, "--org") ?? fail("OIDC login requires --org <organization>");
          const idToken = await obtainOidcIdToken({
            explicitToken: flag(args, "--oidc-token"),
            audience: flag(args, "--audience"),
          });
          const ttlFlag = flag(args, "--ttl");
          const anonymous = new VarlatchClient({ onMaintenance: maintenanceNotice, server });
          const issued = await anonymous.exchangeOidcToken({
            token: idToken,
            organization,
            ...(ttlFlag ? { ttlSeconds: Number(ttlFlag) } : {}),
          });
          token = issued.token;
          issuedMeta = issued;
          console.log(`OIDC exchange succeeded (credential expires ${issued.expiresAt}).`);
        }
        if (!token) {
          // Browser handoff (ADR-0017): loopback listener + passkey sign-in.
          // The callback delivers a 15-minute session bearer; exchange it
          // immediately for a longer-lived CLI credential (ADR-0024; the
          // bearer is revoked server-side by the exchange).
          const handoff = await browserLogin(server);
          const ttlFlag = flag(args, "--ttl");
          const issued = await new VarlatchClient({ onMaintenance: maintenanceNotice, server, token: handoff }).exchangeCliCredential(
            ttlFlag ? { ttlSeconds: Number(ttlFlag) } : {},
          );
          token = issued.token;
          issuedMeta = issued;
          console.log(`Issued CLI credential (expires ${issued.expiresAt}).`);
        }
        const probe = new VarlatchClient({ onMaintenance: maintenanceNotice, server, token });
        const meta = await probe.meta();
        await probe.listOrganizations(); // verifies the credential
        const replaced = replacedCredential(loadCredential(server), token);
        saveCredential(server, {
          token,
          issuedAt: new Date().toISOString(),
          ...(issuedMeta ? { expiresAt: issuedMeta.expiresAt, credentialId: issuedMeta.id } : {}),
        });
        console.log(`Logged in to ${server} (server ${meta.serverVersion}, API v${meta.apiMajor}).`);
        if (replaced) {
          // Revoke only after the new credential is verified and stored: a
          // failed or abandoned login must never leave the user signed out.
          const failure = await revokeStoredCredential(replaced, (id) =>
            new VarlatchClient({ onMaintenance: maintenanceNotice, server, token: replaced.token }).revokeMyCredential(id),
          );
          if (failure === null) {
            console.log("Previous credential revoked.");
          } else {
            console.error(
              `varlatch: previous credential not revoked (${failure}) — it may remain live` +
                `${replaced.expiresAt ? ` until ${replaced.expiresAt}` : ""}.`,
            );
          }
        }
        return;
      }

      case "init": {
        const root = findRepoRoot(process.cwd());
        if (root) fail(`${REPO_CONFIG_FILE} already exists at ${root}`);
        const org = flag(args, "--org") ?? fail("Usage: varlatch init --org <slug> --project <slug> [--server <url>] [--default-environment <name>]");
        const project = flag(args, "--project") ?? fail("Provide --project");
        const server = flag(args, "--server");
        const defaultEnv = flag(args, "--default-environment") ?? "development";
        const lines = [
          ...(server ? [`server = "${server}"`] : []),
          `organization = "${org}"`,
          `project = "${project}"`,
          `default_environment = "${defaultEnv}"`,
          "",
        ];
        writeFileSync(join(process.cwd(), REPO_CONFIG_FILE), lines.join("\n"));
        console.log(`Wrote ${REPO_CONFIG_FILE}. Commit it; it contains no credentials.`);
        return;
      }

      case "logout": {
        // ADR-0032: revoke server-side, delete locally regardless, and say
        // exactly which of the two happened.
        const stored = listCredentials();
        if (stored.length === 0) fail("No stored credentials.");
        let targets: typeof stored;
        if (has(args, "--all")) {
          targets = stored;
        } else {
          const server =
            flag(args, "--server") ??
            (stored.length === 1
              ? (stored[0] as (typeof stored)[number]).server
              : fail(
                  `Multiple servers stored (${stored.map((s) => s.server).join(", ")}). Pass --server <url> or --all.`,
                ));
          const key = server.replace(/\/+$/, "");
          const match = stored.find((s) => s.server === key) ?? fail(`No stored credential for ${server}`);
          targets = [match];
        }
        for (const { server, credential } of targets) {
          const revokeFailure = await revokeStoredCredential(credential, (id) =>
            new VarlatchClient({ onMaintenance: maintenanceNotice, server, token: credential.token }).revokeMyCredential(id),
          );
          deleteCredential(server);
          if (revokeFailure === null) {
            console.log(`${server}: credential revoked and removed.`);
          } else {
            console.log(
              `${server}: removed locally; server revocation failed (${revokeFailure}) — the credential may remain live` +
                `${credential.expiresAt ? ` until ${credential.expiresAt}` : ""}.`,
            );
          }
        }
        return;
      }

      case "status": {
        const servers: ServerStatus[] = [];
        for (const { server, credential } of listCredentials()) {
          if (has(args, "--probe")) {
            const probe = await probeServer(server, credential.token);
            // The probe may have backfilled metadata; report the stored state
            // as it is now, not as it was before the probe.
            const entry = serverStatus(server, loadCredential(server) ?? credential);
            entry.probe = probe;
            servers.push(entry);
          } else {
            servers.push(serverStatus(server, credential));
          }
        }
        let repo: StatusDocument["repo"] = null;
        const root = findRepoRoot(process.cwd());
        if (root) {
          try {
            repo = repoStatus(context(args), loadLocalState(root));
          } catch {
            // Inside a repo with incomplete context: user-level status still prints.
          }
        }
        const doc: StatusDocument = { version: STATUS_SCHEMA_VERSION, servers, repo };
        console.log(has(args, "--json") ? JSON.stringify(doc, null, 2) : formatStatusHuman(doc));
        return;
      }

      case "context": {
        const ctx = context(args);
        const repo = repoStatus(ctx, loadLocalState(ctx.repoRoot));
        if (has(args, "--json")) {
          console.log(JSON.stringify({ version: STATUS_SCHEMA_VERSION, ...repo }, null, 2));
          return;
        }
        console.log(`Server        ${ctx.server}`);
        console.log(`Organization  ${ctx.organization}`);
        console.log(`Project       ${ctx.project}`);
        console.log(`Environment   ${ctx.environment}`);
        console.log(`Source        ${ctx.environmentSource}`);
        if (repo.tier) console.log(`Tier          ${repo.tier} (cached ${repo.tierCachedAt})`);
        console.log(`Repo root     ${ctx.repoRoot}`);
        return;
      }

      case "env": {
        const sub = args[0];
        if (sub === "use") {
          const name = args[1] ?? fail("Usage: varlatch env use <environment>");
          const root = findRepoRoot(process.cwd()) ?? fail(`No ${REPO_CONFIG_FILE} found`);
          // Tier cache (ADR-0032): best-effort at selection time; offline or
          // unauthenticated selection still succeeds, just without a tier.
          // `env use` is the ONLY writer — `env list` runs from CI across
          // tracked directories and must never dirty a working tree.
          let tier: string | undefined;
          try {
            const ctx = resolveContext({ cwd: process.cwd(), environment: name });
            const token = loadToken(ctx.server);
            if (token) {
              const envs = await new VarlatchClient({ onMaintenance: maintenanceNotice, server: ctx.server, token }).listEnvironments(
                ctx.organization,
                ctx.project,
              );
              tier = envs.items.find((e) => e.name === name)?.tier;
            }
          } catch {
            /* tier stays uncached */
          }
          const state: LocalState = { ...loadLocalState(root), selectedEnvironment: name };
          delete state.selectedTier;
          delete state.tierCachedAt;
          if (tier) {
            state.selectedTier = tier;
            state.tierCachedAt = new Date().toISOString();
          }
          saveLocalState(root, state);
          console.log(`Selected ${name} for this repository${tier ? ` (tier ${tier})` : ""}.`);
          return;
        }
        if (sub === "list") {
          const ctx = context(args);
          const envs = await client(ctx).listEnvironments(ctx.organization, ctx.project);
          if (has(args, "--json")) {
            // Machine surface (ADR-0032). The human format below is frozen:
            // consumers regex-parse it in CI.
            const environments = envs.items.map((e) => ({
              name: e.name,
              tier: e.tier,
              kind: e.kind,
              selected: e.name === ctx.environment,
            }));
            console.log(JSON.stringify({ version: STATUS_SCHEMA_VERSION, environments }, null, 2));
            return;
          }
          for (const e of envs.items) {
            const marks = [e.tier, e.kind, e.name === ctx.environment ? "selected" : null]
              .filter(Boolean)
              .join(", ");
            console.log(`${e.name}  (${marks})`);
          }
          return;
        }
        fail("Usage: varlatch env <use|list>");
        return;
      }

      case "run": {
        const sep = args.indexOf("--");
        if (sep < 0 || sep === args.length - 1) {
          fail(
            "Usage: varlatch run [--environment <name>] [--export-context | --strict [--allow-inherited <NAME>]...] [--redact | --no-redact] [--allow-unmasked <NAME>]... [--agent-safe --agent <identity> --allow-host <host[:port]>... --target <NAME=kind:location>... --omit <NAME>...] -- <command> [args...]",
          );
        }
        const preArgs = args.slice(0, sep);
        const agentRun = agentRunOf();
        if (agentRun) {
          // A `varlatch run` the Agent starts inside an agent-safe run
          // (ADR-0043 Decision 5): never disclose, never fall back to the
          // operator's credential. The command gets this run's environment,
          // Placeholders included.
          const unavailable = ["--agent-safe", "--strict", "--export-context"].filter((f) => has(preArgs, f));
          if (unavailable.length > 0) {
            fail(
              `varlatch: this command runs inside agent-safe run ${agentRun}, where Secrets are Placeholders and are never ` +
                `disclosed, so ${unavailable.join(" and ")} cannot run here. Nothing was started.`,
            );
          }
          console.error(
            `varlatch: inside agent-safe run ${agentRun}, Secrets are Placeholders and are never disclosed; the command ` +
              "starts with this run's environment unchanged. Requests to allowed destinations go through the Broker in HTTPS_PROXY.",
          );
          const [cmd, ...cmdArgs] = args.slice(sep + 1) as [string, ...string[]];
          process.exit(await runChild(cmd, cmdArgs, process.env));
        }
        const agentSafe = has(preArgs, "--agent-safe");
        const noRedact = has(preArgs, "--no-redact");
        const allowUnmasked = flags(preArgs, "--allow-unmasked");
        if (agentSafe && (noRedact || allowUnmasked.length > 0)) {
          fail("--no-redact and --allow-unmasked do not apply to --agent-safe runs: the Agent receives Placeholders, not Secrets.");
        }
        if (noRedact && has(preArgs, "--redact")) fail("--redact and --no-redact cannot be combined.");
        if (allowUnmasked.length > 0 && !assisted.on) {
          fail("--allow-unmasked applies only in assisted mode (--assisted), where a Secret too short to mask stops the run.");
        }
        // Assisted mode (ADR-0043 Decision 4): redaction is the default, even
        // when the output is a terminal (the command then gets pipes).
        const assistedRedaction = assisted.on && !agentSafe && !noRedact;
        if (assisted.on && noRedact) {
          console.error("varlatch: --no-redact: this run's output is not masked; a Secret the command prints reaches whatever captures its output.");
        }
        if (!agentSafe && (has(preArgs, "--target") || has(preArgs, "--omit"))) {
          fail("--target and --omit apply only to --agent-safe runs.");
        }
        if (has(preArgs, "--export-context") && (has(preArgs, "--strict") || has(preArgs, "--agent-safe"))) {
          fail("--export-context applies only to default runs; a --strict run always gives the command its run context.");
        }
        // Output redaction (ADR-0038 Decision 10): refused before anything is fetched.
        const redact = has(preArgs, "--redact");
        if (redact) {
          const refusal = redactRefusal({
            agentSafe,
            stdoutIsTTY: !assisted.on && Boolean(process.stdout.isTTY),
            stderrIsTTY: !assisted.on && Boolean(process.stderr.isTTY),
          });
          if (refusal) fail(`varlatch: ${refusal}. Nothing was started.`);
        }
        const log = (line: string) => console.error(line);
        const ctx = context(preArgs);
        const api = client(ctx);

        if (has(preArgs, "--strict") && has(preArgs, "--agent-safe")) {
          const { runAgentSafeStrict } = await import("./agentRun.js");
          const { UsageError } = await import("./strictRun.js");
          const agent = flag(preArgs, "--agent") ?? fail("Agent-safe runs need --agent <agent-identity name or id>");
          const [cmd, ...cmdArgs] = args.slice(sep + 1) as [string, ...string[]];
          try {
            const code = await runAgentSafeStrict(
              ctx,
              api,
              {
                agent,
                brokerCredentialFile: flag(preArgs, "--broker-credential-file"),
                allowHosts: flags(preArgs, "--allow-host"),
                strict: flag(preArgs, "--agent-network") === "strict",
                ttlSeconds: Number(flag(preArgs, "--ttl") ?? 3600),
                metadataCredential: has(preArgs, "--agent-metadata"),
                targets: targetFlags(preArgs),
                omit: flags(preArgs, "--omit"),
                allowInherited: flags(preArgs, "--allow-inherited"),
              },
              cmd,
              cmdArgs,
            );
            process.exit(code);
          } catch (err) {
            if (err instanceof UsageError) fail(`varlatch: ${err.message}. Nothing was started.`);
            if (err instanceof VarlatchApiError) throw err;
            fail(err instanceof Error ? err.message : String(err));
          }
        }
        if (has(preArgs, "--strict")) {
          const { runStrict, UsageError } = await import("./strictRun.js");
          const [cmd, ...cmdArgs] = args.slice(sep + 1) as [string, ...string[]];
          try {
            const code = await runStrict(api, {
              organization: ctx.organization,
              project: ctx.project,
              environment: ctx.environment,
              allowInherited: flags(preArgs, "--allow-inherited"),
              parent: process.env,
              start: async (env, secrets, secretNames) => {
                if (!assistedRedaction) return runChild(cmd, cmdArgs, env, redact ? secrets : undefined);
                const plan = planAssistedRedaction(assistedRedactionSet(secrets, env, process.env, secretNames), allowUnmasked);
                if (!assistedGate(plan, log)) return STRICT_EXIT;
                return runChild(cmd, cmdArgs, env, plan.entries, "assisted");
              },
              log,
            });
            process.exit(code);
          } catch (err) {
            if (err instanceof UsageError) fail(`varlatch: ${err.message}. Nothing was started.`);
            throw err;
          }
        }
        if (has(preArgs, "--allow-inherited")) fail("--allow-inherited applies only to --strict runs.");

        if (has(preArgs, "--agent-safe")) {
          // ADR-0022: placeholders + local broker; the child gets no bearer.
          const { runAgentSafe } = await import("./agentRun.js");
          const agent = flag(preArgs, "--agent") ?? fail("Agent-safe runs need --agent <agent-identity name or id>");
          const [cmd, ...cmdArgs] = args.slice(sep + 1) as [string, ...string[]];
          try {
            const code = await runAgentSafe(
              ctx,
              api,
              {
                agent,
                brokerCredentialFile: flag(preArgs, "--broker-credential-file"),
                allowHosts: flags(preArgs, "--allow-host"),
                strict: flag(preArgs, "--agent-network") === "strict",
                ttlSeconds: Number(flag(preArgs, "--ttl") ?? 3600),
                metadataCredential: has(preArgs, "--agent-metadata"),
                targets: targetFlags(preArgs),
                omit: flags(preArgs, "--omit"),
              },
              cmd,
              cmdArgs,
            );
            process.exit(code);
          } catch (err) {
            if (err instanceof VarlatchApiError) throw err;
            const { UsageError } = await import("./strictRun.js");
            if (err instanceof UsageError) fail(`varlatch: ${err.message}. Nothing was started.`);
            fail(err instanceof Error ? err.message : String(err));
          }
        }
        const exporting = has(preArgs, "--export-context") ? await import("./exportContext.js") : null;
        const read = async () => {
          const effective = await api.effectiveConfiguration(
            ctx.organization,
            ctx.project,
            ctx.environment,
            { includeValues: true },
          );
          // Before any Secret is disclosed: a run that cannot export its context discloses nothing.
          const exportContext = exporting
            ? await exporting.prepareExportedContext(api, ctx.organization, ctx.project, effective)
            : null;
          // Secrets require the explicit disclosure operation (design R2).
          let disclosureDigest: string | null | undefined = null;
          try {
            const disclosed = await api.discloseSecrets(ctx.organization, ctx.project, ctx.environment, {
              scope: "all-authorized-secrets",
            });
            disclosureDigest = disclosed.stateDigest;
            const byName = new Map(disclosed.items.map((i) => [i.name, i.value]));
            for (const item of effective.items ?? []) {
              const value = byName.get(item.name);
              if (item.sensitive && value !== undefined) item.value = value;
            }
          } catch (err) {
            if (err instanceof VarlatchApiError && (err.code === "PERMISSION_DENIED" || err.code.startsWith("TAILNET_"))) {
              console.error(`varlatch: secrets not disclosed (${err.code}); continuing with non-sensitive values`);
            } else {
              throw err;
            }
          }
          return { configurationDigest: effective.stateDigest, disclosureDigest, result: { effective, exportContext } };
        };
        // Only an exported context checks that both requests saw the same
        // state; a run without the flag makes its two requests once, unchecked.
        const { effective, exportContext } = exporting
          ? await exporting.readConsistently(read, (line) => console.error(line))
          : (await read()).result;
        const withheld = withheldItems(effective);
        if (withheld.length > 0) {
          console.error(`varlatch: ${withheld.length} value(s) withheld by policy: ${withheld.join(", ")}`);
        }
        const [cmd, ...cmdArgs] = args.slice(sep + 1) as [string, ...string[]];
        const env = buildEnv(process.env, effective);
        if (exportContext) env[RUN_CONTEXT] = exportContext(effective, process.env);
        if (assistedRedaction) {
          const secretNames = await knownSecretNames(api, ctx, effective, log);
          const set = assistedRedactionSet(deliveredSecrets(effective.items ?? [], env), env, process.env, secretNames);
          const plan = planAssistedRedaction(set, allowUnmasked);
          if (!assistedGate(plan, log)) process.exit(STRICT_EXIT);
          process.exit(await runChild(cmd, cmdArgs, env, plan.entries, "assisted"));
        }
        const code = await runChild(cmd, cmdArgs, env, redact ? deliveredSecrets(effective.items ?? [], env) : undefined);
        process.exit(code);
        return;
      }

      case "validate": {
        const ctx = context(args);
        const report = await client(ctx).validateEnvironment(ctx.organization, ctx.project, ctx.environment);
        const outcome = validationOutcome(ctx.environment, report);
        for (const line of outcome.stdout) console.log(line);
        for (const line of outcome.stderr) console.error(line);
        if (outcome.exitCode !== 0) process.exit(outcome.exitCode);
        return;
      }

      case "scan": {
        // Local secret scanning (ADR-0038 Decision 14): one audited disclosure
        // with purpose "scan"; findings never show values or line contents.
        const { parseScanArgs, runScan, ScanUsageError, SCAN_USAGE } = await import("./scanCommand.js");
        const { ScanSourceError } = await import("./scanSources.js");
        try {
          process.exitCode = await runScan(
            parseScanArgs(args),
            { context: () => context(args), client },
            { out: (line) => console.log(line), err: (line) => console.error(line), cwd: process.cwd() },
          );
        } catch (err) {
          if (err instanceof ScanUsageError || err instanceof ScanSourceError) {
            fail(`varlatch scan: ${err.message}${err instanceof ScanUsageError && !err.message.startsWith("nothing") ? `\n${SCAN_USAGE}` : ""}`);
          }
          throw err;
        }
        return;
      }

      case "values": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "set" || sub === "rotate") {
          const usage =
            sub === "set"
              ? "Usage: varlatch values set <ITEM> [<value> | --stdin | --from-file <path> | --generate <spec>]"
              : "Usage: varlatch values rotate <ITEM> [<new-value> | --stdin | --from-file <path> | --generate <spec>] [--grace <seconds>]";
          const item = args[1] && !args[1].startsWith("-") ? args[1] : fail(usage);
          const obtained = await obtainValue(sub, item, args, assisted, () => sensitiveItem(api, ctx, item));
          // An unpaired UTF-16 surrogate (possible in a Windows command line) has no exact UTF-8 form.
          if (!isWellFormedText(obtained.value)) fail("varlatch: the value is not well-formed Unicode text; nothing was stored.");
          const how = obtained.generated ? ` to a generated value (${describeGenerated(obtained.generated)}; not shown)` : "";
          if (sub === "set") {
            const version = await api.setValue(ctx.organization, ctx.project, ctx.environment, item, { value: obtained.value });
            console.log(`${item} set (version ${version.versionId})${how}.`);
            return;
          }
          const graceStr = flag(args, "--grace");
          const rot = await api.beginRotation(ctx.organization, ctx.project, ctx.environment, item, {
            value: obtained.value,
            ...(graceStr ? { graceSeconds: Number(graceStr) } : {}),
          });
          console.log(
            `${item} rotating${how} — new primary ${rot.primaryVersionId}, previous value valid until ${rot.rotationDeadline}. Run "varlatch values rotate-complete ${item}" once consumers have migrated.`,
          );
          return;
        }
        if (sub === "list") {
          const effective = await api.effectiveConfiguration(ctx.organization, ctx.project, ctx.environment);
          for (const i of effective.items ?? []) {
            console.log(`${i.name}  (${i.sensitive ? "secret" : "plain"}, ${i.source})`);
          }
          return;
        }
        if (sub === "delete") {
          const item = args[1] ?? fail("Usage: varlatch values delete <ITEM>");
          await api.deleteValue(ctx.organization, ctx.project, ctx.environment, item);
          console.log(`${item} deleted from ${ctx.environment}.`);
          return;
        }
        if (sub === "rotate-complete") {
          const item = args[1] ?? fail("Usage: varlatch values rotate-complete <ITEM>");
          await api.completeRotation(ctx.organization, ctx.project, ctx.environment, item);
          console.log(`${item} rotation complete — previous value retired.`);
          return;
        }
        fail("Usage: varlatch values <set|list|delete|rotate|rotate-complete>");
        return;
      }

      case "import": {
        // ADR-0043 Decision 2: the CLI reads the file itself; values never
        // appear in its output.
        const usage =
          "Usage: varlatch import <file> [--dry-run] [--contract [--plain <NAME>]...] [--delete-source] [-e <env>]";
        const file = args[0] && !args[0].startsWith("-") ? args[0] : fail(usage);
        const { runImport, ImportError } = await import("./importCommand.js");
        const dryRun = has(args, "--dry-run");
        let target: Parameters<typeof runImport>[1];
        try {
          const ctx = context(args);
          target = loadToken(ctx.server) || !dryRun ? { ctx, api: client(ctx) } : { offline: `not signed in to ${ctx.server}` };
        } catch (err) {
          if (!(err instanceof ContextError) || !dryRun) throw err;
          target = { offline: err.message.split(". ")[0] ?? err.message };
        }
        try {
          process.exitCode = await runImport(
            {
              file,
              dryRun,
              contract: has(args, "--contract"),
              plain: flags(args, "--plain"),
              deleteSource: has(args, "--delete-source"),
            },
            target,
            { out: (line) => console.log(line), err: (line) => console.error(line) },
          );
        } catch (err) {
          if (err instanceof ImportError) fail(`varlatch import: ${err.message}`);
          throw err;
        }
        return;
      }

      case "sync": {
        const sub = args[0];
        if (sub !== "push") fail("Usage: varlatch sync push --platform <github-actions|coolify|convex> [--map NAME[=DEST]]... [--exclude NAME|PREFIX*]... ...");
        const ctx = context(args);
        const api = client(ctx);
        const platform = flag(args, "--platform") ?? fail("--platform is required (github-actions, coolify, convex)");
        const base = flag(args, "--base") ?? fail("--base is required (GitHub owner, or a Coolify/Convex https origin)");
        const { runSyncPush } = await import("./syncPush.js");
        const code = await runSyncPush(api, ctx, {
          platform,
          base,
          repo: flag(args, "--repo"),
          ghEnvironment: flag(args, "--gh-environment"),
          app: flag(args, "--app"),
          buildTime: flag(args, "--build-time"),
          tokenEnv: flag(args, "--token-env") ?? "VARLATCH_SYNC_TOKEN",
          maps: flags(args, "--map"),
          excludes: flags(args, "--exclude"),
        });
        process.exit(code);
        return;
      }

      case "contract": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "push") {
          const schemaFile = flag(args, "--schema");
          const jsonFile = flag(args, "--file");
          let contract: unknown;
          let provenance: Record<string, string> | undefined;
          if (schemaFile) {
            // .env.schema: parse, then resolve env(...) names against the
            // project's live root Environments. Unknown names fail loudly
            // here, never approximated. The revision stores the IDs.
            if (!existsSync(schemaFile)) fail(`No such file: ${schemaFile}`);
            const draft = parseEnvSchema(readFileSync(schemaFile, "utf8"));
            const environments =
              draft.environmentNames.length > 0
                ? (await api.listEnvironments(ctx.organization, ctx.project)).items.map((e) => ({
                    id: e.id,
                    name: e.name,
                    parentEnvironmentId: e.parentEnvironmentId ?? null,
                  }))
                : [];
            contract = resolveDraft(draft, environments);
            provenance = { schemaPath: schemaFile, adapter: "varlatch-env-schema" };
          } else if (jsonFile) {
            if (!existsSync(jsonFile)) fail(`No such file: ${jsonFile}`);
            contract = JSON.parse(readFileSync(jsonFile, "utf8")) as unknown;
          } else {
            fail("Usage: varlatch contract push --schema <.env.schema> | --file <contract.json> [--semantics <version|latest>]");
          }
          const semantics = flag(args, "--semantics");
          if (semantics !== undefined) {
            // An explicit pin; without one the server keeps the active
            // revision's version (the newest for a project's first revision).
            const supported = (await api.meta()).semanticsVersions;
            if (!supported) fail("This server does not support Contract Semantics versions; it needs 0.11.0 or later.");
            const version = semantics === "latest" ? Math.max(...supported) : Number(semantics);
            if (!supported.includes(version)) {
              fail(`--semantics must be latest or one of this server's versions: ${supported.join(", ")}`);
            }
            contract = { ...(contract as object), semanticsVersion: version };
          }
          // A type newer than the version this revision will get (integer
          // needs version 3) is refused here, naming the fix, rather than by
          // the server after the push.
          const items = ((contract as { items?: unknown }).items ?? []) as { name: string; type: string }[];
          const { versionNeeded, pushVersionProblem } = await import("./contractPush.js");
          if (Array.isArray(items) && versionNeeded(items).version > 1) {
            const serverVersions = (await api.meta()).semanticsVersions ?? [1];
            let activeVersion: number | null = null;
            try {
              activeVersion = (await api.getActiveContract(ctx.organization, ctx.project)).semanticsVersion ?? 1;
            } catch (err) {
              if (!(err instanceof VarlatchApiError && err.status === 404)) throw err;
            }
            const pinned = (contract as { semanticsVersion?: unknown }).semanticsVersion;
            const problem = pushVersionProblem(items, {
              pinned: typeof pinned === "number" ? pinned : undefined,
              activeVersion,
              serverVersions,
            });
            if (problem) fail(`varlatch contract push: ${problem}. Nothing was pushed.`);
          }
          const revision = await api.pushContractRevision(ctx.organization, ctx.project, {
            contract,
            ...(provenance ? { provenance } : {}),
          });
          console.log(`Revision ${revision.id} (${revision.contentHash})${revision.active ? " [active]" : ""}`);
          console.log(`Contract Semantics version ${revision.semanticsVersion}`);
          if (!revision.active) console.log(`Activate with: varlatch contract activate ${revision.id}`);
          return;
        }
        if (sub === "activate") {
          const revision = args[1] ?? fail("Usage: varlatch contract activate <revision-id>");
          await api.activateContractRevision(ctx.organization, ctx.project, revision);
          console.log(`Activated ${revision}.`);
          return;
        }
        if (sub === "show") {
          const active = await api.getActiveContract(ctx.organization, ctx.project);
          console.log(JSON.stringify(active, null, 2));
          return;
        }
        fail("Usage: varlatch contract <push|activate|show>");
        return;
      }

      case "types": {
        const usage = "Usage: varlatch types --out <file.ts|file.py> [--revision <id>] [--check]";
        const out = flag(args, "--out") ?? fail(usage);
        if (out.startsWith("-")) fail(usage);
        // The output is the same for every Environment, so none needs to be selected.
        const opts: Parameters<typeof resolveContext>[0] = { cwd: process.cwd(), environment: "(unused)" };
        const server = flag(args, "--server");
        if (server) opts.server = server;
        const ctx = resolveContext(opts);
        const { runTypes } = await import("./typesCommand.js");
        const { EMBEDDED_RELEASE } = await import("@varlatch/backup");
        process.exitCode = await runTypes(
          client(ctx),
          {
            organization: ctx.organization,
            project: ctx.project,
            revision: flag(args, "--revision"),
            out,
            check: has(args, "--check"),
            generatorVersion: EMBEDDED_RELEASE.version,
          },
          { out: (line) => console.log(line), err: (line) => console.error(line) },
        );
        return;
      }

      case "invite": {
        const name = args[0] ?? fail("Usage: varlatch invite <name> [--role member|admin]");
        const role = (flag(args, "--role") ?? "member") as "member" | "admin";
        const ctx = context(args);
        const invite = await client(ctx).createInvitation(ctx.organization, { name, role });
        console.log(`Hand this one-time enrollment link to ${name} (${role}):`);
        console.log(`  ${ctx.server}/enroll#${invite.token}`);
        console.log(`Expires: ${invite.expiresAt}. They will create a passkey — no email involved.`);
        return;
      }

      case "tailnet": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "require") {
          // The flagship convenience (ADR-0014 §9): compiles to an ordinary
          // typed Requirement — sugar, never a second authorization system.
          const tier = (flag(args, "--tier") ?? "production") as "development" | "staging" | "production";
          const tailnet = flag(args, "--tailnet") ?? fail("Provide --tailnet <your-tailnet.ts.net>");
          const tags = flag(args, "--tags")?.split(",").filter(Boolean);
          const nodes = flag(args, "--nodes")?.split(",").filter(Boolean);
          const users = flag(args, "--users")?.split(",").filter(Boolean);
          if (!tags?.length && !nodes?.length && !users?.length) {
            fail("Name at least one of --tags, --nodes, or --users");
          }
          const created = await api.createTailnetRequirement(ctx.organization, {
            target: { kind: "tier", tier },
            selector: {
              tailnet,
              ...(tags?.length ? { tags } : {}),
              ...(nodes?.length ? { nodes } : {}),
              ...(users?.length ? { users } : {}),
            },
          });
          console.log(
            `Tailnet Requirement ${created.id}: ${tier}-tier retrieval now requires ` +
              `trusted Tailnet Context from ${tailnet}. Requests outside it fail closed.`,
          );
          return;
        }
        if (sub === "requirements") {
          const page = await api.listRequirements(ctx.organization);
          for (const r of page.items) {
            console.log(`${r.id}  ${JSON.stringify(r.target)}  ${JSON.stringify(r.selector)}`);
          }
          if (page.items.length === 0) console.log("(none)");
          return;
        }
        if (sub === "remove") {
          const id = args[1] ?? fail("Usage: varlatch tailnet remove <requirement-id>");
          await api.deleteRequirement(ctx.organization, id);
          console.log(`Removed ${id}. Constrained operations are unconstrained again.`);
          return;
        }
        fail("Usage: varlatch tailnet <require|requirements|remove>");
        return;
      }

      case "audit": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "list") {
          const page = await api.listAuditEvents(ctx.organization, { limit: 50 });
          for (const e of page.items) {
            console.log(
              `${e.occurredAt}  ${e.decision}  ${e.eventType}  actor=${e.actorIdentityId ?? "-"}`,
            );
          }
          return;
        }
        if (sub === "export") {
          process.stdout.write(await api.exportAuditEventsNdjson(ctx.organization));
          return;
        }
        fail("Usage: varlatch audit <list|export>");
        return;
      }

      case "org": {
        const sub = args[0];
        const server =
          flag(args, "--server") ?? process.env.VARLATCH_SERVER ??
          (findRepoRoot(process.cwd()) ? context(args).server : fail("Provide --server"));
        const token = loadToken(server) ?? fail(`Not authenticated to ${server}`);
        warnIfExpiring(server);
        const api = new VarlatchClient({ onMaintenance: maintenanceNotice, server, token });
        if (sub === "list") {
          const page = await api.listOrganizations();
          for (const o of page.items) console.log(`${o.slug}  (${o.name})`);
          if (page.items.length === 0) console.log("(none — create one with: varlatch org create <slug> <name>)");
          return;
        }
        if (sub === "create") {
          const slug = args[1] ?? fail("Usage: varlatch org create <slug> [name]");
          const name = positional(args, 2) ?? slug;
          const org = await api.createOrganization({ slug, name });
          console.log(`Organization ${org.slug} created (${org.id}). You are its admin.`);
          return;
        }
        fail("Usage: varlatch org <list|create>");
        return;
      }

      case "project": {
        const sub = args[0];
        if (sub === "create") {
          const slug = args[1] ?? fail("Usage: varlatch project create <slug> [name] [--managed]");
          const server = flag(args, "--server") ?? process.env.VARLATCH_SERVER ?? fail("Provide --server");
          const org = flag(args, "--org") ?? fail("Provide --org <slug>");
          const token = loadToken(server) ?? fail(`Not authenticated to ${server}`);
          warnIfExpiring(server);
          const api = new VarlatchClient({ onMaintenance: maintenanceNotice, server, token });
          const project = await api.createProject(org, {
            slug,
            name: positional(args, 2) ?? slug,
            contractAuthority: has(args, "--managed") ? "managed" : "git",
          });
          console.log(`Project ${project.slug} created in ${org} (${project.contractAuthority} contract authority).`);
          console.log(`Set up a repo with: varlatch init --org ${org} --project ${project.slug} --server ${server}`);
          return;
        }
        if (sub === "list") {
          const ctx = context(args);
          const page = await client(ctx).listProjects(ctx.organization);
          for (const p of page.items) console.log(`${p.slug}  (${p.name}, ${p.contractAuthority})`);
          return;
        }
        if (sub === "rename") {
          const slug = args[1] ?? fail("Usage: varlatch project rename <slug> <new-name>");
          const name = positional(args, 2) ?? fail("Provide the new name");
          const ctx = context(args);
          const renamed = await client(ctx).renameProject(ctx.organization, slug, name);
          console.log(`Project ${renamed.slug} renamed to ${renamed.name}. Its slug, grants and contracts are unaffected; the rename is audited.`);
          return;
        }
        fail("Usage: varlatch project <create|list|rename>");
        return;
      }

      case "env-create": {
        const name = args[0] ?? fail("Usage: varlatch env-create <name> --tier development|staging|production [--parent <env>] [--kind personal|preview]");
        const ctx = context(args);
        const api = client(ctx);
        const parent = flag(args, "--parent");
        const input: Parameters<VarlatchClient["createEnvironment"]>[2] = { name };
        if (parent) {
          const envs = await api.listEnvironments(ctx.organization, ctx.project);
          const parentEnv = envs.items.find((e) => e.name === parent || e.id === parent);
          if (!parentEnv) fail(`No such parent environment: ${parent}`);
          input.parentEnvironmentId = parentEnv.id;
          const kind = flag(args, "--kind");
          if (kind) input.kind = kind as "personal" | "preview";
        } else {
          const tier = flag(args, "--tier") ?? fail("Root environments need --tier development|staging|production");
          input.tier = tier as "development" | "staging" | "production";
        }
        const env = await api.createEnvironment(ctx.organization, ctx.project, input);
        console.log(`Environment ${env.name} created (${env.kind}, tier ${env.tier}).`);
        return;
      }

      case "env-delete": {
        const name = args[0] ?? fail("Usage: varlatch env-delete <name> [--confirm <name>]");
        const ctx = context(args);
        const api = client(ctx);
        const envs = await api.listEnvironments(ctx.organization, ctx.project);
        const env =
          envs.items.find((e) => e.name === name || e.id === name) ??
          fail(`No such environment: ${name}`);
        // ADR-0025: production-tier roots get client-side friction — the
        // deletion must repeat the environment name explicitly.
        if (env.tier === "production" && !env.parentEnvironmentId && flag(args, "--confirm") !== env.name) {
          fail(`${env.name} is production-tier; re-type the name to confirm: varlatch env-delete ${env.name} --confirm ${env.name}`);
        }
        await api.deleteEnvironment(ctx.organization, ctx.project, env.name);
        console.log(`Environment ${env.name} deleted (${env.kind}, tier ${env.tier}). The name is free for reuse; grants and mappings never transfer to a successor.`);
        return;
      }

      case "identity": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "list") {
          const page = await api.listIdentities(ctx.organization);
          for (const i of page.items) {
            const state = i.disabled ? "retired" : "active";
            console.log(
              `${i.id}  ${i.name}  (${i.kind}, ${state}, last seen ${i.lastSeenAt ?? "never"})`,
            );
          }
          if (page.items.length === 0) console.log("(none)");
          return;
        }
        if (sub === "rename") {
          const id = args[1] ?? fail("Usage: varlatch identity rename <identity-id> <new-name>");
          const name = positional(args, 2) ?? fail("Provide the new name");
          const renamed = await api.renameIdentity(ctx.organization, id, name);
          console.log(`Identity ${renamed.id} renamed to ${renamed.name}. Grants and credentials are unaffected; the rename is audited.`);
          return;
        }
        if (sub === "retire") {
          const id = args[1] ?? fail("Usage: varlatch identity retire <identity-id> [--confirm <name>]");
          const page = await api.listIdentities(ctx.organization);
          const identity = page.items.find((i) => i.id === id) ?? fail(`No such identity: ${id}`);
          // ADR-0034: retirement revokes every credential; mirror env-delete's
          // ADR-0025 friction — the retirement must repeat the identity name.
          if (flag(args, "--confirm") !== identity.name) {
            fail(`Retiring ${identity.name} revokes ALL of its credentials; re-type the name to confirm: varlatch identity retire ${identity.id} --confirm ${identity.name}`);
          }
          await api.retireIdentity(ctx.organization, identity.id);
          console.log(`Identity ${identity.name} retired — disabled and every credential revoked. Reactivation restores no credentials.`);
          return;
        }
        if (sub === "reactivate") {
          const id = args[1] ?? fail("Usage: varlatch identity reactivate <identity-id>");
          const identity = await api.reactivateIdentity(ctx.organization, id);
          console.log(`Identity ${identity.id} reactivated. It has zero working credentials until you issue one.`);
          return;
        }
        fail("Usage: varlatch identity <list|rename|retire|reactivate>");
        return;
      }

      case "credential": {
        const sub = args[0];
        const ctx = context(args);
        const api = client(ctx);
        if (sub === "list") {
          const id = args[1] ?? fail("Usage: varlatch credential list <identity-id>");
          const page = await api.listIdentityCredentials(ctx.organization, id);
          for (const c of page.items) {
            const marks = [
              c.kind,
              c.name,
              `created ${c.createdAt}`,
              c.expiresAt ? `expires ${c.expiresAt}` : null,
              c.revokedAt ? `revoked ${c.revokedAt}` : null,
              `last used ${c.lastUsedAt ?? "never"}`,
            ]
              .filter(Boolean)
              .join(", ");
            console.log(`${c.id}  (${marks})`);
          }
          if (page.items.length === 0) console.log("(none)");
          return;
        }
        if (sub === "revoke") {
          const id = args[1] ?? fail("Usage: varlatch credential revoke <identity-id> <credential-id>");
          const credentialId = positional(args, 2) ?? fail("Provide the credential id");
          await api.revokeIdentityCredential(ctx.organization, id, credentialId);
          console.log(`Credential ${credentialId} revoked. Every subsequent request with it fails.`);
          return;
        }
        fail("Usage: varlatch credential <list|revoke>");
        return;
      }

      case "admin": {
        if (args[0] !== "backup") fail("Usage: varlatch admin backup create|verify|restore|status");
        const { backupCommand } = await import("./backup.js");
        await backupCommand(args.slice(1));
        break;
      }
      case "setup": {
        // One command from an empty Compose directory to a running,
        // bootstrapped installation (ADR-0035 D7); resumable.
        const { runSetup, SetupError } = await import("./setup.js");
        try {
          process.exitCode = await runSetup({
            dir: flag(args, "--dir") ?? process.cwd(),
            ingress: flag(args, "--ingress") as "public" | "tailnet" | "external" | undefined,
            publicUrl: flag(args, "--public-url"),
            tailnetMachine: flag(args, "--tailnet-machine"),
            tailscaleAuthKeyFile: flag(args, "--tailscale-auth-key-file"),
            webPort: flag(args, "--port") ? Number(flag(args, "--port")) : undefined,
            noWait: has(args, "--no-wait"),
            enrollTimeoutMs: Number(flag(args, "--enroll-timeout") ?? "900") * 1000,
            escrow: flag(args, "--escrow") as "passphrase" | "shamir" | "copy" | undefined,
            escrowPassphraseFile: flag(args, "--escrow-passphrase-file"),
            shares: flag(args, "--shares") ? Number(flag(args, "--shares")) : undefined,
            threshold: flag(args, "--threshold") ? Number(flag(args, "--threshold")) : undefined,
            attest: has(args, "--attest"),
          });
        } catch (err) {
          if (err instanceof SetupError) fail(err.message);
          throw err;
        }
        return;
      }
      case "adopt": {
        // Existing installations onto managed configuration, one verified,
        // checkpointed step at a time (ADR-0035 D13). Dry run by default.
        const { runAdopt } = await import("./adopt.js");
        const { SetupError } = await import("./setup.js");
        try {
          process.exitCode = await runAdopt({
            dir: flag(args, "--dir") ?? process.cwd(),
            apply: has(args, "--apply"),
            only: flag(args, "--only") as never,
            revert: flag(args, "--revert") as never,
            secretsDir: flag(args, "--secrets-dir"),
            escrow: flag(args, "--escrow") as "passphrase" | "shamir" | "copy" | undefined,
            escrowPassphraseFile: flag(args, "--escrow-passphrase-file"),
            shares: flag(args, "--shares") ? Number(flag(args, "--shares")) : undefined,
            threshold: flag(args, "--threshold") ? Number(flag(args, "--threshold")) : undefined,
            attest: has(args, "--attest"),
          });
        } catch (err) {
          if (err instanceof SetupError) fail(err.message);
          throw err;
        }
        return;
      }
      case "doctor": {
        // Read-only Installation Health on THIS host (ADR-0035 D8): host
        // authority via Docker, no API login, changes nothing.
        // --gate judges upgrade completion (D11): exit 0 only when every gate
        // check passes; `varlatch upgrade` runs the target release's copy.
        const { runDoctor, formatDoctor, doctorExitCode, evaluateGate, formatGate } = await import("./doctor.js");
        const report = await runDoctor({
          dir: flag(args, "--dir") ?? process.cwd(),
          waitSeconds: Number(flag(args, "--wait") ?? "15"),
        });
        if (has(args, "--gate")) {
          const gate = evaluateGate(report);
          console.log(has(args, "--json") ? JSON.stringify({ ...report, gate }, null, 2) : `${formatDoctor(report)}\n\n${formatGate(gate)}`);
          process.exitCode = gate.pass ? 0 : 1;
          return;
        }
        console.log(has(args, "--json") ? JSON.stringify(report, null, 2) : formatDoctor(report));
        process.exitCode = doctorExitCode(report);
        return;
      }
      case "version":
      case "--version": {
        // The embedded release manifest is what backup compatibility checks
        // compare against, so it is the version that matters on a host.
        const { EMBEDDED_RELEASE } = await import("@varlatch/backup");
        console.log(`varlatch ${EMBEDDED_RELEASE.version} (migration ${EMBEDDED_RELEASE.migrationVersion})`);
        return;
      }
      case "self-update": {
        // Replaces this CLI's own file with a release build; no login, and
        // nothing else on the host changes.
        const { runSelfUpdate, SelfUpdateError } = await import("./selfUpdate.js");
        const { UpgradeError, DEFAULT_RELEASE_REPO } = await import("./upgrade.js");
        try {
          await runSelfUpdate({
            version: positional(args, 0),
            repo: flag(args, "--repo") ?? process.env.VARLATCH_RELEASE_REPO ?? DEFAULT_RELEASE_REPO,
            check: has(args, "--check"),
            json: has(args, "--json"),
            yes: has(args, "--yes"),
            allowUnverified: has(args, "--allow-unverified"),
            script: process.argv[1] ?? "",
          });
        } catch (err) {
          if (err instanceof SelfUpdateError || err instanceof UpgradeError) fail(err.message);
          throw err;
        }
        return;
      }
      case "upgrade": {
        // Operator tooling (ADR-0019 §19c): upgrades the compose stack on
        // THIS host from the published release set. No API login involved.
        const { runUpgrade, UpgradeError, DEFAULT_RELEASE_REPO } = await import("./upgrade.js");
        try {
          await runUpgrade({
            version: positional(args, 0),
            dir: flag(args, "--dir") ?? process.cwd(),
            repo: flag(args, "--repo") ?? process.env.VARLATCH_RELEASE_REPO ?? DEFAULT_RELEASE_REPO,
            yes: has(args, "--yes"),
            backupDir: flag(args, "--backup-dir"),
            backupArgs: ["--bek-file", "--bek-passphrase-file", "--kek-file", "--destination", "--destinations-file", "--scratch-dir", "--timeout-seconds"].flatMap(name => flag(args, name) ? [name, flag(args, name)!] : []),
            skipDbBackup: has(args, "--skip-db-backup"),
            kekBackupVerified: has(args, "--kek-backup-verified"),
            checkOnly: has(args, "--check"),
            ...(flag(args, "--release-dir") ? { releaseDir: flag(args, "--release-dir")! } : {}),
          });
        } catch (err) {
          if (err instanceof UpgradeError) fail(err.message);
          throw err;
        }
        return;
      }

      default:
        console.log(`varlatch — self-host-first secrets and configuration

Usage:
  varlatch --assisted <command>...                      # a coding agent drives the CLI (or VARLATCH_ASSISTED=1):
               run masks Secrets in the command's output by default and refuses one too short to mask
               (exit 78; --allow-unmasked <NAME> is the human's override, --no-redact turns masking off);
               values set/rotate never take a Secret's value from the command line
  varlatch login --server <url> [--ttl <s>]              # browser passkey sign-in
  varlatch login --server <url> --token <credential>
  varlatch login --server <url> --oidc --org <organization> [--audience <aud>] [--oidc-token <jwt>] [--ttl <s>]
  varlatch logout [--server <url>|--all]                 # revokes server-side, removes locally
  varlatch status [--json] [--probe]                     # stored credentials + repo context; offline unless --probe
  varlatch init --org <slug> --project <slug> [--server <url>]
  varlatch context [--json]
  varlatch env <use <name>|list [--json]>
  varlatch run [-e <env>] [--export-context] [--redact] [--no-redact] [--allow-unmasked <NAME>]... -- <command> [args...]
               (--export-context: also give the command VARLATCH_RUN_CONTEXT, names only, for the Typed Accessor;
                --redact: mask the Secrets delivered to the command in its piped stdout and stderr,
                refused when either is a terminal, and with --agent-safe)
  varlatch run --strict [--allow-inherited <NAME>]... [--redact] -- <command> [args...]
               (validate exactly what the command receives; exit 78 and start nothing on any violation;
                combine with --agent-safe for the agent-safe preflight: Secrets stay placeholders)
  varlatch run --agent-safe --agent <identity> --allow-host <host[:port]>...
               --target <NAME=header:<name>|query:<name>|json:<pointer>|form:<name>>... --omit <NAME>...
               [--broker-credential-file <path>] [--agent-network strict] [--ttl <s>]
               [--agent-metadata] -- <command>...
               (every stored Secret needs a --target or an --omit; it is substituted only there; the Agent gets its own
                empty configuration directory, so a varlatch command it starts never uses the operator's credential)
  varlatch validate [-e <env>]        (exit 1 invalid; 2 incomplete: items this identity may not read)
  varlatch values <set <ITEM> [<value>]|list|delete <ITEM>|rotate <ITEM> [<new-value>] [--grace <s>]|rotate-complete <ITEM>>
                  set/rotate: --stdin | --from-file <path> | --generate <hex|base64|base64url:<bytes>|alnum:<chars>>,
                  or no value in a terminal for a hidden prompt
  varlatch import <file> [--dry-run] [--contract [--plain <NAME>]...] [--delete-source]
               (store a dotenv file's values without printing them; --contract adds new items to a Contract
                revision, Secrets unless --plain; --delete-source removes the file once every value is stored)
  varlatch contract <push --schema <.env.schema> | push --file <json> | activate <rev> | show>
                   push [--semantics <version|latest>]   (pin Contract Semantics; default keeps the active version)
  varlatch types --out <file.ts|file.py> [--revision <id>] [--check]
                 (one TypeScript or Python module, by extension, with typed config and the Typed Accessor,
                  from the active Contract; --check exits 1 when the file is stale)
  varlatch sync push --platform <github-actions|coolify|convex> --base <owner|https://origin>
                     (--repo <name> [--gh-environment <name>] | --app <uuid> [--build-time true|false]
                      | nothing for convex: --base is the deployment URL)
                     [--token-env VAR] [--map NAME[=DEST]]... [--exclude NAME|PREFIX*]... [-e <env>]
                     # client-side push for installations without server egress (ADR-0031)
  varlatch admin backup create|verify|restore|status [--dir <compose-directory>]
  varlatch setup [--dir <compose-directory>] [--ingress public|tailnet|external] [--public-url <url>]
                 [--tailnet-machine <name>] [--tailscale-auth-key-file <f>] [--port <web-port>] [--no-wait]
                 [--escrow passphrase|shamir|copy] [--escrow-passphrase-file <f>] [--attest]
                                                       # install: one command, resumable
  varlatch adopt [--dir <compose-directory>] [--apply] [--only <step>] [--revert <step>] [--secrets-dir <dir>]
                                                       # existing installation → managed, step by step
  varlatch doctor [--dir <compose-directory>] [--json] [--wait <s>] [--gate]
                                                       # read-only installation health on this host
  varlatch scan (--staged | <path>...) [-e <env>] [--json] [--baseline <file>] [--write-baseline]
                [--max-file-size <size>] [--max-total-size <size>]
               (look for this identity's Secrets in staged files or build output; one audited disclosure;
                exit 1 findings, 2 some files not scanned; never prints values or line contents)
  varlatch scan --install-hook [-e <env>]              # pre-commit hook running varlatch scan --staged
  varlatch invite <name> [--role member|admin]
  varlatch tailnet <require --tailnet <tn> --tags tag:prod|requirements|remove <id>>
  varlatch audit <list|export>
  varlatch org <list|create <slug> [name]> [--server <url>]
  varlatch project <create <slug> --org <org> --server <url> [--managed]|list|rename <slug> <new-name>>
  varlatch env-create <name> --tier <tier> | --parent <env> [--kind personal|preview]
  varlatch env-delete <name> [--confirm <name>]        # --confirm required for production-tier roots
  varlatch identity <list|rename <id> <new-name>|retire <id> [--confirm <name>]|reactivate <id>>
                                                       # --confirm required: retire revokes all credentials
  varlatch credential <list <identity-id>|revoke <identity-id> <credential-id>>
  varlatch --version                                   # CLI release; refresh it after every upgrade
  varlatch self-update [<version>] [--check [--json]] [--yes [--allow-unverified]] [--repo <owner/repo>]
                                                       # replace this CLI with a release build (checksum, signature)
  varlatch upgrade [<version>] [--dir <compose-dir>] [--check] [--repo <owner/repo>]
                   [--bek-file <path> | --bek-passphrase-file <path>] --kek-file <path> [--yes]
                   # backup-gated compose upgrade on this host (run where docker-compose.yml lives)`);
        process.exit(command ? 1 : 0);
    }
  } catch (err) {
    if (err instanceof Error && err.name === "BackupError") fail(err.message);
    if (err instanceof Error && err.name === "ExportContextError") fail(`varlatch: ${err.message}. Nothing was started.`);
    if (err instanceof ContextError) fail(err.message);
    if (err instanceof EnvSchemaParseError || err instanceof UnknownEnvironmentNameError) fail(err.message);
    if (err instanceof VarlatchApiError && err.code === "MAINTENANCE") {
      fail(`The installation is still in maintenance (restore or upgrade); try again later. (request ${err.requestId})`);
    }
    if (err instanceof VarlatchApiError) {
      fail(`Error ${err.code}: ${err.message} (request ${err.requestId})`);
    }
    throw err;
  }
}

void main();
