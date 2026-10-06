// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { doctorExitCode, formatDoctor, runDoctor, type Check } from "./doctor.js";
import {
  COMPOSE_OVERRIDE, CONFIG_FILE, docker, ENV_HEADER, ENV_KEEP, escrowComplete, escrowPhase, loadInstallConfig, renderEnv,
  SetupError, varlatchd, waitHealthy, type CustodyStatus, type EscrowMethod, type InstallConfig,
} from "./setup.js";

/**
 * `varlatch adopt` (ADR-0035 D13): moves an existing, hand-configured
 * installation — like one deployed on Coolify with every secret in its env
 * settings — onto managed configuration, one verified step at a time.
 *
 * Core adoption only takes ownership of what already works: networking,
 * ingress (a separate Convex domain stays), and backup arrangements are left
 * alone. Rules: a dry run by default; every step checks its prerequisites;
 * a working setting is removed only after its replacement is verified in
 * operation; .env edits are checkpointed and reversible only when nothing
 * changed since; on Coolify, whose env settings are its own source of truth,
 * adopt prints the exact change (names, never secret values) and verifies
 * the result after you redeploy. Secret values stay in memory: they go from
 * the resolved Compose configuration into 0644 files in a 0700 directory.
 */

export const CANONICAL_JWKS = "http://varlatchd:8686/.well-known/jwks.json";

/** Each per-service secret: its variable, its secret file, and where Compose resolves its value. */
export const SECRETS = [
  { variable: "POSTGRES_SUPERUSER_PASSWORD", secret: "postgres-superuser-password", service: "postgres", key: "POSTGRES_PASSWORD" },
  { variable: "VARLATCH_MIGRATE_PASSWORD", secret: "varlatch-migrate-password", service: "postgres", key: "VARLATCH_MIGRATE_PASSWORD" },
  { variable: "VARLATCH_RUNTIME_PASSWORD", secret: "varlatch-runtime-password", service: "postgres", key: "VARLATCH_RUNTIME_PASSWORD" },
  { variable: "CONVEX_DB_PASSWORD", secret: "convex-db-password", service: "postgres", key: "CONVEX_DB_PASSWORD" },
  { variable: "CONVEX_INSTANCE_SECRET", secret: "convex-instance-secret", service: "convex-backend", key: "INSTANCE_SECRET" },
  { variable: "TS_AUTHKEY", secret: "tailscale-authkey", service: "tailscale", key: "TS_AUTHKEY" },
] as const;
type SecretSpec = (typeof SECRETS)[number];

export type Platform = "compose" | "coolify";
export type StepId = "config" | "secret-files" | "remove-variables" | "trust" | "deploy-authority" | "custody" | "managed-env";
export type StepStatus = "done" | "pending" | "blocked" | "n/a";

export interface Observed {
  platform: Platform;
  publicUrl: string | null;
  convexOrigin: string | null;
  webPort: number | null;
  bindAddress: string | null;
  /** Secrets whose variable is set, with the resolved value (memory only). */
  variables: { spec: SecretSpec; value: string }[];
  /** Secrets mounted from a real file (not the /dev/null default). */
  mounted: string[];
  jwksUrl: string | null;
  adminKeyProvided: boolean;
  instanceSecretAvailable: boolean;
  custodyComplete: boolean;
  configRecorded: boolean;
  managedEnv: boolean;
}

export interface PlannedStep {
  id: StepId;
  status: StepStatus;
  summary: string;
  /** What undoing it means (ADR-0035 D13: no unconditional revert). */
  reversibility: string;
  blockedBy?: string;
}

const order: StepId[] = ["config", "secret-files", "remove-variables", "trust", "deploy-authority", "custody", "managed-env"];

/** Pure: the ordered plan for an observed installation. */
export function plan(o: Observed): PlannedStep[] {
  const unmounted = o.variables.filter((v) => !o.mounted.includes(v.spec.secret));
  const steps: Record<StepId, PlannedStep> = {
    config: o.platform === "coolify"
      ? { id: "config", status: "n/a", summary: "Coolify's env settings are this installation's configuration", reversibility: "—" }
      : {
          id: "config", status: o.configRecorded ? "done" : "pending",
          summary: `record ${o.publicUrl ?? "?"}${o.convexOrigin ? `, Convex origin ${o.convexOrigin} kept` : ""} in ${CONFIG_FILE}`,
          reversibility: "reversible (bookkeeping only)",
        },
    "secret-files": {
      id: "secret-files", status: unmounted.length ? "pending" : "done",
      summary: unmounted.length
        ? `write ${unmounted.map((v) => v.spec.variable).join(", ")} to files with their current values and mount them`
        : "every secret is mounted from a file",
      reversibility: "reversible while the variables still exist",
    },
    "remove-variables": {
      id: "remove-variables", status: o.variables.length ? (unmounted.length ? "blocked" : "pending") : "done",
      summary: o.variables.length ? `remove the variables ${o.variables.map((v) => v.spec.variable).join(", ")}` : "no secret variables left",
      reversibility: "reversible from its checkpoint only if .env is unchanged since",
      ...(unmounted.length && o.variables.length ? { blockedBy: "secret-files" } : {}),
    },
    trust: {
      id: "trust", status: o.jwksUrl === CANONICAL_JWKS ? "done" : "pending",
      summary: o.jwksUrl === CANONICAL_JWKS ? "Convex trusts varlatchd at its contract-fixed name"
        : `VARLATCH_JWKS_URL ${o.jwksUrl ?? "(unset)"} → ${CANONICAL_JWKS}`,
      reversibility: "forward only — archives with the old URL still restore (the `tailscale` legacy alias)",
    },
    "deploy-authority": {
      id: "deploy-authority",
      status: !o.adminKeyProvided ? "done" : o.instanceSecretAvailable ? "pending" : "blocked",
      summary: o.adminKeyProvided ? "prove the derived Convex admin key works, then remove CONVEX_ADMIN_KEY" : "the deploy job derives its key",
      reversibility: "reversible from its checkpoint only if .env is unchanged since",
      ...(o.adminKeyProvided && !o.instanceSecretAvailable ? { blockedBy: "the deploy job has no instance secret" } : {}),
    },
    custody: {
      id: "custody", status: o.custodyComplete ? "done" : "pending",
      summary: o.custodyComplete ? "both recovery keys attested" : "Root KEK escrow and custody attestations",
      reversibility: "append-only",
    },
    "managed-env": o.platform === "coolify"
      ? { id: "managed-env", status: "n/a", summary: "Coolify's env settings stay the source of truth", reversibility: "—" }
      : {
          id: "managed-env", status: o.managedEnv ? "done" : "pending",
          summary: "hand .env over to `varlatch setup` (paths and derived values; your other lines kept)",
          reversibility: "reversible from its checkpoint only if .env is unchanged since",
        },
  };
  const result = order.map((id) => steps[id]);
  if (steps["managed-env"].status === "pending" && result.slice(0, order.indexOf("managed-env")).some((s) => s.status === "pending" || s.status === "blocked")) {
    steps["managed-env"].status = "blocked";
    steps["managed-env"].blockedBy = "the steps before it";
  }
  return result;
}

/** Pure: set, replace, or remove KEY=value lines; other lines and order kept. */
export function editEnv(text: string, changes: Record<string, string | null>): string {
  const lines = text.split("\n");
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of lines) {
    const key = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)?.[1];
    if (key && key in changes) {
      if (seen.has(key)) continue;
      seen.add(key);
      const value = changes[key];
      if (value !== null && value !== undefined) out.push(`${key}=${value}`);
      continue;
    }
    out.push(line);
  }
  const missing = Object.entries(changes).filter(([k, v]) => v !== null && !seen.has(k));
  if (missing.length) {
    while (out.length && out[out.length - 1] === "") out.pop();
    out.push(...missing.map(([k, v]) => `${k}=${v}`), "");
  }
  return out.join("\n");
}

const sha = (text: string) => createHash("sha256").update(text).digest("hex");

/** Paths (never values) where two JSON documents differ. */
export function differingPaths(a: unknown, b: unknown, path = ""): string[] {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const keys = new Set([...Object.keys(a as object), ...Object.keys(b as object)]);
    return [...keys].flatMap((k) => differingPaths((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], path ? `${path}.${k}` : k));
  }
  return [path || "(root)"];
}

// ---- Observation ------------------------------------------------------------

export interface ComposeConfig {
  services: Record<string, { environment?: Record<string, string | null>; ports?: { published?: string; host_ip?: string; target?: number }[] }>;
  secrets?: Record<string, { file?: string }>;
}

function composeConfig(dir: string): ComposeConfig {
  return JSON.parse(docker(dir, ["--profile", "deploy", "config", "--format", "json"])) as ComposeConfig;
}

/** What the resolved configuration and the directory show; no container is queried. */
export function observeConfig(cfg: ComposeConfig, dir: string): Omit<Observed, "custodyComplete"> {
  const env = (service: string) => cfg.services[service]?.environment ?? {};
  const platform: Platform = "COOLIFY_RESOURCE_UUID" in env("varlatchd") ? "coolify" : "compose";
  const variables = SECRETS.filter((s) => cfg.services[s.service])
    .map((spec) => ({ spec, value: env(spec.service)[spec.key] ?? "" }))
    .filter((v) => v.value !== "");
  const mounted = SECRETS.map((s) => s.secret).filter((name) => {
    const file = cfg.secrets?.[name]?.file;
    return Boolean(file && file !== "/dev/null" && existsSync(file));
  });
  const deploy = env("convex-deploy");
  const webPort = cfg.services["varlatch-web"]?.ports?.find((p) => p.target === 80);
  const publicUrl = env("varlatchd").VARLATCH_PUBLIC_URL || null;
  const webConvex = env("varlatch-web").CONVEX_URL || null;
  const envPath = join(dir, ".env");
  return {
    platform,
    publicUrl,
    convexOrigin: webConvex && publicUrl && webConvex !== `${publicUrl}/convex` ? webConvex : null,
    webPort: webPort?.published ? Number(webPort.published) : null,
    bindAddress: webPort?.host_ip ?? null,
    variables,
    mounted,
    jwksUrl: deploy.VARLATCH_JWKS_URL || null,
    adminKeyProvided: Boolean(deploy.CONVEX_SELF_HOSTED_ADMIN_KEY),
    instanceSecretAvailable: Boolean(deploy.CONVEX_INSTANCE_SECRET) || mounted.includes("convex-instance-secret"),
    configRecorded: existsSync(join(dir, CONFIG_FILE)),
    managedEnv: existsSync(envPath) && readFileSync(envPath, "utf8").startsWith(ENV_HEADER),
  };
}

function observe(dir: string): Observed {
  let custodyComplete = false;
  try { custodyComplete = escrowComplete(JSON.parse(varlatchd(dir, ["admin", "custody", "status"])) as CustodyStatus); } catch { /* not running */ }
  return { ...observeConfig(composeConfig(dir), dir), custodyComplete };
}

/**
 * Doctor's advisory finding (D13): which adoption steps are still open.
 * Custody has its own check, so it is left out here.
 */
export function checkAdoption(cfg: ComposeConfig | null, dir: string): Check {
  const base = { id: "installation.adopted", title: "Configuration managed by Varlatch", class: "advisory" as const };
  if (!cfg?.services) return { ...base, status: "unknown", detail: "could not resolve the Compose configuration" };
  const open = plan({ ...observeConfig(cfg, dir), custodyComplete: true }).filter((s) => s.status === "pending" || s.status === "blocked");
  return open.length
    ? { ...base, status: "fail", detail: `not adopted: ${open.map((s) => s.id).join(", ")} open`, remedy: "Run `varlatch adopt` for the plan (a dry run changes nothing)" }
    : { ...base, status: "pass", detail: "adopted" };
}

// ---- Checkpoints --------------------------------------------------------------

interface Checkpoint { step: StepId; at: string; file: string; before: string; after: string }

function statePath(dir: string) { return join(dir, ".adopt", "state.json"); }
function readState(dir: string): Checkpoint[] {
  try { return JSON.parse(readFileSync(statePath(dir), "utf8")) as Checkpoint[]; } catch { return []; }
}

/** Writes a new .env, keeping the previous one as a protected checkpoint. */
function writeEnvWithCheckpoint(dir: string, step: StepId, next: string): void {
  const envPath = join(dir, ".env");
  const current = existsSync(envPath) ? readFileSync(envPath, "utf8") : "";
  mkdirSync(join(dir, ".adopt", "checkpoints"), { recursive: true, mode: 0o700 });
  const file = join(dir, ".adopt", "checkpoints", `${new Date().toISOString().replace(/[:.]/g, "-")}-${step}.env`);
  writeFileSync(file, current, { mode: 0o600 });
  writeFileSync(envPath, next, { mode: 0o600 });
  const state = readState(dir);
  state.push({ step, at: new Date().toISOString(), file, before: sha(current), after: sha(next) });
  writeFileSync(statePath(dir), JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
}

export function revertStep(dir: string, step: StepId): string {
  if (step === "trust") throw new SetupError("The trust step is forward only; archives with the old URL still restore through the `tailscale` legacy alias.");
  const state = readState(dir);
  const last = [...state].reverse().find((c) => c.step === step);
  if (!last) throw new SetupError(`No checkpoint for ${step}`);
  const current = readFileSync(join(dir, ".env"), "utf8");
  if (sha(current) !== last.after) {
    throw new SetupError(`.env changed after ${step} (by hand, by Coolify, or by a later step); revert the later steps first or restore ${last.file} deliberately.`);
  }
  copyFileSync(last.file, join(dir, ".env"));
  chmodSync(join(dir, ".env"), 0o600);
  state.push({ step, at: new Date().toISOString(), file: last.file, before: last.after, after: last.before });
  writeFileSync(statePath(dir), JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  return last.file;
}

// ---- Steps ------------------------------------------------------------------------

function writeSecretFiles(secretsDir: string, variables: Observed["variables"]): Record<string, string> {
  mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  chmodSync(secretsDir, 0o700);
  const paths: Record<string, string> = {};
  for (const { spec, value } of variables) {
    const file = join(secretsDir, spec.secret);
    if (existsSync(file)) {
      if (readFileSync(file, "utf8").trim() !== value) throw new SetupError(`${file} exists with a different value; adopt never overwrites a secret file`);
    } else {
      writeFileSync(file, `${value}\n`, { mode: 0o644 });
    }
    paths[`${spec.variable}_HOST_PATH`] = file;
  }
  return paths;
}

async function redeployAndVerify(dir: string, opts: { reconcile?: boolean; recreate?: boolean } = {}): Promise<void> {
  // Compose does not recreate a container when only a top-level secret's
  // source file changes: steps that move secrets force recreation.
  docker(dir, ["up", "-d", "--remove-orphans", ...(opts.recreate ? ["--force-recreate"] : [])], { stream: true });
  await waitHealthy(dir, 10 * 60_000);
  if (opts.reconcile) docker(dir, ["run", "--rm", "convex-deploy"], { stream: true });
  const report = await runDoctor({ dir, waitSeconds: 30 });
  if (doctorExitCode(report) !== 0) {
    console.log(formatDoctor(report));
    throw new SetupError("Verification failed after this step: mandatory doctor checks fail (above). Revert the step with --revert, or fix and rerun.");
  }
}

/**
 * Secrets that some RUNNING consumer still mounts from the empty default —
 * i.e. not yet deployed with its file. Consumers come from the Compose
 * configuration; one-shot services that are not running are skipped.
 */
function undeployedSecrets(dir: string, names: string[]): string[] {
  const cfg = composeConfig(dir) as ComposeConfig & { services: Record<string, { secrets?: { source: string }[] }> };
  const missing = new Set<string>();
  for (const [service, def] of Object.entries(cfg.services)) {
    const consumed = (def.secrets ?? []).map((s) => s.source).filter((n) => names.includes(n));
    if (!consumed.length) continue;
    const id = docker(dir, ["ps", "-q", service]);
    if (!id) continue;
    const mounts = JSON.parse(execFileSync("docker", ["inspect", id, "--format", "{{json .Mounts}}"], { encoding: "utf8" })) as { Source: string; Destination: string }[];
    for (const name of consumed) {
      if (!mounts.some((m) => m.Destination === `/run/secrets/${name}` && m.Source !== "/dev/null")) missing.add(name);
    }
  }
  return [...missing];
}

export interface AdoptOptions {
  dir: string;
  apply: boolean;
  only?: StepId | undefined;
  revert?: StepId | undefined;
  secretsDir?: string | undefined;
  escrow?: EscrowMethod | undefined;
  escrowPassphraseFile?: string | undefined;
  shares?: number | undefined;
  threshold?: number | undefined;
  attest: boolean;
}

/** Exit codes: 0 adopted, 1 failed verification, 5 manual step pending (Coolify) or dry run with work left. */
export async function runAdopt(opts: AdoptOptions): Promise<number> {
  const dir = resolve(opts.dir);
  for (const step of [opts.only, opts.revert]) {
    if (step && !order.includes(step)) throw new SetupError(`Unknown step ${step}; steps: ${order.join(", ")}`);
  }
  if (opts.revert) {
    const file = revertStep(dir, opts.revert);
    console.log(`Restored .env from ${file}; redeploying.`);
    await redeployAndVerify(dir);
    return 0;
  }
  let observed = observe(dir);
  const print = (steps: PlannedStep[]) => {
    console.log(`\nvarlatch adopt — ${dir} (${observed.platform === "coolify" ? "Coolify" : "plain Compose"})\n`);
    steps.forEach((s, i) => {
      const mark = s.status === "done" ? "✓" : s.status === "n/a" ? "–" : s.status === "blocked" ? "✗" : "→";
      console.log(`  ${mark} ${i + 1}. ${s.id.padEnd(17)} ${s.status.padEnd(8)} ${s.summary}`);
      if (s.status === "pending" || s.status === "blocked") console.log(`       ${s.blockedBy ? `needs ${s.blockedBy}; ` : ""}${s.reversibility}`);
    });
  };
  const steps = plan(observed);
  print(steps);
  const open = steps.filter((s) => s.status === "pending" || s.status === "blocked");
  if (!open.length) { console.log("\nAdopted: this installation is managed."); return 0; }
  if (!opts.apply) { console.log("\nDry run: nothing changed. Run with --apply to perform the pending steps in order."); return 5; }

  const secretsDir = resolve(opts.secretsDir ?? (observed.platform === "coolify" ? "/data/varlatch/secrets" : join(dir, "secrets")));
  const coolifyPlan = (lines: string[]) => {
    console.log("\n  In Coolify's env settings for this resource:");
    for (const l of lines) console.log(`    ${l}`);
    console.log("  Then redeploy and rerun `varlatch adopt` to verify — adoption stays incomplete until then.");
    return 5;
  };

  for (const id of order) {
    if (opts.only && id !== opts.only) continue;
    observed = observe(dir);
    const step = plan(observed).find((s) => s.id === id)!;
    if (step.status === "done" || step.status === "n/a") continue;
    if (step.status === "blocked") { console.log(`\n✗ ${id}: blocked — needs ${step.blockedBy}`); return 5; }
    console.log(`\n→ ${id}: ${step.summary}`);
    const envPath = join(dir, ".env");
    const envText = () => (existsSync(envPath) ? readFileSync(envPath, "utf8") : "");

    if (id === "config") {
      const config: InstallConfig = {
        schemaVersion: 1, publicUrl: observed.publicUrl ?? "",
        webPort: observed.webPort ?? 8787, bindAddress: observed.bindAddress ?? "127.0.0.1",
        ...(observed.convexOrigin ? { convexOrigin: observed.convexOrigin } : {}),
      };
      if (!config.publicUrl) throw new SetupError("VARLATCH_PUBLIC_URL is not set in this installation; set it before adopting");
      writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(config, null, 2) + "\n");
      console.log(`  ✓ ${CONFIG_FILE}`);
    } else if (id === "secret-files") {
      const pending = observed.variables.filter((v) => !observed.mounted.includes(v.spec.secret));
      const paths = writeSecretFiles(secretsDir, pending);
      console.log(`  ✓ wrote ${pending.map((v) => v.spec.secret).join(", ")} to ${secretsDir} (current values; 0644 in a 0700 directory)`);
      if (observed.platform === "coolify") return coolifyPlan(Object.entries(paths).map(([k, v]) => `add ${k}=${v}`));
      writeEnvWithCheckpoint(dir, id, editEnv(envText(), paths));
      await redeployAndVerify(dir, { recreate: true });
      const stale = undeployedSecrets(dir, pending.map((v) => v.spec.secret));
      if (stale.length) throw new SetupError(`After redeploying, still not mounted from its file: ${stale.join(", ")}`);
      console.log("  ✓ every consumer mounts its file; verified (variables still present)");
    } else if (id === "remove-variables") {
      const notDeployed = undeployedSecrets(dir, observed.variables.map((v) => v.spec.secret));
      if (notDeployed.length) {
        console.log(`  ✗ not yet running with its file: ${notDeployed.join(", ")} — redeploy (recreating the containers) first`);
        return 5;
      }
      const names = observed.variables.map((v) => v.spec.variable);
      if (observed.platform === "coolify") return coolifyPlan(names.map((n) => `delete ${n}`));
      writeEnvWithCheckpoint(dir, id, editEnv(envText(), Object.fromEntries(names.map((n) => [n, null]))));
      await redeployAndVerify(dir, { recreate: true });
      console.log(`  ✓ removed ${names.join(", ")}; verified`);
    } else if (id === "trust") {
      try {
        docker(dir, ["exec", "-T", "convex-backend", "curl", "-fsS", "-o", "/dev/null", CANONICAL_JWKS]);
      } catch {
        throw new SetupError(`Convex cannot reach ${CANONICAL_JWKS}; the trust change would break Mirror publication. Not changed.`);
      }
      if (observed.platform === "coolify") return coolifyPlan([`set VARLATCH_JWKS_URL=${CANONICAL_JWKS}`]);
      writeEnvWithCheckpoint(dir, id, editEnv(envText(), { VARLATCH_JWKS_URL: CANONICAL_JWKS }));
      await redeployAndVerify(dir, { reconcile: true });
      console.log("  ✓ Convex trusts varlatchd at its fixed name; Mirrors verified");
    } else if (id === "deploy-authority") {
      const proof = docker(dir, ["run", "--rm", "-e", "CONVEX_SELF_HOSTED_ADMIN_KEY=", "convex-deploy"]);
      if (!/deployment authority derived/.test(proof)) throw new SetupError("The deploy job could not derive its admin key; CONVEX_ADMIN_KEY kept.");
      console.log("  ✓ the derived admin key works");
      if (observed.platform === "coolify") return coolifyPlan(["delete CONVEX_ADMIN_KEY"]);
      writeEnvWithCheckpoint(dir, id, editEnv(envText(), { CONVEX_ADMIN_KEY: null }));
      await redeployAndVerify(dir, { reconcile: true });
      console.log("  ✓ CONVEX_ADMIN_KEY removed");
    } else if (id === "custody") {
      if (!(await escrowPhase(dir, opts))) return 5;
    } else if (id === "managed-env") {
      const recorded = loadInstallConfig(dir);
      if (!recorded) throw new SetupError(`${CONFIG_FILE} missing; run the config step first`);
      // Record where this installation actually keeps its secret files, so the
      // managed .env (and later setup runs) point at the same files.
      const secretPaths: Record<string, string> = {};
      for (const line of envText().split("\n")) {
        const m = line.match(/^\s*((?:[A-Z0-9_]+_HOST_PATH))\s*=\s*(.+?)\s*$/);
        if (m && m[1] !== "TS_AUTHKEY_HOST_PATH") secretPaths[m[1]!] = m[2]!;
      }
      const config: InstallConfig = { ...recorded, secretPaths };
      writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(config, null, 2) + "\n");
      const managedKeys = new Set(renderEnv(config).split("\n").map((l) => l.match(/^([A-Z_][A-Z0-9_]*)=/)?.[1]).filter(Boolean) as string[]);
      const additions = envText().split("\n")
        .filter((l) => { const k = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)?.[1]; return k && !managedKeys.has(k); })
        .join("\n");
      const next = renderEnv(config, additions ? `${additions}\n` : "", { override: existsSync(join(dir, COMPOSE_OVERRIDE)) });
      // The managed file must describe the same installation: compare the
      // resolved Compose configuration before and after, then keep or roll back.
      const before = composeConfig(dir);
      writeEnvWithCheckpoint(dir, id, next);
      const changed = differingPaths(before, composeConfig(dir));
      if (changed.length) {
        revertStep(dir, id);
        throw new SetupError(`The managed .env would change the resolved configuration at ${changed.slice(0, 8).join(", ")}; restored the previous .env.`);
      }
      console.log("  ✓ .env is managed by `varlatch setup` from now on (resolved configuration unchanged)");
    }
    if (opts.only) break;
  }
  observed = observe(dir);
  const after = plan(observed);
  print(after);
  const remaining = after.filter((s) => s.status === "pending" || s.status === "blocked");
  if (remaining.length) { console.log(`\nIncomplete: ${remaining.map((s) => s.id).join(", ")}`); return 5; }
  console.log("\nAdopted: this installation is managed.");
  return 0;
}
