// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, parse as parsePath, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";

/**
 * Deterministic context resolution (ADR-0017 §7):
 *
 *   explicit --environment flag
 *     > VARLATCH_ENV
 *       > per-repo local selection (.varlatch/local.json, gitignored)
 *         > committed default (varlatch.toml)
 *
 * Never inferred from Git branches, usernames, hostnames, or the existence of
 * personal environments. Repo context records choices; credentials live only
 * in the user-level store. Copying a working tree never copies a credential.
 */

export interface RepoConfig {
  server?: string;
  organization: string;
  project: string;
  defaultEnvironment?: string;
}

export interface LocalState {
  selectedEnvironment?: string;
  serverOverride?: string;
  /** Tier of the selected environment, cached at `env use` time (ADR-0032).
      A point-in-time snapshot for offline consumers, never authorization. */
  selectedTier?: string;
  tierCachedAt?: string;
}

export type EnvironmentSource = "flag" | "env-var" | "local-selection" | "committed-default";

export interface ResolvedContext {
  server: string;
  organization: string;
  project: string;
  environment: string;
  environmentSource: EnvironmentSource;
  repoRoot: string;
}

export class ContextError extends Error {
  override name = "ContextError";
}

export const REPO_CONFIG_FILE = "varlatch.toml";
const LOCAL_DIR = ".varlatch";
const LOCAL_STATE_FILE = "local.json";

export function findRepoRoot(cwd: string): string | null {
  let dir = resolve(cwd);
  const { root } = parsePath(dir);
  while (true) {
    if (existsSync(join(dir, REPO_CONFIG_FILE))) return dir;
    if (dir === root) return null;
    dir = dirname(dir);
  }
}

export function loadRepoConfig(repoRoot: string): RepoConfig {
  const raw = readFileSync(join(repoRoot, REPO_CONFIG_FILE), "utf8");
  let parsed: Record<string, unknown>;
  try {
    parsed = parseToml(raw) as Record<string, unknown>;
  } catch (err) {
    throw new ContextError(
      `Invalid ${REPO_CONFIG_FILE}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const str = (key: string): string | undefined => {
    const v = parsed[key];
    return typeof v === "string" && v.length > 0 ? v : undefined;
  };
  const organization = str("organization");
  const project = str("project");
  if (!organization || !project) {
    throw new ContextError(
      `${REPO_CONFIG_FILE} must declare "organization" and "project"`,
    );
  }
  const config: RepoConfig = { organization, project };
  const server = str("server");
  if (server) config.server = server;
  const defaultEnvironment = str("default_environment");
  if (defaultEnvironment) config.defaultEnvironment = defaultEnvironment;
  return config;
}

export function loadLocalState(repoRoot: string): LocalState {
  const path = join(repoRoot, LOCAL_DIR, LOCAL_STATE_FILE);
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as LocalState;
  } catch {
    return {};
  }
}

export function saveLocalState(repoRoot: string, state: LocalState): void {
  const dir = join(repoRoot, LOCAL_DIR);
  mkdirSync(dir, { recursive: true });
  // Make accidental commits hard (ADR-0017 §5): the directory ignores itself.
  const ignore = join(dir, ".gitignore");
  if (!existsSync(ignore)) writeFileSync(ignore, "*\n");
  writeFileSync(join(dir, LOCAL_STATE_FILE), `${JSON.stringify(state, null, 2)}\n`);
}

export interface ResolveOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  /** Explicit --environment flag. */
  environment?: string;
  /** Explicit --server flag. */
  server?: string;
}

export function resolveContext(options: ResolveOptions): ResolvedContext {
  const env = options.env ?? process.env;
  const repoRoot = findRepoRoot(options.cwd);
  if (!repoRoot) {
    throw new ContextError(
      `No ${REPO_CONFIG_FILE} found from ${options.cwd} upward. ` +
        "Run inside a configured repository or create one with the CLI.",
    );
  }
  const repo = loadRepoConfig(repoRoot);
  const local = loadLocalState(repoRoot);

  let environment: string | undefined;
  let environmentSource: EnvironmentSource;
  if (options.environment) {
    environment = options.environment;
    environmentSource = "flag";
  } else if (env.VARLATCH_ENV) {
    environment = env.VARLATCH_ENV;
    environmentSource = "env-var";
  } else if (local.selectedEnvironment) {
    environment = local.selectedEnvironment;
    environmentSource = "local-selection";
  } else if (repo.defaultEnvironment) {
    environment = repo.defaultEnvironment;
    environmentSource = "committed-default";
  } else {
    throw new ContextError(
      "No environment selected. Pass --environment, set VARLATCH_ENV, run " +
        "`varlatch env use <name>`, or commit default_environment in varlatch.toml.",
    );
  }

  const server =
    options.server ?? env.VARLATCH_SERVER ?? local.serverOverride ?? repo.server;
  if (!server) {
    throw new ContextError(
      "No server configured. Pass --server, set VARLATCH_SERVER, or commit " +
        `"server" in ${REPO_CONFIG_FILE}.`,
    );
  }

  return {
    server,
    organization: repo.organization,
    project: repo.project,
    environment,
    environmentSource,
    repoRoot,
  };
}

// ---- User-level credential store (never in the repo) ----------------------

export function credentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  const base =
    env.VARLATCH_CONFIG_DIR ??
    (env.XDG_CONFIG_HOME ? join(env.XDG_CONFIG_HOME, "varlatch") : join(homedir(), ".config", "varlatch"));
  return join(base, "credentials.json");
}

/** One stored entry. Pre-ADR-0032 files carry only `token`; every other
    field is best-effort metadata for offline session disclosure. */
export interface StoredCredential {
  token: string;
  issuedAt?: string;
  expiresAt?: string;
  credentialId?: string;
  name?: string;
}

interface CredentialsFile {
  servers: Record<string, StoredCredential>;
}

function readCredentialsFile(env: NodeJS.ProcessEnv): CredentialsFile | null {
  const path = credentialsPath(env);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as CredentialsFile;
  } catch {
    return null;
  }
}

function writeCredentialsFile(file: CredentialsFile, env: NodeJS.ProcessEnv): void {
  const path = credentialsPath(env);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`);
  chmodSync(path, 0o600);
}

export function loadToken(server: string, env: NodeJS.ProcessEnv = process.env): string | null {
  if (env.VARLATCH_TOKEN) return env.VARLATCH_TOKEN;
  return loadCredential(server, env)?.token ?? null;
}

/** Store entry only — deliberately blind to VARLATCH_TOKEN, which is a
    caller-provided credential with no stored metadata. */
export function loadCredential(
  server: string,
  env: NodeJS.ProcessEnv = process.env,
): StoredCredential | null {
  return readCredentialsFile(env)?.servers?.[server.replace(/\/+$/, "")] ?? null;
}

export function listCredentials(
  env: NodeJS.ProcessEnv = process.env,
): Array<{ server: string; credential: StoredCredential }> {
  const servers = readCredentialsFile(env)?.servers ?? {};
  return Object.entries(servers).map(([server, credential]) => ({ server, credential }));
}

export function saveCredential(
  server: string,
  credential: StoredCredential,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const parsed = readCredentialsFile(env) ?? { servers: {} };
  parsed.servers ??= {};
  parsed.servers[server.replace(/\/+$/, "")] = credential;
  writeCredentialsFile(parsed, env);
}

export function saveToken(server: string, token: string, env: NodeJS.ProcessEnv = process.env): void {
  saveCredential(server, { token }, env);
}

/** Returns false when there was nothing stored for that server. */
export function deleteCredential(server: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const parsed = readCredentialsFile(env);
  const key = server.replace(/\/+$/, "");
  if (!parsed?.servers?.[key]) return false;
  delete parsed.servers[key];
  writeCredentialsFile(parsed, env);
  return true;
}
