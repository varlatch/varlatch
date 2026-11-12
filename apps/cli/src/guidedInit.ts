// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { CONTRACT_SCHEMA_VERSION, LATEST_SEMANTICS_VERSION, type ConfigurationContract, type ContractItem, type ItemType } from "@varlatch/contract";
import type { ResolvedContext } from "@varlatch/context";
import type { Environment, Project } from "@varlatch/protocol";
import type { VarlatchClient } from "@varlatch/sdk";
import { VarlatchApiError } from "@varlatch/sdk";
import { EXIT, apiErrorExit, networkFailure } from "./exitCodes.js";
import { checkEntries, formatRows, ImportError, planRows, readActiveContract, readPresent, readSource, storeValues, finishSource, type Row } from "./importCommand.js";
import type { DotenvEntry } from "./dotenv.js";
import type { Prompter } from "./prompt.js";

/**
 * Guided `varlatch init` (ADR-0058 Decision 2). Runs only on a terminal,
 * outside assisted mode, when --org or --project is missing; asks only for
 * what is missing. It plans every .env file before writing anything,
 * leaves out the replacements the person declines, pushes one Contract
 * revision for all files, asks separately before activating it, and offers
 * to delete a file only when all of its values are stored and its items are
 * in the active Contract. Every step prints the command it stands for;
 * nothing it prints carries a value or a credential.
 */

/** The client calls the guided run makes. */
export type GuidedApi = Pick<
  VarlatchClient,
  | "listOrganizations"
  | "createOrganization"
  | "listProjects"
  | "createProject"
  | "listEnvironments"
  | "createEnvironment"
  | "getActiveContract"
  | "pushContractRevision"
  | "activateContractRevision"
  | "effectiveConfiguration"
  | "setValue"
>;

export interface GuidedInitDeps {
  cwd: string;
  prompt: Prompter;
  out: (line: string) => void;
  err: (line: string) => void;
  /** The server already resolved (flag, VARLATCH_SERVER, default, only credential), if any. */
  server: string | undefined;
  /** Validates and normalizes an address the person typed (setup's rule). */
  validateServer: (raw: string) => string;
  /** A client for the server, signing in first when there is no valid credential. */
  signIn: (server: string) => Promise<GuidedApi>;
  /** Writes varlatch.toml and the agent files, as `init` with flags does. */
  writeRepository: (config: { server: string; organization: string; project: string; defaultEnvironment: string }) => Promise<void>;
  organization?: string;
  project?: string;
  defaultEnvironment?: string;
}

const SLUG = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** Files that describe configuration rather than hold it. */
const NOT_VALUES = /\.(example|sample|template|schema|defaults|dist)$/;

function slugFrom(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);
  return SLUG.test(slug) ? slug : "project";
}

/** .env and .env.<name> files in the directory, never examples or schemas. */
export function findEnvFiles(cwd: string): string[] {
  return readdirSync(cwd)
    .filter((f) => (f === ".env" || f.startsWith(".env.")) && !NOT_VALUES.test(f))
    .filter((f) => {
      try {
        return statSync(join(cwd, f)).isFile();
      } catch {
        return false;
      }
    })
    .sort((a, b) => (a === ".env" ? -1 : b === ".env" ? 1 : a.localeCompare(b)));
}

interface FilePlan {
  file: string;
  path: string;
  environment: Environment;
  bytes: Buffer;
  entries: DotenvEntry[];
  rows: Row[];
  /** Names left out: replacements the person declined. */
  declined: string[];
}

/** What the run is doing, for a failure message that names the step and never the server's text. */
interface Phase {
  label: string;
  /** .env files were found: a failure says every one of them is kept. */
  files: boolean;
}

export async function guidedInit(deps: GuidedInitDeps): Promise<number> {
  const phase: Phase = { label: "setting up", files: false };
  try {
    return await guidedSteps(deps, phase);
  } catch (err) {
    // Value-free: an API error's code, a network failure's name, an
    // ImportError's own message (built from names only); never err.message
    // from a server, which could echo what was sent.
    if (err instanceof ImportError) {
      deps.err(`varlatch init: ${phase.label}: ${err.message}`);
    } else {
      const network = networkFailure(err);
      const code = (err as NodeJS.ErrnoException | null)?.code;
      const reason =
        err instanceof VarlatchApiError
          ? `${err.code}, HTTP ${err.status}`
          : (network ?? (typeof code === "string" && /^E[A-Z]+$/.test(code) ? code : err instanceof Error ? err.name : "an error"));
      deps.err(`varlatch init: ${phase.label} failed (${reason}).`);
    }
    if (phase.files) deps.err("varlatch init: every .env file is kept.");
    if (err instanceof ImportError) return err.exitCode;
    return err instanceof VarlatchApiError ? apiErrorExit(err) : networkFailure(err) ? EXIT.unavailable : EXIT.failure;
  }
}

async function guidedSteps(deps: GuidedInitDeps, phase: Phase): Promise<number> {
  const { prompt, out } = deps;
  const command = (line: string) => out(`  $ ${line}`);

  // 1. Server and sign-in.
  let server = deps.server;
  if (!server) {
    for (;;) {
      const typed = await prompt.text("Your Varlatch installation's address (https://...)");
      try {
        server = deps.validateServer(typed);
        break;
      } catch (err) {
        // A fixed message: what was typed may hold a credential, and is never echoed.
        prompt.say("That is not an installation's address: use https://<host>[:port], or http://localhost for a local trial, without a path or query.");
      }
    }
  }
  out(`Server: ${server}`);
  phase.label = "signing in";
  const api = await deps.signIn(server);
  phase.label = "reading or creating the organization";

  // 2. Organization.
  let organization = deps.organization;
  if (!organization) {
    const orgs = (await api.listOrganizations()).items;
    const choice = orgs.length
      ? await prompt.select("Organization:", [...orgs.map((o) => `${o.slug} (${o.name})`), "Create a new organization"], 0)
      : orgs.length;
    if (choice < orgs.length) {
      organization = (orgs[choice] as { slug: string }).slug;
    } else {
      const slug = await askSlug(prompt, "New organization's slug (lowercase letters, digits, hyphens)");
      const name = await prompt.text("Its name", slug);
      if (!(await prompt.confirm(`Create organization ${slug} (${name})?`, true))) return stopped(deps, "No organization was created.");
      await api.createOrganization({ slug, name });
      command(`varlatch org create ${slug} ${JSON.stringify(name)}`);
      organization = slug;
    }
  }

  // 3. Project.
  phase.label = "reading or creating the project";
  let project = deps.project;
  let projectInfo: Project | undefined;
  const projects = (await api.listProjects(organization)).items;
  if (!project) {
    const choice = projects.length
      ? await prompt.select("Project:", [...projects.map((p) => `${p.slug} (${p.name})`), "Create a new project"], 0)
      : projects.length;
    if (choice < projects.length) {
      projectInfo = projects[choice] as Project;
      project = projectInfo.slug;
    } else {
      const slug = await askSlug(prompt, "New project's slug", slugFrom(basename(deps.cwd)));
      const name = await prompt.text("Its name", slug);
      if (!(await prompt.confirm(`Create project ${slug} in ${organization}? Its Contract comes from the repository.`, true))) {
        return stopped(deps, "No project was created.");
      }
      projectInfo = await api.createProject(organization, { slug, name, contractAuthority: "git" });
      command(`varlatch project create ${slug} --org ${organization}`);
      project = slug;
    }
  } else {
    projectInfo = projects.find((p) => p.slug === project);
  }

  // 4. Environments.
  phase.label = "reading or creating the environments";
  let environments = (await api.listEnvironments(organization, project)).items;
  if (environments.length === 0) {
    if (await prompt.confirm("The project has no environments. Create development (tier development) and production (tier production)?", true)) {
      for (const [name, tier] of [["development", "development"], ["production", "production"]] as const) {
        await api.createEnvironment(organization, project, { name, tier });
        command(`varlatch env-create ${name} --tier ${tier}`);
      }
      environments = (await api.listEnvironments(organization, project)).items;
    }
  }
  const shared = environments.filter((e) => e.kind === "shared");
  let defaultEnvironment = deps.defaultEnvironment;
  if (!defaultEnvironment) {
    if (shared.length > 1) {
      const pre = Math.max(0, shared.findIndex((e) => e.name === "development"));
      defaultEnvironment = (shared[await prompt.select("Default environment for this repository:", shared.map((e) => `${e.name} (${e.tier})`), pre)] as Environment).name;
    } else {
      defaultEnvironment = shared[0]?.name ?? "development";
    }
  }

  // 5. varlatch.toml and the agent files.
  phase.label = "writing varlatch.toml";
  await deps.writeRepository({ server, organization, project, defaultEnvironment });
  command(`varlatch init --org ${organization} --project ${project} --server ${server}${defaultEnvironment !== "development" ? ` --default-environment ${defaultEnvironment}` : ""}`);

  // 6. .env files: plan everything first.
  const files = findEnvFiles(deps.cwd);
  if (files.length === 0 || shared.length === 0) {
    if (files.length > 0) out("The project has no environments, so no .env file was imported.");
    return done(deps);
  }
  out(`Found ${files.join(", ")}.`);
  phase.files = true;
  phase.label = "reading the Contract";
  const managed = projectInfo?.contractAuthority === "managed";
  const ctx = { organization, project } as ResolvedContext;
  // Read for a managed Contract too: its items keep their definitions, and
  // whether a file's items are in it decides whether the file may go.
  const contract = await readActiveContract(api as VarlatchClient, ctx);
  const canAddItems = !managed && contract !== "forbidden";
  const active = contract === "forbidden" ? null : contract;
  const contracted = new Map((active?.items ?? []).map((i) => [i.name, i]));
  const semanticsVersion = active ? (active.semanticsVersion ?? 1) : LATEST_SEMANTICS_VERSION;
  if (contract === "forbidden") out("You cannot read this project's Contract: values only, and every .env file is kept, since whether its items are in the Contract is unknown.");
  else if (managed) out("This project's Contract is managed in the dashboard: values only; new items are added there.");

  const plans: FilePlan[] = [];
  const used = new Set<string>();
  for (const file of files) {
    const options = [...shared.map((e) => `${e.name} (${e.tier})`), "Skip this file"];
    const guess = file === ".env" ? defaultEnvironment : file.slice(".env.".length);
    let pre = shared.findIndex((e) => e.name === guess && !used.has(e.name));
    if (pre < 0) pre = options.length - 1;
    let environment: Environment | undefined;
    for (;;) {
      const choice = await prompt.select(`Import ${file} into:`, options, pre);
      if (choice === options.length - 1) break;
      const candidate = shared[choice] as Environment;
      if (used.has(candidate.name)) {
        prompt.say(`Another file already goes to ${candidate.name}; one file per environment.`);
        continue;
      }
      environment = candidate;
      break;
    }
    if (!environment) {
      out(`${file}: skipped; it is kept.`);
      continue;
    }
    let source: { bytes: Buffer; entries: DotenvEntry[] };
    try {
      source = readSource(join(deps.cwd, file));
    } catch (err) {
      out(`${file}: ${err instanceof ImportError ? err.message : "cannot be read"} It is kept.`);
      continue;
    }
    const problems = checkEntries(source.entries);
    if (problems.length > 0) {
      for (const p of problems) deps.err(`varlatch init: ${file} ${p}`);
      out(`${file}: ${problems.length} problem(s); nothing from it is imported, and it is kept.`);
      continue;
    }
    if (source.entries.length === 0) {
      out(`${file} sets no values; nothing to import.`);
      continue;
    }
    phase.label = `reading what ${environment.name} already has`;
    const present = await readPresent(api as VarlatchClient, { organization, project, environment: environment.name });
    if (typeof present === "number") {
      out(`${file}: what ${environment.name} already has cannot be read (${present}), so a value could be replaced unseen. Nothing from it is imported, and it is kept.`);
      continue;
    }
    used.add(environment.name);
    const rows = planRows(source.entries, { contracted, present, semanticsVersion, online: true, contract: canAddItems, plain: new Set() });
    out(`${file} → ${organization} / ${project} / ${environment.name} (${environment.tier}): ${rows.length} value(s)`);
    for (const line of formatRows(rows, new Set())) out(line);
    const replacing = rows.filter((r) => r.existing === true).map((r) => r.entry.name);
    const declined: string[] = [];
    if (replacing.length > 0) {
      out(`${environment.name} already has a different value for ${replacing.join(", ")}.`);
      let approved = await prompt.confirm(`Replace ${replacing.length === 1 ? "it" : "them"} with the values in ${file}?`, false);
      if (approved && environment.tier === "production") {
        approved = (await prompt.text(`This is a production environment. Type ${environment.name} to replace them`)) === environment.name;
        if (!approved) out("Not typed: they are left as they are.");
      }
      if (!approved) declined.push(...replacing);
    }
    plans.push({ file, path: join(deps.cwd, file), environment, bytes: source.bytes, entries: source.entries, rows, declined });
  }
  if (plans.length === 0) return done(deps);

  // 7. Contract additions, once for all files.
  const additions = new Map<string, { types: Set<ItemType>; files: string[] }>();
  if (canAddItems) {
    for (const plan of plans) {
      for (const row of plan.rows) {
        if (row.contracted || plan.declined.includes(row.entry.name)) continue;
        const addition = additions.get(row.entry.name) ?? { types: new Set<ItemType>(), files: [] };
        addition.types.add(row.type);
        addition.files.push(plan.file);
        additions.set(row.entry.name, addition);
      }
    }
  }
  const chosenTypes = new Map<string, ItemType>();
  const plain = new Set<string>();
  if (additions.size > 0) {
    out(`New items for the Contract (${additions.size}), each a Secret unless you name it:`);
    for (const [name, a] of additions) {
      if (a.types.size === 1) {
        chosenTypes.set(name, [...a.types][0] as ItemType);
        continue;
      }
      const types = [...new Set<ItemType>(["string", ...a.types])];
      const choice = await prompt.select(`${name}: the files suggest different types (${[...a.types].join(", ")}). Its type:`, types, 0);
      chosenTypes.set(name, types[choice] as ItemType);
    }
    for (const [name] of additions) out(`  ${name}  ${chosenTypes.get(name)}`);
    const named = await prompt.text("Items that are not secret (comma-separated names), or Enter for none", "");
    for (const n of named.split(",").map((x) => x.trim()).filter(Boolean)) {
      if (additions.has(n)) plain.add(n);
      else prompt.say(`${n} is not a new item; ignored.`);
    }
  }

  // 8. Write: one revision, not activated, then the values.
  let revision: { id: string; active: boolean } | null = null;
  if (additions.size > 0) {
    const items: ContractItem[] = [
      ...(active?.items ?? []),
      ...[...additions.keys()].map((name) => ({
        name,
        required: { kind: "never" as const },
        sensitive: !plain.has(name),
        type: chosenTypes.get(name) as ItemType,
      })),
    ];
    const next = { ...((active ?? { schemaVersion: CONTRACT_SCHEMA_VERSION }) as ConfigurationContract), items };
    phase.label = "pushing the Contract revision";
    const pushed = await api.pushContractRevision(organization, project, { contract: next, provenance: { adapter: "varlatch-init" } });
    revision = { id: pushed.id, active: pushed.active };
    out(`Contract revision ${pushed.id} with ${additions.size} new item(s)${pushed.active ? " [active]" : ""}.`);
  }
  phase.label = "storing values";
  for (const [index, plan] of plans.entries()) {
    const approved = plan.entries.filter((e) => !plan.declined.includes(e.name));
    const result = await storeValues(api as VarlatchClient, { organization, project, environment: plan.environment.name }, approved);
    if (result.failure) {
      // One summary for every file: what was stored, what failed, what was never attempted.
      const where = (p: FilePlan) => `${organization} / ${project} / ${p.environment.name} (${p.file})`;
      for (const done of plans.slice(0, index)) {
        deps.err(`varlatch init: stored in ${where(done)}: ${done.entries.filter((e) => !done.declined.includes(e.name)).map((e) => e.name).join(", ")}`);
      }
      if (result.stored.length > 0) deps.err(`varlatch init: stored in ${where(plan)}: ${result.stored.join(", ")}`);
      deps.err(`varlatch init: not stored in ${where(plan)}: ${result.failure.name} (${result.failure.reason})`);
      if (result.failure.skipped.length > 0) deps.err(`varlatch init: not attempted in ${where(plan)}: ${result.failure.skipped.join(", ")}`);
      for (const later of plans.slice(index + 1)) {
        const names = later.entries.filter((e) => !later.declined.includes(e.name)).map((e) => e.name);
        if (names.length > 0) deps.err(`varlatch init: not attempted in ${where(later)}: ${names.join(", ")}`);
      }
      if (revision && !revision.active) deps.err(`varlatch init: Contract revision ${revision.id} was not activated.`);
      deps.err("varlatch init: every .env file is kept. Fix the cause, then import the rest with varlatch import <file> -e <environment>.");
      return result.failure.exitCode;
    }
    out(`Stored ${result.stored.length} value(s) from ${plan.file} in ${plan.environment.name}.`);
    command(`varlatch import ${plan.file} -e ${plan.environment.name}${additions.size > 0 ? " --contract" : ""}`);
    if (plan.declined.length > 0) out(`Left as they were in ${plan.environment.name}: ${plan.declined.join(", ")}.`);
  }

  // 9. Activation, asked on its own.
  let activated = revision?.active ?? false;
  if (revision && !revision.active) {
    out(`Revision ${revision.id} adds: ${[...additions.keys()].map((n) => `${n} (${chosenTypes.get(n)}, ${plain.has(n) ? "plain" : "secret"})`).join(", ")}.`);
    if (await prompt.confirm("Activate it? The Contract applies to the whole project, every environment.", true)) {
      phase.label = `activating Contract revision ${revision.id}`;
      await api.activateContractRevision(organization, project, revision.id);
      activated = true;
      command(`varlatch contract activate ${revision.id}`);
    } else {
      out(`Not activated. To activate it later: varlatch contract activate ${revision.id}`);
    }
  } else if (canAddItems && additions.size === 0) {
    out("Every item was already in the Contract; no revision was needed.");
  }

  // 10. Deleting the sources: last, default no, only when nothing is left behind.
  phase.label = "deleting .env files";
  // In the active Contract after this run: what it had, plus the additions once activated.
  const inActive = (name: string) => contracted.has(name) || (activated && additions.has(name));
  for (const plan of plans) {
    const missing = plan.rows.filter((r) => !inActive(r.entry.name)).map((r) => r.entry.name);
    const why =
      plan.declined.length > 0
        ? "it holds values you chose not to store"
        : contract === "forbidden"
          ? "whether its items are in the Contract cannot be read"
          : missing.length > 0
            ? managed
              ? `${missing.join(", ")} still need adding to the Contract in the dashboard`
              : "its new items are not in the active Contract"
            : null;
    if (why) {
      out(`${plan.file} is kept: ${why}.`);
      continue;
    }
    if (!(await prompt.confirm(`Delete ${plan.file}? Its values are stored in ${plan.environment.name}; other copies (CI, teammates) are not affected.`, false))) {
      out(`${plan.file} is kept; delete it once you no longer need it.`);
      continue;
    }
    if (finishSource(plan.path, plan.bytes)) out(`Deleted ${plan.file}.`);
    else out(`${plan.file} changed or disappeared since it was read; it was not deleted.`);
  }
  return done(deps);
}

async function askSlug(prompt: Prompter, question: string, defaultValue?: string): Promise<string> {
  for (;;) {
    const slug = await prompt.text(question, defaultValue);
    if (SLUG.test(slug)) return slug;
    prompt.say("Use lowercase letters, digits and hyphens, starting and ending with a letter or digit.");
  }
}

/**
 * The normal `varlatch login`, run as a child on this terminal for the
 * guided sign-in. Its input and its output (the address to open, the code)
 * are the terminal's; its error output is captured and dropped, since a
 * server's error text could carry what was sent. On a failure the caller
 * prints a fixed message instead. Returns the child's exit status.
 */
export function runLoginChild(command: string, args: string[]): number {
  const result = spawnSync(command, args, { stdio: ["inherit", "inherit", "pipe"] });
  if (result.error) return EXIT.failure;
  return result.status ?? EXIT.failure;
}

function stopped(deps: GuidedInitDeps, message: string): number {
  deps.out(`${message} No file was written.`);
  return 1;
}

function done(deps: GuidedInitDeps): number {
  deps.out("Done. Run your application with its configuration: varlatch run -- <command>");
  return 0;
}
