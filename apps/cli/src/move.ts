// SPDX-License-Identifier: Apache-2.0
import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { createBackup, verifyBackup } from "./backup.js";
import { clearMoveState, readMoveState, writeMoveState } from "./moveState.js";
import {
  CONFIG_FILE,
  INGRESS,
  INGRESS_FILES,
  type Ingress,
  type InstallConfig,
  loadInstallConfig,
  rewriteManagedEnv,
  runSetup,
  SetupError,
  validatePublicHost,
  validatePublicUrl,
  varlatchd,
} from "./setup.js";

/**
 * `varlatch move` (issue #103): the supported way to give an installation
 * another public URL. The URL is the passkeys' relying party, so a move is a
 * re-enrollment event (ADR-0035, "Domain changes"): archive first, then the
 * new address through setup's own steps, then the passkeys of the old
 * address are removed once, and every person gets a one-time link to enroll
 * a new passkey on their existing identity.
 *
 * The move is resumable: `varlatch-move.json` records where it is, so a rerun
 * neither takes a second archive nor removes the passkeys people enrolled at
 * the new address in between.
 */

export interface MoveFacts {
  publicUrl: string | null;
  people: number;
  installationAdmins: number;
  passkeys: number;
  sessions: number;
  tailnetConstraints: number;
  pendingInvitations: number;
}

export interface MoveOptions {
  dir: string;
  publicUrl?: string | undefined;
  ingress?: Ingress | undefined;
  /** Passed through to `varlatch admin backup create|verify`; the archive stays local. */
  backupArgs: string[];
  yes: boolean;
  /** Lifetime of the re-enrollment links (1 to 168 hours). */
  reenrollHours?: number | undefined;
  noWait: boolean;
  enrollTimeoutMs: number;
  /** Give up an open move: the configuration goes back to the old address. */
  abandon?: boolean;
}

export const REENROLL_HOURS_MAX = 168;

/** The Installation Configuration after the move; pure, so it is testable. */
export function movedConfig(config: InstallConfig, to: { publicUrl: string; ingress: Ingress }): { config: InstallConfig; notes: string[] } {
  const notes: string[] = [];
  const next: InstallConfig = { ...config, publicUrl: to.publicUrl, ingress: to.ingress };
  if (to.ingress !== "tailnet") {
    delete next.tailnetMachine;
    delete next.tailnetName;
  }
  if (config.convexOrigin !== undefined) {
    if (config.convexOrigin === `${config.publicUrl}/convex`) {
      delete next.convexOrigin;
    } else {
      notes.push(
        `Convex keeps its own address, ${config.convexOrigin}. If that address moves too, set convexOrigin in ${CONFIG_FILE} and rerun \`varlatch setup\`.`,
      );
    }
  }
  return { config: next, notes };
}

/** Where the move goes, validated, or why it cannot. */
export function moveTarget(config: InstallConfig, opts: Pick<MoveOptions, "publicUrl" | "ingress">): { publicUrl: string; ingress: Ingress } {
  if (opts.ingress && !INGRESS.includes(opts.ingress)) throw new SetupError(`--ingress must be one of public, external`);
  const ingress = opts.ingress ?? config.ingress ?? "external";
  if (ingress === "tailnet") {
    throw new SetupError(
      "Moving to the tailnet ingress is not supported yet: the Tailscale node keeps its own name and state. " +
        "Move to the public or external ingress, or set up a new installation on the tailnet and restore an archive into it.",
    );
  }
  if (!opts.publicUrl) throw new SetupError("Pass --public-url <the new address people will open>");
  let publicUrl = validatePublicUrl(opts.publicUrl);
  if (ingress === "public") publicUrl = validatePublicHost(publicUrl);
  if (publicUrl === config.publicUrl && ingress === (config.ingress ?? "external")) {
    throw new SetupError(`This installation already answers at ${publicUrl} (${ingress} ingress): nothing to move.`);
  }
  if (publicUrl === config.publicUrl) {
    throw new SetupError(
      `The address stays ${publicUrl}: changing only the ingress is not a move (every passkey keeps working), and it is not supported yet.`,
    );
  }
  return { publicUrl, ingress };
}

/** What the operator reads before confirming. */
export function movePlan(from: InstallConfig, to: { publicUrl: string; ingress: Ingress }, facts: MoveFacts): string[] {
  const fromIngress = from.ingress ?? "external";
  const lines = [
    `Move ${from.publicUrl} (${fromIngress} ingress) to ${to.publicUrl} (${to.ingress} ingress).`,
    "",
    "Passkeys belong to the address, so a move is a re-enrollment event:",
    `  - every passkey stops working (${facts.passkeys} enrolled), and every browser session ends (${facts.sessions});`,
    `  - each of the ${facts.people} people gets a one-time link to enroll a new passkey on the same identity`,
    "    (their access, memberships, and audit history stay as they are);",
    "  - CLI, agent, and machine credentials keep working: change the server address where they are",
    "    configured (varlatch.toml, CI, VARLATCH_SERVER), and people sign in again with",
    `    \`varlatch login --server ${to.publicUrl}\`;`,
    `  - passkeys and the dashboard no longer work at ${from.publicUrl}${fromIngress === "external" ? " (your proxy may still route it)" : ", which stops answering"}.`,
    "",
    "First, an archive of the installation is taken and verified. Restoring it is the way back.",
  ];
  if (fromIngress === "tailnet" && facts.tailnetConstraints > 0) {
    lines.push(
      "",
      `This installation has ${facts.tailnetConstraints} Tailnet Constraint(s). Without the tailnet ingress nothing reaches`,
      "the tailnet listener, so the access they guard is denied until you remove them.",
    );
  }
  if (facts.pendingInvitations > 0) {
    lines.push(
      "",
      `${facts.pendingInvitations} invitation link(s) are still open. They keep working, but they name the old address:`,
      "send people the same link with the new address in front of /enroll#.",
    );
  }
  return lines;
}

async function confirm(question: string, yes: boolean): Promise<boolean> {
  if (yes) return true;
  if (!process.stdin.isTTY) throw new SetupError("Not a terminal: pass --yes once you have read what a move does (run without --yes in a terminal to see it).");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} [y/N] `)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

export async function runMove(opts: MoveOptions): Promise<number> {
  const dir = resolve(opts.dir);
  const config = loadInstallConfig(dir);
  if (!config) {
    throw new SetupError(
      `No ${CONFIG_FILE} in ${dir}: \`varlatch move\` changes installations that \`varlatch setup\` or \`varlatch adopt\` manages. ` +
        "On Coolify, follow docs/operations/move-installation.md.",
    );
  }
  if (opts.reenrollHours !== undefined && !(Number.isFinite(opts.reenrollHours) && opts.reenrollHours > 0 && opts.reenrollHours <= REENROLL_HOURS_MAX)) {
    throw new SetupError(`--reenroll-hours must be more than 0 and at most ${REENROLL_HOURS_MAX}. Nothing changed.`);
  }
  const pending = readMoveState(dir);
  if (opts.abandon) return abandonMove(dir, config, pending);
  if (pending) {
    if (opts.publicUrl && validatePublicUrl(opts.publicUrl) !== pending.to) {
      throw new SetupError(`A move to ${pending.to} is in progress: finish it with \`varlatch move\` (no --public-url), or give it up with \`varlatch move --abandon\`.`);
    }
    if (opts.ingress && opts.ingress !== pending.toIngress) {
      throw new SetupError(`The move in progress goes to the ${pending.toIngress} ingress, not ${opts.ingress}.`);
    }
    if (config.publicUrl === pending.from) {
      // Stopped between recording the move and writing the new address.
      writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(movedConfig(config, { publicUrl: pending.to, ingress: pending.toIngress }).config, null, 2) + "\n");
    } else if (config.publicUrl !== pending.to || (config.ingress ?? "external") !== pending.toIngress) {
      throw new SetupError(
        `${CONFIG_FILE} names ${config.publicUrl} (${config.ingress ?? "external"} ingress), but the move in progress goes from ${pending.from} to ` +
          `${pending.to} (${pending.toIngress} ingress). Put ${pending.to} back, or give the move up with \`varlatch move --abandon\`.`,
      );
    }
    console.log(`Resuming the move from ${pending.from} to ${pending.to} (archive ${pending.archive}).`);
  } else {
    const to = moveTarget(config, opts);
    if (!config.publicUrl) throw new SetupError(`${CONFIG_FILE} names no public URL yet: finish \`varlatch setup\` first.`);
    const missing = INGRESS_FILES[to.ingress].filter((f) => !existsSync(join(dir, f)));
    if (missing.length) throw new SetupError(`The ${to.ingress} ingress needs ${missing.join(", ")} in ${dir}: use a release bundle that includes them, or infra/compose.`);
    let facts: MoveFacts;
    try {
      facts = JSON.parse(varlatchd(dir, ["admin", "move-facts"])) as MoveFacts;
    } catch (err) {
      throw new SetupError(`Could not read the installation's state from varlatchd (it must be running and 0.15.0 or newer): ${err instanceof Error ? err.message : String(err)}`);
    }
    if (facts.publicUrl && facts.publicUrl !== config.publicUrl) {
      throw new SetupError(`${CONFIG_FILE} names ${config.publicUrl}, but varlatchd runs at ${facts.publicUrl}: rerun \`varlatch setup\` before moving.`);
    }
    if (facts.installationAdmins === 0) {
      throw new SetupError(
        "No Installation Admin is enabled, so nobody could finish the move. Recover one first: " +
          "`docker compose exec varlatchd node dist/cli.js admin recover --new-admin`. Nothing changed.",
      );
    }
    const { config: next, notes } = movedConfig(config, to);
    console.log([...movePlan(config, to, facts), ...notes.map((n) => `\nNote: ${n}`)].join("\n"));
    if (!(await confirm(`\nMove this installation to ${to.publicUrl}?`, opts.yes))) {
      console.log("Nothing changed.");
      return 1;
    }

    console.log("\nTaking an archive (the way back) ...");
    const archive = await createBackup(opts.backupArgs, dir);
    // Checked against the release this installation runs: the archive is for
    // going back to it, not forward.
    const installed = join(dir, "varlatch-release.json");
    const verifyArgs = [...opts.backupArgs, "--in", archive, ...(existsSync(installed) ? ["--target-release", installed] : [])];
    try {
      await verifyBackup([...verifyArgs, "--record"], dir);
    } catch (err) {
      // Recording the result in the backup status is a Compose exec into
      // varlatchd of its own, and it can fail while the archive is fine
      // (varlatch/varlatch#1). Verify again without it: a damaged archive
      // still stops the move here.
      await verifyBackup(verifyArgs, dir);
      console.log(
        `  Note: the archive is verified, but the result could not be recorded in the backup status ` +
          `(${err instanceof Error ? err.message : String(err)}).`,
      );
    }
    console.log(`  ✓ archive ${archive} verified`);

    writeMoveState(dir, {
      from: config.publicUrl,
      fromIngress: config.ingress ?? "external",
      to: to.publicUrl,
      toIngress: to.ingress,
      archive,
      startedAt: new Date().toISOString(),
      previousConfig: config,
    });
    writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(next, null, 2) + "\n");
  }
  return runSetup({
    dir,
    noWait: opts.noWait,
    enrollTimeoutMs: opts.enrollTimeoutMs,
    attest: false,
    move: { ...(opts.reenrollHours !== undefined ? { reenrollHours: opts.reenrollHours } : {}) },
  });
}

/**
 * `varlatch move --abandon`: the configuration and .env go back to the old
 * address and the move is closed. Before the old passkeys were removed that
 * is all a way back needs (then `varlatch setup`); after, the archive the move
 * took is restored first, which brings the old passkeys back.
 */
function abandonMove(dir: string, config: InstallConfig, pending: ReturnType<typeof readMoveState>): number {
  if (!pending) throw new SetupError("No move in progress: nothing to give up.");
  const previous = pending.previousConfig ?? { ...config, publicUrl: pending.from, ingress: pending.fromIngress };
  writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(previous, null, 2) + "\n");
  rewriteManagedEnv(dir, previous);
  clearMoveState(dir);
  console.log(`The move to ${pending.to} is given up: ${CONFIG_FILE} and .env name ${pending.from} again.`);
  if (pending.passkeysRetiredAt) {
    console.log(
      `The passkeys of ${pending.from} were removed at ${pending.passkeysRetiredAt}. To get them back, restore the archive the move took, ` +
        `${pending.archive} (docs/operations/backup.md), then run \`varlatch setup\`.`,
    );
  } else {
    console.log("No passkey was removed. Run `varlatch setup` to bring the installation back at its old address.");
  }
  return 0;
}
