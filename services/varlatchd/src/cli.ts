#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Maintenance, prepareRestore, activeGate } from "@varlatch/backup";
import { operatorLease } from "./backup/operator-lock.js";
import { stateDir, startBackupControl, control } from "./backup/control.js";
import { MirrorStatusReporter } from "./mirror/status.js";
import { readFileSync, writeFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import { whois } from "./tailnet/whois.js";
import { startMirrorLoop } from "./mirror/publisher.js";
import { startWebhookLoop } from "./domain/webhooks.js";
import { ConfigError, loadConfig, type VarlatchdConfig } from "./config.js";
import { createPgQuerier } from "./db/pg.js";
import { runMigrations, schemaIsCurrent } from "./db/migrate.js";
import type { AppCtx } from "./domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
  issueRecoveryGrant,
  verifyLoadedKek,
} from "./domain/bootstrap.js";
import { issueCredential } from "./auth/credentials.js";
import {
  combineKek,
  exportKekEscrow,
  restoreKekEscrow,
  splitKek,
  type EscrowBlob,
} from "./crypto/escrow.js";
import { buildApp, SERVER_VERSION } from "./http/app.js";
import { buildHumanAuth } from "./auth/humanauth.js";
import { fileURLToPath } from "node:url";

/**
 * varlatchd entrypoints (ADR-0019/0020):
 *   varlatchd serve                      — the Secret Plane daemon (runtime role)
 *   varlatchd migrate                    — one-shot forward-only migrations (migrate role)
 *   varlatchd admin bootstrap            — issue the one-time setup grant (host exec)
 *   varlatchd admin recover ...          — break-glass recovery grant (host exec)
 *   varlatchd admin doctor [--wait s]    — read-only Installation Health checks (JSON)
 *   varlatchd admin kek verify [--file]  — verify a KEK candidate against the canary
 *   varlatchd admin kek export --out     — passphrase-wrapped KEK escrow blob
 *   varlatchd admin kek restore --in --out — decrypt an escrow blob back to a KEK file
 *   varlatchd admin kek split --shares N --threshold K — Shamir shares of the KEK
 *   varlatchd admin kek combine --out    — reconstruct the KEK from shares on stdin
 *
 * The same image serves and migrates; Compose mounts different credentials
 * per service ("different execution authority, not different image bytes").
 */

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function has(flag: string): boolean {
  return process.argv.includes(flag);
}

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  try {
    switch (command ?? "serve") {
      case "serve":
        return await serveCommand();
      case "migrate":
        return await migrateCommand();
      case "admin":
        return await adminCommand(rest);
      default:
        fail(`Unknown command: ${command}\nCommands: serve | migrate | admin`);
    }
  } catch (err) {
    if (err instanceof ConfigError) fail(err.message);
    throw err;
  }
}

async function serveCommand(): Promise<void> {
  const config = loadConfig();
  const rootKek = config.loadRootKek();
  const db = createPgQuerier(config.databaseUrl);
  const maintenance = new Maintenance(stateDir());
  const ctx: AppCtx = { db, rootKek, maintenance };

  const interruptedCapture = maintenance.gate;
  if (interruptedCapture?.kind === "capture") maintenance.finishCapture(interruptedCapture.id);
  // Restore may start on an empty or partially restored database. No bootstrapping or workers until released.
  if (maintenance.gate?.kind !== "restore") {

    if (!(await schemaIsCurrent(db))) {
      fail(
        "Database schema is not current. Run the migrate entrypoint first " +
          "(canonical Compose gates varlatchd on varlatch-migrate).",
      );
    }
    await ensureInstallation(ctx);
    if (!(await verifyLoadedKek(ctx))) {
      fail(
        "The configured root KEK does not verify against this installation's " +
          "canary. Refusing to start with a wrong key (ADR-0019).",
      );
    }
  }
  const issuer = config.publicUrl ?? `http://localhost:${config.port}`;
  const humanAuth = buildHumanAuth({
    ctx,
    databaseUrl: config.databaseUrl,
    publicUrl: issuer,
  });
  startBackupControl(ctx, maintenance, config.convexUrl ? { convexUrl: config.convexUrl, issuer } : null);
  const app = buildApp(ctx, {
    clientAddress: c => getConnInfo(c).remote.address ?? "unknown",
    issuer,
    humanAuth,
    enrollBundlePath: fileURLToPath(new URL("./enroll.js", import.meta.url)),
    sync: config.sync,
  });
  serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`varlatchd ${SERVER_VERSION} listening on :${info.port} (ordinary listener)`);
  });

  if (config.convexUrl) {
    startMirrorLoop(ctx, { convexUrl: config.convexUrl, issuer }, undefined, undefined, new MirrorStatusReporter(stateDir()));
    console.log(`mirror publisher -> ${config.convexUrl}`);
  }

  startWebhookLoop(ctx);

  if (config.sync) {
    const { startSyncLoop } = await import("./domain/syncdelivery.js");
    startSyncLoop(ctx, {
      ...(config.sync.adapters ? { allowedAdapters: config.sync.adapters } : {}),
    });
    console.log(
      `sync targets enabled (adapters: ${config.sync.adapters?.join(",") ?? "all"})`,
    );
  } else {
    console.log("sync targets disabled by VARLATCH_SYNC=off (CLI mode remains available)");
  }

  if (config.tailscale) {
    const ts = config.tailscale;
    // Shared-namespace topology: leave (and be restarted) if the sidecar's
    // namespace goes away under us rather than sit healthy and unreachable.
    const { startNetnsWatchdog } = await import("./netns-watchdog.js");
    startNetnsWatchdog();
    // The dedicated tailnet listener (ADR-0014 §7): the ONLY place trusted
    // Tailnet Context can be created, from the true socket peer via WhoIs.
    const tailnetApp = buildApp(ctx, {
      clientAddress: c => getConnInfo(c).remote.address ?? "unknown",
      resolveTailnetContext: async (c) => {
        const info = getConnInfo(c);
        const addr = info.remote.address;
        const port = info.remote.port;
        if (!addr || port === undefined) return null;
        return whois(
          { socketPath: ts.socketPath, expectedTailnet: ts.expectedTailnet },
          addr,
          port,
        );
      },
      sync: config.sync,
    });
    serve(
      { fetch: tailnetApp.fetch, port: ts.port, hostname: ts.bind },
      (info) => {
        console.log(
          `varlatchd tailnet listener on ${ts.bind}:${info.port} (tailnet ${ts.expectedTailnet})`,
        );
      },
    );
  }
}

async function migrateCommand(): Promise<void> {
  const config = loadConfig(process.env, { requireKek: false });
  const db = createPgQuerier(config.databaseUrl);
  const release = await operatorLease(db);
  try {
    const gate = activeGate(stateDir());
    if (gate && (gate.kind !== "restore" || arg("--restore-gate") !== gate.id)) throw new Error("Migration refused during installation maintenance");
    // Never overlap an online backup capture (ADR-0036 D5): wait for it, bounded.
    const { withCaptureExclusion } = await import("./backup/online.js");
    const { applied } = await withCaptureExclusion(db, 15 * 60_000, () => runMigrations(db),
      () => console.log("Waiting for a running backup capture to finish…"));
    console.log(
      applied.length === 0
        ? "Schema already current."
        : `Applied migrations: ${applied.map((m) => `${m.id} (${m.name})`).join(", ")}`,
    );
  } finally { await release(); await db.end(); }
}

/** Reads the escrow passphrase without echoing it, or from a file/env for automation. */
async function readPassphrase(prompt: string, opts: { confirm?: boolean } = {}): Promise<string> {
  const file = arg("--passphrase-file");
  if (file) return readFileSync(file, "utf8").replace(/\r?\n$/, "");
  const fromEnv = process.env["VARLATCH_KEK_PASSPHRASE"];
  if (fromEnv) return fromEnv;
  if (!process.stdin.isTTY) {
    fail("No TTY: supply the passphrase via --passphrase-file or VARLATCH_KEK_PASSPHRASE");
  }
  const readHidden = (label: string): Promise<string> =>
    new Promise((resolve) => {
      process.stderr.write(label);
      const stdin = process.stdin;
      stdin.setRawMode?.(true);
      stdin.resume();
      let value = "";
      const onData = (chunk: Buffer) => {
        for (const ch of chunk.toString("utf8")) {
          if (ch === "\r" || ch === "\n") {
            stdin.setRawMode?.(false);
            stdin.pause();
            stdin.off("data", onData);
            process.stderr.write("\n");
            resolve(value);
            return;
          }
          if (ch === "\u0003") process.exit(130);
          if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
          else value += ch;
        }
      };
      stdin.on("data", onData);
    });
  const passphrase = await readHidden(prompt);
  if (opts.confirm) {
    const again = await readHidden("Confirm passphrase: ");
    if (again !== passphrase) fail("Passphrases do not match.");
  }
  return passphrase;
}

async function adminCommand(rest: string[]): Promise<void> {
  const sub = rest[0];
  if (sub === "backup-control") {
    const command = rest[1];
    const input = JSON.parse(readFileSync(0, "utf8") || "{}");
    try {
    const result = command === "prepare-restore"
      ? prepareRestore(stateDir(), input.archiveId)
      : await control({ ...input, command });
    console.log(JSON.stringify(result));
    } catch (error) { console.log(JSON.stringify({ error: error instanceof Error ? error.message : "Backup control failed" })); process.exitCode = 1; }
    return;
  }

  if (sub === "custody" && rest[1] === "status") {
    // Read-only (ADR-0035 D9): which recovery keys have a current attestation.
    const { custodyStatus } = await import("./domain/custody.js");
    const config = loadConfig(process.env, { requireKek: false });
    const db = createPgQuerier(config.databaseUrl);
    try { console.log(JSON.stringify(await custodyStatus(db))); } finally { await db.end(); }
    return;
  }

  if (sub === "bootstrap-status") {
    // Read-only (ADR-0035 D7): lets `varlatch setup` resume its bootstrap
    // phase, including after an interrupted enrollment.
    const { bootstrapStatus } = await import("./domain/bootstrap.js");
    const config = loadConfig(process.env, { requireKek: false });
    const db = createPgQuerier(config.databaseUrl);
    try { console.log(JSON.stringify(await bootstrapStatus(db))); } finally { await db.end(); }
    return;
  }

  if (sub === "doctor") {
    // Read-only Installation Health (ADR-0035 D8): no operator lease and no
    // maintenance refusal — it must report, not block, an active backup, and
    // it must still answer when the Root KEK cannot be loaded.
    const { serverDoctor } = await import("./doctor.js");
    const config = loadConfig(process.env, { requireKek: false });
    const db = createPgQuerier(config.databaseUrl);
    try {
      let rootKek: Buffer | null = null;
      try { rootKek = config.loadRootKek(); } catch { rootKek = null; }
      const waitSeconds = Number(arg("--wait") ?? "15");
      const report = await serverDoctor({
        ctx: rootKek ? { db, rootKek } : null,
        db,
        stateDir: stateDir(),
        publicUrl: config.publicUrl,
        convexUrl: config.convexUrl,
        waitMs: Number.isFinite(waitSeconds) ? Math.max(0, waitSeconds) * 1000 : 15_000,
      });
      rootKek?.fill(0);
      console.log(JSON.stringify(report));
    } finally { await db.end(); }
    return;
  }

  // `kek restore`/`kek combine` legitimately run when no KEK is configured
  // yet; every other admin path loads it on demand via makeCtx.
  const config = loadConfig(process.env, { requireKek: false });
  const db = createPgQuerier(config.databaseUrl);
  const release = await operatorLease(db);
  const makeCtx = (): AppCtx => ({ db, rootKek: config.loadRootKek() });
  try {
    if (activeGate(stateDir())) throw new Error("Installation is in maintenance; ordinary admin operations are blocked");
    switch (sub) {
      case "bootstrap": {
        const ctx = makeCtx();
        await ensureInstallation(ctx);
        const grant = await issueBootstrapGrant(ctx);
        if (has("--cli-credential")) {
          // Headless fallback: consume immediately, issue a CLI credential.
          const { identityId } = await consumeSetupGrant(ctx, grant.token, {
            adminName: arg("--name") ?? "Installation Admin",
          });
          const cred = await issueCredential(db, {
            identityId,
            kind: "cli",
            name: "bootstrap credential",
          });
          console.log("Installation bootstrapped.");
          console.log(`Installation Admin identity: ${identityId}`);
          console.log("One-time CLI credential (store it now; it is not retrievable):");
          console.log(cred.token);
          break;
        }
        const base = config.publicUrl ?? `http://localhost:${config.port}`;
        console.log("Open this one-time enrollment URL in your browser to create");
        console.log("the first Installation Admin's passkey (ADR-0006):");
        console.log(`  ${base}/enroll#${grant.token}`);
        console.log(`Expires: ${grant.expiresAt}. If it lapses, run bootstrap again.`);
        break;
      }
      case "recover": {
        const ctx = makeCtx();
        const identityId = arg("--identity");
        const input = has("--new-admin")
          ? ({ mode: "new-admin" } as const)
          : identityId
            ? ({ mode: "identity", identityId, enable: has("--enable") } as const)
            : fail("Usage: varlatchd admin recover --identity <id> [--enable] | --new-admin");
        const grant = await issueRecoveryGrant(ctx, input);
        if (has("--cli-credential")) {
          const { identityId: subject } = await consumeSetupGrant(ctx, grant.token, {
            adminName: arg("--name") ?? "Installation Admin",
          });
          const cred = await issueCredential(db, {
            identityId: subject,
            kind: "cli",
            name: "recovery credential",
          });
          console.log(`Recovery completed for ${subject}.`);
          console.log("One-time CLI credential (store it now; it is not retrievable):");
          console.log(cred.token);
          break;
        }
        const base = config.publicUrl ?? "http://localhost:8686";
        console.log("Open this one-time recovery URL to enroll a new passkey:");
        console.log(`  ${base}/enroll#${grant.token}`);
        console.log(`Expires: ${grant.expiresAt}.`);
        break;
      }
      case "mirror-sync": {
        if (!config.convexUrl) fail("Set VARLATCH_CONVEX_URL to enable mirror sync");
        const { syncAllMirrors } = await import("./mirror/publisher.js");
        const result = await syncAllMirrors(makeCtx(), {
          convexUrl: config.convexUrl,
          issuer: config.publicUrl ?? "varlatch",
        });
        console.log(`Mirrored ${result.pushed} records to the Application Plane.`);
        break;
      }
      case "kek":
        return await kekCommand(rest.slice(1), config, db);
      case "custody": {
        // An attestation is a claim, not a check (ADR-0035 D9): recorded,
        // dated, and aged — the installation cannot verify it.
        if (rest[1] !== "attest") fail("Usage: varlatchd admin custody attest --key root-kek|backup-key --method passphrase-escrow|shamir-split|copy | custody status");
        const { attestCustody } = await import("./domain/custody.js");
        const attestation = await attestCustody(db, { key: arg("--key") ?? "", method: arg("--method") ?? "" });
        console.log(JSON.stringify(attestation));
        break;
      }
      default:
        fail(
          "Usage: varlatchd admin <bootstrap | bootstrap-status | recover | mirror-sync | doctor [--wait <s>] | custody attest|status | " +
            "kek verify|export|restore|split|combine>",
        );
    }
  } finally {
    await release();
    await db.end();
  }
}

function parseKekFile(path: string): Buffer {
  const raw = readFileSync(path, "utf8").trim();
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) fail(`${path} does not contain a 32-byte KEK`);
  return key;
}

function writeKekFile(path: string, kek: Buffer): void {
  writeFileSync(path, kek.toString("hex") + "\n", { mode: 0o600 });
}

function collectArgs(flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === flag) {
      const v = process.argv[i + 1];
      if (v !== undefined) out.push(v);
    }
  }
  return out;
}

async function readStdinLines(): Promise<string[]> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks)
    .toString("utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/**
 * Verifies a recovered KEK against the installation canary when the database
 * is reachable; a fresh host with no restored database gets a loud warning
 * instead of a hard failure.
 */
async function verifyRecoveredKek(
  db: AppCtx["db"],
  kek: Buffer,
  label: string,
): Promise<void> {
  let ok: boolean;
  try {
    ok = await verifyLoadedKek({ db, rootKek: kek }, kek);
  } catch {
    console.error(
      `WARNING: could not reach the database to verify the ${label} against ` +
        "the installation canary. Run `admin kek verify` once the database is restored.",
    );
    return;
  }
  if (!ok) fail(`The ${label} does not match this installation's canary; refusing to write it.`);
  console.log(`${label} verified against the installation canary.`);
}

async function kekCommand(
  rest: string[],
  config: VarlatchdConfig,
  db: AppCtx["db"],
): Promise<void> {
  switch (rest[0]) {
    case "verify": {
      const file = arg("--file");
      const candidate = file ? parseKekFile(file) : undefined;
      const rootKek = candidate ?? config.loadRootKek();
      const ok = await verifyLoadedKek({ db, rootKek }, candidate);
      if (ok) console.log("KEK backup matches this installation.");
      else fail("KEK verification failed.");
      break;
    }
    case "export": {
      const file = arg("--file");
      const kek = file ? parseKekFile(file) : config.loadRootKek();
      const passphrase = await readPassphrase("Escrow passphrase (min 12 chars): ", {
        confirm: true,
      });
      const blob = exportKekEscrow(kek, passphrase);
      const json = JSON.stringify(blob, null, 2) + "\n";
      const out = arg("--out");
      if (out) {
        writeFileSync(out, json);
        console.log(`Escrow blob written to ${out}.`);
      } else {
        process.stdout.write(json);
      }
      console.error(
        "The blob is safe to store anywhere (even with database backups); " +
          "only the passphrase must be custodied separately. Losing the " +
          "passphrase makes the blob useless.",
      );
      break;
    }
    case "restore": {
      const input = arg("--in") ?? fail("Usage: admin kek restore --in <blob.json> --out <kek-file>");
      const out = arg("--out") ?? fail("Usage: admin kek restore --in <blob.json> --out <kek-file>");
      const blob = JSON.parse(readFileSync(input, "utf8")) as EscrowBlob;
      const passphrase = await readPassphrase("Escrow passphrase: ");
      const kek = restoreKekEscrow(blob, passphrase);
      await verifyRecoveredKek(db, kek, "restored KEK");
      writeKekFile(out, kek);
      console.log(`KEK written to ${out} (mode 0600).`);
      break;
    }
    case "split": {
      const n = Number(arg("--shares"));
      const k = Number(arg("--threshold"));
      if (!Number.isInteger(n) || !Number.isInteger(k)) {
        fail("Usage: admin kek split --shares <n> --threshold <k> [--file <kek-file>]");
      }
      const file = arg("--file");
      const kek = file ? parseKekFile(file) : config.loadRootKek();
      const { shares, fingerprint } = splitKek(kek, { shares: n, threshold: k });
      console.error(
        `Any ${k} of these ${n} shares reconstruct the KEK; fewer reveal nothing.\n` +
          "Give each share to a different custodian; never store two together.\n" +
          `Split fingerprint: ${fingerprint}\n`,
      );
      for (const share of shares) console.log(share);
      break;
    }
    case "combine": {
      const out = arg("--out") ?? fail("Usage: admin kek combine --out <kek-file> [--share <s>]...");
      const fromFlags = collectArgs("--share");
      const shares = fromFlags.length > 0 ? fromFlags : await readStdinLines();
      if (shares.length === 0) fail("Provide shares via --share flags or one per line on stdin.");
      const kek = combineKek(shares);
      await verifyRecoveredKek(db, kek, "combined KEK");
      writeKekFile(out, kek);
      console.log(`KEK written to ${out} (mode 0600).`);
      break;
    }
    default:
      fail("Usage: varlatchd admin kek <verify | export | restore | split | combine>");
  }
}

void main().catch(() => { console.error("Operator command failed; check configuration and maintenance status."); process.exitCode = 1; });
