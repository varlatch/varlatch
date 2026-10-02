// SPDX-License-Identifier: Apache-2.0
import { lookup } from "node:dns/promises";
import {
  deletePendingSignIn,
  loadCredential,
  loadPendingSignIn,
  saveCredential,
  savePendingSignIn,
} from "@varlatch/context";
import { DeviceSignInRedirectError, VarlatchApiError, VarlatchClient, type DeviceSignInPoll } from "@varlatch/sdk";
import { EXIT, networkFailure } from "./exitCodes.js";
import { replacedCredential, revokeStoredCredential } from "./revoke.js";

/**
 * Device-authorization sign-in (ADR-0043 Decision 2; design notes
 * "Device-authorization sign-in"): `login --start` requests a pending
 * sign-in, keeps its device code in private local state, prints the
 * verification address and the user code, and exits at once; the person
 * approves in a browser on any device; `login --wait` polls within a
 * deadline, collects the credential once, verifies it, and stores it as
 * every login does. The device code is a bearer: it never appears in
 * output, argv, or logs, and travels only over HTTPS (or to loopback).
 */

/** Exit 75 (EX_TEMPFAIL): the sign-in is still pending at the deadline; run `--wait` again. */
export const PENDING_EXIT = EXIT.tempfail;

export const WAIT_DEFAULT_SECONDS = 60;
export const WAIT_MAX_SECONDS = 600;
/** Bound on --start's single request: an agent's shell must not hang on it. */
const START_TIMEOUT_MS = 30_000;

export interface DeviceLoginIO {
  out: (line: string) => void;
  err: (line: string) => void;
  /** Machine output: one JSON document on stdout. */
  json: ((doc: Record<string, unknown>) => void) | null;
  /** Prefix for suggested commands: "varlatch" or "varlatch --assisted". */
  cli: string;
  assisted: boolean;
  userAgent: string;
  /** Test seam: name resolution for the localhost check. */
  resolve?: (host: string) => Promise<{ address: string }[]>;
  /** Test seam: the clock. */
  now?: () => number;
}

const LOOPBACK_V4 = /^127(?:\.\d{1,3}){3}$/;

function isLoopbackAddress(address: string): boolean {
  return LOOPBACK_V4.test(address) || address === "::1";
}

/**
 * Why device sign-in must not run against `server`, or null: only
 * `https://`, except `http://` to a loopback address (127.0.0.1, ::1, or
 * localhost resolving only to loopback) in local development. Checked
 * before any request.
 */
export async function transportRefusal(server: string, resolve = defaultResolve): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(server);
  } catch {
    return `${server} is not a URL; give the server's address, such as https://varlatch.example.com`;
  }
  if (url.protocol === "https:") return null;
  const rule =
    "device sign-in sends a code that collects a credential, and receives that credential, so it runs only over " +
    "https:// (or http:// to 127.0.0.1, ::1, or localhost in local development)";
  if (url.protocol !== "http:") return `${server}: ${rule}`;
  if (url.hostname === "127.0.0.1" || url.hostname === "[::1]") return null;
  if (url.hostname === "localhost") {
    const addresses = await resolve("localhost").catch(() => []);
    if (addresses.length > 0 && addresses.every((a) => isLoopbackAddress(a.address))) return null;
    return `${server}: localhost does not resolve only to loopback addresses here; ${rule}`;
  }
  return `${server}: ${rule}. Use https://${url.host}${url.pathname.replace(/\/+$/, "")}`;
}

function defaultResolve(host: string): Promise<{ address: string }[]> {
  return lookup(host, { all: true });
}

function isAbort(err: unknown): boolean {
  return err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
}

/** A client whose every request ends by `deadline` (a fetch wrapper; the SDK's own calls take no signal). */
function boundedClient(server: string, io: DeviceLoginIO, deadline: number, token?: string): VarlatchClient {
  const now = io.now ?? Date.now;
  return new VarlatchClient({
    server,
    ...(token ? { token } : {}),
    userAgent: io.userAgent,
    // A maintenance window is a temporary failure here, not something to wait out past the deadline.
    maintenanceRetryMs: 0,
    fetch: (input, init) => globalThis.fetch(input, { ...init, signal: AbortSignal.timeout(Math.max(1, deadline - now())) }),
  });
}

function shownExpiry(expiresAt: string, now: number): string {
  const minutes = Math.max(0, Math.round((Date.parse(expiresAt) - now) / 60_000));
  return `${expiresAt}, in ${minutes} minute${minutes === 1 ? "" : "s"}`;
}

const USER_CODE_SHAPE = /^[A-Z]{4}-[A-Z]{4}$/;

/** `varlatch login --server <url> --start [--ttl <s>]`. Returns the exit status. */
export async function startDeviceLogin(server: string, ttlSeconds: number | undefined, io: DeviceLoginIO): Promise<number> {
  const refusal = await transportRefusal(server, io.resolve);
  if (refusal) {
    io.err(`varlatch login: ${refusal}. Nothing was sent.`);
    return EXIT.usage;
  }
  const now = io.now ?? Date.now;
  const client = new VarlatchClient({ server, userAgent: io.userAgent, maintenanceRetryMs: 0 });
  let started;
  try {
    started = await client.startDeviceSignIn(ttlSeconds === undefined ? {} : { ttlSeconds }, {
      signal: AbortSignal.timeout(START_TIMEOUT_MS),
    });
  } catch (err) {
    return startFailure(err, server, io);
  }
  const verification = await transportRefusal(started.verificationUri, io.resolve).catch(() => "not a URL");
  if (
    typeof started.deviceCode !== "string" ||
    started.deviceCode.length === 0 ||
    !USER_CODE_SHAPE.test(started.userCode) ||
    verification !== null
  ) {
    io.err("varlatch login: the server's answer is not a device sign-in this CLI can show (the verification address must be HTTPS). Nothing was stored.");
    return EXIT.failure;
  }
  const expiresAt = new Date(now() + started.expiresIn * 1000).toISOString();
  const replaced = savePendingSignIn({
    server,
    deviceCode: started.deviceCode,
    userCode: started.userCode,
    verificationUri: started.verificationUri,
    expiresAt,
    interval: started.interval,
    startedAt: new Date(now()).toISOString(),
  });
  if (replaced && Date.parse(replaced.expiresAt) > now()) {
    io.err(
      `varlatch login: the sign-in started earlier from this CLI for ${server} (code ${replaced.userCode}) no longer completes here; ` +
        "it expires unused on the server.",
    );
  }
  const wait = `${io.cli} login --server ${server} --wait`;
  if (io.json) {
    io.json({ verificationUri: started.verificationUri, userCode: started.userCode, expiresAt });
    return EXIT.ok;
  }
  io.out(io.assisted ? "Give the person this address and code. They open the address in a browser, on any device, sign in with their passkey, and enter the code:" : "Open this address in a browser, on any device, sign in with your passkey, and enter the code:");
  io.out("");
  io.out(`  ${started.verificationUri}`);
  io.out("");
  io.out(`  ${started.userCode}`);
  io.out("");
  io.out(`The code expires at ${shownExpiry(expiresAt, now())}.`);
  io.out(
    io.assisted
      ? `Then stop and wait until they say they approved it; only then run:\n  ${wait}`
      : `After approving, run:\n  ${wait}`,
  );
  return EXIT.ok;
}

async function startFailure(err: unknown, server: string, io: DeviceLoginIO): Promise<number> {
  if (err instanceof DeviceSignInRedirectError) {
    io.err(redirectMessage(err, server, "Nothing was stored."));
    return EXIT.failure;
  }
  if (err instanceof VarlatchApiError) {
    if (err.status === 404) return unsupported(server, io);
    if (err.code === "MAINTENANCE") {
      io.err(`varlatch login: ${server} is in maintenance; try again in a moment.`);
      return EXIT.unavailable;
    }
    io.err(`varlatch login: the server refused to start a sign-in (${err.code}): ${err.message}`);
    return err.status >= 500 ? EXIT.unavailable : EXIT.failure;
  }
  if (isAbort(err)) {
    io.err(`varlatch login: ${server} did not answer within ${START_TIMEOUT_MS / 1000} seconds. Nothing was stored.`);
    return EXIT.unavailable;
  }
  const network = networkFailure(err);
  if (network) {
    io.err(`varlatch login: cannot reach ${server} (${network}). Nothing was stored.`);
    return EXIT.unavailable;
  }
  throw err;
}

async function unsupported(server: string, io: DeviceLoginIO): Promise<number> {
  io.err(
    `varlatch login: ${server} does not offer device sign-in (capability auth.device: Varlatch 0.14.0 or later, ` +
      `with an HTTPS public address). Sign in in a browser on this machine instead: varlatch login --server ${server}`,
  );
  return EXIT.unavailable;
}

function redirectMessage(err: DeviceSignInRedirectError, server: string, kept: string): string {
  return (
    `varlatch login: ${server} answered ${err.status} with a redirect${err.location ? ` to ${err.location}` : ""}. ` +
    `Device sign-in follows no redirect, so its code was not sent there. ${kept} ` +
    "Check --server: give the address the server answers at."
  );
}

export interface WaitOptions {
  timeoutSeconds: number;
}

/** `varlatch login --server <url> --wait [--timeout <s>]`. Returns the exit status. */
export async function waitDeviceLogin(server: string, options: WaitOptions, io: DeviceLoginIO): Promise<number> {
  const refusal = await transportRefusal(server, io.resolve);
  if (refusal) {
    io.err(`varlatch login: ${refusal}. Nothing was sent.`);
    return EXIT.usage;
  }
  const entry = loadPendingSignIn(server);
  if (!entry) {
    io.err(`varlatch login: no sign-in was started from this CLI for ${server}. Start one: ${io.cli} login --server ${server} --start`);
    return EXIT.usage;
  }
  const now = io.now ?? Date.now;
  const timeoutMs = options.timeoutSeconds * 1000;
  const deadline = now() + timeoutMs;
  // Polls stop early enough to leave time to verify and store a collected
  // credential: the credential is collected once, so it must not be lost to
  // the deadline after collection. Everything still ends by the deadline.
  const pollDeadline = deadline - Math.min(5_000, timeoutMs / 4);
  const startNext = `${io.cli} login --server ${server} --start`;
  let interval = entry.interval;
  let seenPending = false;
  let lastPolledAt: number | null = null;
  let nextPollAt = entry.lastPolledAt ? Date.parse(entry.lastPolledAt) + interval * 1000 : now();
  if (!io.json) io.err(`Waiting up to ${options.timeoutSeconds} seconds for approval of code ${entry.userCode}...`);

  const keep = (polledAt: number | null) => {
    savePendingSignIn({ ...entry, interval, ...(polledAt ? { lastPolledAt: new Date(polledAt).toISOString() } : {}) });
  };
  const stillPending = (polledAt: number | null): number => {
    keep(polledAt);
    if (io.json) io.json({ state: "pending" });
    io.err(
      `varlatch login: not approved yet. Code ${entry.userCode} is still waiting at ${entry.verificationUri} ` +
        `(it expires at ${entry.expiresAt}). Run again: ${io.cli} login --server ${server} --wait`,
    );
    return PENDING_EXIT;
  };

  for (;;) {
    // No poll fits before the deadline (an earlier --wait may have polled just now): still pending.
    const wait = Math.max(0, nextPollAt - now());
    if (now() + wait >= pollDeadline) return stillPending(lastPolledAt);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const remaining = pollDeadline - now();
    if (remaining <= 0) return stillPending(lastPolledAt);
    let polled: DeviceSignInPoll;
    try {
      const client = new VarlatchClient({ server, userAgent: io.userAgent, maintenanceRetryMs: 0 });
      lastPolledAt = now();
      polled = await client.pollDeviceSignIn(entry.deviceCode, { signal: AbortSignal.timeout(Math.max(1, remaining)) });
    } catch (err) {
      return waitFailure(err, { server, io, keep: () => keep(lastPolledAt), deadlinePassed: now() >= pollDeadline, seenPending, stillPending: () => stillPending(lastPolledAt) });
    }
    switch (polled.state) {
      case "pending":
        seenPending = true;
        interval = polled.interval;
        nextPollAt = lastPolledAt + interval * 1000;
        continue;
      case "slow_down":
        seenPending = true;
        interval = polled.interval;
        nextPollAt = lastPolledAt + interval * 1000;
        keep(lastPolledAt);
        continue;
      case "denied":
        deletePendingSignIn(server);
        if (io.json) io.json({ state: "denied" });
        io.err(`varlatch login: the sign-in was denied in the browser. Nothing was stored. Start again: ${startNext}`);
        return EXIT.denied;
      case "expired":
        deletePendingSignIn(server);
        if (entry.collectedCredentialId) return collectedButNotStored(entry.collectedCredentialId, io, startNext);
        if (io.json) io.json({ state: "expired" });
        io.err(`varlatch login: the sign-in expired before it was approved and collected (a code lasts 10 minutes). Nothing was stored. Start again: ${startNext}`);
        return EXIT.denied;
      case "consumed": {
        const credentialId = polled.credentialId ?? entry.collectedCredentialId ?? null;
        // An earlier --wait stored it and only failed to remove this entry.
        if (credentialId && loadCredential(server)?.credentialId === credentialId) {
          deletePendingSignIn(server);
          if (io.json) io.json({ state: "signed-in", credentialId, expiresAt: loadCredential(server)?.expiresAt ?? null });
          else io.out(`Already logged in to ${server} with this sign-in's credential.`);
          return EXIT.ok;
        }
        deletePendingSignIn(server);
        return collectedButNotStored(credentialId, io, startNext);
      }
      case "issued":
        // Before anything else can fail or be interrupted: record which
        // credential was collected. The entry stays until the credential is
        // stored, so a later --wait can still name it for revocation.
        try {
          savePendingSignIn({ ...entry, interval, collectedCredentialId: polled.credential.id });
        } catch {
          // The messages below name the credential either way.
        }
        return storeCollected(server, polled.credential, deadline, io, startNext);
    }
  }
}

/** The sign-in's credential was collected, but never stored here: name it for revocation. */
function collectedButNotStored(credentialId: string | null, io: DeviceLoginIO, startNext: string): number {
  if (io.json) io.json({ state: "consumed", credentialId });
  io.err(
    "varlatch login: this sign-in's credential was already collected, but never stored by this CLI (its answer was lost, " +
      "or an earlier --wait was interrupted or failed). The credential this CLI had, if any, is unchanged. " +
      `Revoke credential ${credentialId ?? "(id unknown)"} in the dashboard (Account, Sessions), then start again: ${startNext}`,
  );
  return EXIT.denied;
}

function waitFailure(
  err: unknown,
  state: { server: string; io: DeviceLoginIO; keep: () => void; deadlinePassed: boolean; seenPending: boolean; stillPending: () => number },
): number {
  const { server, io } = state;
  // At the deadline with the sign-in last seen pending: 75, as a plain pending deadline.
  if ((isAbort(err) || networkFailure(err)) && state.deadlinePassed && state.seenPending) return state.stillPending();
  state.keep();
  const kept = `The pending sign-in is kept; run again: ${io.cli} login --server ${server} --wait`;
  if (err instanceof DeviceSignInRedirectError) {
    io.err(redirectMessage(err, server, "The pending sign-in is kept."));
    return EXIT.failure;
  }
  if (err instanceof VarlatchApiError) {
    if (err.status === 404) {
      io.err(`varlatch login: ${server} does not offer device sign-in (capability auth.device). ${kept}`);
      return EXIT.unavailable;
    }
    if (err.code === "MAINTENANCE" || err.status === 502 || err.status === 503 || err.status === 504) {
      io.err(`varlatch login: ${server} is unavailable or in maintenance (${err.status}). ${kept}`);
      return EXIT.unavailable;
    }
    io.err(`varlatch login: the server refused the poll (${err.code}): ${err.message}. ${kept}`);
    return err.status >= 500 ? EXIT.unavailable : EXIT.failure;
  }
  if (isAbort(err)) {
    io.err(`varlatch login: ${server} did not answer before the deadline. ${kept}`);
    return EXIT.unavailable;
  }
  const network = networkFailure(err);
  if (network) {
    io.err(`varlatch login: cannot reach ${server} (${network}). ${kept}`);
    return EXIT.unavailable;
  }
  throw err;
}

/**
 * Verify the collected credential, store it, and only then revoke the one
 * it replaces: nothing exits 0 before a credential is stored, and a failed
 * sign-in never leaves the person signed out.
 */
async function storeCollected(
  server: string,
  credential: { id: string; token: string; expiresAt: string },
  deadline: number,
  io: DeviceLoginIO,
  startNext: string,
): Promise<number> {
  let meta;
  try {
    const probe = boundedClient(server, io, deadline, credential.token);
    meta = await probe.meta();
    await probe.listOrganizations(); // verifies the credential
  } catch (err) {
    const why = err instanceof VarlatchApiError ? err.code : isAbort(err) ? "no answer before the deadline" : (networkFailure(err) ?? String(err));
    io.err(
      `varlatch login: the sign-in was approved, but the new credential could not be verified (${why}); it was not stored. ` +
        `Revoke credential ${credential.id} in the dashboard (Account, Sessions), then start again: ${startNext}`,
    );
    // The pending entry stays, naming the credential: a later --wait says it again.
    if (err instanceof VarlatchApiError) return err.status === 401 || err.status === 403 ? EXIT.denied : EXIT.unavailable;
    return EXIT.unavailable;
  }
  const replaced = replacedCredential(loadCredential(server), credential.token);
  try {
    saveCredential(server, {
      token: credential.token,
      issuedAt: new Date((io.now ?? Date.now)()).toISOString(),
      expiresAt: credential.expiresAt,
      credentialId: credential.id,
    });
  } catch (err) {
    io.err(
      `varlatch login: the sign-in was approved and its credential verified, but it could not be stored ` +
        `(${err instanceof Error ? err.message : String(err)}). The credential this CLI had, if any, is unchanged. ` +
        `Revoke credential ${credential.id} in the dashboard (Account, Sessions), fix the problem, then start again: ${startNext}`,
    );
    return EXIT.failure;
  }
  // Only now, with the credential stored, is the pending entry done with.
  try {
    deletePendingSignIn(server);
  } catch (err) {
    io.err(`varlatch: the pending sign-in could not be removed (${err instanceof Error ? err.message : String(err)}); the credential is stored.`);
  }
  if (io.json) io.json({ state: "signed-in", credentialId: credential.id, expiresAt: credential.expiresAt });
  else io.out(`Logged in to ${server} (server ${meta.serverVersion}, API v${meta.apiMajor}). The credential expires at ${credential.expiresAt}.`);
  if (replaced) {
    const failure = await revokeStoredCredential(replaced, (id) =>
      boundedClient(server, io, deadline, replaced.token).revokeMyCredential(id),
    );
    const say = io.json ? io.err : io.out;
    if (failure === null) say("Previous credential revoked.");
    else io.err(`varlatch: previous credential not revoked (${failure}); it may remain live${replaced.expiresAt ? ` until ${replaced.expiresAt}` : ""}.`);
  }
  return EXIT.ok;
}
