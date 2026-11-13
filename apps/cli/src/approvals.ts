// SPDX-License-Identifier: Apache-2.0
import { VarlatchApiError, type Approval, type VarlatchClient } from "@varlatch/sdk";
import { EXIT } from "./exitCodes.js";
import { shellWord } from "./members.js";
import { printable, safeTime } from "./safeText.js";

/**
 * Step-up approvals in the CLI (ADR-0054 Decision 3). When an operation
 * needs the person's approval with a trusted passkey, the server stores a
 * pending approval bound to that exact request and answers
 * STEP_UP_REQUIRED. The CLI prints its summary and the dashboard address on
 * stderr (never stdout, and never anything but the server's summary, the
 * address and the expiry), then:
 *
 * - outside assisted mode, waits, polling at the approval's interval (5
 *   seconds; SLOW_DOWN adds to it, as in device sign-in), until it is
 *   approved, and repeats the request once with the Varlatch-Approval
 *   header (the SDK does that when the handler resolves true);
 * - in assisted mode (ADR-0043), does not wait: a coding agent must stop,
 *   show the address to the person, and once they approved run the same
 *   command again with `--approval <id>`. Exit 75.
 *
 * `--approval <id>` resumes: the CLI waits for that approval (bounded by its
 * expiry) before the command's first change, then sends it with every
 * change request. An operation that needs no approval ignores it.
 *
 * Exit statuses: 75 when the approval is still pending and the CLI does not
 * wait (assisted mode), or it expired before anyone approved it; 77 when it
 * was cancelled or closed, was used already, or does not exist for this
 * person; 130 when the person stopped the wait with Ctrl-C (the CLI then
 * cancels the approval, best effort).
 */

/** The global option that resumes with an approved approval. */
export const APPROVAL_OPTION = "--approval";

/** An approval wait that ended without an approval; `exit` is the status to exit with. */
export class ApprovalError extends Error {
  override name = "ApprovalError";
  constructor(message: string, readonly exit: number) {
    super(message);
  }
}

/**
 * Remove `--approval <id>` from the CLI's own arguments (those before a
 * `--`). Null when absent; a missing value, or the option given twice, is
 * reported as `error`.
 */
export function takeApprovalOption(argv: string[]): { argv: string[]; approval: string | null; error: string | null } {
  const separator = argv.indexOf("--");
  const own = separator < 0 ? argv : argv.slice(0, separator);
  const rest = separator < 0 ? [] : argv.slice(separator);
  const kept: string[] = [];
  let approval: string | null = null;
  let error: string | null = null;
  for (let i = 0; i < own.length; i++) {
    if (own[i] !== APPROVAL_OPTION) {
      kept.push(own[i] as string);
      continue;
    }
    const value = own[i + 1];
    if (value === undefined || value.startsWith("-")) {
      error = `${APPROVAL_OPTION} needs the approval id the CLI printed`;
    } else if (approval !== null) {
      error = `${APPROVAL_OPTION} given twice`;
    } else if (!/^[A-Za-z0-9_-]{1,100}$/.test(value)) {
      error = `${APPROVAL_OPTION}: not an approval id: ${value}`;
    } else {
      approval = value;
    }
    i++;
  }
  return { argv: [...kept, ...rest], approval, error };
}

/** What the approval asks for, its address and its expiry: the lines the CLI prints on stderr. */
export function approvalLines(approval: Approval): string[] {
  const lines = [`This needs your approval with a trusted passkey: ${approval.summary.title}`];
  for (const change of approval.summary.changes) {
    lines.push(`  ${change.field}: ${change.from ?? "not set"} -> ${change.to ?? "not set"}${change.loosens ? " (loosens)" : ""}`);
  }
  if (approval.url) {
    lines.push(
      "Open this address in a browser where you are signed in to Varlatch as yourself, check what it says, and approve with a trusted passkey:",
      `  ${approval.url}`,
    );
  } else {
    lines.push(
      `Open the Varlatch dashboard as yourself and approve request ${approval.id} with a trusted passkey ` +
        "(this server has no public URL, so the CLI cannot print its address).",
    );
  }
  lines.push(`It expires at ${safeTime(approval.expiresAt)}. Only you can approve it.`);
  // The title, fields, address and id come from the server: escaped (issue #119).
  return lines.map(printable);
}

/** The command line to run again after approving, with `--approval <id>` added. */
export function rerunCommand(argv: readonly string[], approvalId: string, assisted: boolean): string {
  const words = ["varlatch", ...(assisted && !argv.includes("--assisted") ? ["--assisted"] : []), APPROVAL_OPTION, approvalId, ...argv];
  return words.map(shellWord).join(" ");
}

/** For assisted mode: stop, show the address to the person, and run the command again after they approved. */
export function assistedStopLines(approval: Approval, rerun: string): string[] {
  return [
    ...approvalLines(approval),
    "Coding agent: stop here. Show the address above to the person and ask them to approve it themselves; " +
      "do not open or approve it for them. Nothing was changed yet.",
    `After they approved, run the same command again (before ${safeTime(approval.expiresAt)}):`,
    `  ${printable(rerun)}`,
  ];
}

const WAITING = "Waiting for your approval (Ctrl-C stops waiting and cancels it)...";

export interface WaitIo {
  /** One line on stderr. */
  err: (line: string) => void;
  /** Wait `ms`; rejects at once when `signal` aborts. */
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  now: () => number;
}

export const realWaitIo: WaitIo = {
  err: (line) => console.error(line),
  sleep: (ms, signal) =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      const onAbort = () => {
        clearTimeout(timer);
        reject(signal?.reason);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
  now: () => Date.now(),
};

type Polling = Pick<VarlatchClient, "getApproval">;

function ended(approval: Approval): ApprovalError | null {
  switch (approval.state) {
    case "approved":
    case "pending":
      return null;
    case "expired":
      return new ApprovalError(
        `Approval ${approval.id} expired before it was approved. Nothing was changed; run the command again for a new one.`,
        EXIT.tempfail,
      );
    case "consumed":
      return new ApprovalError(`Approval ${approval.id} was already used. Run the command again for a new one.`, EXIT.denied);
    case "closed":
      return new ApprovalError(
        approval.closeReason === "cancelled"
          ? `Approval ${approval.id} was cancelled. Nothing was changed.`
          : approval.closeReason === "reset"
            ? `Approval ${approval.id} was closed by the host operator's reset of the security controls. Nothing was changed.`
            : approval.closeReason === "organization-deleted"
              ? `Approval ${approval.id} was closed: its organization was deleted. Nothing was changed.`
              : `Approval ${approval.id} was closed. Nothing was changed.`,
        EXIT.denied,
      );
  }
}

/**
 * Poll the approval until it is approved, at its interval, honouring
 * SLOW_DOWN, never past its expiry. Resolves with the approved approval;
 * rejects with an ApprovalError for an expired, used, closed or unknown one.
 */
export async function waitForApproval(api: Polling, first: Approval, io: WaitIo, signal?: AbortSignal): Promise<Approval> {
  let approval = first;
  let interval = Math.max(1, approval.interval || 5);
  const deadline = Date.parse(approval.expiresAt);
  for (;;) {
    const stop = ended(approval);
    if (stop) throw stop;
    if (approval.state === "approved") return approval;
    const left = deadline - io.now();
    if (left <= 0) throw ended({ ...approval, state: "expired" })!;
    signal?.throwIfAborted();
    await io.sleep(Math.min(interval * 1000, left), signal);
    signal?.throwIfAborted();
    try {
      approval = await api.getApproval(approval.id, signal ? { signal } : {});
    } catch (err) {
      signal?.throwIfAborted();
      if (err instanceof VarlatchApiError && err.code === "SLOW_DOWN") {
        const asked = Number(err.details?.interval);
        interval = Number.isFinite(asked) && asked > interval ? asked : interval + 5;
        continue;
      }
      if (err instanceof VarlatchApiError && err.code === "RESOURCE_NOT_FOUND") {
        throw new ApprovalError(
          `No approval ${approval.id} exists for you (an approval belongs to the person who asked for it). Nothing was changed.`,
          EXIT.denied,
        );
      }
      throw err;
    }
  }
}

export interface StepUpOptions {
  assisted: boolean;
  /** The CLI's own arguments, for the command to run again. */
  argv: readonly string[];
  io?: WaitIo;
  /** Ctrl-C while waiting: subscribe, and unsubscribe; process SIGINT by default. */
  onInterrupt?: (handler: () => void) => () => void;
  /** Ends the process after an interrupt (exit 130 by default). */
  exit?: (code: number) => never;
}

const processInterrupt = (handler: () => void) => {
  process.once("SIGINT", handler);
  return () => process.off("SIGINT", handler);
};

/**
 * Wait for the approval with Ctrl-C handled. An interrupt aborts the wait
 * at once (the sleep and the poll in flight both see the abort, and the
 * wait loses a race against the interrupt whatever they do), so a poll
 * answering "approved" a moment later can never let the request be sent:
 * this rejects instead. Then it cancels the approval (best effort, a few
 * seconds at most) and exits 130; a second Ctrl-C exits at once.
 */
export async function waitInterruptibly(
  api: Pick<VarlatchClient, "getApproval" | "cancelApproval">,
  approval: Approval,
  options: Pick<StepUpOptions, "io" | "onInterrupt" | "exit"> & {
    /** Lines to print once Ctrl-C is handled: a signal before that would end the process without cancelling. */
    announce?: readonly string[];
  },
): Promise<Approval> {
  const io = options.io ?? realWaitIo;
  const exit = options.exit ?? ((code: number) => process.exit(code));
  const controller = new AbortController();
  const stopped = new ApprovalError(`Stopped waiting; approval ${approval.id} was cancelled. Nothing was changed.`, EXIT.interrupted);
  let interrupted = false;
  let interrupt!: (err: ApprovalError) => void;
  const interruption = new Promise<never>((_, reject) => {
    interrupt = reject;
  });
  interruption.catch(() => undefined);
  const unsubscribe = (options.onInterrupt ?? processInterrupt)(() => {
    if (interrupted) exit(EXIT.interrupted);
    interrupted = true;
    controller.abort(stopped);
    interrupt(stopped);
  });
  try {
    for (const line of options.announce ?? []) io.err(line);
    const approved = await Promise.race([waitForApproval(api, approval, io, controller.signal), interruption]);
    if (interrupted) throw stopped;
    return approved;
  } catch (err) {
    if (!interrupted) throw err;
    io.err(`Stopped waiting. Cancelling approval ${printable(approval.id)}; nothing was changed.`);
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      api.cancelApproval(approval.id).catch(() => undefined),
      new Promise((resolve) => {
        timer = setTimeout(resolve, 3000);
      }),
    ]);
    clearTimeout(timer);
    exit(EXIT.interrupted);
    throw stopped;
  } finally {
    unsubscribe();
  }
}

/**
 * The client's onStepUp for the CLI: print what is asked and where to
 * approve it; in assisted mode stop with exit 75, otherwise wait and let
 * the SDK repeat the request with the approval.
 */
export function stepUpHandler(
  api: () => Pick<VarlatchClient, "getApproval" | "cancelApproval">,
  options: StepUpOptions,
): (approval: Approval) => Promise<boolean> {
  const io = options.io ?? realWaitIo;
  return async (approval) => {
    if (options.assisted) {
      for (const line of assistedStopLines(approval, rerunCommand(options.argv, approval.id, true))) io.err(line);
      throw new ApprovalError(`Waiting for the person to approve ${approval.id}.`, EXIT.tempfail);
    }
    await waitInterruptibly(api(), approval, { ...options, announce: [...approvalLines(approval), WAITING] });
    io.err("Approved. Sending the request again with the approval.");
    return true;
  };
}

/**
 * A fetch for a client that resumes with `--approval <id>`: before the
 * command's first change request (anything but a GET), wait until the
 * approval is approved, then let the request go (the client adds the
 * Varlatch-Approval header). Reads go out at once.
 */
export function resumingFetch(
  approvalId: string,
  api: () => Pick<VarlatchClient, "getApproval" | "cancelApproval">,
  options: Pick<StepUpOptions, "io" | "onInterrupt" | "exit">,
  inner: typeof fetch = (...args) => globalThis.fetch(...args),
): typeof fetch {
  let ready: Promise<void> | null = null;
  const io = options.io ?? realWaitIo;
  return async (input, init) => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method !== "GET") {
      ready ??= (async () => {
        const client = api();
        let approval: Approval;
        try {
          approval = await client.getApproval(approvalId);
        } catch (err) {
          if (err instanceof VarlatchApiError && err.code === "RESOURCE_NOT_FOUND") {
            throw new ApprovalError(
              `No approval ${approvalId} exists for you (an approval belongs to the person who asked for it). Nothing was changed.`,
              EXIT.denied,
            );
          }
          throw err;
        }
        await waitInterruptibly(client, approval, {
          ...options,
          io,
          announce: approval.state === "pending" ? [...approvalLines(approval), WAITING] : [],
        });
      })();
      await ready;
    }
    return inner(input, init);
  };
}
