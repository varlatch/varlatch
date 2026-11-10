// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { VarlatchApiError, type Approval } from "@varlatch/sdk";
import {
  ApprovalError,
  approvalLines,
  rerunCommand,
  resumingFetch,
  stepUpHandler,
  takeApprovalOption,
  waitForApproval,
  waitInterruptibly,
  type WaitIo,
} from "../src/approvals.js";
import { EXIT, apiErrorExit } from "../src/exitCodes.js";

/** The CLI's step-up approval handling (ADR-0054 Decision 3), with a fake clock and server. */

const T0 = Date.parse("2026-11-10T12:00:00.000Z");

function approval(state: Approval["state"], extra: Partial<Approval> = {}): Approval {
  return {
    id: "apr_1",
    operation: "security_control.change",
    organization: { id: "org_1", slug: "acme", name: "Acme" },
    summary: { title: "Change admin-step-up in Acme", changes: [{ field: "mode", from: "report", to: "off", loosens: true }] },
    state,
    closeReason: null,
    requestedBy: { credentialKind: "cli", client: null },
    url: "https://varlatch.example/approve/apr_1",
    interval: 5,
    createdAt: new Date(T0).toISOString(),
    expiresAt: new Date(T0 + 600_000).toISOString(),
    approvedAt: null,
    consumedAt: null,
    closedAt: null,
    ...extra,
  };
}

/** A fake clock that advances with every sleep, and the lines written. */
function fakeIo(): WaitIo & { lines: string[]; slept: number[]; clock: number } {
  const io = {
    lines: [] as string[],
    slept: [] as number[],
    clock: T0,
    err: (line: string) => io.lines.push(line),
    sleep: async (ms: number) => {
      io.slept.push(ms);
      io.clock += ms;
    },
    now: () => io.clock,
  };
  return io;
}

/** A server whose answers are given in turn: an Approval, or an error to throw. */
function fakeApi(answers: (Approval | VarlatchApiError)[]) {
  const calls: string[] = [];
  return {
    calls,
    getApproval: async (id: string) => {
      calls.push(`get ${id}`);
      const next = answers.length > 1 ? answers.shift()! : answers[0]!;
      if (next instanceof VarlatchApiError) throw next;
      return next;
    },
    cancelApproval: async (id: string) => {
      calls.push(`cancel ${id}`);
      return approval("closed", { closeReason: "cancelled" });
    },
  };
}

const apiError = (status: number, code: string, details?: Record<string, unknown>) =>
  new VarlatchApiError(status, { code: code as never, message: code, requestId: "req_1", ...(details ? { details } : {}) });

describe("waitForApproval", () => {
  it("polls at the approval's interval until it is approved, and slows down when told", async () => {
    const io = fakeIo();
    const api = fakeApi([approval("pending"), apiError(429, "SLOW_DOWN", { interval: 10 }), approval("approved")]);
    const done = await waitForApproval(api, approval("pending"), io);
    expect(done.state).toBe("approved");
    expect(io.slept).toEqual([5000, 5000, 10000]);
  });

  it("never sleeps past the expiry, and an approval still pending then has expired (75)", async () => {
    const io = fakeIo();
    const api = fakeApi([approval("pending")]);
    const err = await waitForApproval(api, approval("pending", { expiresAt: new Date(T0 + 12_000).toISOString() }), io).catch((e) => e);
    expect(err).toBeInstanceOf(ApprovalError);
    expect(err.exit).toBe(EXIT.tempfail);
    expect(io.slept).toEqual([5000, 5000, 2000]);
  });

  it("ends with 77 for a cancelled, reset or used approval, and one that is not this person's", async () => {
    for (const [answer, words] of [
      [approval("closed", { closeReason: "cancelled" }), "was cancelled"],
      [approval("closed", { closeReason: "reset" }), "host operator's reset"],
      [approval("consumed"), "already used"],
      [apiError(404, "RESOURCE_NOT_FOUND"), "No approval apr_1 exists for you"],
    ] as const) {
      const err = await waitForApproval(fakeApi([answer]), approval("pending"), fakeIo()).catch((e) => e);
      expect(err).toBeInstanceOf(ApprovalError);
      expect(err.exit).toBe(EXIT.denied);
      expect(err.message).toContain(words);
    }
  });
});

describe("stepUpHandler", () => {
  it("prints the summary, the address and the expiry on its io, then waits and resolves true", async () => {
    const io = fakeIo();
    const api = fakeApi([approval("approved")]);
    const handler = stepUpHandler(() => api, { assisted: false, argv: ["security", "set", "admin-step-up", "off"], io, onInterrupt: () => () => {} });
    expect(await handler(approval("pending"))).toBe(true);
    expect(io.lines.slice(0, 5)).toEqual([
      "This needs your approval with a trusted passkey: Change admin-step-up in Acme",
      "  mode: report -> off (loosens)",
      "Open this address in a browser where you are signed in to Varlatch as yourself, check what it says, and approve with a trusted passkey:",
      "  https://varlatch.example/approve/apr_1",
      "It expires at 2026-11-10T12:10:00.000Z. Only you can approve it.",
    ]);
    expect(api.calls).toEqual(["get apr_1"]);
  });

  it("in assisted mode stops at once with 75 and the command to run again, without polling", async () => {
    const io = fakeIo();
    const api = fakeApi([approval("approved")]);
    const handler = stepUpHandler(() => api, { assisted: true, argv: ["security", "set", "admin-step-up", "off", "--org", "my org"], io });
    const err = await handler(approval("pending")).catch((e) => e);
    expect(err).toBeInstanceOf(ApprovalError);
    expect(err.exit).toBe(EXIT.tempfail);
    expect(io.lines.join("\n")).toContain("Coding agent: stop here.");
    expect(io.lines.at(-1)).toBe("  varlatch --assisted --approval apr_1 security set admin-step-up off --org 'my org'");
    expect(api.calls).toEqual([]);
  });

  it("Ctrl-C cancels the approval and exits 130", async () => {
    const io = fakeIo();
    let interrupt: () => void = () => {};
    const api = fakeApi([approval("pending")]);
    // A sleep that interrupts the wait the first time.
    io.sleep = async () => {
      interrupt();
      await new Promise(() => {});
    };
    const exited = new Promise<number>((resolve) => {
      void waitInterruptibly(api, approval("pending"), {
        io,
        onInterrupt: (handler) => {
          interrupt = handler;
          return () => {};
        },
        exit: ((code: number) => resolve(code)) as (code: number) => never,
      });
    });
    expect(await exited).toBe(130);
    expect(api.calls).toEqual(["cancel apr_1"]);
    expect(io.lines).toContain("Stopped waiting. Cancelling approval apr_1; nothing was changed.");
  });
});

describe("resumingFetch", () => {
  it("lets reads through and holds the first change until the approval is approved", async () => {
    const io = fakeIo();
    const api = fakeApi([approval("pending"), approval("approved")]);
    const sent: string[] = [];
    const inner = (async (input: RequestInfo | URL, init?: RequestInit) => {
      sent.push(`${init?.method ?? "GET"} ${String(input)}`);
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const f = resumingFetch("apr_1", () => api, { io, onInterrupt: () => () => {} }, inner);
    await f("https://v/v1/meta");
    expect(api.calls).toEqual([]);
    await f("https://v/v1/x", { method: "PATCH" });
    await f("https://v/v1/y", { method: "POST" });
    expect(api.calls).toEqual(["get apr_1", "get apr_1"]);
    expect(sent).toEqual(["GET https://v/v1/meta", "PATCH https://v/v1/x", "POST https://v/v1/y"]);
  });
});

describe("the --approval option and lines", () => {
  it("is taken from the CLI's own arguments only", () => {
    expect(takeApprovalOption(["--approval", "apr_1", "security", "set", "x", "off"])).toEqual({
      argv: ["security", "set", "x", "off"],
      approval: "apr_1",
      error: null,
    });
    expect(takeApprovalOption(["run", "--", "tool", "--approval", "x"]).approval).toBeNull();
    expect(takeApprovalOption(["--approval"]).error).toContain("needs the approval id");
    expect(takeApprovalOption(["--approval", "a", "--approval", "b"]).error).toContain("given twice");
    expect(takeApprovalOption(["--approval", "a b"]).error).toContain("not an approval id");
  });

  it("names the dashboard when the server has no public URL", () => {
    expect(approvalLines(approval("pending", { url: null })).join("\n")).toContain("approve request apr_1 with a trusted passkey");
  });

  it("adds --assisted only once to the command to run again", () => {
    expect(rerunCommand(["security", "set", "a", "off"], "apr_1", false)).toBe("varlatch --approval apr_1 security set a off");
    expect(rerunCommand(["--assisted", "security"], "apr_1", true)).toBe("varlatch --approval apr_1 --assisted security");
  });

  it("maps the new error codes to exit statuses", () => {
    expect(apiErrorExit(apiError(409, "APPROVAL_INVALID"))).toBe(EXIT.denied);
    expect(apiErrorExit(apiError(403, "STEP_UP_REQUIRED"))).toBe(EXIT.denied);
    expect(apiErrorExit(apiError(422, "CONTROL_MODE_UNAVAILABLE"))).toBe(EXIT.failure);
  });
});
