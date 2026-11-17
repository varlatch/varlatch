// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { VarlatchApiError, VarlatchClient, stepUpApproval, type MaintenanceWait } from "@varlatch/sdk";
import { afterAll, describe, expect, it, vi } from "vitest";
import { approvalLines } from "../src/approvals.js";
import { EXIT, apiErrorExit } from "../src/exitCodes.js";
import { passkeyVerificationLines } from "../src/passkeyVerification.js";
import { apiErrorLine, forgetSecrets, rememberSecret, requestNote, serverMessage } from "../src/safeText.js";
import { envTokenExpiryWarning, expiryWarning } from "../src/status.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's API client (internal docs/design/go-cli.md, slice
 * 5.1c), from the TypeScript code itself:
 *
 * - answers: what VarlatchClient makes of an answer (status, headers, body
 *   bytes): the value, or the VarlatchApiError's fields; and for an error,
 *   what main.ts's catch prints and exits with (a pending step-up approval,
 *   a passkey verification, maintenance that outlasted the wait, any other
 *   API error), with a bearer the CLI holds masked in the server's text;
 * - maintenance: the maintenance retry (ADR-0036 D6) over a sequence of
 *   answers, with Math.random and the clock fixed: every wait's length and
 *   what remained of the budget, the notice maintenance.ts prints, the
 *   requests made, and the result;
 * - expiry: status.ts's expiryWarning and envTokenExpiryWarning;
 * - encodeURIComponent, which the SDK applies to every path segment.
 *
 * main.ts's catch is not exported: `cliFailure` below is its API-error
 * branch, in its order, from the same exported pieces.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-apiclient.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/apiclient.json", import.meta.url));
/** The bearer the vectors' client holds; a server echoing it gets it masked. */
const TOKEN = "vlt_cli_vectorTokenAAAA";
const HELD = "a-held-secret-value";

const config = mkdtempSync(join(tmpdir(), "varlatch-apiclient-vectors-"));
afterAll(() => rmSync(config, { recursive: true, force: true }));

interface Answer {
  status: number;
  headers?: Array<[string, string]>;
  /** The body as text (UTF-8), or bodyHex for exact bytes. */
  body?: string;
  bodyHex?: string;
}

const json = (status: number, value: unknown, headers: Array<[string, string]> = []): Answer => ({
  status,
  headers: [["content-type", "application/json"], ...headers],
  body: JSON.stringify(value),
});
const error = (status: number, err: unknown): Answer => json(status, { error: err });
const REQ = "req_01234567-89ab-4def-8123-456789abcdef";
const APPROVAL = {
  id: "apr_0123",
  url: "https://varlatch.example/approve/apr_0123",
  expiresAt: "2026-11-17T12:00:00Z",
  summary: {
    title: "Change the control \u001b[31mvalues.reveal",
    changes: [
      { field: "mode", from: "off", to: "on", loosens: false },
      { field: "ttl", from: null, to: 3600, loosens: true },
      { field: "note", to: `held ${HELD}` },
    ],
  },
};

const ANSWERS: Answer[] = [
  json(200, { ok: true, n: 1.5, list: [1, "a", null] }),
  json(200, null),
  json(201, "text"),
  { status: 200, headers: [["content-type", "application/json"]], body: "" },
  { status: 204 },
  { status: 200, body: "﻿{\"bom\":1}" },
  { status: 200, bodyHex: "7b2261223a22ff227d" },
  { status: 200, headers: [["content-type", "text/plain; charset=utf-8"]], body: "hello" },
  { status: 200, body: "not json" },
  { status: 200, headers: [["content-type", "  ; x"]], body: "<" },
  { status: 200, headers: [["content-type", "a/b"], ["content-type", "c/d"]], body: "{" },
  error(401, { code: "INVALID_CREDENTIAL", message: "The credential is not valid", requestId: REQ }),
  error(401, { code: "INVALID_CREDENTIAL", message: `bad token ${TOKEN} and vlt_svc_other_123`, requestId: REQ }),
  error(403, { code: "PERMISSION_DENIED", message: "line\nbreak ‮", requestId: "not-a-request-id" }),
  error(403, { code: "ORGANIZATION_FROZEN", message: "frozen", requestId: REQ }),
  error(404, { code: "RESOURCE_NOT_FOUND", message: "missing" }),
  error(409, { code: "VERSION_CONFLICT", message: "conflict", requestId: REQ, details: { currentVersionId: "ver_2" } }),
  error(400, { code: "APPROVAL_INVALID", message: "does not fit" }),
  error(400, { code: "CONTROL_MODE_UNAVAILABLE", message: "not offered" }),
  error(403, { code: "CONTROL_MODE_UNAVAILABLE", message: "not offered" }),
  error(403, { code: "PASSKEY_VERIFICATION_REQUIRED", message: "verify", requestId: REQ }),
  error(403, { code: "STEP_UP_REQUIRED", message: "approve it", requestId: REQ, details: { approval: APPROVAL } }),
  error(403, { code: "STEP_UP_REQUIRED", message: "approve it", details: { approval: { ...APPROVAL, url: null, expiresAt: "garbage" } } }),
  error(403, { code: "STEP_UP_REQUIRED", message: "approve it", details: { approval: { ...APPROVAL, summary: { title: "t", changes: "ab" } } } }),
  error(403, { code: "STEP_UP_REQUIRED", message: "no approval", details: {} }),
  error(403, { code: "STEP_UP_REQUIRED", message: "id not a string", details: { approval: { ...APPROVAL, id: 5 } } }),
  error(403, { code: "STEP_UP_REQUIRED", message: "approval without summary", details: { approval: { id: "apr_1" } } }),
  error(503, { code: "MAINTENANCE", message: "still restoring", requestId: REQ }),
  error(500, { code: "INTERNAL", message: "boom", requestId: REQ }),
  error(502, { code: "INTERNAL", message: "bad gateway" }),
  error(504, { code: "MADE_UP", message: "timeout" }),
  error(422, { code: 7, message: { nested: true }, requestId: 12 }),
  error(400, { code: "VALIDATION_FAILED", message: ["a", null, 2] }),
  error(400, { code: "VALIDATION_FAILED", message: null }),
  error(400, { code: "VALIDATION_FAILED" }),
  error(400, "a string"),
  error(400, 0),
  error(400, []),
  json(400, { notError: 1 }),
  json(400, null),
  { status: 400, body: "" },
  { status: 502, headers: [["content-type", "text/html"], ["x-request-id", "req_from_proxy"]], body: "<html>" },
  { status: 418, headers: [["x-request-id", ""]], body: "<" },
  { status: 302, headers: [["content-type", "application/json"]], body: "{}" },
  { status: 599, headers: [["content-type", "text/plain"]], body: "unexpected request" },
];

/** The answer as fetch returns it. */
function response(a: Answer): Response {
  const body = a.status === 204 ? null : a.bodyHex !== undefined ? Buffer.from(a.bodyHex, "hex") : (a.body ?? null);
  return new Response(body, { status: a.status, headers: a.headers ?? [] });
}

/** A JSON value that may be undefined, for the vectors: undefined is left out. */
function errorFields(err: VarlatchApiError): Record<string, unknown> {
  const out: Record<string, unknown> = { status: err.status, message: err.message };
  if (err.code !== undefined) out.code = err.code;
  if (err.requestId !== undefined) out.requestId = err.requestId;
  if (err.details !== undefined) out.details = err.details;
  return out;
}

/** main.ts's catch for an API error, in its order. */
function cliFailure(err: VarlatchApiError): { stderr: string; exit: number } | { throws: string } {
  try {
    const pending = stepUpApproval(err);
    if (pending) return { stderr: [...approvalLines(pending), `Error STEP_UP_REQUIRED: ${serverMessage(err.message)}`].join("\n"), exit: EXIT.denied };
    const verification = passkeyVerificationLines(err);
    if (verification) return { stderr: verification.join("\n"), exit: EXIT.denied };
    if (err.code === "MAINTENANCE") {
      return { stderr: `The installation is still in maintenance (restore or upgrade); try again later.${requestNote(err)}`, exit: EXIT.unavailable };
    }
    return { stderr: apiErrorLine(err), exit: apiErrorExit(err) };
  } catch (thrown) {
    return { throws: thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : String(thrown) };
  }
}

async function answerVector(a: Answer): Promise<Record<string, unknown>> {
  // No maintenance wait here (0): the maintenance vectors below cover it.
  const client = new VarlatchClient({ server: "http://vectors.example", token: TOKEN, maintenanceRetryMs: 0, fetch: async () => response(a) });
  try {
    const value = await client.meta();
    return { answer: a, result: value === undefined ? { undefined: true } : { value } };
  } catch (err) {
    if (!(err instanceof VarlatchApiError)) throw err;
    return { answer: a, result: { error: errorFields(err) }, cli: cliFailure(err) };
  }
}

interface Sequence {
  title: string;
  random: number;
  /** How many calls the command makes (meta() each). */
  calls?: number;
  answers: Answer[];
}

const maint = (retryAfter?: string | string[], body: unknown = { error: { code: "MAINTENANCE", message: "m", requestId: REQ } }): Answer => ({
  status: 503,
  headers: [
    ["content-type", "application/json"],
    ...(retryAfter === undefined ? [] : (Array.isArray(retryAfter) ? retryAfter : [retryAfter]).map((v): [string, string] => ["retry-after", v])),
  ],
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const OK = json(200, { capabilities: [] });

const SEQUENCES: Sequence[] = [
  { title: "Retry-After 0, then an answer", random: 0.5, answers: [maint("0"), OK] },
  { title: "Retry-After 2 twice", random: 0.5, answers: [maint("2"), maint("2"), OK] },
  { title: "the lowest jitter", random: 0, answers: [maint("2"), OK] },
  { title: "the highest jitter", random: 0.999999, answers: [maint("2"), OK] },
  { title: "no Retry-After: Number(null) is 0", random: 0.5, answers: [maint(), OK] },
  { title: "an empty Retry-After is 0", random: 0.5, answers: [maint(""), OK] },
  { title: "a Retry-After that is not a number: 5 s", random: 0.999, answers: [maint("abc"), OK] },
  { title: "a negative Retry-After: 5 s", random: 0.5, answers: [maint("-1"), OK] },
  { title: "a fractional Retry-After", random: 0.3, answers: [maint("1.5"), OK] },
  { title: "Retry-After with spaces", random: 0.5, answers: [maint(" 3 "), OK] },
  { title: "Retry-After in hex", random: 0.5, answers: [maint("0x10"), OK] },
  { title: "Retry-After 1e1", random: 0.5, answers: [maint("1e1"), OK] },
  { title: "Retry-After Infinity: 5 s", random: 0.5, answers: [maint("Infinity"), OK] },
  { title: "Retry-After as an HTTP date: 5 s", random: 0.5, answers: [maint("Wed, 21 Oct 2015 07:28:00 GMT"), OK] },
  { title: "two Retry-After headers: '1, 2' is not a number", random: 0.5, answers: [maint(["1", "2"]), OK] },
  { title: "a wait longer than the budget is cut to it", random: 0.5, answers: [maint("200"), OK] },
  { title: "the budget runs out: the MAINTENANCE error surfaces", random: 0.5, answers: [maint("60"), maint("60"), maint("60"), maint("60")] },
  { title: "the budget runs out with jitter", random: 0.9, answers: [maint("50"), maint("50"), maint("50"), maint("50"), maint("50")] },
  { title: "maintenance, then a refusal", random: 0.5, answers: [maint("1"), error(401, { code: "INVALID_CREDENTIAL", message: "no", requestId: REQ })] },
  { title: "a 503 that is not maintenance is not retried", random: 0.5, answers: [error(503, { code: "INTERNAL", message: "down" }), OK] },
  { title: "a 503 whose body is not JSON is not retried", random: 0.5, answers: [maint("1", "<html>"), OK] },
  { title: "a 503 maintenance body with a byte order mark is maintenance", random: 0.5, answers: [maint("1", "﻿{\"error\":{\"code\":\"MAINTENANCE\"}}"), OK] },
  { title: "a 503 with error.code MAINTENANCE but a string error is not", random: 0.5, answers: [maint("1", { error: "MAINTENANCE" }), OK] },
  { title: "the budget belongs to the client: a second call continues it", random: 0.5, calls: 2, answers: [maint("100"), OK, maint("100"), OK] },
  { title: "the budget resets once the server answers normally", random: 0.5, calls: 3, answers: [maint("60"), maint("60"), OK, maint("60"), maint("60"), OK, maint("60"), OK] },
  { title: "a 204 ends the maintenance too", random: 0.5, calls: 2, answers: [maint("1"), { status: 204 }, maint("1"), OK] },
];

async function sequenceVector(s: Sequence): Promise<Record<string, unknown>> {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], now: Date.UTC(2026, 10, 17, 12) });
  const random = vi.spyOn(Math, "random").mockReturnValue(s.random);
  vi.resetModules();
  const { maintenanceNotice } = await import("../src/maintenance.js");
  const written: string[] = [];
  const stderr = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    written.push(String(chunk));
    return true;
  });
  try {
    const answers = [...s.answers];
    let requests = 0;
    const waits: Array<{ retryInMs: number; remainingMs: number }> = [];
    const client = new VarlatchClient({
      server: "http://vectors.example",
      token: TOKEN,
      fetch: async () => {
        requests++;
        const next = answers.shift();
        if (!next) throw new Error("the sequence ran out of answers");
        return response(next);
      },
      onMaintenance: (wait: MaintenanceWait) => {
        waits.push({ retryInMs: wait.retryInMs, remainingMs: wait.remainingMs });
        maintenanceNotice(wait);
      },
    });
    const results: unknown[] = [];
    for (let call = 0; call < (s.calls ?? 1); call++) {
      let done = false;
      const p = client.meta().then(
        (value) => (value === undefined ? { undefined: true } : { value }),
        (err: unknown) => ({ error: errorFields(err as VarlatchApiError) }),
      ).finally(() => {
        done = true;
      });
      for (let spins = 0; !done; spins++) {
        if (spins > 10_000) throw new Error(`${s.title}: the call never finished`);
        await vi.advanceTimersToNextTimerAsync();
      }
      results.push(await p);
    }
    return { ...s, waits, notice: written.join(""), requests, results };
  } finally {
    stderr.mockRestore();
    random.mockRestore();
    vi.useRealTimers();
  }
}

const NOW = Date.UTC(2026, 10, 17, 12);
const CREDENTIALS: unknown[] = [
  null,
  {},
  { issuedAt: "2026-11-17T00:00:00.000Z" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "2026-11-18T00:00:00.000Z" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "2026-11-17T14:00:00.000Z" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "2026-11-17T12:00:00.000Z" },
  { issuedAt: "2026-11-16T00:00:00.000Z", expiresAt: "2026-11-17T11:00:00.000Z" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "2026-11-17T14:00:00+02:00" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "Nov 17 2026 13:00 GMT" },
  { issuedAt: "2026-11-17T00:00:00.000Z", expiresAt: "garbage" },
  { issuedAt: "2026-11-18T00:00:00.000Z", expiresAt: "2026-11-17T00:00:00.000Z" },
];
const HEADER_EXPIRIES = [
  "2026-11-20T00:00:00.000Z",
  "2026-11-17T12:00:00.000Z",
  "2026-11-17T11:59:59.999Z",
  "2026-01-01T00:00:00Z",
  "2026-11-20T01:00:00+01:00",
  "Fri, 20 Nov 2026 00:00:00 GMT",
  "1763380800000",
  "garbage",
  "",
];
const URI_COMPONENTS = ["plain", "a b/c?d#e&f=g", "-_.!~*'()", "é中😀", "%41", "@:+$,;[]"];

describe("Go API client vectors", () => {
  it("are what the TypeScript code answers", async () => {
    const savedConfig = process.env.VARLATCH_CONFIG_DIR;
    const savedToken = process.env.VARLATCH_TOKEN;
    process.env.VARLATCH_CONFIG_DIR = config;
    delete process.env.VARLATCH_TOKEN;
    forgetSecrets();
    rememberSecret(TOKEN);
    rememberSecret(HELD);
    try {
      const answers = [];
      for (const a of ANSWERS) answers.push(await answerVector(a));
      const maintenance = [];
      for (const s of SEQUENCES) maintenance.push(await sequenceVector(s));
      const vectors = {
        comment: "Written by apps/cli/test/go-vectors-apiclient.test.ts from the TypeScript code; do not edit.",
        token: TOKEN,
        held: HELD,
        now: NOW,
        answers,
        maintenance,
        expiry: {
          stored: CREDENTIALS.map((credential) => ({ credential, warning: expiryWarning("https://s.example", credential as never, NOW) })),
          header: HEADER_EXPIRIES.map((expiresAt) => ({ expiresAt, warning: envTokenExpiryWarning("https://s.example", expiresAt, NOW) })),
        },
        encodeURIComponent: URI_COMPONENTS.map((text) => ({ text, encoded: encodeURIComponent(text) })),
      };
      const result = writeOrCompare(VECTORS, `${JSON.stringify(vectors, null, 2)}\n`);
      expect(result.current, "apiclient.json is stale: regenerate it (see this file's comment)").toBe(true);
    } finally {
      forgetSecrets();
      if (savedConfig === undefined) delete process.env.VARLATCH_CONFIG_DIR;
      else process.env.VARLATCH_CONFIG_DIR = savedConfig;
      if (savedToken !== undefined) process.env.VARLATCH_TOKEN = savedToken;
    }
  }, 60_000);
});
