// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { VarlatchApiError, type Approval } from "@varlatch/sdk";
import { approvalLines, assistedStopLines } from "../src/approvals.js";
import { passkeyVerificationLines } from "../src/passkeyVerification.js";
import {
  REDACTED,
  UNRECOGNIZED_TIME,
  UNRECOGNIZED_VERSION,
  apiErrorLine,
  forgetSecrets,
  maskSecrets,
  printable,
  rememberSecret,
  requestNote,
  safe,
  safeApiMajor,
  safeRequestId,
  safeTime,
  safeVersion,
  serverMessage,
} from "../src/safeText.js";

/**
 * Checked text from server responses (issue #119): fields with a known shape
 * print only in that shape, and a server's free text is escaped with every
 * secret the CLI knows of masked.
 */

const STORED = "stored-credential-canary-4f2a9c";
const BEARER = "bearer-canary-env-token-7d3e";
const SENT = "sent-value-canary-a81b";
const REQUEST_ID = "req_0b6c2f1e-3d4a-4c5b-9e8f-7a6b5c4d3e2f";

const dir = mkdtempSync(join(tmpdir(), "varlatch-safe-text-"));
const saved = { config: process.env.VARLATCH_CONFIG_DIR, token: process.env.VARLATCH_TOKEN };

beforeAll(() => {
  writeFileSync(join(dir, "credentials.json"), JSON.stringify({ servers: { "https://other.example": { token: STORED } } }));
  process.env.VARLATCH_CONFIG_DIR = dir;
  process.env.VARLATCH_TOKEN = BEARER;
});

afterAll(() => {
  for (const [name, value] of [["VARLATCH_CONFIG_DIR", saved.config], ["VARLATCH_TOKEN", saved.token]] as const) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => forgetSecrets());

const apiError = (body: { code: string; message: string; requestId: string }) => new VarlatchApiError(400, body as never);

describe("safeTime", () => {
  it("prints an ISO 8601 timestamp, normalized to UTC", () => {
    expect(safeTime("2026-11-13T10:00:00.000Z")).toBe("2026-11-13T10:00:00.000Z");
    expect(safeTime("2026-11-13T10:00:00Z")).toBe("2026-11-13T10:00:00.000Z");
    expect(safeTime("2026-11-13T12:00:00+02:00")).toBe("2026-11-13T10:00:00.000Z");
  });

  it("prints a fixed phrase for anything else, and keeps a missing time missing", () => {
    for (const bad of [`2026-11-13T10:00:00.000Z\n${STORED}`, BEARER, "2026-11-13", "2026-13-45T99:00:00Z", "\u001b[31m", "", 1_700_000_000, {}]) {
      expect(safeTime(bad), String(bad)).toBe(UNRECOGNIZED_TIME);
    }
    expect(safeTime(null)).toBeUndefined();
    expect(safeTime(undefined) ?? "never").toBe("never");
  });
});

describe("safeVersion and safeApiMajor", () => {
  it("prints a semantic version as it is", () => {
    for (const v of ["0.21.0", "1.0.0-rc.1", "1.2.3+build.5"]) expect(safeVersion(v)).toBe(v);
  });

  it("prints a fixed phrase for anything else, a known secret included", () => {
    rememberSecret(SENT);
    for (const bad of ["0.21", "v0.21.0", `0.21.0\n${STORED}`, "0.21.0\u001b[31m", `1.0.0-${SENT}`, `1.0.0-${"a".repeat(70)}`, 21]) {
      expect(safeVersion(bad), String(bad)).toBe(UNRECOGNIZED_VERSION);
    }
    expect(safeVersion(undefined) ?? "an older release").toBe("an older release");
  });

  it("takes an API major only as a small whole number", () => {
    expect(safeApiMajor(1)).toBe(1);
    expect(safeApiMajor(0)).toBe(0);
    for (const bad of [-1, 1.5, 1000, "1", NaN, null]) expect(safeApiMajor(bad), String(bad)).toBeUndefined();
  });
});

describe("request ids", () => {
  it("are shown only in the server's format", () => {
    expect(safeRequestId(REQUEST_ID)).toBe(REQUEST_ID);
    for (const bad of ["req_1", `req_${BEARER}`, `${REQUEST_ID}\n`, "unknown", 7]) expect(safeRequestId(bad), String(bad)).toBeNull();
    expect(requestNote(apiError({ code: "INTERNAL", message: "m", requestId: REQUEST_ID }))).toBe(` (request ${REQUEST_ID})`);
    expect(requestNote(apiError({ code: "INTERNAL", message: "m", requestId: STORED }))).toBe("");
  });
});

describe("masking", () => {
  it("masks every stored credential, VARLATCH_TOKEN, registered values and Varlatch token formats", () => {
    rememberSecret(SENT);
    const token = `vlt_cli_${"Ab3_-".repeat(9)}`;
    expect(maskSecrets(`a ${STORED} b ${BEARER} c ${SENT} d ${token} e vlt_whsec_x1`)).toBe(
      `a ${REDACTED} b ${REDACTED} c ${REDACTED} d ${REDACTED} e ${REDACTED}`,
    );
  });

  it("masks the longest secret first, and leaves short strings and ordinary text alone", () => {
    rememberSecret("abcdefgh");
    rememberSecret("abcdefgh-longer");
    rememberSecret("short");
    expect(maskSecrets("abcdefgh-longer abcdefgh short value")).toBe(`${REDACTED} ${REDACTED} short value`);
    expect(maskSecrets("Project web not found")).toBe("Project web not found");
  });

  it("escapes control characters after masking", () => {
    rememberSecret(SENT);
    expect(serverMessage(`${SENT}\nError FAKE: forged\u001b[31m‮`)).toBe(`${REDACTED}\\u000aError FAKE: forged\\u001b[31m\\u202e`);
  });
});

describe("apiErrorLine", () => {
  it("shows the protocol's code, the masked message and a well-formed request id", () => {
    expect(apiErrorLine(apiError({ code: "PERMISSION_DENIED", message: "denied", requestId: REQUEST_ID }))).toBe(
      `Error PERMISSION_DENIED: denied (request ${REQUEST_ID})`,
    );
    expect(apiErrorLine(apiError({ code: `${BEARER}\n`, message: `echo ${BEARER}\nError FAKE: x`, requestId: `req_${STORED}` }))).toBe(
      `Error UNRECOGNIZED_ERROR: echo ${REDACTED}\\u000aError FAKE: x`,
    );
  });
});

describe("safe", () => {
  it("escapes each interpolated value and leaves the template's own text as it is", () => {
    expect(safe`${"Acme"}  (${"acme"})`).toBe("Acme  (acme)");
    expect(safe`Org ${"evil\n\u001b[2J‮"} (${3}) ${null}`).toBe("Org evil\\u000a\\u001b[2J\\u202e (3) null");
    expect(safe`plain`).toBe("plain");
  });

  it("is idempotent with printable, so nesting never escapes twice", () => {
    const once = printable("a\u001bb");
    expect(printable(once)).toBe(once);
    expect(safe`${once}`).toBe(once);
  });
});

describe("other server text the CLI prints", () => {
  it("a passkey verification refusal: the message masked and escaped, the request id only when well formed", () => {
    const lines = passkeyVerificationLines(
      new VarlatchApiError(403, { code: "PASSKEY_VERIFICATION_REQUIRED", message: `needs a passkey ${BEARER}\nError FAKE: x\u001b[31m`, requestId: `req_${STORED}` }),
    );
    expect(lines?.[0]).toBe(`Error PASSKEY_VERIFICATION_REQUIRED: needs a passkey ${REDACTED}\\u000aError FAKE: x\\u001b[31m`);
  });

  it("an approval: its title, fields, address and id escaped, its expiry checked", () => {
    const approval = {
      id: "apr_1\u001b[2J",
      operation: "security_control.change",
      organization: { id: "org_1", slug: "acme", name: "Acme" },
      summary: { title: "Change admin-step-up\nError FAKE: x", changes: [{ field: "mode‮", from: "report", to: "off", loosens: true }] },
      state: "pending",
      closeReason: null,
      requestedBy: { credentialKind: "cli", client: null },
      url: "https://varlatch.example/approve/apr_1\u001b]52;c;x\u0007",
      interval: 5,
      createdAt: "2026-11-13T10:00:00.000Z",
      expiresAt: `${STORED}`,
      approvedAt: null,
      consumedAt: null,
      closedAt: null,
    } as unknown as Approval;
    const text = [...approvalLines(approval), ...assistedStopLines(approval, "varlatch --approval 'apr_1\u001b[2J' security set")].join("\n");
    expect(text).not.toMatch(/[\u001b\u0007‮]/);
    expect(text).not.toContain(STORED);
    expect(text).not.toMatch(/^Error FAKE/m);
    expect(text).toContain("It expires at an unrecognized time.");
  });
});
