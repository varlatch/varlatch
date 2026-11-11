// SPDX-License-Identifier: Apache-2.0
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { outboundAdvisory, runOutboundCheck } from "../src/outbound.js";

/** The host side of the outbound check (ADR-0057 Decision 10): the wrapper and the upgrade's advisory. */

const REPORT = {
  allow: [],
  destinations: [
    { organization: "acme", kind: "coolify", id: "pc_1", host: "coolify.lan", port: 443, verdict: "refused", reason: "private_address" },
    { organization: "acme", kind: "webhook", id: "wh_1", host: "sink.example", port: 443, verdict: "public" },
  ],
  suggested: "coolify.lan",
  apart: [{ host: "10.0.0.9", port: 443, why: "a literal private address" }],
  exitCode: 1,
};

afterEach(() => vi.unstubAllEnvs());

describe("outbound check on the host", () => {
  it("shows refused destinations and the line to add, and nothing when all are allowed", () => {
    const lines = outboundAdvisory({ status: 1, stdout: JSON.stringify(REPORT), stderr: "" })?.join("\n") ?? "";
    expect(lines).toMatch(/refuses outbound requests to private and internal addresses/);
    expect(lines).toContain("acme  coolify  pc_1  coolify.lan:443  (private_address)");
    expect(lines).toContain("VARLATCH_OUTBOUND_ALLOW=coolify.lan");
    expect(lines).toContain("Not suggested: 10.0.0.9:443");
    expect(lines).not.toContain("sink.example");
    expect(outboundAdvisory({ status: 0, stdout: JSON.stringify({ ...REPORT, destinations: [] }), stderr: "" })).toBeNull();
    // An older image without the command, or no docker: no finding, never a failure.
    expect(outboundAdvisory({ status: 1, stdout: "Usage: varlatchd admin <...>", stderr: "" })).toBeNull();
    expect(outboundAdvisory({ status: null, stdout: "", stderr: "" })).toBeNull();
  });

  it("runs varlatchd's command in the container, or in a one-off container of the new image", () => {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-outbound-"));
    const calls = join(dir, "calls.log");
    writeFileSync(join(dir, "docker"), `#!/bin/sh\necho "$*" >> ${calls}\necho '{"destinations":[]}'\nexit 2\n`);
    chmodSync(join(dir, "docker"), 0o700);
    vi.stubEnv("PATH", `${dir}:${process.env.PATH}`);
    expect(runOutboundCheck(dir, ["--json"])).toMatchObject({ status: 2, stdout: '{"destinations":[]}\n' });
    runOutboundCheck(dir, ["--json"], "run");
    expect(readFileSync(calls, "utf8").trim().split("\n")).toEqual([
      "compose exec -T varlatchd node dist/cli.js admin outbound check --json",
      "compose run --rm --no-deps -T varlatchd admin outbound check --json",
    ]);
  });
});
