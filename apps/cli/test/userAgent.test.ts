// SPDX-License-Identifier: Apache-2.0
import { EMBEDDED_RELEASE } from "@varlatch/backup";
import { afterEach, describe, expect, it } from "vitest";
import { cliUserAgent, formatUserAgent, setAssistedUserAgent } from "../src/userAgent.js";

/**
 * The CLI's User-Agent: varlatchd records its summary on credentials and
 * audit events, so assisted mode (ADR-0043 Decision 3) is visible in the
 * audit log as the token `assisted`.
 */
describe("the CLI's User-Agent", () => {
  afterEach(() => setAssistedUserAgent(false));

  it("names the version, platform, and architecture, and assisted mode as a third token", () => {
    expect(formatUserAgent("0.16.0", false, "linux", "x64")).toBe("varlatch-cli/0.16.0 (linux; x64)");
    expect(formatUserAgent("0.16.0", true, "linux", "x64")).toBe("varlatch-cli/0.16.0 (linux; x64; assisted)");
    expect(formatUserAgent("0.16.0-rc.1", true, "win32", "arm64")).toBe("varlatch-cli/0.16.0-rc.1 (win32; arm64; assisted)");
  });

  it("is this release's on this machine, assisted once main() says so", () => {
    const plain = `varlatch-cli/${EMBEDDED_RELEASE.version} (${process.platform}; ${process.arch})`;
    expect(cliUserAgent()).toBe(plain);
    setAssistedUserAgent(true);
    expect(cliUserAgent()).toBe(`varlatch-cli/${EMBEDDED_RELEASE.version} (${process.platform}; ${process.arch}; assisted)`);
    setAssistedUserAgent(false);
    expect(cliUserAgent()).toBe(plain);
  });
});
