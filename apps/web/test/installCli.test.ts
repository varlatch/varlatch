// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { VERIFIED_INSTALL_URL, detectOs, installLine } from "../src/lib/installCli";

describe("the CLI install line (ADR-0058)", () => {
  it("is install.ps1 on Windows and install.sh elsewhere", () => {
    expect(detectOs({ userAgentData: { platform: "Windows" } })).toBe("windows");
    expect(detectOs({ platform: "Win32" })).toBe("windows");
    expect(detectOs({ platform: "MacIntel" })).toBe("posix");
    expect(detectOs({ platform: "Linux x86_64" })).toBe("posix");
    expect(detectOs({})).toBe("posix");
    expect(installLine("https://vault.example.com", "posix")).toBe("curl -fsSL https://vault.example.com/install.sh | sh");
    expect(installLine("https://vault.example.com", "windows")).toBe("irm https://vault.example.com/install.ps1 | iex");
  });

  it("links the verified route to an anchor that exists before and after the docs split", () => {
    expect(VERIFIED_INSTALL_URL).toBe("https://docs.varlatch.com/getting-started/#get-the-cli");
  });
});
