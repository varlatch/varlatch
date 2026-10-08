// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { browserCommand, NO_BROWSER_ENV } from "../src/browser.js";

const PAGE = "https://vault.example.com/enroll?callback=http%3A%2F%2F127.0.0.1%3A50123%2F&x=1";

describe("browserCommand", () => {
  it("on Windows, starts the URL protocol handler without a shell, with the address as one argument", () => {
    expect(browserCommand("win32", PAGE, {})).toEqual({ command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", PAGE] });
  });

  it("uses open on macOS and xdg-open everywhere else", () => {
    expect(browserCommand("darwin", PAGE, {})).toEqual({ command: "open", args: [PAGE] });
    for (const platform of ["linux", "freebsd", "openbsd"] as const) {
      expect(browserCommand(platform, PAGE, {}), platform).toEqual({ command: "xdg-open", args: [PAGE] });
    }
  });

  it(`opens nothing when ${NO_BROWSER_ENV} is set to anything but empty or 0`, () => {
    for (const platform of ["win32", "darwin", "linux"] as const) {
      for (const value of ["1", "true", "yes", "false", " ", "00"]) {
        expect(browserCommand(platform, PAGE, { [NO_BROWSER_ENV]: value }), `${platform} ${JSON.stringify(value)}`).toBeNull();
      }
    }
  });

  it(`opens the browser when ${NO_BROWSER_ENV} is unset, empty, or 0`, () => {
    for (const env of [{}, { [NO_BROWSER_ENV]: "" }, { [NO_BROWSER_ENV]: "0" }]) {
      expect(browserCommand("win32", PAGE, env)?.command, JSON.stringify(env)).toBe("rundll32.exe");
      expect(browserCommand("darwin", PAGE, env)?.command, JSON.stringify(env)).toBe("open");
      expect(browserCommand("linux", PAGE, env)?.command, JSON.stringify(env)).toBe("xdg-open");
    }
  });
});
