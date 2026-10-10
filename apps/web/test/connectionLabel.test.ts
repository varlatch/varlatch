// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { connectionLabel } from "../src/features/sync/platform-meta";

describe("connectionLabel", () => {
  it("adds the platform to a bare name, and never repeats it", () => {
    expect(connectionLabel({ platform: "github-actions", name: "acme" })).toBe("GitHub (acme)");
    // The default name of an App installation's connection already says it.
    expect(connectionLabel({ platform: "github-actions", name: "GitHub (varlatch-app-check-101)" })).toBe("GitHub (varlatch-app-check-101)");
    expect(connectionLabel({ platform: "github-actions", name: "github acme" })).toBe("github acme");
    expect(connectionLabel({ platform: "coolify", name: "production" })).toBe("Coolify (production)");
  });
});
