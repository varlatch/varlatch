// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { SOURCE_REPOSITORY, sourceUrl } from "../src/lib/source";

describe("source link", () => {
  it("points at the release tag the server reports", () => {
    expect(sourceUrl("0.14.1")).toBe(`${SOURCE_REPOSITORY}/tree/v0.14.1`);
    expect(sourceUrl("0.15.0-rc.1")).toBe(`${SOURCE_REPOSITORY}/tree/v0.15.0-rc.1`);
  });

  it("falls back to the repository without a release version", () => {
    expect(sourceUrl(undefined)).toBe(SOURCE_REPOSITORY);
    expect(sourceUrl("")).toBe(SOURCE_REPOSITORY);
    expect(sourceUrl("dev")).toBe(SOURCE_REPOSITORY);
    expect(sourceUrl("0.14.1/../../evil")).toBe(SOURCE_REPOSITORY);
  });
});
