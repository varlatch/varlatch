// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { pushVersionProblem, versionNeeded } from "../src/contractPush.js";

const PORT = { name: "PORT", type: "integer" };
const RATIO = { name: "RATIO", type: "number" };

describe("the semantics version a push needs (ADR-0042)", () => {
  it("only integer needs a newer version", () => {
    expect(versionNeeded([RATIO])).toEqual({ version: 1, items: [] });
    expect(versionNeeded([RATIO, PORT])).toEqual({ version: 3, items: ["PORT (integer)"] });
  });

  it("nothing to check without an integer item", () => {
    expect(pushVersionProblem([RATIO], { activeVersion: 1, serverVersions: [1, 2] })).toBeNull();
  });

  it("refuses a push that keeps an older active version, naming the fix", () => {
    const problem = pushVersionProblem([PORT], { activeVersion: 2, serverVersions: [1, 2, 3] });
    expect(problem).toContain("PORT (integer) needs Contract Semantics version 3, but this revision would get version 2");
    expect(problem).toContain("the active revision's version, which a push keeps");
    expect(problem).toContain("Push with --semantics latest");
    expect(problem).toContain("dashboard's Contract page");
  });

  it("refuses an older pin", () => {
    expect(pushVersionProblem([PORT], { pinned: 2, activeVersion: 3, serverVersions: [1, 2, 3] })).toContain("the version this push pins");
  });

  it("accepts version 3, pinned or kept, and a first revision, which gets the newest", () => {
    expect(pushVersionProblem([PORT], { activeVersion: 3, serverVersions: [1, 2, 3] })).toBeNull();
    expect(pushVersionProblem([PORT], { pinned: 3, activeVersion: 1, serverVersions: [1, 2, 3] })).toBeNull();
    expect(pushVersionProblem([PORT], { activeVersion: null, serverVersions: [1, 2, 3] })).toBeNull();
  });

  it("names the server upgrade when the server does not evaluate version 3", () => {
    expect(pushVersionProblem([PORT], { activeVersion: null, serverVersions: [1, 2] })).toContain(
      "which this server does not evaluate (it supports 1, 2); upgrade it to Varlatch 0.13.0 or later",
    );
  });
});
