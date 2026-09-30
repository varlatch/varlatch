// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  ITEM_TYPE_SINCE,
  canMoveRules,
  movedContract,
  moveConsequences,
  newestSemanticsVersion,
  reviewMove,
  revisionSemanticsVersion,
  semanticsSteps,
  typeOffer,
} from "../src/features/projects/semanticsMove";

const items = [
  {
    name: "LOG_LEVEL",
    required: { kind: "never" },
    sensitive: false,
    type: "enum",
    enumValues: ["debug", "info"],
    defaultValue: "info",
    description: "Log verbosity",
    example: "debug",
  },
  { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number", rotationGraceSeconds: 60 },
];
const v1 = { id: "rev_1", contract: { schemaVersion: 1, items } };

describe("semantics versions", () => {
  it("the newest is the highest listed; a server that lists none evaluates only version 1", () => {
    expect(newestSemanticsVersion([1, 3, 2])).toBe(3);
    expect(newestSemanticsVersion(undefined)).toBe(1);
    expect(newestSemanticsVersion([])).toBe(1);
  });

  it("a revision without a version is version 1", () => {
    expect(revisionSemanticsVersion({})).toBe(1);
    expect(revisionSemanticsVersion({ semanticsVersion: 2 })).toBe(2);
  });

  it("offers the move only below the newest version", () => {
    expect(canMoveRules(1, 3)).toBe(true);
    expect(canMoveRules(2, 3)).toBe(true);
    expect(canMoveRules(3, 3)).toBe(false);
    expect(canMoveRules(1, 1)).toBe(false);
  });
});

describe("item types offered by the editor", () => {
  it("offers integer only at version 3 or later", () => {
    expect(typeOffer("integer", 3, 3)).toEqual({ enabled: true });
    expect(typeOffer("integer", 4, 4)).toEqual({ enabled: true });
    const older = typeOffer("integer", 2, 3);
    expect(older.enabled).toBe(false);
    if (!older.enabled) {
      expect(older.reason).toContain("Needs semantics version 3");
      expect(older.reason).toContain("uses version 2");
      expect(older.reason).toContain("Move to the newest rules");
      expect(older.reason).toContain("Edits keep the version");
    }
  });

  it("says when the server does not support the type at all", () => {
    const offer = typeOffer("integer", 1, 1);
    expect(offer.enabled).toBe(false);
    if (!offer.enabled) expect(offer.reason).toContain("this server does not support");
  });

  it("does not offer integer while the version is unknown", () => {
    expect(typeOffer("integer", undefined, 3).enabled).toBe(false);
  });

  it("offers every other type at every version", () => {
    for (const t of ["string", "number", "boolean", "url", "email", "enum"]) {
      expect(typeOffer(t, 1, 3)).toEqual({ enabled: true });
    }
  });
});

describe("moving to the newest rules", () => {
  it("the moved Contract is the active one with only the version set", () => {
    const moved = movedContract(v1.contract, 3);
    expect(moved).toEqual({ schemaVersion: 1, items, semanticsVersion: 3 });
    expect(moved.items).toBe(items);
    expect(movedContract({ schemaVersion: 1, semanticsVersion: 2, items }, 3).semanticsVersion).toBe(3);
  });

  it("a revision that differs only in the version is activatable", () => {
    // Key order differs from the base: that is not a change.
    const reordered = items.map((i) => Object.fromEntries(Object.entries(i).reverse()));
    const pushed = { id: "rev_2", semanticsVersion: 3, contract: { items: reordered, semanticsVersion: 3, schemaVersion: 1 } };
    expect(reviewMove(v1, pushed, 3)).toEqual({
      versionChange: { from: 1, to: 3 },
      otherChanges: [],
      activatable: true,
    });
  });

  it("any other difference is listed and refuses activation", () => {
    const pushed = {
      id: "rev_2",
      semanticsVersion: 3,
      contract: {
        schemaVersion: 1,
        semanticsVersion: 3,
        items: [
          { ...items[0], description: "changed" },
          { name: "NEW_ITEM", required: { kind: "never" }, sensitive: true, type: "string" },
        ],
      },
    };
    const review = reviewMove(v1, pushed, 3);
    expect(review.versionChange).toEqual({ from: 1, to: 3 });
    expect(review.otherChanges).toEqual(["Item added: NEW_ITEM", "Item changed: LOG_LEVEL", "Item removed: PORT"]);
    expect(review.activatable).toBe(false);
  });

  it("a changed top-level field refuses activation", () => {
    const pushed = { id: "rev_2", semanticsVersion: 3, contract: { schemaVersion: 2, semanticsVersion: 3, items } };
    expect(reviewMove(v1, pushed, 3)).toMatchObject({
      otherChanges: ["Contract field changed: schemaVersion"],
      activatable: false,
    });
  });

  it("a revision at another version than requested refuses activation", () => {
    const pushed = { id: "rev_2", semanticsVersion: 2, contract: { schemaVersion: 1, semanticsVersion: 2, items } };
    const review = reviewMove(v1, pushed, 3);
    expect(review.versionChange).toEqual({ from: 1, to: 2 });
    expect(review.otherChanges).toEqual(["The pushed revision uses semantics version 2, not 3."]);
    expect(review.activatable).toBe(false);
  });

  it("getting the active revision back refuses activation", () => {
    const review = reviewMove(v1, { ...v1 }, 3);
    expect(review.versionChange).toBeNull();
    expect(review.activatable).toBe(false);
  });
});

describe("what the review explains", () => {
  it("lists every version step between the current and the newest version", () => {
    expect(semanticsSteps(1, 3)).toEqual([
      {
        version: 2,
        change:
          "Numbers are bounded at 2^53 - 1 in magnitude, and values convert to typed values for generated types.",
      },
      { version: 3, change: "Adds the integer type." },
    ]);
    expect(semanticsSteps(2, 3)).toEqual([{ version: 3, change: "Adds the integer type." }]);
    expect(semanticsSteps(3, 3)).toEqual([]);
    expect(semanticsSteps(3, 4)[0]?.change).toContain("release notes");
  });

  it("names the consequences, with the number bound only when crossing version 2", () => {
    const fromTwo = moveConsequences(2, 3, "managed");
    expect(fromTwo).toEqual([
      "Generated types from `varlatch types` become stale; regenerate them.",
      "A CLI that does not implement version 3 refuses `varlatch run --strict` for this project; upgrade CLIs that run it.",
      "Existing values are re-validated with the newer rules.",
    ]);
    const fromOne = moveConsequences(1, 3, "managed");
    expect(fromOne[0]).toContain("Version 1 defines no conversion");
    expect(fromOne[2]).toBe(
      "Existing values are re-validated with the newer rules (numbers larger than 2^53 - 1 in magnitude become invalid from version 2).",
    );
  });

  it("tells git projects that later pushes keep the version", () => {
    expect(moveConsequences(1, 3, "git")).toContain(
      "Later pushes from your repository keep version 3; you do not need to change the file.",
    );
    expect(moveConsequences(1, 3, "managed").some((c) => c.includes("repository"))).toBe(false);
  });

  it("uses no em or en dashes", () => {
    const texts = [
      ...moveConsequences(1, 3, "git"),
      ...semanticsSteps(1, 4).map((s) => s.change),
      ...["integer", "number"].flatMap((t) => {
        const o = typeOffer(t, 1, 3);
        return o.enabled ? [] : [o.reason];
      }),
    ];
    for (const t of texts) expect(t).not.toMatch(/[\u2013\u2014]/);
  });
});

describe("kept in step with @varlatch/contract", () => {
  // The web app does not depend on the contract package, so these tests
  // read its sources directly: a new type or version there fails here until
  // the dashboard's copy follows.
  it("the per-type minimum version matches the contract package", async () => {
    const { ITEM_TYPES, ITEM_TYPE_SINCE_SEMANTICS } = await import("../../../packages/contract/src/types.ts");
    expect({ ...ITEM_TYPE_SINCE }).toEqual({ ...ITEM_TYPE_SINCE_SEMANTICS });
    expect(Object.keys(ITEM_TYPE_SINCE).sort()).toEqual([...ITEM_TYPES].sort());
  });

  it("every version after 1 has its own explanation", async () => {
    const { SEMANTICS_VERSIONS } = await import("../../../packages/contract/src/semantics.ts");
    for (const version of SEMANTICS_VERSIONS.filter((v: number) => v > 1)) {
      expect(semanticsSteps(version - 1, version)[0]?.change, `version ${version}`).not.toContain("release notes");
    }
  });
});
