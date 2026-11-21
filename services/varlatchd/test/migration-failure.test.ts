// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { migrationFailure } from "../src/migration/failure.js";

describe("an admin migration command's unexpected failure", () => {
  it("names a system error's code, call and path", () => {
    const err = Object.assign(new Error("EACCES: permission denied, open '/backups/x.jsonl.partial'"), { code: "EACCES", syscall: "open", path: "/backups/x.jsonl.partial", errno: -13 });
    expect(migrationFailure("export", err)).toBe("varlatchd admin migration export failed: EACCES open /backups/x.jsonl.partial");
  });

  it("names PostgreSQL's SQLSTATE and objects, never its message (which can quote a value)", () => {
    const err = Object.assign(new Error('invalid input syntax for type uuid: "a-value-from-the-bundle"'), { code: "22P02", severity: "ERROR", table: "secret_versions", column: "id" });
    const said = migrationFailure("import", err);
    expect(said).toBe("varlatchd admin migration import failed: PostgreSQL error 22P02 (table secret_versions, column id)");
    expect(said).not.toContain("a-value-from-the-bundle");
  });

  it("keeps the catch-all for anything else, and never prints the error's message", () => {
    const said = migrationFailure("barrier", new Error("something holding a-secret-value"));
    expect(said).toBe("varlatchd admin migration barrier failed unexpectedly; check configuration and maintenance status.");
    expect(migrationFailure("", "a string")).toBe("varlatchd admin migration failed unexpectedly; check configuration and maintenance status.");
  });
});
