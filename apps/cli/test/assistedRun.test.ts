// SPDX-License-Identifier: Apache-2.0
import { PassThrough, Readable } from "node:stream";
import { labelledFormsOf, type SecretEntry } from "@varlatch/matcher";
import { describe, expect, it } from "vitest";
import { assistedRedactionSet, planAssistedRedaction, unmaskableItems, unmaskableRefusal } from "../src/assistedRun.js";
import { OutputRedaction } from "../src/redact.js";

/**
 * Assisted mode's redaction set and short-value refusal (ADR-0043 Decision
 * 4), and the redactor it feeds, on the same inputs with each protection
 * disabled as the negative control.
 */

// Chosen so every form exists: `/` gives a JSON `\/` form, `>>?` gives base64 `+` and `/`.
const DELIVERED = "delivered-canary/7f3a+é=q>>?";
const INHERITED = "inherited-canary/19bd+ü=z>>?";
const UNKNOWN = "unknown-name-canary-4410";

describe("assistedRedactionSet", () => {
  const delivered: SecretEntry[] = [{ item: "API_TOKEN", value: DELIVERED }];

  it("holds the delivered Secrets and inherited values under known Secret names", () => {
    const parent = { LEGACY_KEY: INHERITED, WITHHELD: "withheld-canary-55", API_TOKEN: "shell-copy-of-token" };
    const child = { ...parent, API_TOKEN: DELIVERED };
    const set = assistedRedactionSet(delivered, child, parent, ["API_TOKEN", "LEGACY_KEY", "WITHHELD", "NOT_SET"]);
    expect(set).toEqual([
      { item: "API_TOKEN", value: DELIVERED },
      { item: "LEGACY_KEY", value: INHERITED },
      { item: "WITHHELD", value: "withheld-canary-55" },
    ]);
  });

  it("does not hold an inherited value the command never receives (a delivered value replaced it)", () => {
    const set = assistedRedactionSet(delivered, { API_TOKEN: DELIVERED }, { API_TOKEN: "shell-copy-of-token" }, ["API_TOKEN"]);
    expect(set.map((e) => e.value)).toEqual([DELIVERED]);
  });

  it("limit check (not a control): an inherited secret under a name Varlatch does not know is not held", () => {
    const parent = { SOME_OTHER_TOKEN: UNKNOWN };
    expect(assistedRedactionSet([], parent, parent, ["API_TOKEN"])).toEqual([]);
  });

  it("holds only what the command holds: an item left out with --omit is neither delivered nor inherited, so a short one cannot stop the run", () => {
    const short: SecretEntry[] = [...delivered, { item: "PIN", value: "1234567" }];
    const parent = { PIN: "7654321", LEGACY_KEY: INHERITED };
    // The command's environment without PIN, as buildEnv makes it for --omit PIN.
    const child = { LEGACY_KEY: INHERITED, API_TOKEN: DELIVERED };
    const set = assistedRedactionSet(short, child, parent, ["API_TOKEN", "LEGACY_KEY", "PIN"]);
    expect(set).toEqual([
      { item: "API_TOKEN", value: DELIVERED },
      { item: "LEGACY_KEY", value: INHERITED },
    ]);
    expect(planAssistedRedaction(set, [])).toMatchObject({ refused: [], allowed: [] });
    // Control, same input: with PIN in the command's environment, the delivered short value stops the run.
    const control = assistedRedactionSet(short, { ...child, PIN: "1234567" }, parent, ["API_TOKEN", "LEGACY_KEY", "PIN"]);
    expect(planAssistedRedaction(control, [])).toMatchObject({ refused: ["PIN"] });
  });

  it("skips empty values, which carry nothing to mask and cannot be short", () => {
    const set = assistedRedactionSet([{ item: "EMPTY", value: "" }], { LEGACY_KEY: "" }, { LEGACY_KEY: "" }, ["LEGACY_KEY"]);
    expect(set).toEqual([]);
    expect(unmaskableItems(set)).toEqual([]);
  });
});

describe("planAssistedRedaction", () => {
  const set: SecretEntry[] = [
    { item: "PIN", value: "1234567" },
    { item: "REDIS_PASSWORD", value: "abcdefg" },
    { item: "API_TOKEN", value: DELIVERED },
    { item: "EIGHT", value: "12345678" },
  ];

  it("refuses every value shorter than 8 bytes that nobody allowed", () => {
    expect(planAssistedRedaction(set, [])).toMatchObject({ refused: ["PIN", "REDIS_PASSWORD"], allowed: [], unusedAllowances: [] });
  });

  it("--allow-unmasked lets a named short value pass; other names are reported unused", () => {
    expect(planAssistedRedaction(set, ["PIN", "API_TOKEN", "TYPO"])).toMatchObject({
      refused: ["REDIS_PASSWORD"],
      allowed: ["PIN"],
      unusedAllowances: ["API_TOKEN", "TYPO"],
    });
  });

  it("the refusal names items and remedies, never a value", () => {
    const lines = unmaskableRefusal(["PIN", "REDIS_PASSWORD"], { target: "-e production", runOptions: ["--strict"] }).join("\n");
    expect(lines).toMatch(/shorter than 8 bytes.*: PIN, REDIS_PASSWORD/);
    // Every command names the run's environment, so it acts on the same values.
    // First the remedy that needs no approval: leaving the items out, as the agent's own command, keeping the run's options.
    expect(lines).toMatch(
      /^ {2}If the command does not need them, rerun with --omit PIN --omit REDIS_PASSWORD: the command then does not get them, and no approval is needed \(leave out only the ones it does not need\):\n {6}varlatch --assisted run -e production --strict --omit PIN --omit REDIS_PASSWORD -- <command>\n {2}If it needs one, stop and ask/m,
    );
    // Otherwise stop and ask; an approved replacement is the agent's own command, with --assisted.
    expect(lines).toMatch(/stop and ask the human what to do about each item it needs\. Approval for one item or action never covers another\./);
    expect(lines).toMatch(/Only if they approve replacing PIN with a new random value \(it overwrites the current one\):\n {6}varlatch --assisted values set PIN -e production --replace PIN --generate hex:32 {3}\(each item needs its own approval\)/);
    // No generated replacement is printed without --assisted: an agent could run it outside assisted mode.
    expect(lines).not.toMatch(/^\s*varlatch values set .*--generate/m);
    expect(lines).not.toMatch(/: varlatch values set \S+ -e production --generate/);
    // The human's alone: a provider's credential, and showing a Secret unmasked.
    expect(lines).toMatch(/the human enters it, in their own terminal: varlatch values set PIN -e production$/m);
    expect(lines).toMatch(/Showing it unmasked is the human's alone, in their own terminal .*\n {6}varlatch run -e production --strict --allow-unmasked PIN -- <command>/);
    expect(lines).toMatch(/marking PIN as not secret \(a Contract change, for the whole project\): varlatch --assisted agents guide contract/);
    expect(lines).not.toMatch(/contract update/);
    // The Contract is the server's: an overridden server is named for every contract command.
    expect(lines).not.toMatch(/add --server/);
    const overridden = unmaskableRefusal(["PIN"], { target: "-e production --server https://b.example" }).join("\n");
    expect(overridden).toMatch(/varlatch --assisted agents guide contract \(add --server https:\/\/b\.example to every contract command\)/);
    expect(lines).not.toMatch(/1234567|abcdefg/);
  });

  it("the --omit remedy comes first; for the human's override it has no --assisted and keeps the allowances", () => {
    const agent = unmaskableRefusal(["PIN"], { target: "-e production" });
    expect(agent[1]).toBe("  If the command does not need PIN, rerun with --omit PIN: the command then does not get it, and no approval is needed:");
    expect(agent[2]).toBe("      varlatch --assisted run -e production --omit PIN -- <command>");
    expect(agent[3]).toMatch(/^ {2}If it needs it, stop and ask the human what to do about PIN\./);
    const human = unmaskableRefusal(["PIN_TWO"], { target: "-e production", runOptions: ["--allow-unmasked PIN"], assisted: false });
    expect(human[2]).toBe("      varlatch run -e production --allow-unmasked PIN --omit PIN_TWO -- <command>");
  });
});

async function relay(entries: SecretEntry[], out: Buffer[], err: Buffer[]): Promise<{ stdout: Buffer; stderr: Buffer }> {
  const redaction = new OutputRedaction(entries, "assisted");
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const collected = { stdout: [] as Buffer[], stderr: [] as Buffer[] };
  stdout.on("data", (d: Buffer) => collected.stdout.push(d));
  stderr.on("data", (d: Buffer) => collected.stderr.push(d));
  await redaction.relay([
    [Readable.from(out), stdout],
    [Readable.from(err), stderr],
  ]);
  return { stdout: Buffer.concat(collected.stdout), stderr: Buffer.concat(collected.stderr) };
}

/**
 * Every form the matcher recognises (raw, JSON-escaped with and without
 * `\/`, percent-encoded in both hex cases, base64 and base64url at each
 * alignment), each split at every byte offset, on stdout and on stderr.
 */
describe("assisted output redaction across forms and chunk boundaries", () => {
  const parent = { LEGACY_KEY: INHERITED };
  const set = assistedRedactionSet([{ item: "API_TOKEN", value: DELIVERED }], { ...parent, API_TOKEN: DELIVERED }, parent, ["LEGACY_KEY"]);
  const cases = [
    ...labelledFormsOf(DELIVERED).map((f) => ({ item: "API_TOKEN", value: DELIVERED, ...f })),
    ...labelledFormsOf(INHERITED).map((f) => ({ item: "LEGACY_KEY", value: INHERITED, ...f })),
  ];

  it("covers every matcher form of both values", () => {
    expect(new Set(cases.map((c) => c.form))).toEqual(new Set(["raw", "json", "percent", "base64", "base64url"]));
    expect(cases.length).toBeGreaterThanOrEqual(20);
  });

  it.each(cases.map((c, i) => [`${c.item} ${c.form} #${i}`, c] as const))(
    "masks %s split at every offset; with the protection disabled the same input leaks",
    async (_name, c) => {
      const line = Buffer.concat([Buffer.from("log: "), Buffer.from(c.bytes), Buffer.from(" end\n")]);
      for (let at = 1; at < line.length; at++) {
        const chunks = [line.subarray(0, at), line.subarray(at)];
        const masked = await relay(set, chunks, chunks);
        for (const stream of [masked.stdout, masked.stderr]) {
          expect(stream.includes(Buffer.from(c.bytes))).toBe(false);
          expect(stream.toString()).toBe(`log: [REDACTED:${c.item}] end\n`);
        }
      }
      // Negative control, same input: redaction off (an empty set) leaks it.
      const off = await relay([], [line], [line]);
      expect(off.stdout.includes(Buffer.from(c.bytes))).toBe(true);
      expect(off.stderr.includes(Buffer.from(c.bytes))).toBe(true);
    },
  );

  it("negative control for inherited-value filtering: the delivered-only set of --redact leaks the inherited value", async () => {
    const line = Buffer.from(`k=${INHERITED}\n`);
    const withInherited = await relay(set, [line], [line]);
    expect(withInherited.stdout.toString()).toBe("k=[REDACTED:LEGACY_KEY]\n");
    const deliveredOnly = await relay([{ item: "API_TOKEN", value: DELIVERED }], [line], [line]);
    expect(deliveredOnly.stdout.toString()).toBe(line.toString());
  });
});
