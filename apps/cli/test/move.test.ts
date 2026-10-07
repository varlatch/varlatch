// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as backup from "../src/backup.js";
import { movedConfig, movePlan, moveTarget, runMove, type MoveFacts } from "../src/move.js";
import { MOVE_STATE_FILE, readMoveState } from "../src/moveState.js";
import { CONFIG_FILE, type InstallConfig, renderEnv, runningPublicUrl, runSetup, varlatchd } from "../src/setup.js";

/** `varlatch move` (issue #103). */

const OLD = "https://old.example.com";
const NEW = "https://new.example.com";
const base: InstallConfig = { schemaVersion: 1, publicUrl: OLD, ingress: "external", webPort: 8787, bindAddress: "127.0.0.1" };
const facts: MoveFacts = { publicUrl: OLD, people: 3, installationAdmins: 1, passkeys: 4, sessions: 2, tailnetConstraints: 0, pendingInvitations: 0 };

describe("where a move may go", () => {
  it("needs a new address, valid for the target ingress", () => {
    expect(moveTarget(base, { publicUrl: `${NEW}/` })).toEqual({ publicUrl: NEW, ingress: "external" });
    expect(moveTarget(base, { publicUrl: NEW, ingress: "public" })).toEqual({ publicUrl: NEW, ingress: "public" });
    expect(() => moveTarget(base, {})).toThrow(/--public-url/);
    expect(() => moveTarget(base, { publicUrl: "http://new.example.com" })).toThrow();
    expect(() => moveTarget(base, { publicUrl: "https://10.0.0.5", ingress: "public" })).toThrow();
    expect(() => moveTarget(base, { publicUrl: NEW, ingress: "bogus" as never })).toThrow(/--ingress must be one of/);
  });

  it("refuses the same address, an ingress-only change, and the tailnet as a target", () => {
    expect(() => moveTarget(base, { publicUrl: OLD })).toThrow(/already answers at/);
    expect(() => moveTarget(base, { publicUrl: OLD, ingress: "public" })).toThrow(/changing only the ingress/);
    expect(() => moveTarget(base, { publicUrl: NEW, ingress: "tailnet" })).toThrow(/not supported yet/);
    const tailnet: InstallConfig = { ...base, ingress: "tailnet", tailnetMachine: "varlatch", tailnetName: "tn.ts.net" };
    expect(() => moveTarget(tailnet, { publicUrl: NEW })).toThrow(/not supported yet/);
    expect(moveTarget(tailnet, { publicUrl: NEW, ingress: "public" })).toEqual({ publicUrl: NEW, ingress: "public" });
  });
});

describe("the configuration after a move", () => {
  it("drops the tailnet fields when leaving the tailnet", () => {
    const tailnet: InstallConfig = { ...base, ingress: "tailnet", tailnetMachine: "varlatch", tailnetName: "tn.ts.net" };
    const { config, notes } = movedConfig(tailnet, { publicUrl: NEW, ingress: "public" });
    expect(config).toEqual({ ...base, publicUrl: NEW, ingress: "public" });
    expect(notes).toEqual([]);
  });

  it("lets a derived Convex address follow, and keeps a separate one with a note", () => {
    expect(movedConfig({ ...base, convexOrigin: `${OLD}/convex` }, { publicUrl: NEW, ingress: "external" }).config.convexOrigin).toBeUndefined();
    const kept = movedConfig({ ...base, convexOrigin: "https://convex.example.com" }, { publicUrl: NEW, ingress: "external" });
    expect(kept.config.convexOrigin).toBe("https://convex.example.com");
    expect(kept.notes[0]).toMatch(/Convex keeps its own address/);
  });
});

describe("the plan the operator confirms", () => {
  it("states the re-enrollment and what keeps working", () => {
    const text = movePlan(base, { publicUrl: NEW, ingress: "external" }, facts).join("\n");
    expect(text).toContain(`Move ${OLD} (external ingress) to ${NEW} (external ingress).`);
    expect(text).toContain("every passkey stops working (4 enrolled)");
    expect(text).toContain("each of the 3 people gets a one-time link");
    expect(text).toContain(`varlatch login --server ${NEW}`);
    expect(text).not.toMatch(/Tailnet Constraint|invitation link/);
  });

  it("warns about Tailnet Constraints only when leaving the tailnet, and about open invitations", () => {
    const tailnet: InstallConfig = { ...base, ingress: "tailnet" };
    const withBoth = { ...facts, tailnetConstraints: 2, pendingInvitations: 1 };
    const text = movePlan(tailnet, { publicUrl: NEW, ingress: "public" }, withBoth).join("\n");
    expect(text).toMatch(/2 Tailnet Constraint\(s\)/);
    expect(text).toMatch(/1 invitation link\(s\) are still open/);
    expect(movePlan(base, { publicUrl: NEW, ingress: "public" }, withBoth).join("\n")).not.toMatch(/Tailnet Constraint/);
  });
});

// The move against a stand-in `docker` on PATH that answers what a move asks
// of Compose and of varlatchd, and logs every call.
describe("runMove and setup's move mode", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  function fakeDocker(opts: { admins?: number; adminEnrolled?: boolean } = {}): string {
    const bin = mkdtempSync(join(tmpdir(), "move-bin-"));
    const calls = join(bin, "calls.log");
    const healthy = ["postgres", "varlatchd", "varlatch-web", "convex-backend"]
      .map((s) => `{"Service":"${s}","State":"running","Health":"healthy"}`).join("\\n");
    writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "$*" >> "${calls}"
case "$*" in
  "compose version --short") echo 2.29.7; exit 0;;
  "volume inspect"*) exit 1;;
  "compose up -d --remove-orphans") exit 0;;
  "compose ps -a --format json") printf '${healthy}\\n'; exit 0;;
  "compose run --rm convex-deploy") exit 0;;
  *"admin move-facts") echo '{"publicUrl":"${OLD}","people":2,"installationAdmins":${opts.admins ?? 1},"passkeys":2,"sessions":1,"tailnetConstraints":0,"pendingInvitations":0}'; exit 0;;
  *"admin reenroll --identity idn_typo"*) echo "No person with identity idn_typo" >&2; exit 1;;
  *"admin public-url-changed --from ${OLD}") echo '{"from":"${OLD}","to":"${NEW}","passkeysRemoved":2,"sessionsEnded":1,"browserCredentialsRevoked":1}'; exit 0;;
  *"admin reenroll --all --json"*) echo '{"links":[{"name":"Jeremy","identityId":"idn_a","installationAdmin":true,"link":"${NEW}/enroll#vlt_reenroll_x","expiresAt":"2026-10-08T00:00:00.000Z"}]}'; exit 0;;
  *"admin bootstrap-status") echo '{"initialized":true,"bootstrapped":true,"admins":[{"id":"idn_a","enabled":true,"hasPasskey":${opts.adminEnrolled ? "true" : "false"}}]}'; exit 0;;
esac
exit 1
`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    return calls;
  }

  function installation(config: InstallConfig = base): string {
    const dir = mkdtempSync(join(tmpdir(), "move-run-"));
    writeFileSync(join(dir, "docker-compose.yml"), "name: vltest\nservices: {}\n");
    writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(config, null, 2) + "\n");
    writeFileSync(join(dir, ".env"), renderEnv(config), { mode: 0o600 });
    return dir;
  }

  const options = (dir: string, extra: Partial<Parameters<typeof runMove>[0]> = {}) => ({
    dir, backupArgs: ["--kek-file", "/k"], yes: true, noWait: true, enrollTimeoutMs: 0, ...extra,
  });
  const count = (calls: string, text: string) => readFileSync(calls, "utf8").split("\n").filter((l) => l.includes(text)).length;

  it("archives, moves, removes the old passkeys once, issues the links once, and resumes without repeating", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const calls = fakeDocker();
    const dir = installation();
    const capture = vi.spyOn(backup, "createBackup").mockResolvedValue("/backups/pre-move.vltbak");
    const verify = vi.spyOn(backup, "verifyBackup").mockResolvedValue({} as never);

    expect(await runMove(options(dir, { publicUrl: NEW }))).toBe(3); // waits for an admin, --no-wait
    expect(capture).toHaveBeenCalledWith(["--kek-file", "/k"], dir);
    expect(verify).toHaveBeenCalledWith(["--kek-file", "/k", "--in", "/backups/pre-move.vltbak", "--record"], dir);
    expect(JSON.parse(readFileSync(join(dir, CONFIG_FILE), "utf8")).publicUrl).toBe(NEW);
    expect(runningPublicUrl(join(dir, ".env"))).toBe(NEW);
    expect(readMoveState(dir)).toMatchObject({ from: OLD, to: NEW, archive: "/backups/pre-move.vltbak" });
    expect(readMoveState(dir)?.passkeysRetiredAt).toBeTruthy();
    expect(readMoveState(dir)?.linksIssuedAt).toBeTruthy();
    expect(log).toHaveBeenCalledWith(`    Jeremy (Installation Admin)\n      ${NEW}/enroll#vlt_reenroll_x`);
    // Retirement comes after the new address is live and Convex trusts it.
    const order = readFileSync(calls, "utf8");
    expect(order.indexOf("up -d")).toBeLessThan(order.indexOf("convex-deploy"));
    expect(order.indexOf("convex-deploy")).toBeLessThan(order.indexOf("public-url-changed"));

    // Resume: no second archive, no second retirement, no new links.
    expect(await runMove(options(dir))).toBe(3);
    expect(capture).toHaveBeenCalledOnce();
    expect(count(calls, "public-url-changed")).toBe(1);
    expect(count(calls, "admin reenroll")).toBe(1);
    // A plain setup rerun does not finish (or skip) a move.
    await expect(runSetup({ dir, noWait: true, enrollTimeoutMs: 0, attest: false })).rejects.toThrow(/move to https:\/\/new\.example\.com is in progress/);
    // Nor does another address while one move is open.
    await expect(runMove(options(dir, { publicUrl: "https://third.example.com" }))).rejects.toThrow(/in progress/);
  });

  it("resumes a move that stopped before the new address was written", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const calls = fakeDocker();
    const dir = installation();
    writeFileSync(join(dir, MOVE_STATE_FILE), JSON.stringify({ from: OLD, fromIngress: "external", to: NEW, toIngress: "external", archive: "/a", startedAt: "2026-10-07T00:00:00Z" }));
    expect(await runMove(options(dir))).toBe(3);
    expect(JSON.parse(readFileSync(join(dir, CONFIG_FILE), "utf8")).publicUrl).toBe(NEW);
    expect(count(calls, "public-url-changed")).toBe(1);
  });

  it("checks the target ingress's files before it changes anything", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker();
    const dir = installation();
    const capture = vi.spyOn(backup, "createBackup").mockResolvedValue("/x");
    await expect(runMove(options(dir, { publicUrl: NEW, ingress: "public" }))).rejects.toThrow(/public ingress needs docker-compose\.caddy\.yml, Caddyfile/);
    expect(capture).not.toHaveBeenCalled();
    expect(existsSync(join(dir, MOVE_STATE_FILE))).toBe(false);
  });

  it("goes on when only recording the verification fails, and stops when the archive itself fails (#1)", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker();
    const dir = installation();
    vi.spyOn(backup, "createBackup").mockResolvedValue("/backups/pre-move.vltbak");
    const verify = vi.spyOn(backup, "verifyBackup").mockImplementation(async (args) => {
      if (args.includes("--record")) throw new Error("Compose exec failed; installation may remain isolated.");
      return {} as never;
    });
    expect(await runMove(options(dir, { publicUrl: NEW }))).toBe(3);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(verify.mock.calls[1]![0]).not.toContain("--record");
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/archive is verified, but the result could not be recorded/));
    expect(readMoveState(dir)?.to).toBe(NEW);

    const other = installation();
    verify.mockReset().mockRejectedValue(new Error("Backup verification checks failed"));
    await expect(runMove(options(other, { publicUrl: NEW }))).rejects.toThrow(/Backup verification checks failed/);
    expect(existsSync(join(other, MOVE_STATE_FILE))).toBe(false);
    expect(JSON.parse(readFileSync(join(other, CONFIG_FILE), "utf8")).publicUrl).toBe(OLD);
  });

  it("checks the link lifetime and that an Installation Admin can finish, before anything changes", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker({ admins: 0 });
    const dir = installation();
    const capture = vi.spyOn(backup, "createBackup").mockResolvedValue("/x");
    for (const reenrollHours of [0, 200, Number.NaN]) {
      await expect(runMove(options(dir, { publicUrl: NEW, reenrollHours }))).rejects.toThrow(/--reenroll-hours must be/);
    }
    await expect(runMove(options(dir, { publicUrl: NEW }))).rejects.toThrow(/No Installation Admin is enabled/);
    expect(capture).not.toHaveBeenCalled();
    expect(existsSync(join(dir, MOVE_STATE_FILE))).toBe(false);
  });

  it("refuses to resume when the configuration or the ingress no longer matches the move", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker();
    const dir = installation({ ...base, publicUrl: "https://third.example.com" });
    writeFileSync(join(dir, MOVE_STATE_FILE), JSON.stringify({ from: OLD, fromIngress: "external", to: NEW, toIngress: "external", archive: "/a", startedAt: "x" }));
    await expect(runMove(options(dir))).rejects.toThrow(/names https:\/\/third\.example\.com .* goes from/);
    await expect(runMove(options(dir, { ingress: "public" }))).rejects.toThrow(/goes to the external ingress, not public/);
  });

  it("gives up a move: before the passkeys were removed nothing else is needed; after, the archive brings them back", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const dir = installation({ ...base, publicUrl: NEW });
    const state = { from: OLD, fromIngress: "external", to: NEW, toIngress: "external", archive: "/backups/pre-move.vltbak", startedAt: "x", previousConfig: base };
    writeFileSync(join(dir, MOVE_STATE_FILE), JSON.stringify(state));
    writeFileSync(join(dir, ".env"), renderEnv({ ...base, publicUrl: NEW }) + "MY_ADDITION=1\n");
    expect(await runMove(options(dir, { abandon: true }))).toBe(0);
    expect(JSON.parse(readFileSync(join(dir, CONFIG_FILE), "utf8"))).toEqual(base);
    expect(runningPublicUrl(join(dir, ".env"))).toBe(OLD);
    expect(existsSync(join(dir, MOVE_STATE_FILE))).toBe(false);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/No passkey was removed/));
    // After the passkeys were removed, the way back is the archive.
    writeFileSync(join(dir, MOVE_STATE_FILE), JSON.stringify({ ...state, passkeysRetiredAt: "2026-10-07T01:00:00Z" }));
    expect(await runMove(options(dir, { abandon: true }))).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/restore the archive the move took, \/backups\/pre-move\.vltbak/));
    await expect(runMove(options(dir, { abandon: true }))).rejects.toThrow(/No move in progress/);
  });

  it("finishes without asking for custody, and points failures at `varlatch move`", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const calls = fakeDocker({ adminEnrolled: true });
    const dir = installation();
    vi.spyOn(backup, "createBackup").mockResolvedValue("/a");
    vi.spyOn(backup, "verifyBackup").mockResolvedValue({} as never);
    const code = await runMove(options(dir, { publicUrl: NEW }));
    expect(count(calls, "custody")).toBe(0);
    expect(log).toHaveBeenCalledWith("  ✓ unchanged by a move (`varlatch setup` finishes any pending custody)");
    // The stand-in docker has no doctor: the health step fails, and says how to resume.
    expect(code).not.toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/The move finished with mandatory failures above; fix them and rerun `varlatch move`/));
  });

  it("shows varlatchd's reason when an admin command fails", async () => {
    fakeDocker();
    const dir = installation();
    expect(() => varlatchd(dir, ["admin", "reenroll", "--identity", "idn_typo"])).toThrow(/failed \(exit 1\): No person with identity idn_typo/);
  });

  it("refuses a damaged move state with a clear error, in move and in setup", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker();
    const dir = installation();
    for (const bad of ["{\"from\": \"https://old", "{}", "null"]) {
      writeFileSync(join(dir, MOVE_STATE_FILE), bad);
      await expect(runMove(options(dir))).rejects.toThrow(/varlatch-move\.json is unreadable, so the move's progress is unknown\. Nothing was changed/);
      await expect(runSetup({ dir, noWait: true, enrollTimeoutMs: 0, attest: false })).rejects.toThrow(/is unreadable/);
    }
  });

  it("changes nothing when the operator does not confirm", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const calls = fakeDocker();
    const dir = installation();
    const capture = vi.spyOn(backup, "createBackup").mockResolvedValue("/x");
    expect(process.stdin.isTTY).toBeFalsy(); // as in CI and under an agent
    await expect(runMove(options(dir, { publicUrl: NEW, yes: false }))).rejects.toThrow(/Not a terminal: pass --yes/);
    expect(capture).not.toHaveBeenCalled();
    expect(existsSync(join(dir, MOVE_STATE_FILE))).toBe(false);
    expect(JSON.parse(readFileSync(join(dir, CONFIG_FILE), "utf8")).publicUrl).toBe(OLD);
    expect(count(calls, "public-url-changed")).toBe(0);
  });

  it("refuses an installation setup does not manage, and one whose varlatchd runs elsewhere", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    fakeDocker();
    const bare = mkdtempSync(join(tmpdir(), "move-bare-"));
    await expect(runMove(options(bare, { publicUrl: NEW }))).rejects.toThrow(/No varlatch-install\.json/);
    const drifted = installation({ ...base, publicUrl: "https://drifted.example.com" });
    await expect(runMove(options(drifted, { publicUrl: NEW }))).rejects.toThrow(/varlatchd runs at https:\/\/old\.example\.com/);
  });
});

describe("setup refuses an address edited into varlatch-install.json", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it("names the running address and the move command, before any Docker step but the version check", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const bin = mkdtempSync(join(tmpdir(), "setup-edit-bin-"));
    const calls = join(bin, "calls.log");
    writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$*" >> "${calls}"\n[ "$*" = "compose version --short" ] && echo 2.29.7 && exit 0\nexit 1\n`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    const dir = mkdtempSync(join(tmpdir(), "setup-edit-"));
    writeFileSync(join(dir, "docker-compose.yml"), "name: vltest\nservices: {}\n");
    writeFileSync(join(dir, ".env"), renderEnv(base), { mode: 0o600 });
    writeFileSync(join(dir, CONFIG_FILE), JSON.stringify({ ...base, publicUrl: NEW }) + "\n");
    await expect(runSetup({ dir, noWait: true, enrollTimeoutMs: 0, attest: false })).rejects.toThrow(
      `varlatch-install.json names ${NEW}, but this installation runs at ${OLD}. To move it, put ${OLD} back in varlatch-install.json and run \`varlatch move --public-url ${NEW}\`.`,
    );
    expect(readFileSync(calls, "utf8")).toBe("compose version --short\n");
    expect(runningPublicUrl(join(dir, ".env"))).toBe(OLD);
  });

  it("reads the running address only from a setup-managed .env", () => {
    const dir = mkdtempSync(join(tmpdir(), "setup-env-"));
    expect(runningPublicUrl(join(dir, ".env"))).toBeNull();
    writeFileSync(join(dir, ".env"), "VARLATCH_PUBLIC_URL=https://hand.example.com\n");
    expect(runningPublicUrl(join(dir, ".env"))).toBeNull();
    writeFileSync(join(dir, ".env"), renderEnv({ ...base, publicUrl: "" }));
    expect(runningPublicUrl(join(dir, ".env"))).toBeNull();
  });
});
