// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { checkProbe } from "../scripts/e2e-proxy-probe.mjs";

/** The e2e proxy probe's checker: only the specific outcome proves the behaviour. */

const created = { status: 201, code: null, cap: null };
const capped = { status: 429, code: "RATE_LIMITED", cap: "pending-per-client" };
const generalLimit = { status: 429, code: "PERMISSION_DENIED", cap: null };
const caller = "172.27.0.1";
const nginx = ["172.27.0.5"];
const tenRows = (ip: string) => Array.from({ length: 10 }, () => ({ requesterIp: ip }));
const proven = { responses: [...Array(10).fill(created), capped, capped], rows: tenRows(caller), nginxIps: nginx };

describe("checkProbe", () => {
  it("passes ten new sign-ins, then the per-client pending cap, all recorded as the caller", () => {
    expect(checkProbe(proven)).toEqual([]);
  });

  it("fails when every request met the general request window (no sign-in created)", () => {
    expect(checkProbe({ ...proven, responses: Array(12).fill(generalLimit), rows: [] }).length).toBeGreaterThan(0);
  });

  it("fails when only rows from earlier suites exist (the probe's own name finds nothing)", () => {
    expect(checkProbe({ ...proven, rows: [] })).toContain("expected 10 sign-ins under the probe's name, found 0");
  });

  it("fails on another refusal in place of the pending cap: the general window, the total cap, a server error", () => {
    for (const other of [generalLimit, { status: 429, code: "RATE_LIMITED", cap: "pending-total" }, { status: 503, code: "MAINTENANCE", cap: null }]) {
      expect(checkProbe({ ...proven, responses: [...Array(10).fill(created), other, capped] }).length).toBeGreaterThan(0);
    }
  });

  it("fails when a forged address or nginx is recorded, or the requests split across addresses", () => {
    expect(checkProbe({ ...proven, rows: tenRows("198.18.0.3") }).join()).toMatch(/forged/);
    expect(checkProbe({ ...proven, rows: tenRows("172.27.0.5") }).join()).toMatch(/nginx/);
    expect(checkProbe({ ...proven, rows: [...tenRows(caller).slice(0, 9), { requesterIp: "198.18.0.10" }] }).join()).toMatch(/one requester/);
  });

  it("fails when the cap is reached early or never (a wrong starting count)", () => {
    expect(checkProbe({ ...proven, responses: [...Array(9).fill(created), capped, capped, capped] }).length).toBeGreaterThan(0);
    expect(checkProbe({ ...proven, responses: Array(12).fill(created) }).length).toBeGreaterThan(0);
  });
});
