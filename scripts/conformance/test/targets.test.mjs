// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { adapterProblems, loadTarget, TARGET_NAMES } from "../targets/index.mjs";

const file = JSON.parse(readFileSync(new URL("../targets/capabilities.json", import.meta.url), "utf8"));
const fn = () => {};
/** An adapter with every required operation and the given optional ones. */
const adapter = (...ops) =>
  Object.fromEntries(["up", "down", "origin", "bootstrap", "recover", "restart", "logs", "requestLog", ...ops].map((op) => [op, fn]));

test("a target's capabilities come from capabilities.json alone, and every adapter implements what it lists", async () => {
  for (const [name, spec] of [["ts-source", "ts-source"], ["ts-release", "ts-release:0.22.0"], ["go-binary", "go-binary:/opt/varlatchd"]]) {
    assert.ok(TARGET_NAMES.includes(name));
    const loaded = await loadTarget(spec);
    assert.deepEqual(loaded.capabilities, file[name], name);
    assert.equal(loaded.target.capabilities, undefined, `${name} declares no capabilities of its own`);
  }
});

test("an adapter that lacks a listed capability's operation is refused", () => {
  const caps = file["ts-source"];
  assert.deepEqual(adapterProblems("ts-source", adapter("probe", "maintenance", "serveCli", "tsStack", "webhookReceiver"), caps), []);
  // maintenance listed, the adapter without its operation.
  assert.match(adapterProblems("ts-source", adapter("probe", "serveCli", "tsStack", "webhookReceiver"), caps).join("\n"), /gives target ts-source maintenance, but its adapter has no maintenance operation/);
  // webhook-receiver listed, the adapter without webhookReceiver.
  assert.match(adapterProblems("ts-source", adapter("probe", "maintenance", "serveCli", "tsStack"), caps).join("\n"), /webhook-receiver, but its adapter has no webhookReceiver operation/);
  // go-server listed for a target whose adapter has no goServer.
  assert.match(adapterProblems("ts-source", adapter("probe", "maintenance", "serveCli", "tsStack", "webhookReceiver"), [...caps, "go-server"]).join("\n"), /go-server, but its adapter has no goServer operation/);
  assert.match(adapterProblems("go-binary", adapter("probe", "goServer"), ["no-such-capability"]).join("\n"), /unknown capability no-such-capability/);
});

test("an adapter that declares capabilities of its own, missing or extra, is refused", () => {
  const caps = file["ts-source"];
  const ops = adapter("probe", "maintenance", "serveCli", "tsStack", "goServer");
  // Extra: go-server added in the adapter only; missing: maintenance taken out there.
  assert.match(adapterProblems("ts-source", { ...ops, capabilities: [...caps, "go-server"] }, caps).join("\n"), /declares its own capabilities/);
  assert.match(adapterProblems("ts-source", { ...ops, capabilities: caps.filter((c) => c !== "maintenance") }, caps).join("\n"), /declares its own capabilities/);
  // Even one equal to the file's: there is a single source.
  assert.match(adapterProblems("ts-source", { ...ops, capabilities: [...caps] }, caps).join("\n"), /declares its own capabilities/);
  assert.match(adapterProblems("ts-source", { up: fn }, []).join("\n"), /lacks required operations: down, origin/);
});
