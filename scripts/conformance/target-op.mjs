#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * One operation of the target under test, for a suite (suite-kit.mjs calls
 * it). The runner names the target's state file in CONFORMANCE_TARGET_STATE.
 *
 *   target-op.mjs origin
 *   target-op.mjs bootstrap                          the admin CLI's output
 *   target-op.mjs recover <identity> [--cli-credential]
 *   target-op.mjs restart
 *   target-op.mjs logs                               the server's logs
 *   target-op.mjs request-log                        one JSON record per line
 *   target-op.mjs probe <name> [args...]             JSON
 *   target-op.mjs maintenance <ttl ms>
 *   target-op.mjs serve-cli on|off
 *   target-op.mjs ts-stack compose <args...> | compose-env
 *
 * An optional operation the target does not have exits 3.
 */
import { readFileSync } from "node:fs";
import { loadTarget } from "./targets/index.mjs";

const [operation, ...args] = process.argv.slice(2);
const stateFile = process.env.CONFORMANCE_TARGET_STATE;
if (!stateFile) {
  console.error("CONFORMANCE_TARGET_STATE is not set: target operations run under scripts/conformance/run.mjs");
  process.exit(64);
}
const state = JSON.parse(readFileSync(stateFile, "utf8"));
const { name, target, capabilities } = await loadTarget(state.target);

const needs = (capability) => {
  if (!capabilities.includes(capability)) {
    console.error(`target ${name} has no ${capability} capability`);
    process.exit(3);
  }
};
const print = (text) => process.stdout.write(text.endsWith("\n") || text === "" ? text : `${text}\n`);

switch (operation) {
  case "origin":
    print(target.origin(state));
    break;
  case "bootstrap":
    print(await target.bootstrap(state));
    break;
  case "recover":
    if (!args[0]) throw new Error("recover <identity> [--cli-credential]");
    print(await target.recover(state, args[0], { cliCredential: args.includes("--cli-credential") }));
    break;
  case "restart":
    await target.restart(state);
    break;
  case "logs":
    print(await target.logs(state));
    break;
  case "request-log":
    print((await target.requestLog(state)).map((r) => JSON.stringify(r)).join("\n"));
    break;
  case "probe":
    needs(`probe:${args[0]}`);
    print(JSON.stringify(await target.probe(state, ...args)));
    break;
  case "maintenance":
    needs("maintenance");
    await target.maintenance(state, Number(args[0]));
    break;
  case "serve-cli":
    needs("serve-cli");
    if (!["on", "off"].includes(args[0])) throw new Error("serve-cli on|off");
    await target.serveCli(state, args[0] === "on");
    break;
  case "ts-stack": {
    needs("ts-stack");
    const r = await target.tsStack(state, ...args);
    process.stdout.write(r.stdout);
    process.stderr.write(r.stderr);
    process.exit(r.status);
    break;
  }
  default:
    console.error(`unknown operation ${operation ?? "(none)"}`);
    process.exit(64);
}
