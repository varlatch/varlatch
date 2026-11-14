# Conformance harness

The end-to-end suites, run against a chosen server (a **target**) with a
chosen CLI, each check reporting under a stable ID. It is how the Go server
(ADR-0059) is shown to behave as the TypeScript one does, and it is what
`scripts/ci-e2e.sh` runs in CI today:

```sh
pnpm build
scripts/ci-e2e.sh                     # = node scripts/conformance/run.mjs --target ts-source --cli source
scripts/ci-e2e.sh --report out.json   # also write the report as JSON
scripts/ci-e2e.sh --suite values      # one suite (plus the setup it needs); a partial report
```

A run is as heavy as the old `ci-e2e.sh`: a Compose stack built from source
and a headless Chromium. Check `free -g` first, and do not run it next to
`pnpm verify` or another stack.

## Pieces

| File | What it is |
| --- | --- |
| `run.mjs` | The runner: starts the target, runs the suites of `plan.mjs` in order, paces them, collects results, judges the run against the inventory, removes the target. |
| `inventory.json` | Every check a run must account for: its suite, kind, title and, for ts-stack checks, its replacement. Each suite's script and the capabilities it needs. |
| `plan.mjs` | The order of the suites and how each gets its arguments. |
| `suite-kit.mjs` | What a suite imports: the result reporter, the CLI under test, target operations. |
| `target-op.mjs` | One target operation, run by a suite as a subprocess. |
| `targets/` | Target adapters (`ts-source`) and the registry. |
| `suites/` | Suites that were inline shell in the old `ci-e2e.sh` (reconcile, doctor, Convex down, CLI download, server logs). |
| `lib/` | The runner's pure logic: result lines, inventory rules, the request-log check. |
| `test/` | Unit tests: `pnpm test:conformance`. |

The runner and everything in this directory are Apache-2.0. The suites under
`apps/web/scripts/` and `services/varlatchd/scripts/` stay AGPL-3.0-or-later
in their own paths; the runner only starts them as processes and never
imports them.

## Results

A suite prints one line per check, through `suite-kit.mjs`:

```
PASS  [dashboard.csp-strict] the dashboard is served with a strict Content-Security-Policy, ...
FAIL  [values.grid-masks-secret] grid masks secret - detail
N/A  [<id>] why the check does not apply to this target
PREDATES-CLI  [<id>] the CLI under test is older than the feature
ERROR  a problem outside any one check
```

A check may report more than once (a loop over fixed cases); it passes only
when every report passes.

## The inventory is the gate

Every check has a **kind**:

- `conformance`: must run and pass on every target;
- `ts-stack`: about the TypeScript deployment itself (Convex, nginx,
  Compose). Not applicable on a target without the `ts-stack` capability.
  Each names its `replacement`: a conformance check ID in the inventory,
  `{ "none": "<why>" }`, or `{ "open": "<the step that writes it>" }`;
- `component`: tests this checkout's code, not the target (the enroll page
  against a stub server). Kept in the run, never counted as conformance.

A run fails on any of these:

- a check in the inventory that did not report;
- a reported check that is not in the inventory, or that another suite reported;
- a failed check;
- a conformance or component check reported not applicable;
- a `PREDATES-CLI` result the runner cannot confirm. It is accepted only for
  a check whose inventory entry names the version that introduced its
  feature (`introducedIn`), never for a compatibility-core check (`core`),
  and only when the CLI's verified version is older;
- an `ERROR` line, a `FAIL` line that names no check, a suite that exits
  non-zero without a failed check, a suite that runs longer than 30 minutes,
  or a setup step that fails. An error is never a skip.

A suite whose `needs` the target lacks is not started; its checks are
reported not applicable, which fails the run unless they are ts-stack checks.

Adding a check: give it an ID that starts with its suite's name, write it in
the suite, and add it to `inventory.json`. `pnpm test:conformance` fails
until the two agree. Check IDs are stable: other records will name them.

## The target contract

A target adapter (`targets/<name>.mjs`, registered in `targets/index.mjs`)
implements these operations:

| Operation | Gives |
| --- | --- |
| `up` / `down` | a fresh installation on free loopback ports; `down` removes all of it |
| `origin` | the dashboard origin the suites use (the TypeScript nginx; `varlatchd` itself in Go) |
| `bootstrap` | the first enrollment URL, as `varlatchd admin bootstrap` prints it |
| `recover <identity> [--cli-credential]` | an enrollment URL, or a CLI token on the last line, as `varlatchd admin recover` prints them |
| `restart` | the server restarts with its data kept |
| `logs` | the server's logs, for the no-secret-in-logs checks |
| `request-log` | one record per request the server answered: `{ client, method, path, status, completedAt, arrivedAt?, resolutionMs?, forwardedFor? }` |

The admin output format (an `http://…/enroll#…` URL on a line, the token as
the last line) is part of the contract.

`request-log` is required. Before each suite the runner waits until the
trailing request window has room (the server allows 600 requests per 60 s
per client, and every suite comes from one address). At the end it checks
that the server answered no 429 other than the proxy probe's expected
pending-cap answers: `POST /v1/auth/device`, while the proxy-probe suite ran,
and, where the target records the forwarded header, from one of the probe's
forged addresses. A suite too large for one window is split; the limit is
never raised.

Optional **capabilities**, each a named operation a suite asks for instead
of reaching into Compose or the database:

| Capability | Operation |
| --- | --- |
| `probe:audit-event-count` | `probe audit-event-count`: how many audit events the server holds |
| `probe:expire-pending-device-sign-ins` | `probe expire-pending-device-sign-ins`: no device sign-in is pending afterwards |
| `probe:device-sign-in-addresses` | `probe device-sign-in-addresses <name>`: `[{ "requesterIp": ... }]` for the sign-ins requested under that name |
| `probe:proxy-addresses` | `probe proxy-addresses`: the addresses of any proxy in front of the server (`[]` when none) |
| `maintenance` | `maintenance <ttl ms>`: the `503 MAINTENANCE` admission a restore uses, for a lease |
| `serve-cli` | `serve-cli on\|off`: the server serves the CLI and install scripts, or not (ADR-0058 Decision 3) |
| `ts-stack` | `ts-stack compose <args...>` and `ts-stack compose-env`: Compose control for the ts-stack checks |

A probe is a fixed, named read; a suite never sends SQL. A conformance check
that needs a capability the target lacks fails.

Suites get the CLI under test in `VARLATCH_CLI` (a script run with Node;
`--cli source` is `apps/cli/dist/varlatch.cjs`) and the target's state in
`CONFORMANCE_TARGET_STATE`, which `target-op.mjs` reads.

### Targets

- `ts-source`: the TypeScript stack built from this checkout, as a
  disposable Compose project. It has every capability.

Released TypeScript stacks, released CLIs, expectations per target and the
gate mode for ADR-0059's acceptance gates come later in step 2.
