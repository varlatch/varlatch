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
node scripts/conformance/run.mjs --target ts-source --cli 0.22.0   # a released CLI, verified first
```

A run is as heavy as the old `ci-e2e.sh`: a Compose stack built from source
and a headless Chromium. Check `free -g` first, and do not run it next to
`pnpm verify` or another stack.

## Pieces

| File | What it is |
| --- | --- |
| `run.mjs` | The runner: prepares the clients, starts the target, runs the suites of `plan.mjs` in order, paces them, collects results, judges the run against the inventory, removes the target. |
| `inventory.json` | Every check a run must account for: its suite, kind, title, the CLI feature it exercises and, for ts-stack checks, its replacement. Each suite's script and the capabilities it needs. Each CLI feature, with the CHANGELOG entry that introduced it. |
| `clients.json` | The released CLIs a run can select, pinned by version, release commit and hash, and the pinned cosign that verifies them. |
| `clients.mjs` | Downloads and verifies a pinned CLI; bundles `packages/sdk` for the sdk suite. |
| `plan.mjs` | The order of the suites and how each gets its arguments. |
| `suite-kit.mjs` | What a suite imports: the result reporter, the CLI under test, target operations. |
| `target-op.mjs` | One target operation, run by a suite as a subprocess. |
| `targets/` | Target adapters (`ts-source`) and the registry. |
| `suites/` | Suites that were inline shell in the old `ci-e2e.sh` (reconcile, doctor, Convex down, CLI download, server logs), and the client suites: the CLI's compatibility core, `varlatch mcp`, and the sdk smoke. |
| `lib/` | The runner's pure logic: result lines, inventory rules, the request-log check, the client pins. |
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
  a check whose feature names the version that introduced it
  (`introducedIn`), never for a compatibility-core feature, and only when
  the CLI's verified version is older (see [Clients](#clients));
- an `ERROR` line, a `FAIL` line that names no check, a suite that exits
  non-zero without a failed check, a suite that runs longer than 30 minutes,
  or a setup step that fails. An error is never a skip.

A suite whose `needs` the target lacks is not started; its checks are
reported not applicable, which fails the run unless they are ts-stack checks.

Adding a check: give it an ID that starts with its suite's name, write it in
the suite, and add it to `inventory.json`. `pnpm test:conformance` fails
until the two agree. Check IDs are stable: other records will name them. A
check that exercises a CLI feature names it (`"feature"`); see below.

## The target contract

A target adapter (`targets/<name>.mjs`, registered in `targets/index.mjs`)
implements these operations:

| Operation | Gives |
| --- | --- |
| `up` / `down` | a fresh installation on free loopback ports; `up` hands its state to `onState` before it creates anything, so a cancelled start can be removed; `down` removes all of it |
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
`--cli source` is `apps/cli/dist/varlatch.cjs`), its verified version in
`VARLATCH_CLI_VERSION` (empty for `source`), the sdk bundle in
`VARLATCH_SDK`, their own name in `CONFORMANCE_SUITE`, and the target's state
in `CONFORMANCE_TARGET_STATE`, which `target-op.mjs` reads.

### Targets

- `ts-source`: the TypeScript stack built from this checkout, as a
  disposable Compose project. It has every capability.

Released TypeScript stacks, expectations per target and the gate mode for
ADR-0059's acceptance gates come later in step 2.

## Clients

`--cli` chooses the CLI under test: `source` (built from this checkout) or a
released TypeScript CLI pinned in `clients.json` by version, release commit
and the hash of `varlatch-cli-<version>.cjs`, never "latest". The pins now
are 0.21.0 and 0.22.0; a later release is added by hand (its commit from
`gh api repos/varlatch/varlatch/commits/v<V> --jq .sha`, its hash from the
verified `SHA256SUMS`).

Before the target starts, a pinned CLI is downloaded from its GitHub release
into a new, empty directory and verified as
`docs/operations/verify-release.md` says. Any failure stops the run:

1. cosign verifies `SHA256SUMS` with `SHA256SUMS.sigstore.json` against the
   release's own identity
   (`.github/workflows/release.yml@refs/tags/v<version>` of the pinned
   repository) and GitHub's OIDC issuer. cosign is the release binary
   `clients.json` pins by version and hash (2.6.5, linux x64 and arm64),
   checked by hash on every use and kept in `~/.cache/varlatch-conformance`
   (`CONFORMANCE_CACHE_DIR` moves it);
2. `SHA256SUMS` lists the CLI asset exactly once, with the hash of the
   download, and that hash is the one `clients.json` pins;
3. `node varlatch-cli-<version>.cjs --version` reports the requested version.

The report records the CLI's version, commit, hash and how it was verified.

`packages/sdk` reaches users inside the CLI, so the sdk suite drives the sdk
from the same source as the CLI under test: bundled from the pinned
release's commit (fetched by hash when a shallow checkout lacks it, as
`apps/cli/test/controlCli.ts` builds the 0.13.0 CLI), or from this checkout
for `--cli source`. The report records the bundle's hash.

### Features, groups and the compatibility core

Each check that exercises a CLI feature names it in the inventory
(`"feature"`). A feature cites the CHANGELOG entry that introduced it
(`changelog: { release, quote }`; `pnpm test:conformance` checks that the
release's section says it) and is one of:

- **the compatibility core** (`"core": true`): token sign-in, `whoami`,
  `env list`, `run`, `run --export-context`, `types` in TypeScript and
  Python, browser and device sign-in. Never version-gated: every pinned CLI
  must run and pass it;
- **version-gated** (`introducedIn`, the cited release). A suite runs the
  feature's checks as one group behind `kit.supports("<feature>")`. With a
  CLI older than the feature, that call reports each of the group's checks
  `PREDATES-CLI` and the suite skips the group; the rest of the suite runs.
  The runner accepts the result only after comparing the CLI's verified
  version with the inventory itself. `pnpm test:conformance` checks that
  every version-gated feature is gated in each suite that has its checks.

An old CLI failing a check whose feature it already had is a finding, not a
reason to gate the check.
