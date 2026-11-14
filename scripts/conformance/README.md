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
node scripts/conformance/run.mjs --target ts-release:0.22.0 --cli source   # a signed release, verified, pulled by digest
```

A run is as heavy as the old `ci-e2e.sh`: a Compose stack built from source
and a headless Chromium. Check `free -g` first, and do not run it next to
`pnpm verify` or another stack.

## Pieces

| File | What it is |
| --- | --- |
| `run.mjs` | The runner: prepares the clients, starts the target, runs the suites of `plan.mjs` in order, paces them, collects results, judges the run against the inventory and the target's expected failures (and, with `--gate`, the gate), removes the target. |
| `inventory.json` | Every check a run must account for: its suite, kind, title, the CLI feature it exercises and, for ts-stack checks, its replacement. Each suite's script and the capabilities it needs. Each CLI feature, with the CHANGELOG entry that introduced it. The external suites the runner does not run, with their replacements. |
| `expect/` | Expected failures, one file per target: `expect/<target name>.json`. |
| `expect-check.mjs` | CI's check that a pull request adds no expected failure without the `conformance-regression` label. |
| `source-images.mjs` | Builds the `ts-source` images once, for several runs to share (the weekly matrix). |
| `clients.json` | The released CLIs a run can select, pinned by version, release commit and hash, and the pinned cosign that verifies them. |
| `clients.mjs` | Downloads and verifies a pinned CLI; bundles `packages/sdk` for the sdk suite. |
| `plan.mjs` | The order of the suites and how each gets its arguments. |
| `suite-kit.mjs` | What a suite imports: the result reporter, the CLI under test, target operations. |
| `target-op.mjs` | One target operation, run by a suite as a subprocess. |
| `targets/` | Target adapters (`ts-source`, `ts-release`, the `go-binary` stub; the first two share `compose-stack.mjs`) and the registry. |
| `suites/` | Suites that were inline shell in the old `ci-e2e.sh` (reconcile, doctor, Convex down, CLI download, server logs), and the client suites: the CLI's compatibility core, `varlatch mcp`, and the sdk smoke. |
| `lib/` | The runner's pure logic: result lines, inventory rules, the request-log check, the client pins, release verification, expected failures, gate mode. |
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
when every report passes. Mixed results for one check (a `FAIL` with a
`PASS`, an `N/A` or a `PREDATES-CLI`) fail it as inconsistent reporting,
which no expected failure covers.

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
- a failed check, unless the target's expectations list it (see
  [Expected failures](#expected-failures)); an expected failure that passes;
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
  disposable Compose project. It has every capability. With
  `CONFORMANCE_SOURCE_IMAGES=<tag>` it uses images `source-images.mjs <tag>`
  built earlier instead of building. It refuses them, and the run fails
  before anything starts, unless their label names the checkout's own
  commit (`git rev-parse HEAD`) and the checkout is exactly that commit: a
  changed tracked file or an untracked file that git does not ignore would
  be in a build from this checkout but is not in the images.
  `source-images.mjs` refuses such a checkout too, so the label is true.
  The run fails rather than building instead, since the variable says the
  images come from elsewhere; unset it to build from the checkout.
- `ts-release:<version>`: a released TypeScript stack, from the release's
  own compose bundle (`varlatch-compose-<version>.tar.gz`) with every image
  pulled by the digest `varlatch-release.json` pins. Nothing is built. The
  bundle's Compose file is the canonical one with each `build:` replaced by
  its digest-pinned image, so the stack is laid out as `ts-source`'s is:
  the same services, the admin CLI inside the varlatchd image
  (`node dist/cli.js admin`), the same ports and environment, the same
  bootstrap and seed. It has every capability, through the same operations
  (`targets/compose-stack.mjs`). The suites are this checkout's.
- `go-binary:<path>`: the Go server. A stub that fails with "not built yet"
  until ADR-0059 step 3 writes the server and its adapter.

Before a `ts-release` target starts, the release is verified as
`docs/operations/verify-release.md` says, and any failure stops the run:

1. only a signed release can be selected: 0.15.1 or later. 0.15.0 and
   earlier were published unsigned and are refused;
2. cosign (pinned in `clients.json`, checked by hash) verifies `SHA256SUMS`
   with `SHA256SUMS.sigstore.json` against
   `.github/workflows/release.yml@refs/tags/v<version>` of the pinned
   repository and GitHub's OIDC issuer;
3. `SHA256SUMS` lists the bundle and `varlatch-release.json` each exactly
   once, with the hash of the download;
4. the manifest is for `<version>` and pins every image by digest; the
   bundle holds only regular files and directories under
   `varlatch-<version>/` (checked before it is extracted), and its copy of
   the manifest is the same bytes;
5. cosign verifies each Varlatch image (varlatchd, varlatch-web,
   convex-deploy) by its digest, for the same identity, with the signatures
   in `ghcr.io/varlatch/varlatch-signatures` (`clients.json`
   `imageSignatures`);
6. the bundle's Compose file, as `docker compose config` resolves it, runs
   only images the manifest pins, by digest, and builds nothing.

The report's `targetDetails.release` records the verified hashes of
`SHA256SUMS` and each asset, and every image digest with how it was
verified. Third-party images (PostgreSQL, the Convex backend) are pinned by
digest in the signed manifest; they have no signature of their own.

## Expected failures

`expect/<target name>.json` lists the checks a target is known to fail:

```json
{
  "schema": 1,
  "expected": {
    "ts-release:0.22.0": {
      "*": {
        "<check id>": { "reason": "<why it fails>", "removedBy": "<the step that removes it>" }
      }
    }
  }
}
```

Entries are keyed by target (`ts-source`, `ts-release:<version>`,
`go-binary` whatever its path), then by client (`source`, a version
`clients.json` pins, or `*` for every CLI), then by check ID. In a run:

- an expected check that fails by its own `FAIL` line is reported
  `EXPECTED-FAIL`, with its reason and the step that removes it, in the
  output and the report. It is never hidden, and it does not fail the run;
- an expected check that fails any other way still fails the run: it did
  not report, a conformance check reported not applicable, a
  `PREDATES-CLI` result the runner cannot confirm, or inconsistent results.
  An expectation covers a known wrong answer, never a missing one;
- an expected check that passes fails the run: remove its entry;
- an expected check that did not apply or predates the CLI is listed as
  not exercised;
- an entry covers only that check's failure. A run-level problem (an
  `ERROR`, a setup step that failed) is never expected.

The list only shrinks by default. `.github/workflows/conformance-expect.yml`
runs `expect-check.mjs` on a pull request that changes it: it compares the
files at the pull request's head with its merge base, and fails when the
head adds an entry (moving one to another client or target counts as
adding one), unless the pull request carries the `conformance-regression`
label. The same label is needed to delete or rename a target's file (or
the whole directory), the checker, a module it imports, `inventory.json` or
`clients.json`. Adding or removing the label runs the check again.

The workflow runs on `pull_request_target`: its definition and the checker
come from the base branch, so a pull request can change neither the check
nor the checker that judges it. It checks out the base commit only, fetches
the pull request's head as git objects, and reads the head's files with
`git show` as JSON; nothing from the head is checked out, installed,
imported or executed, the token is read-only and no secret is used. A base
without the checker fails the job. A push to `main` validates the files it
lands. For `go-binary`
the file starts, in step 3, as the conformance checks the Go server does
not pass yet, and is the step 4 parity tracker.

## External suites

The lifecycle and installer suites (`scripts/test-*.mjs`: setup, adopt,
upgrade, backup, move, ingress, sidecar, installers, the manual tailnet and
Coolify checks) test the TypeScript installation and do not run under the
runner. `inventory.json` lists each in `externalSuites`, with its
`replacement` the way a ts-stack check names one: the Go counterparts come
in ADR-0059 steps 4, 6 and 7, so each is `{ "open": "<the step>" }` today.
`pnpm test:conformance` fails when a `scripts/test-*.mjs` is not listed.

## Gate mode

`--gate` judges a run as ADR-0059's G1 (parity) and G2 (old clients) are
judged:

```sh
node scripts/conformance/run.mjs --target go-binary:<path> --cli source \
  --gate --walkthrough docs/evidence/<walkthrough record> [--recent-cli-report <report.json>]
```

Besides passing as an ordinary run, a gate run must have:

- no expected failure in force for its target and client;
- every ts-stack check's replacement, and every external suite's, present
  and passing: a replacement check that passed in this run, or `none`
  with its reason. An `open` replacement fails the gate;
- the browser-walkthrough evidence file (G1's full browser walkthrough,
  done by hand and kept under `docs/evidence/`), named with
  `--walkthrough`. The run stops before the target starts when it is
  missing; the report records its path and hash;
- every suite (no `--suite`);
- the target's record of what it ran (`implementation` in the report):
  for `ts-source` the commit, whether the tree was exactly that commit, and
  the image IDs the stack ran; for `ts-release` the version, the hashes of
  the signed `SHA256SUMS` and each asset, each image digest and the image
  IDs; for `go-binary` the binary's sha256 (not its path);
- a CLI recent enough that nothing reports `PREDATES-CLI`, or, for a run
  with an older CLI (G2), `--recent-cli-report` naming the report of a run
  with a CLI that predates nothing. That report is judged again from
  scratch, never by its own `ok` or `gate` fields: the same target and the
  same `implementation`, a complete run with every inventory check present
  once and passing (not applicable only for a ts-stack check), no problem,
  no expected failure, a CLI that predates no feature of the current
  inventory, the same walkthrough evidence, and the gate's replacement
  rules.

Image IDs match only for runs that ran the same images: the cells of one
matrix run, which share the prebuilt images, not two separate builds.

Gate evidence comes from CI: the reports of one workflow run, downloaded
from that run's artifacts (`gh run download <run id>`), with the run named
in the gate record. A report is a JSON file anyone can write, so a local
report, or one from another run, is not evidence. The runner could instead
run the recent CLI itself in the same invocation, but that doubles a gate
run's length and needs a second stack; taking both reports from one
workflow run gives the same assurance.

The report's `gate` holds the verdict and each problem; a gate failure
prints `CONFORMANCE GATE FAILED` and exits 1. Gate mode fails today on every
target: the realtime checks' replacements (G11's checks, step 3), doctor's
(step 6) and every external suite's are still open. `test/gate.test.mjs`
shows this on the inventory as it stands.

## The weekly matrix

`.github/workflows/conformance.yml` runs weekly and on manual dispatch
(`gh workflow run conformance.yml --ref <branch>`), on GitHub-hosted
runners with only the read-only job token:

| | CLI `source` | CLI `0.21.0` | CLI `0.22.0` |
| --- | --- | --- | --- |
| `ts-source` | ✓ | ✓ | ✓ |
| `ts-release:0.22.0` | ✓ | ✓ | ✓ |

The `images` job builds the source images once (`source-images.mjs`) and
passes them to the `ts-source` cells as an artifact. Each cell is its own
job, with its own stack on its own free ports, at most three at a time and
60 minutes each, and uploads its `conformance-report.json`
(`conformance-report-<target>-cli-<cli>`, tokens masked as in the logs). A
`go-binary` row joins in step 3.

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
