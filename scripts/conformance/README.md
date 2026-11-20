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
scripts/ci-e2e.sh --shard 2/3         # the second of three shards (CI runs all three in parallel)
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
| `inventory.json` | Every check a run must account for: its suite, kind, title, the CLI feature it exercises and, for ts-stack checks, its replacement. Each suite's script, the capabilities it needs and the operations it needs. The named operations outside the OpenAPI document. Each CLI feature, with the CHANGELOG entry that introduced it. The external suites the runner does not run, with their replacements. |
| `expect/` | Expected failures and declared gaps (`lacks`), one file per target: `expect/<target name>.json`. |
| `expect-check.mjs` | CI's check that a pull request adds no expected failure and no gap without the `conformance-regression` label. |
| `lacks-probe.mjs` | Asks the target about each operation it declares it lacks (the stale-`lacks` probe). |
| `source-images.mjs` | Builds the `ts-source` images once, for several runs to share (the weekly matrix). |
| `clients.json` | The released CLIs a run can select, pinned by version, release commit and hash, and the pinned cosign that verifies them. |
| `clients.mjs` | Downloads and verifies a pinned CLI; bundles `packages/sdk` for the sdk suite. |
| `client-go.json` | The CLI features the Go CLI (`--cli go:<path>`) does not have yet, each with the slice that builds it: their checks report client-lacks (`lib/client-lacks.mjs`). |
| `plan.mjs` | The order of the suites and how each gets its arguments. |
| `shard.mjs`, `shard-weights.json` | `--shard <k>/<n>`: which suites each shard runs, balanced by each suite's measured seconds. |
| `suite-kit.mjs` | What a suite imports: the result reporter, the CLI under test, target operations. |
| `target-op.mjs` | One target operation, run by a suite as a subprocess. |
| `targets/` | Target adapters (`ts-source`, `ts-release`, `go-binary`, `go-container`; the first two share `compose-stack.mjs`, and `go-container` is `go-binary` with varlatchd in the single-container image, run with go-binary's capabilities and expectations), the registry, and each target's optional capabilities as data (`capabilities.json`). |
| `suites/` | Suites that were inline shell in the old `ci-e2e.sh` (reconcile, doctor, Convex down, CLI download, server logs), the client suites (the CLI's compatibility core, `varlatch mcp`, and the sdk smoke), G11's checks on the Go server's server-sent events (`realtime-events`), and the suites where the e2e suites cover nothing (Security Controls over the API, audit webhook delivery, the audit export, Sync Target delivery). |
| `lib/` | The runner's pure logic: result lines, inventory rules, operations and declared gaps, the request-log check, the client pins, release verification, expected failures, gate mode. |
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

One more result exists, which only the runner gives:
`TARGET-LACKS [<id>] the target lacks <operations>` (see
[Declared gaps](#declared-gaps)). A suite that prints it has made an error.

## The inventory is the gate

Every check has a **kind**:

- `conformance`: must run and pass on every target;
- `ts-stack`: about the TypeScript deployment itself (Convex, nginx,
  Compose). Not applicable on a target without the `ts-stack` capability.
  Each names its `replacement`: a conformance or go-server check ID in the
  inventory, `{ "none": "<why>" }`, or `{ "open": "<the step that writes
  it>" }`;
- `component`: tests this checkout's code, not the target (the enroll page
  against a stub server). Kept in the run, never counted as conformance;
- `go-server`: about a mechanism of the Go server that the TypeScript
  deployment has no counterpart of (its server-sent events, gate G11). Its
  suite needs the `go-server` capability; it is not applicable on a target
  without it, and must run and pass on one with it. A gate run on
  `go-binary` refuses it not applicable. Each is listed in the inventory's
  `goServerChecks` with why the TypeScript server cannot pass it, so making
  a check go-server is visible in review;
- `go-client`: about the Go CLI together with the TypeScript CLI, the
  hand-over of internal `docs/design/go-cli.md` (decision 11). Its suite
  says `"client": "go"` and holds only go-client checks. With `--cli
  go:<path>` the runner pairs the Go CLI with a TypeScript CLI
  (`--handover-cli source|<version>`, verified as `--cli` is; 0.22.0 by
  default) and hands its path to the suite (`VARLATCH_HANDOVER_CLI`,
  suite-kit's `handoverCliCommand`); the check must run and pass on every
  target. With a TypeScript CLI under test the suite is not started and its
  checks are not applicable, which a gate run accepts only then.

A run fails on any of these:

- a check in the inventory that did not report;
- a reported check that is not in the inventory, or that another suite reported;
- a failed check, unless the target's expectations list it (see
  [Expected failures](#expected-failures)); an expected failure that passes;
- a conformance or component check reported not applicable (a ts-stack or
  go-server check may be, and a go-client check when the CLI under test is
  not the Go CLI);
- a `PREDATES-CLI` result the runner cannot confirm. It is accepted only for
  a check whose feature names the version that introduced it
  (`introducedIn`), never for a compatibility-core feature, and only when
  the CLI's verified version is older (see [Clients](#clients));
- an `ERROR` line, a `FAIL` line that names no check, a suite that exits
  non-zero without a failed check, a suite that runs longer than 30 minutes,
  or a setup step that fails. An error is never a skip.

A suite whose `needs` the target lacks is not started; its checks are
reported not applicable, which fails the run unless they are ts-stack or
go-server checks.

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

### Shards

`--shard <k>/<n>` runs one of n parts of the plan against a server of its
own, so each part has the whole request window and the parts can run in
parallel (CI's `e2e` and `go-binary` jobs run three). `shard.mjs` assigns
every suite of the plan to exactly one shard, greedily, heaviest first, by
the seconds in `shard-weights.json` (measured from CI logs without the
request-budget waits; a suite not listed weighs 60 s), and keeps the plan's
order within a shard. A shard is a `--suite` selection: the `always` suites
and the setup still run, and the report and the expected failures cover
only the checks of the suites it selects, so each check and each expected
failure is judged in the one shard that owns its suite. The lacks probe asks
every shard's server. Two suites check the server itself and are in every
shard besides: `request-budget` (no unexpected 429 from this shard's
server) and `server-logs` (no seeded secret in its logs). `--shard 1/1` is a
full run; `--shard` with `--suite` or `--gate` is a usage error. Re-measure
the weights when a suite's time changes by a minute or more
(`test/shard.test.mjs` keeps the three-shard split within a minute).

Optional **capabilities**, each a named operation a suite asks for instead
of reaching into Compose or the database:

| Capability | Operation |
| --- | --- |
| `probe:audit-event-count` | `probe audit-event-count`: how many audit events the server holds |
| `probe:expire-pending-device-sign-ins` | `probe expire-pending-device-sign-ins`: no device sign-in is pending afterwards |
| `probe:device-sign-in-addresses` | `probe device-sign-in-addresses <name>`: `[{ "requesterIp": ... }]` for the sign-ins requested under that name |
| `probe:proxy-addresses` | `probe proxy-addresses`: the addresses of any proxy in front of the server (`[]` when none) |
| `probe:deletion-due` | `probe deletion-due <odl_...>`: an Organization's open deletion request made due now (as if scheduled 40 days ago, due a second ago), so the deletion loop's next pass, within a minute, runs it (ADR-0051) |
| `probe:sync-repair-due` | `probe sync-repair-due <target id>`: the Sync Target's last repair pass moved hours into the past and nothing else changed, so that only the periodic repair schedule makes it due; answers `{"needsSync", "nextAttemptAt"}`, which it leaves as they are (the TypeScript stacks: SQL in the database container; go-binary: the conformance build's probe) |
| `probe:github-app-pending-expired` | `probe github-app-pending-expired <ghr_...>`: a pending GitHub App conversion's hour over (converted two hours ago, expired a second ago), so the registration sweep's next pass, within a minute, ends it. The conversion's material is written once by a trigger, which the probe sets aside for this one update (the TypeScript stacks: the superuser's replica role in one transaction; go-binary: the trigger dropped and created again from its own SQL in one transaction, in the conformance build's probe) |
| `probe:audit-export-drain-due` | `probe audit-export-drain-due <org_...>`: a deleted Organization's draining audit export past its deadline (a second ago), so the deletion loop's next pass, within a minute, abandons it (ADR-0056 Decision 10; the TypeScript stacks: SQL in the database container; go-binary: the conformance build's probe) |
| `probe:deletion-teardown` | `probe deletion-teardown <org_...>`: read only, the Organization's Sync Targets, Platform Connections and webhooks, each `{ id, revoked }`, and its GitHub Apps, each `{ id, removed, keyKept }`, as stored, also once the Organization is deleted (the TypeScript stacks: SQL in the database container; go-binary: the conformance build's probe) |
| `probe:sync-runs` | `probe sync-runs <snt_...>`: read only, `{ runs, generations }`, the Sync Target's runs in progress (its `sync_runs` rows, by generation; a run deletes its own when it ends, fenced or not), so a suite can follow one run by its generation and wait for it to finish (the TypeScript stacks: SQL in the database container; go-binary: the conformance build's probe) |
| `probe:sync-trigger-position` | `probe sync-trigger-position`: `{"cursor", "latest"}`, where the converge engine's trigger scan stands (`sync_cursor.cursor_order`) and the last audit event it reads (not `sync.*`): a value change reaches the engine once the cursor passes its event (the TypeScript stacks: SQL in the database container; go-binary: the conformance build's probe) |
| `maintenance` | `maintenance <ttl ms>`: the `503 MAINTENANCE` admission a restore uses, for a lease |
| `serve-cli` | `serve-cli on\|off`: the server serves the CLI and install scripts, or not (ADR-0058 Decision 3) |
| `ts-stack` | `ts-stack compose <args...>` and `ts-stack compose-env`: Compose control for the ts-stack checks |
| `webhook-receiver` | `webhook-receiver url\|requests`: a local endpoint the server reaches on its own loopback (`url` starts it when it is not running and answers the URL to register; `requests` what it recorded: `[{ at, method, target, contentType, signature, body, status }]`); a path with a segment `fail-<n>` answers 500 to its first n requests. The target's outbound allow list opens that port and nothing else private (the TypeScript stacks run it inside varlatchd's container with `VARLATCH_OUTBOUND_ALLOW`; go-binary as a process of its own with `outbound_allow`) |
| `host-admin` | `host-admin audit-export <args...>`: one `varlatchd admin audit-export` host command, run as the operator runs it (the TypeScript stacks: in the container; go-binary: through the daemon's control socket). JSON: `{ status, stdout, stderr }`, whatever the status, so a suite can check a refusal |
| `oidc-issuer` | `oidc-issuer start`: a local OIDC issuer over https (lib/oidc-issuer.cjs) at `https://127.0.0.1:<port>`, its self-signed certificate made when the target starts and trusted by its server (the TypeScript stacks: `NODE_EXTRA_CA_CERTS`, the issuer inside varlatchd's container; go-binary: `SSL_CERT_FILE`, the issuer on a host loopback port). The allow list opens its port. JSON `{ issuer }`. `keys <json>` sets its JWKS (`{ keys }`); `counts` answers `{ discovery, jwks }`, its documents fetched so far |
| `platform-fakes` | `platform-fakes start`: fake GitHub, Coolify and Convex services (lib/platform-fakes.cjs) the server's sync engine reaches under the platforms' own host names: `api.github.com`, `coolify.conformance.test`, `convex.conformance.test`, over https with a certificate made when the target starts and trusted by its server. The TypeScript stacks run them inside varlatchd's container on its loopback port 443, with `extra_hosts` leading the names there and `NODE_EXTRA_CA_CERTS`; go-binary runs them on a host loopback port, which the conformance build's host override (`VARLATCH_CONFORMANCE_OUTBOUND_HOSTS`, never in a release) leads the names to, with `SSL_CERT_FILE`. Either way the outbound allow list is what lets the fakes' address through. JSON `{ github, coolify, convex }` (the base identities). `state` answers what they hold and every request they saw (`{ github, coolify, running, convex, requests, githubApps, codesUsed, mints }`, credentials, keys and sealed values left out); `drift <resource> <key> <value>` changes a Coolify value behind Varlatch's back; `github <json>` sets up the fake GitHub's App side (a manifest code the conversion hands an App over for, an App registered directly with its private key answered, its keys added or deleted, an installation), which then answers the App's JWT, its installations and installation tokens narrowed to repositories and permissions as GitHub does |
| `object-store` | `object-store start`: a local S3 server with Object Lock (MinIO, pinned by digest), running until `down` removes it by its name. JSON: `{ endpoint, hostEndpoint, region, accessKeyId, secretAccessKey }`, the endpoint the server reaches it at and the one the suite does. The target's outbound allow list opens it and nothing else private (the TypeScript stacks: an alias on the Compose project's network; go-binary: a loopback port) |
| `go-server` | `go-server fixture <name> [args...]`: the Go server's fixtures for its go-server checks (organizations, people, browser sessions, audit events, a removal), written while the `/v1` writes that would make them are not built (ADR-0059 step 4); JSON |

`targets/capabilities.json` is the only source of a target's capabilities:
`loadTarget` reads them from it, and refuses an adapter that declares a
list of its own, or that lacks the operation a listed capability needs
(`probe:<name>` the `probe` operation; `maintenance`, `serveCli`,
`tsStack`, `goServer`). So what the merge-base check judges is what the
runner uses. Every target is seeded the same way, through `/v1`.

A probe is a fixed, named read; a suite never sends SQL. A conformance check
that needs a capability the target lacks fails.

Suites get the CLI under test in `VARLATCH_CLI` (a script run with Node;
`--cli source` is `apps/cli/dist/varlatch.cjs`; with `VARLATCH_CLI_NATIVE=1`
a native binary, the Go CLI), and run it with suite-kit's `cliCommand(args)`,
which gives `[node, cli, ...args]` or `[cli, args]`; its verified version in
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
- `go-binary:<path>`: the Go `varlatchd` at `<path>`, run as a process
  (`targets/go-binary.mjs`). `up` makes a fresh installation in a new
  temporary directory: the data directory, a random Root KEK (mode 0600),
  `varlatchd.conf` listening on a free loopback port with the access log
  in the directory, and the server's own output; it starts
  `varlatchd serve` and waits for `/readyz`. The origin is `varlatchd`
  itself (it serves the dashboard and the API), `restart` stops it with
  SIGTERM and serves again on the same data, `logs` is its output, and
  `request-log` is its access log: the requests its request window counted,
  with millisecond arrival and completion times, the client address and
  the X-Forwarded-For header. `bootstrap` and `recover` run
  `varlatchd admin bootstrap|recover`; `serveCli` restarts varlatchd with
  `serve_cli` set, which it refuses until it knows the setting. Its
  optional capabilities are device sign-in's probes, which it runs as
  `varlatchd admin conformance-probe`, a command only a build with the
  `conformance` tag has (`up` refuses a binary without it), and
  `go-server`, whose fixtures it runs as `varlatchd admin
  conformance-fixture`, from the same build. It signals only
  the process it started, by the PID it recorded, after checking that PID
  still runs its configuration. Build the binary with the dashboard first:
  `go generate ./server/web` then
  `go build -tags conformance ./cmd/varlatchd` in `go/`.

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
the whole directory), the checker, a module it imports, `inventory.json`,
`clients.json` or `targets/capabilities.json`. Adding or removing the label runs the check again.

The workflow runs on `pull_request_target`: its definition and the checker
come from the base branch, so a pull request can change neither the check
nor the checker that judges it. It checks out the base commit only, fetches
the pull request's head as git objects, and reads the head's files with
`git show` as JSON; nothing from the head is checked out, installed,
imported or executed, the token is read-only and no secret is used. A base
without the checker fails the job. A push to `main` validates the files it
lands.

The same check covers the declared gaps: see [Declared gaps](#declared-gaps).
It also covers coverage itself: a check of the merge base that the head makes
newly not applicable on a target (`NEWLY-N/A <target>|<check>`), because its
kind changed, it moved to a suite that needs more, its suite needs more, or
the target's capabilities in `targets/capabilities.json` lost one, needs the
label. Each side is judged with its own inventory and capabilities file,
which is data, so nothing from the head runs. A new check is not counted.
This pull request's own run of the check, like any, uses the base's
checker; a change to the checker takes effect for the pull requests after
it merges.

## Declared gaps

A target that does not yet have an operation declares it, instead of
failing every check that needs it (ADR-0059 step 3, varlatchd-core
decision 5). This is how the Go server runs the whole inventory before its
features are ported, and `expect/go-binary.json` is the parity tracker.

**Operations.** An operation is an OpenAPI `operationId`
(`packages/protocol/openapi.yaml`, read by `lib/operations.mjs`) or a named
operation outside `/v1`, listed in `inventory.json` `operations`:

- `{ "method", "path" }`: an HTTP route outside `/v1` (`enroll-page`, the
  enrollment page; `browser-session`, the browser's session under `/auth`);
- `{ "target" }`: a target operation (`admin-bootstrap` and
  `admin-recover`, the targets' `bootstrap` and `recover`; `serve-cli`,
  `serveCli`);
- `{ "uses": [...] }`: the `seed`, the runner's own writes through `/v1`,
  which lacks exactly when an operation it uses does. It is never listed
  itself.

Each suite lists the operations it needs (`suites.<name>.operations`), and a
check may add its own (`checks.<id>.operations`), for a feature group that
needs more than the rest of its suite.

**Operation groups** (ADR-0059 step 4, feature-parity decision 2). A suite
that mixes operations from several slices is split into groups, so the part
a target can pass runs while the rest is still lacking:
`suites.<name>.groups.<group>` has a title and the operations its checks and
their setup need beyond the suite's, and each of its checks names it
(`"group"`). A check's operations are its suite's, its group's and its own.
The runner tells a suite which of its checks lack an operation
(`CONFORMANCE_LACKING`), and the suite runs each group's setup and checks
behind `kit.group("<group>")`, false when every check of the group lacks
one, and work only one check needs behind `kit.runs("<check id>")`. The
runner reports the skipped checks `target-lacks`. A split never changes
what a check asserts. The guarantee that a skipped group's work does not
run is at run time: a result reported for a check of a skipped group fails
the run, in the kit (which knows the group was asked) and in the runner
(which knows it was skipped, whether the suite asked or not; the one result
it allows there is `PREDATES-CLI`, and only when the CLI's verified version
predates the check's feature, as the evaluation decides), and work run
anyway meets the target's `501 NOT_IMPLEMENTED_YET` answers. `pnpm
test:conformance` also checks each suite script's calls against a narrow
gate convention (`repository.test.mjs`): a lint aid that catches the usual
mistakes, not a proof. A suite's own operations are what every check of it
needs; an operation a page requests in the background, whose failure no
check sees (a panel that stays empty), is not one. `pnpm test:conformance`
checks that every group is named in its suite's script. Suites whose checks are all ts-stack
list none: they never run on a target without the stack. `pnpm
test:conformance` fails on a name that is neither.

**`lacks`.** `expect/<target>.json` lists, per target key, the operations
the target does not have, each with a reason and the step that adds it:

```json
"lacks": {
  "go-binary": {
    "whoami": { "reason": "sessions ... are not built yet in the Go server", "step": "ADR-0059 step 3.4" }
  }
}
```

**In a run:**

- before the suites, the runner asks the target about every listed
  operation (`lacks-probe.mjs`): a request to its method and path (path
  parameters filled with `placeholder`, a body `{}` where the method takes
  one), or the target operation for a named one. The answer must be
  exactly the Go server's shared stub: `501` with the code
  `NOT_IMPLEMENTED_YET` (an error with that code from a target operation).
  Any other answer means the target provides the operation: the run fails,
  naming the stale entry (`STALE-LACKS` in the output). The stub answers
  before authentication, validation, body decoding or storage, so the probe
  needs no fixtures;
- a check whose operations include a lacking one is reported
  `target-lacks`, with the operations, by the runner. A suite all of whose
  checks lack something is not started; otherwise it runs, and the runner
  replaces what it printed for the lacking checks. A ts-stack check on a
  target without the stack stays not applicable;
- the first enrollment and the seed are skipped when they need a lacking
  operation;
- the report counts the checks each lacking operation holds back, and
  records the declared and any stale entries (`lacks`);
- `--gate` refuses any `target-lacks` result and any `lacks` entry in
  force.

**The merge-base check** (`expect-check.mjs`) treats gaps like expected
failures: with each side's own inventory, it computes which checks report
`target-lacks` on each target at the merge base and at the head. A pull
request that adds a `lacks` entry, or makes any check newly report
`target-lacks` (a new entry, or a new operation in the inventory that a
lacking target does not have), needs the `conformance-regression` label, so
an operation a target provides cannot quietly drop out of what is checked.
Removing an entry, or a dependency, needs nothing.

## External suites

The lifecycle and installer suites (`scripts/test-*.mjs`: setup, adopt,
upgrade, backup, move, ingress, sidecar, installers, the manual tailnet and
Coolify checks) test the TypeScript installation and do not run under the
runner. `inventory.json` lists each in `externalSuites`, with its
`replacement` the way a ts-stack check names one: the Go counterparts come
in ADR-0059 steps 4, 6 and 7, so each is `{ "open": "<the step>" }` until
its counterpart lands. A counterpart that runs in the Go workflow
(`.github/workflows/go.yml`) rather than under the runner is named in a
`{ "none": "<why>" }`: `backup-e2e`'s are Go tests (the backup and
restore end to end, the maintenance lease) and the step that restores a
Go archive in a fresh container and runs the conformance suites against
it; `backup-s3`'s is the step that runs the S3 client's tests against a
local S3 server with `VARLATCH_REQUIRE_S3=1`. `test/repository.test.mjs`
checks that every Go test and go.yml step such a reason names exists.
`pnpm test:conformance` fails when a `scripts/test-*.mjs` is not listed.

## Gate mode

`--gate` judges a run as ADR-0059's G1 (parity) and G2 (old clients) are
judged:

```sh
node scripts/conformance/run.mjs --target go-binary:<path> --cli source \
  --gate --walkthrough docs/evidence/<walkthrough record> [--recent-cli-report <report.json>]
```

Besides passing as an ordinary run, a gate run must have:

- no expected failure in force for its target and client, no `lacks` entry
  in force for its target, and no `target-lacks` result;
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
  once and passing (not applicable only for a ts-stack check, or a
  go-server check off `go-binary`), no problem,
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
target: doctor's replacements (step 6) and every external suite's but the
two backup suites' are still open; on `go-binary`, its declared gaps too. The Convex realtime
checks' replacements are the `realtime-degraded` checks (step 3.5), and
G11's own checks on the Go server's events are the `realtime-events`
go-server checks, which a gate run on `go-binary` needs passing. `test/gate.test.mjs`
shows this on the inventory as it stands.

## The weekly matrix

`.github/workflows/conformance.yml` runs weekly and on manual dispatch
(`gh workflow run conformance.yml --ref <branch>`), on GitHub-hosted
runners with only the read-only job token:

| | CLI `source` | CLI `0.21.0` | CLI `0.22.0` |
| --- | --- | --- | --- |
| `ts-source` | ✓ | ✓ | ✓ |
| `ts-release:0.22.0` | ✓ | ✓ | ✓ |
| `go-binary` | ✓ | | |

The `images` job builds the source images once (`source-images.mjs`) and
passes them to the `ts-source` cells as an artifact. The `go-binary` cell
builds the dashboard and `varlatchd` from the checkout. Each cell is its own
job, with its own stack (or server) on its own free ports, at most three at
a time and 60 minutes each, and uploads its `conformance-report.json`
(`conformance-report-<target>-cli-<cli>`, tokens masked as in the logs).
`go.yml` also runs the `go-binary` target with the source CLI on every pull
request that changes `go/` or the harness's `go-binary` pieces, in three
shards ([Shards](#shards)), as `ci.yml`'s `e2e` job runs `ts-source`.

## Clients

`--cli` chooses the CLI under test: `source` (built from this checkout),
`go:<path>` (the Go CLI, ADR-0059 step 5, a native binary built from this
checkout: `cd go && go build -o <path> ./cmd/varlatch`), or a
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

### The Go CLI's gaps: client-lacks

The Go CLI is ported in slices (internal `docs/design/go-cli.md`), so for a
while it lacks CLI features the suites exercise. `client-go.json` lists
them, each with the slice that builds it, the client's counterpart of a
target's `lacks` (one file, since the gaps are the client's, the same on
every target). A check lacks when its feature, a feature its suite's setup
uses (`suites.<name>.cliNeeds`), or one its `cliNeeds` lists, is in the
file. A check's `cliNeeds` names what it needs besides its own feature (a
`types` check that starts the generated module's application under
`run --export-context` needs `run-export-context`), or, for a check without
a feature, everything it needs:

- the runner reports it `client-lacks` itself; a suite cannot;
- a suite all of whose checks lack something is not started; otherwise it
  runs, and what it prints for a lacking check is replaced, except a PASS,
  which fails the run as a stale entry (remove it in the pull request that
  builds the feature);
- a check that lacks nothing is judged as always: client-lacks never hides
  it;
- only the `go` client has gaps; a TypeScript CLI ignores the file;
- gate mode refuses any client-lacks: G1 at 0.50.0 runs the Go CLI with
  nothing left out.

`client-runtime`'s two whole-suite checks, "the audit export holds no
value" and "varlatchd logs hold no value", need no CLI feature of their
own. On the Go CLI before slices 5.4b and 5.4d they cover only what the
suite's setup and `types` did: no run or scan has disclosed anything yet,
so they prove the server side only until those slices land.

`go/cmd/varlatch`'s `TestClientLacksNotStale` also fails while an entry
names a slice the Go CLI marks built (`go/cmd/varlatch/testdata/built/`).
`cliNeeds` is recorded conservatively for the checks without a feature (every feature of their
suite); a slice that finds a check needing less narrows it. The setup's
`init --org --project --server` (slice 5.1d) and token sign-in (slice
5.1e) are built, so every suite's setup runs on the Go CLI.

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
