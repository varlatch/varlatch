# Go rewrite

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). The
groundwork ADR-0059 amendment 2 allowed was built on the `rewrite/go`
branch and merged into `main` after the TypeScript release v0.22.0, as the
start of step 1 (ADR-0059 "Order"). Nothing here ships until the first Go
release. CI routes by path: `.github/workflows/go.yml` checks `go/`, and
`scripts/ci-changes.sh` keeps a Go-only change out of the TypeScript tests.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later. See
  "varlatchd" below.
- `server/api/`: the `/v1` contract in Go (Decision 3, spec-first
  OpenAPI), generated from `packages/protocol/openapi.yaml`: the request
  and response types, `StrictServerInterface` (one method per operation)
  and its `net/http` wiring on a `ServeMux`. See "The OpenAPI document"
  below.
- `server/db/`: the SQLite schema (Decision 2, step 3.1), AGPL. See
  "The schema" below.
- `lib/storage/`: the SQLite storage engine (Decision 2): the single
  writer with group commit, the checkpointer that bounds the WAL, paced
  snapshots, metrics.
- `lib/diskprobe/`: the fsync probe (Decision 2's disk requirement, p99
  under 10 ms) that setup, `varlatch doctor` and the G9a harness run.
- `lib/envelope/`: the encryption envelope (ADR-0011, unchanged by
  Decision 2): AES-256-GCM, canonical-JSON associated data, the purposes
  in use (`context.go`, including ADR-0056's audit export credential and
  its drain copy since 0.22.0), Root KEK parsing and the canary.
  `testdata/` holds fixtures the TypeScript server's own code sealed
  (opened by the Go tests) and fixtures Go sealed (opened by that code in
  CI, `tsfixtures.mjs`). `ts-v0.22.0.json` comes from v0.22.0 and supplies
  the vectors; `ts-v0.21.0.json` stays, since what 0.21.0 sealed must still
  open. A TypeScript release that adds a purpose gets a fixture of its own
  (`node tsfixtures.mjs generate --ref v<release> ts-v<release>.json`,
  listed in `tsFixtures` in `envelope_test.go`).
- `lib/release/`: the embedded release verifier (Decision 8): a release's
  SHA256SUMS must be signed by the release workflow for its tag (Sigstore,
  pinned identity and issuer; cosign's earlier bundle format and the newer
  Sigstore bundle both read), and every asset must match it.
- `install/install.sh`: the installer of Decision 8 (CLI for the current
  user, or `--server` as root), and its tests: every prefix under sh, dash
  and bash runs nothing or the whole script (G8), and end-to-end runs
  against a local HTTPS server. The downloaded CLI checks the signature
  (`varlatch verify-release`) before anything is put in place.
- `install/install.ps1`: the Windows installer (CLI for the current user,
  in `%LOCALAPPDATA%\Programs\Varlatch`, added to the user `PATH`), with
  the same checks as `install.sh` and its G8 tests under PowerShell 5.1 and
  7 (the prefix runner is `install/testdata/ps1prefix.ps1`; the Windows CI
  job runs the end-to-end install).
- `install/varlatchd.service`: the systemd unit (data in
  `/var/lib/varlatch`, configuration in `/etc/varlatch/varlatchd.conf`, the
  Root KEK and BEK as systemd credentials, user `varlatch`, a strict
  sandbox). CI checks it with `systemd-analyze verify` and `security`, and
  runs `install/unitprobe` under it (`install/test-unit.sh`).
- `bench/g9a/`: the G9a storage benchmark harness (`run.sh`, the k6
  script, the `g9a` command): G9a's load profile, every checkpoint and the
  WAL size logged, paced backups, converge runs, the disk record, and a
  report that judges a run by G9a's criteria. Until step 3 builds
  varlatchd it serves the load from a stand-in workload on `lib/storage`,
  whose runs are inconclusive by design; see `bench/g9a/README.md`.
- `internal/spdxheader/`: puts the SPDX line on generated files.
- `cmd/varlatch/`, `lib/` and everything else: Apache-2.0. No Apache-2.0
  package may depend on an AGPL-3.0-or-later one; `licensing_test.go`
  enforces it.

Checks (Go 1.27, `CGO_ENABLED=0`), as `.github/workflows/go.yml` runs them:

```sh
cd go
gofmt -l .
go mod tidy -diff
go generate ./...   # then: git diff --exit-code
go vet ./...
go test ./...
CGO_ENABLED=1 go test -race ./...
```

`go generate ./...` includes `go generate ./server/web`, which builds the
dashboard and needs the pinned Node (26) and pnpm (the root
`package.json`'s `packageManager`, 12.3.4) on the `PATH`. go.yml sets
`VARLATCH_REQUIRE_DASHBOARD=1` for the tests, so a build without the
dashboard fails there instead of skipping the check that the embedded
dashboard comes from the checkout.

## varlatchd

`varlatchd serve [--config /etc/varlatch/varlatchd.conf]` (ADR-0059 step
3.2) reads its configuration (`server/config`; the format, every setting
and its default are in `install/varlatchd.conf.example`), sets
`PR_SET_DUMPABLE` to 0, reads the Root KEK from its file (by default the
unit's `root-kek` credential), opens `varlatch.db` in the data directory with
`lib/storage` (ADR-0059 Decision 2's settings, which are not options),
creates the schema on an empty file (`server/db` `Init`), creates the
installation and its Root KEK canary on first start and checks the canary
on every start, then serves HTTP until SIGTERM or SIGINT, when it lets
requests in flight finish (20 seconds at most) and closes the database.

Exit statuses: 0 after a clean stop; 1 for anything a restart may fix (the
disk, the database, the network, a port in use); 78 for a configuration
error no restart can fix: an unparsable file, an unknown or repeated
setting, an invalid value, missing or unparsable Root KEK material, and a
Root KEK that does not open this installation's canary (the installation
was read; a failure to read it stays 1). The unit has `RestartPreventExitStatus=78`, pinned in
`install/unit_test.go`. `varlatchd admin bootstrap|recover` answer
`NOT_IMPLEMENTED_YET` (exit 69) until step 3.4.

The server's packages:

- `server/config`: `varlatchd.conf`.
- `server/clientaddr`: the client address behind trusted proxies, as the
  TypeScript server finds it (`trusted_proxies`).
- `server/httpserver`: the HTTP layer, on the strict server generated
  from the OpenAPI document (`server/api`):
  - every `/v1` operation not built yet is routed to one shared stub,
    which answers `501` with the code `NOT_IMPLEMENTED_YET` before the
    generated code binds parameters or decodes the body, so before any
    authentication, validation or storage access (varlatchd-core decision
    5; the conformance harness's stale-`lacks` probe relies on it).
    `BuiltOperations` lists the ones served (`GET /v1/meta` so far);
  - the TypeScript server's error envelope, and its two known differences
    (decision 4): an unknown route answers the plain-text `404 Not Found`
    (under `/v1` only after authentication, as the TypeScript server
    orders it: without a bearer credential, `401 AUTHENTICATION_REQUIRED`;
    until step 3.4 verifies credentials, any bearer reaches the 404), and
    the request window (600 requests per 60 s per client address, before
    authentication) answers `429` with `PERMISSION_DENIED` and Retry-After.
    `server/httpserver/testdata/known-differences.json` holds these
    answers, and both servers' tests run it from raw request targets
    (`services/varlatchd/test/go-parity.test.ts`);
  - routing on the paths the TypeScript deployment uses (`target.go`): the
    dashboard's nginx chose dashboard or API on the raw target decoded
    first (`%2f` included), then with dot segments resolved and slashes
    merged; varlatchd's router (Hono) routes, authenticates and
    counts on the WHATWG-normalized path after `decodeURI` (dot segments
    and `%2e` resolved, `%2f` kept, slashes never merged), so for example
    `/v1/organizations/../meta` is `/v1/meta` and `/v1%2fmeta` is no route.
    The two are derived separately from the raw target, since they do not
    commute: `/v1%2fx/../dashboard` reaches the API (nginx sees
    `/v1/dashboard`) as `/dashboard`, a 404;
  - an access log (`access_log`): a JSON line per request with arrival and
    completion time, client address, method, path (never the query),
    status, X-Forwarded-For and whether the request window counted it.
    X-Forwarded-For is read from all its lines, joined as Node joins them;
  - `/healthz`, `/readyz` (schema, Root KEK, installation) and `/v1/meta`,
    whose capabilities are the TypeScript server's list (checked against
    `packages/protocol/src/errors.ts`), less what this installation does not
    offer;
  - the dashboard: a file of its build where the path names one, its
    `index.html` for every other path (single-page routing), with the
    dashboard's Content-Security-Policy (`connect-src 'self'`: there is no
    Convex in the Go server). `/v1`, `/auth`, `/enroll`, `/healthz`,
    `/readyz` and `/.well-known` never serve it; `/auth` and `/enroll`
    answer the stub until step 3.4.
- `server/web`: the dashboard varlatchd embeds (decision 8).
  `go generate ./server/web` builds `apps/web` as its image does, with the
  pinned Node and pnpm, and stages it in `server/web/dist/` with a record of
  the sources' hash and the commit; `dist/` is not committed, and without it
  varlatchd embeds a placeholder page, so `go build` works in a clean
  checkout. A test checks that the embedded build comes from the
  checkout's sources (and, in CI, its commit).
- `server/daemon`: `serve` itself. The first start records
  `installation.initialized`.
- `server/audit` (step 3.3): Security Audit Events (ADR-0016). `Record`
  writes events inside the caller's write job, exposure index rows first
  (ADR-0052 Decision 6), and returns their positions: the rowid, so under
  the single writer they are contiguous and in commit order, a job rolled
  back to its savepoint gives its positions back, and a failed batch keeps
  none (`positions_test.go`). Inside a request (`WithAttribution`) an event
  whose actor is the request's identity names its credential, client,
  listener and tailnet resolution (ADR-0045, ADR-0046 Decision 8), unless
  the caller set them. `Serialize`, `EventJSON`, `ExportLines` and
  `ExportStreamLine` give the audit listing's, webhook delivery's and the
  exports' bytes as the TypeScript server gives them, which read every JSON
  column back through PostgreSQL's jsonb (key order: shorter keys first)
  and `JSON.parse` (integer-like keys first). Webhook URLs are redacted on
  the way out, as there.
- `server/authz` (step 3.3): the authorization evaluator (ADR-0015), a
  port of `authz/evaluate.ts`; `LoadGrants` and `LoadRequirements` as
  `loadGrants` and `loadTailnetRequirements` (Roles, Groups and Teams
  expanded, ADR-0028; decision-time provenance, ADR-0029); `Decide` as
  `decide` (existence hiding, denial classes, the denial's audit event);
  the incident freeze at Organization entry and in
  `RefuseIfIncidentFrozen` (ADR-0055); and Destination Selectors
  (`authz/destination.ts`).
- `server/jsvalue`: JSON as `JSON.parse` and `JSON.stringify` read and
  write it (member order, numbers, escapes, lone UTF-16 surrogates kept as
  `\udxxx`), and jsonb's key order and refusals.
- `server/whatwg`: what the TypeScript code gets from Node.js's URL
  parser, `url.domainToASCII`, `net.isIP` and string functions, as far as
  audit redaction and Destination Selectors use them. Domain to ASCII is
  ada's (Node's URL library): its label rules ported, with x/net for the
  UTS #46 mapping, and which code points ada keeps and their combining,
  Bidi and joining properties read from Node itself
  (`nodeidna_table.go`, generated by `testdata/nodeidna.mjs`), since ada's
  tables follow neither current Unicode data nor x/net's. A test holds
  every code point, in fifteen labels, to Node's answers
  (`testdata/node-idna.json`). After a Node.js update, regenerate both
  with `node go/server/whatwg/testdata/nodeidna.mjs`; the vector test in
  `services/varlatchd` fails until then.
- `server/ids`, `server/domainerr`: domain IDs (`db/ids.ts`) and
  `DomainError`.

`server/authz/testdata/ts-vectors.json` and
`server/audit/testdata/ts-vectors.json` are vectors the TypeScript server's
own code produced: the evaluator's decisions and reasons (every Grant
scope, Roles live, revoked and empty, Groups and Teams, Requirements and
Tailnet Contexts, the denial classes with and without existence hiding,
the incident freeze before authorization), what `loadGrants` loads from a
database fixture, and audit events of every type recorded and serialized.
The Go tests must give the same answers. `services/varlatchd/test/go-authz-vectors.test.ts`
and `go-audit-vectors.test.ts` produce them and fail when the committed
files differ from what the TypeScript code produces now; they run with
varlatchd's tests, which a change to these files also selects
(`scripts/ci-changes.sh`). To regenerate after a change on either side:

```sh
VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-authz-vectors.test.ts test/go-audit-vectors.test.ts
```

The TypeScript `loadGrants` query has no `ORDER BY`, so PostgreSQL returns
Grants in whatever order its plan gives; the Go query orders by rowid
(insertion order). The vectors compare the Grants a database loads, and
the lists derived from them (`grantIds`, `groupIds`, `roleIds`,
`applied`), as sets; the pure evaluator vectors check their order.

## The OpenAPI document

The `/v1` contract is `packages/protocol/openapi.yaml` (OpenAPI 3.1),
derived from `packages/protocol` (ADR-0059 Order, step 1). It stays there
while the TypeScript server and dashboard use it; the TypeScript types are
generated from it with openapi-typescript (`pnpm --filter
@varlatch/protocol generate`), and ci.yml fails when they are stale.

- **Go**: `go generate ./server/api` runs oapi-codegen, pinned by the
  `tool` directive in `go.mod` (v2.8.1, `go tool oapi-codegen`), with
  `server/api/oapi-codegen.yaml`: models, the standard library server
  (`net/http` `ServeMux` patterns) and the strict server, whose methods
  take a typed request and return a typed response. v2.8.1 reads OpenAPI
  3.1 itself (`type: [T, "null"]` included), so the document is used as it
  is. Its option `resolve-type-name-collisions` names the parameters and
  headers that share a name with a schema (`ApprovalParameter`,
  `ApprovalHeader`, `EnvironmentParameter`, `ProjectParameter`).
  `internal/spdxheader` then adds the package's SPDX line, which the
  generator cannot write. Never edit `api.gen.go`; change the document and
  generate again.
- **Licensing**: the types and the server interface are one AGPL package.
  A models-only Apache package that the server imports does not work:
  the strict server's response types for `oneOf` bodies use the models'
  unexported fields, which only the same package can reach. The CLI (step
  5) will not import `server/api` (G12); it gets its own client and types,
  generated from the same document into an Apache package (for example
  `lib/apiclient`), so both sides follow one contract without sharing Go
  code.
- **CI** (`go.yml`, which runs when the document changes):
  - "Generated code is current" regenerates and fails on any difference
    (G12, stale output).
  - The `openapi` job compares the document of a pull request with its
    base using oasdiff (pinned image) and fails on a breaking change (G12).
    Before product 1.0 a breaking change may be made on purpose (ADR-0018):
    label the pull request `api-breaking`, add a CHANGELOG.md entry to it
    and re-run the job, which then reports the changes as warnings. Without
    a CHANGELOG.md change the label does not help.

Left for step 1: "checked against the TypeScript server". The spec
coverage test (`services/varlatchd/test/spec-coverage.test.ts`) already
fails when a served route and the document disagree; the TypeScript
server's responses are validated against the document in a pull request of
its own. Step 2 (the conformance harness) starts after that.

## The schema

`server/db/` holds varlatchd's SQLite schema, written fresh for the tables
the TypeScript server has at v0.22.0 (Decision 2), not a replay of its
migrations.

- `schema.sql`: every table `STRICT`, with foreign keys, `CHECK`
  enumerations (named as in PostgreSQL), indexes and the triggers that keep
  PostgreSQL's guarantees (commit-ordered, append-only audit positions;
  forward-only passkey counters; a session's end revoking its browser
  credentials; GitHub App conversions written once), guarded against
  `REPLACE`, which would bypass them (the guarded tables with text keys are
  `WITHOUT ROWID`, so no hidden rowid escapes the guards). Times are integer microseconds since
  the epoch, UTC; `jsonb` is JSON text; `text[]` is a JSON array of strings
  or nulls (element triggers); `integer` keeps PostgreSQL's 32-bit range
  (`int4_<column>` checks), so values can go back for a reverse migration.
- `MAPPING.md` and `mapping.json`: every PostgreSQL table, column,
  constraint, index and trigger mapped to `schema.sql` or dropped with the
  reason, and every type rule. `mapping_test.go` checks the mapping, CHECK
  expressions and index predicates compared as parsed trees, against
  `testdata/pg-v0.22.0.json`, a dump of v0.22.0's schema made by
  `testdata/pgschema.mjs` on PGlite (MAPPING.md says how to regenerate it),
  and against a database `Init` created. The migration manifest (step 7)
  is built from the mapping.
- `db.go`: `Init` creates the schema on an empty file in one write job and
  records `SchemaVersion` in the `schema_version` table (a row rather than
  `PRAGMA user_version`; `db.go` says why), and on later starts checks the
  recorded version, accepting a newer one only when its `compatible_from`
  allows (rollback-safe releases, G6).
- `query/`: typed queries generated by sqlc from `schema.sql` and
  `queries/*.sql` with `sqlc.json` (boolean columns as `bool`). sqlc is
  pinned by the `tool` directive in `go.mod` (v1.31.1, `go tool sqlc`);
  `go generate ./server/db` regenerates, and "Generated code is current" in
  `go.yml` fails on stale output (G12). Queries are added with the features
  that need them; `*storage.Tx` is sqlc's `DBTX`, so a job calls
  `query.New(tx)`.

## The conformance harness (step 2)

Step 2's harness is `scripts/conformance/` (its README has the details):
the end-to-end suites, the released CLIs 0.21.0 and 0.22.0 and the app
libraries, run against a chosen target: `ts-source` (this checkout),
`ts-release:<version>` (a signed release, verified and pulled by digest)
and `go-binary:<path>`, this server, run as a process. Each target keeps
its known failures in `scripts/conformance/expect/`, with a reason and the
step that removes them, and the operations it does not have yet (`lacks`,
step 3): `expect/go-binary.json` lists every operation varlatchd does not
serve, a check that needs one reports `target-lacks`, and the runner first
asks varlatchd that each really answers `NOT_IMPLEMENTED_YET`. `--gate` is
how G1 and G2 are judged. Step 2 is complete once its last pull request (the release
target, expected failures, gate mode and the weekly matrix,
`.github/workflows/conformance.yml`) is merged and the weekly matrix
passes, every failure in it listed with a reason.

## Before the first Go release

- The Go release workflow: binaries named `varlatch-<version>-<os>-<arch>`
  (`.exe` on Windows) and `varlatchd-<version>-linux-<arch>`, plus
  `varlatchd.service`, all in `SHA256SUMS`; `install.sh` attached with
  `@VARLATCH_VERSION@` replaced by the version; varlatch.com serving the
  latest one with a `Content-Length`.
- Step 3 points the G9a harness at varlatchd (`bench/g9a/README.md`,
  "Against varlatchd") before G9a is run as the gate.
- List the Go module's dependencies (`go list -m all`, modernc.org/sqlite
  and its own) in THIRD-PARTY-NOTICES.md and its generator.
