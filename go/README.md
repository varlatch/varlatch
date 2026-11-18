# Go rewrite

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). The
groundwork ADR-0059 amendment 2 allowed was built on the `rewrite/go`
branch and merged into `main` after the TypeScript release v0.22.0, as the
start of step 1 (ADR-0059 "Order"). Nothing here ships until the first Go
release. CI routes by path: `.github/workflows/go.yml` checks `go/`, and
`scripts/ci-changes.sh` keeps a Go-only change out of the TypeScript tests.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later. See
  "varlatchd" below.
- `cmd/varlatch/`: the CLI, Apache-2.0 (ADR-0059 step 5), ported from
  `apps/cli` slice by slice (internal `docs/design/go-cli.md`). See "The
  varlatch CLI" below.
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
- `lib/contract/` (step 4.1b): the Configuration Contract model, a port of
  `packages/contract` that the server and (in step 5) the CLI share:
  validating and normalizing a pushed Contract with zod's messages and
  order (zod 4 measures strings in code points), canonical bytes and the
  content hash (`sha256:` over the canonical JSON, keys in UTF-16 order,
  JSON.stringify's escaping), the semantic diff, and Contract Semantics 1
  to 3. A url value is valid when `lib/whatwg`'s `ParseURL` (`new URL`
  as Node.js runs it, ada's domain to ASCII included) accepts it.
  `ParseJSON` reads a Contract file as the TypeScript CLI does
  (`readFileSync` as UTF-8, then `JSON.parse`): lone UTF-16 surrogates in
  `\u` escapes are kept (as WTF-8), so they reach the canonical bytes and
  the hash as they do there. Its tests run `packages/contract/test/vectors`
  (every semantics version's golden and portability vectors) and
  `testdata/ts-vectors.json`, what the TypeScript package makes of 115
  Contracts, valid and invalid, and what `JSON.parse` makes of 46 JSON
  texts (`services/varlatchd/test/go-contract-vectors.test.ts`,
  regenerated with `VARLATCH_WRITE_GO_VECTORS=1` as the other vectors).
- `lib/targets/` (step 4.6): substitution targets (ADR-0039 Decisions 1
  and 2), a port of `packages/protocol`'s `targets.ts` that the server and
  (in step 5) the CLI's Broker share: `header:` (lower-cased, never a
  transport-owned header), `query:` and `form:` (1 to 256 UTF-16 units, no
  control characters), `json:` (an RFC 6901 pointer); a Capability's
  targets canonical (at most 4 per item, none repeated, every item covered,
  items and targets in JavaScript's UTF-16 order) and their audit form.
- `lib/sync/` (step 4.9a): the Platform Adapters of Sync Targets
  (ADR-0031 §8), a port of `packages/sync` that varlatchd and (in step 5)
  the CLI's `sync push` and `sync check` share: GitHub Actions secrets
  (the sealed box, GitHub App listings, token expiry), Coolify
  applications and services (flags, value fidelity, `platformExpands`,
  redeploys, the Compose file's usage), and Convex. The adapters take the
  caller's `*http.Client` and never build one (decision 6;
  `structure_test.go` checks it): varlatchd passes the outbound policy's,
  the CLI a plain one. Platform answers are read as `JSON.parse` reads
  them (JavaScript's property order, repeated keys, lone surrogates kept)
  by `lib/jsjson` (which `server/jsvalue`, AGPL-3.0-or-later, duplicates;
  the server may switch to the Apache package),
  and a Compose file as the `yaml` package reads it, on
  `go.yaml.in/yaml/v3`'s nodes. The vectors
  (`testdata/ts-exchanges.json`, 707 cases) are recorded from the
  TypeScript adapters while their own tests and extra cases run
  (`packages/sync/test/go-vectors.test.ts`, regenerated with
  `VARLATCH_WRITE_GO_VECTORS=1`): each call's arguments, every request
  (method, URL, headers, body; a sealed value by its length, and by what
  it opens to when sealed to one of the file's known recipients) and the fake
  service's answer or transport failure, the send checks, the expiry
  reports, and the result. Both languages replay the file and must send
  the same requests and give the same results; the sealed box and Node's
  base64 decoding have byte vectors of their own, and
  `TestGitHubSealsEachRequestedValue` opens every value a write sends.
  The YAML reader follows the `yaml` package where yaml.v3 reads
  otherwise: the non-specific tag `!` (a string, which yaml.v3 does not
  report: found from the text at the node's position, after the one
  leading byte order mark both drop), `%YAML 1.2` (which yaml.v3 refuses:
  read strictly, then given to it as 1.1, a repeat as a comment),
  and `!!merge` (a merge key whatever its quoting; a value so tagged is
  read by no rule, so unknown). Where Go answers otherwise:
  - A Compose file the Go reader does not read is unreadable, so every
    verdict is unknown (the conservative reading). The Go reader reads a
    subset of YAML, an allowlist, and calls everything else unreadable
    (#218, Sol's fourth round; `inSubset` and `subsetCharacters` in
    `compose.go`):
    - characters: printable ones, tab, line feed, and carriage return
      only before a line feed. No other control character (C0, DEL, C1,
      NEL), no U+2028 or U+2029, no byte order mark past the first, no
      U+FFFE or U+FFFF, nothing that is not UTF-8 (a lone surrogate);
    - quoted and plain scalars, keys included, start and end on one line,
      only a blank, `:`, `,`, `]` or `}` follows a closing quote, and a
      double-quoted one holds only YAML 1.2's escapes (not `\'`).
      Block scalars (`|`, `>`) are read, with a strict header (no `#` run
      into it, as in `>#-`);
    - in a block mapping, a scalar value on a later line than its key is
      indented more than the key (a block sequence there is read);
    - flow collections (`{…}`, `[…]`) close on the line they open on, with
      nothing run into the closing bracket,
      hold no `?` outside quotes (an explicit key: `{?:}` is read two
      ways), and no plain scalar in them is empty or holds a `:` (where
      one ends a key, as in `{7:, A: x}`, the parsers disagree);
    - anchors and aliases named with letters, digits, `_`, `-` and `.`;
      tags `!`, `!name` or `!!name`, with a name of letters, digits and
      `-`, and none of the YAML 1.1 types, on a key either (`!!binary <<`);
    - directives: only `%YAML 1.2`, with a `---` after it; no document
      end marker (`...`).

    **What this costs.** Some valid Compose files fall outside the subset,
    and for them every name's verdict is unknown, names the file never
    mentions included, where TypeScript checks them. Among them:
    - a flow list spread over lines (`command: [` then one argument per
      line);
    - a quoted or plain value continued on the next line (a long
      `command:` string);
    - an unquoted `host:container` port in a flow list (`ports:
      [8080:80]`);
    - a key and value without a blank in a flow mapping (`{A:x}`).

    For a Coolify service whose file falls outside, a run then does what
    it does with any compose file it cannot read: it notes that usage
    could not be checked, holds values containing `$` (the file might
    copy them where Docker Compose expands `$`), and stops deleting again
    names it deleted (the file might re-create them). Block style and
    quoted ports keep a file readable.

    TypeScript reads some of what falls outside: a lone surrogate, quoted
    or plain values over indented lines, an escaped line break, a flow
    collection over indented lines, a property alone on its line, the
    flow forms above. It also
    reads the YAML 1.1 types (`!!binary`, `!!timestamp`, `!!set`,
    `!!omap`, `!!pairs`), a mapping or sequence as a key, and an alias
    inside its own anchor (on which TypeScript overflows its stack and
    `inspectUsage` throws: defect 6, below). The vectors record each of
    those (`divergence:`), and each class outside the subset that
    TypeScript cannot read either (`subset:`).
  - The differential fuzz: `packages/sync/test/go-compose-fuzz.test.ts`
    writes mutants of every Compose input the vectors hold, with awkward
    characters and forms inserted or swapped in, each with TypeScript's
    verdict. `TestComposeFuzzDifferential` fails on each mutant where Go's
    verdict is more confident than TypeScript's. It runs nightly on ten
    random seeds, printed in the log (`.github/workflows/compose-fuzz.yml`,
    which keeps a failing seed's mutants), and by hand with the commands in
    the test file. Its mutations include `:` and
    `?` at flow collections' delimiters, keys and values. At #218's fifth
    round, wide runs (61 seeds, 1 to 60 and 137, 366,000 mutants each)
    found nine more classes, each now outside the subset with a vector: a
    flow key ending in `:`, `{?:}` (and empty flow scalars), text run into
    a closing quote, or into a closing bracket, a value at its key's
    column, `...` markers, a block scalar header with a comment run into
    it, YAML 1.1 tags on keys, and escapes YAML 1.2 does not have. They
    also found one rule bug, fixed: the key of a merge-tagged value, which
    `JSON.stringify` drops.
    The final run had none more confident in Go: 331,287 gave the same
    verdict, 34,713 were unreadable only in Go.
  - An error that is not the adapter's own (an answer that is not JSON,
    or of the wrong shape) keeps JavaScript's name (`SyntaxError`,
    `TypeError`, `URIError`) with Go's wording, not V8's.
  - A transport failure is named as Node's fetch names it (`TypeError`,
    `TimeoutError`, `AbortError`, and `OutboundRefusedError` for the
    outbound policy's refusal anywhere in the error).
  - An answer is read up to 32 MiB (`MaxResponseBytes`); TypeScript reads
    any size.
  - A Coolify variable whose key is not a string never matches a name
    and is left out; one whose value is neither a string nor null reads
    as unreadable (`nil`), which, like TypeScript's non-string, never
    equals a value.
  - A Coolify listing's labels sort in `golang.org/x/text`'s root
    collation, where `localeCompare` uses ICU's; the vectors hold them to
    the same order on mixed case, accents, digits, punctuation and
    scripts.
  - GitHub names uppercase as `toUpperCase` does wherever the result is
    ASCII (the only names any pattern accepts).
- `lib/jsjson/` (step 5.1a): JSON as JavaScript's `JSON.parse` and
  `JSON.stringify` read and write it: objects in JavaScript's property
  order (array indexes first, then insertion; a repeated key keeps its first
  place and its last value), lone UTF-16 surrogates kept in their WTF-8
  bytes, numbers as `Number::toString` prints them, `JSON.stringify`'s
  escaping (`<`, `>`, `&`, U+2028 and U+2029 not escaped), and
  `StringifyIndent` for `JSON.stringify(v, null, n)`, which is how the CLI
  prints every document. It was `lib/sync`'s reader; the adapters keep
  their names for it (`lib/sync/json.go`). `testdata/ts-vectors.json` holds
  what Node.js makes of a set of JSON texts (written by
  `apps/cli/test/go-vectors-framework.test.ts`).
- `lib/whatwg/`: what the TypeScript code gets from Node.js's URL
  parser, `url.domainToASCII`, `net.isIP` and string functions, as far as
  audit redaction, Destination Selectors and url Config Items use them. Domain to ASCII is
  ada's (Node's URL library): its label rules ported (`idna.go`, from ada
  4.0.0, commit b12a893a4580, under the MIT License: `LICENSE-ada-MIT`,
  listed in `scripts/third-party-code.json` and THIRD-PARTY-NOTICES.md;
  its SPDX header is `Apache-2.0 AND MIT`), with x/net for the
  UTS #46 mapping, and which code points ada keeps and their combining,
  Bidi and joining properties read from Node itself
  (`nodeidna_table.go`, generated by `testdata/nodeidna.mjs`), since ada's
  tables follow neither current Unicode data nor x/net's. A test holds
  every code point, in fifteen labels, to Node's answers
  (`testdata/node-idna.json`). After a Node.js update, regenerate both
  with `node go/lib/whatwg/testdata/nodeidna.mjs`; the vector test in
  `services/varlatchd` fails until then.
  Apache-2.0 since step 4.1b (it was `server/whatwg`): `lib/contract`
  validates a url Config Item with its `ParseURL`, and the CLI (step 5)
  shares that.
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
- `lib/backup/` (step 4.14): the installation archive (ADR-0033 as
  ADR-0036 and Decision 7 amend it), Apache-2.0 for the CLI's `admin
  backup` in steps 5 and 6.
  - **The seal** is `packages/backup`'s, byte for byte: `VLTBAK01`, a
    salt and a nonce, then one AES-256-GCM message (the header as
    additional data) over the manifest's length, the manifest and the
    components, under scrypt(BEK, salt), whether the BEK is a 32-byte key
    file or a passphrase. One GCM message over up to 60 GiB needs a
    streaming GCM (`gcm.go`, CTR and a 4-bit-table GHASH); its output
    equals `crypto/cipher`'s for every length, additional data and write
    split tested.
  - **Sealing and opening.** `Seal` writes to a temporary file and links
    it into place: never a partial archive, never a replaced one. `Open`
    authenticates the whole stream before it reads the manifest, then
    checks each component's size and SHA-256.
  - **Manifests:** formats 1 and 2 are the TypeScript server's (step 7's
    converter reads them), checked as its zod schema checks them; format 3
    is Go's (`varlatch.db`, `configuration.json`; the release, its API
    major and the database's schema version).
  - **The keys:** `CheckKeys` opens the canaries with the candidate Root
    KEKs, and `DistinctKeys` refuses a BEK that is a Root KEK.
  - **Vectors in both directions:** `testdata/ts-vectors.json` holds
    archives the TypeScript code sealed and manifests with zod's verdicts
    (`services/varlatchd/test/go-backup-vectors.test.ts`), and go.yml has
    the TypeScript code open what `TestGoVectors` seals.
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
  report that judges a run by G9a's criteria. It drives varlatchd built
  with the `g9a` build tag (`varlatchd g9a`, step 3.6) as a process; see
  `bench/g9a/README.md`.
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

## The varlatch CLI

`cmd/varlatch` is the CLI (ADR-0059 Decision 1), a port of the TypeScript
CLI (`apps/cli`) that behaves as v0.22.0 does, observed from outside: the
same bytes on stdout and stderr and the same exit status (internal
`docs/design/go-cli.md`, decision 2). It is built in slices; a command not
ported yet says so and exits 64, and `adopt` (a Compose installation) never
comes. `verify-release`, which the installers run, is Go's own.

- `internal/cli/`: the framework (slice 5.1a): the command table
  (`commands.go`, each command with the slice that builds it), the global
  `--assisted` and `--approval` options, help (`usage.txt`, the TypeScript
  CLI's `USAGE` byte for byte, and `CommandHelp`), exit statuses, the
  terminal-safe text and secret masking of `safeText.ts`, assisted mode
  and the User-Agent (`varlatch-cli/<version> (<platform>; <arch>[;
  assisted])` with Node.js's platform and processor names, which varlatchd
  summarizes into the audit's client).
- `internal/clientctx/`: `packages/context` (slice 5.1b): where the CLI
  finds `varlatch.toml` and `.varlatch/local.json`, how it resolves the
  server and Environment (ADR-0017 §7; ADR-0058 Decision 1: `--server` >
  `VARLATCH_SERVER` > the local override > `varlatch.toml`, and outside a
  repository the default server > the only stored credential;
  `--environment`/`-e` > `VARLATCH_ENV` > the local selection > the
  committed default), and the user-level `credentials.json` and
  `settings.json`: the same directory (`VARLATCH_CONFIG_DIR`, else
  `$XDG_CONFIG_HOME/varlatch`, else `<home>/.config/varlatch` on every
  platform, home as Node.js's `os.homedir()` finds it), schema, bytes
  (`JSON.stringify(value, null, 2)` and a newline) and modes (0600,
  replaced atomically) as the TypeScript CLI, keeping keys and entries it
  does not know, so a sign-in made by either CLI works with the other
  (internal `docs/design/go-cli.md`, decision 11). Inside an agent-safe run
  (`VARLATCH_AGENT_RUN`) the operator's default store is never read or
  written. When neither `HOME` (`USERPROFILE` on Windows) nor the system's
  user record names a home directory, a command that needs one exits 64:
  `varlatch: the home directory is unknown: HOME is empty or unset, and the
  system records none for this user. Set HOME, or VARLATCH_CONFIG_DIR`. An
  explicit `VARLATCH_CONFIG_DIR` works without a home directory, inside an
  agent-safe run too. Files are read with no schema, as JavaScript reads them: a
  hand-edited file holding JSON of another shape gives what the TypeScript
  code gives (`lib/jsjson` values, `internal/jsval`'s property reads), and
  where that code throws a `TypeError`, a `*TypeError` (the `uncaught`
  difference below). The commands `status`, `server`, `server use` and
  `context` are `internal/cli`'s `contextcmds.go`.
- `internal/apiclient/`: the client half of `packages/sdk` (slice 5.1c):
  the transport behaves as Node.js's fetch does for the TypeScript CLI
  (undici's timing: 10 s to connect, 300 s for the headers and between body
  chunks, no overall deadline; HTTP/1.1; at most 20 redirects, with 303,
  and 301 or 302 after a POST, becoming a GET without the body,
  Authorization dropped when the origin changes, and a redirect to a URL
  with credentials refused; the Fetch standard's bad ports refused;
  `Accept: */*`); the requests carry the same
  Authorization, User-Agent, Content-Type, Approval and Idempotency-Key
  headers as the SDK's (the TypeScript CLI passes no idempotency key, so
  neither does the Go CLI); answers come back as `lib/jsjson` values
  (`Undefined` for none), and error answers as `*APIError` with the
  server's fields as JavaScript holds them. A 503 `MAINTENANCE` is ridden
  out within the client's budget (180 s, from the first such answer until
  the server answers otherwise; `Retry-After` read with `Number()`, so a
  missing one is 0 and one that is not a number is 5 s, with ±20% jitter).
  A failure to connect is a `*FetchError` ("fetch failed") with the code
  `exitCodes.ts`'s `networkFailure` gives (`ECONNREFUSED`, `ENOTFOUND`,
  ..., else "network error"). `apiclient/v1` holds the request and
  response types generated from `packages/protocol/openapi.yaml`
  (oapi-codegen, models only; `go generate ./...`), never imported from
  `server/api`. `internal/cli`'s `client.go` is how commands use it:
  `connectClient` (no credential, or one only an agent-safe run's operator
  holds: 77), the stored credential's expiry warning and the server's
  `Varlatch-Credential-Expires` warning for `VARLATCH_TOKEN` (once per
  process, on stderr), the maintenance notice (once per process), and
  main.ts's mapping of what the client throws to a message and an exit
  status (a pending step-up approval and a passkey verification 77,
  maintenance that outlasted the wait 69, any other API error by
  `apiErrorExit`, a server that cannot be reached 69). `probe.go` is
  `status --probe`, reading each answer as JavaScript would, so an answer
  of another shape gives the TypeScript CLI's `TypeError` text as the
  probe's detail.
- `testdata/vectors/apiclient.json` (`apps/cli/test/go-vectors-apiclient.test.ts`):
  what the SDK makes of 45 answers (the value, or the error's fields) and
  what main.ts's catch prints and exits with for each error, 26 maintenance
  sequences with the clock and `Math.random` fixed (every wait, the
  notice, the requests, the results), the expiry warnings, and
  `encodeURIComponent`. `internal/apiclient` and `internal/cli` replay
  them through the real transport.
- `internal/toml/`: `varlatch.toml` as smol-toml 1.9.0 (which the
  TypeScript CLI bundles) reads it: a port of its parser, under its
  BSD-3-Clause license as well (`LICENSE-smol-toml-BSD-3-Clause`, listed in
  `scripts/third-party-code.json`), with its error messages, and positions
  and columns in UTF-16 code units, so a refused file gets the same message
  and caret.
- `internal/jsval/`: JavaScript's own semantics where an answer depends on
  them: a property read of any JSON value, strict equality, `Number(text)`,
  the default sort order, how `readFileSync(path, "utf8")` decodes bytes
  (the WHATWG decoder: one U+FFFD per ill-formed sequence), how Node.js
  writes a lone surrogate (U+FFFD), and `Date.parse`: V8's date parser
  ported (`date.go`, from V8 14.6.202 under its BSD-3-Clause license as
  well, `LICENSE-v8-BSD-3-Clause`): the ISO form with V8's extensions, then
  its older parser ("Nov 17 2026", "2026-11-17 10:00:00", "5"), local time
  through the time zone database, taking the offset before a change of
  offset as V8 does.
- `testdata/vectors/context.json` (`apps/cli/test/go-vectors-context.test.ts`):
  213 `varlatch.toml` documents and what `loadRepoConfig` makes of each
  (every one of smol-toml's messages), `Date.parse` of 127 texts in
  America/New_York, UTF-8 decoding, `Number(text)`, and 34 sequences of
  credential store, settings and local state operations from the files a
  CLI or a person may leave, each with its results and every file
  afterwards, byte for byte and mode for mode (`internal/clientctx`'s
  `TestStoreVectors`).
- `internal/transcript/`: the transcript replayer (test infrastructure).
  `apps/cli/test/go-transcripts.test.ts` records cases from the TypeScript
  CLI as users get it (its arguments, a clean environment, files, standard
  input and a scripted fake server; what it printed, its status, the
  requests it sent and the case directory's whole final tree) into
  `testdata/transcripts/`, and `TestTranscripts` replays every case
  against this CLI and compares byte for byte, strictly both ways: an
  unexpected or missing request, and any file, directory or link added,
  deleted, changed or given another mode, inputs included, fails a case.
  Request bodies are compared as JSON values through `lib/jsjson`, so lone
  surrogates stay distinct. Both sides run under umask 022; on Windows only
  a mode's read-only bit is compared. A case may unset variables of the
  clean environment (`unset`, to reach the default configuration
  directory). Regenerate after changing the cases with
  `VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run
  test/go-transcripts.test.ts`.
- `testdata/vectors/framework.json`: what the TypeScript code answers for
  the option parser, help, safe text, assisted mode, the global options,
  the User-Agents and the exit status of an API error
  (`apps/cli/test/go-vectors-framework.test.ts`); `internal/cli`'s tests
  replay them.
- `testdata/cli-inventory.json`: every command, option literal and
  environment variable of the TypeScript CLI, with the files it appears in
  (held equal to the source both ways by `apps/cli/test/cli-inventory.test.ts`),
  each command's slice, the precedence chains and the command-specific exit
  statuses. `TestInventoryCoverage` checks that the command table agrees
  with it and that everything of a built slice (`built`) has a recorded
  case or a vector: a built command, each of its options, each variable,
  chain and exit status. Missing coverage fails. `TestClientLacksNotStale`
  checks `scripts/conformance/client-go.json` against `built`.
- `internal/agents/`: `varlatch agents guide` and `agents install`
  (slice 5.1d), a port of `apps/cli/src/agents` (`install.ts`, `files.ts`,
  `toml.ts`, `mcpConfig.ts`, `skill.ts` and the files `guardrails.ts`
  writes): the skill in `.agents/skills/varlatch` and
  `.claude/skills/varlatch`, the marked block in `AGENTS.md`, the
  adapters (`CLAUDE.md`'s import, the Gemini CLI's `context.fileName`,
  `.aider.conf.yml`'s `read:`), `--guardrails` (Claude Code's
  `.claude/settings.json`, Codex's `.codex/hooks.json` and the marked
  region of `.codex/config.toml`) and `--mcp` (each coding agent's MCP
  file), with `--check` and `--remove`. Files get the TypeScript CLI's
  bytes and modes (a new file the default mode less the umask, a changed
  one its own mode kept). A file is replaced by a temporary file in the
  same directory, created readable by its owner only, synced, given its
  final mode, then renamed over it. A file with several names (hard links)
  is replaced only when every name is one install itself gives it (an
  `AGENTS.md` and the `CLAUDE.md` that is it, found in the root); each name
  is then renamed onto the new file, so they stay one file, and
  `--remove` takes such a pair away under both names, reporting each once.
  Any other second name (one the CLI cannot see, possibly outside the
  root, or any second name of a file outside a project's pair, such as a
  skill file) refuses the run before anything is written or removed (78):
  `<path> has another name (a hard link) the CLI does not manage, so
  nothing was changed; replace it with a plain copy of itself, then run
  this again`. The names are counted before the replacement, not as one snapshot with it:
  a name created during the run may keep the old content, and nothing
  outside the root is ever changed. A pair is renamed one name at a time,
  not as a transaction: a crash between the two renames leaves one name
  with the old content and the other with the new, each complete, never
  partly written. They are then two files, and running install again
  treats them so (`CLAUDE.md` gains the import of `AGENTS.md`). A
  directory below the scope's root (the project, or the home directory
  for `--scope user`) that is a symbolic link or a Windows junction, on
  the way to a file the run reads, writes, removes or prunes, refuses the
  run before anything is touched (78). Every write and removal checks the
  path again and goes through an `os.Root` at that root, which confines
  path resolution to the root (not other names of the same file: that is
  the hard-link rule's job). Planning reads use ordinary file calls,
  after that check; an `AGENTS.md` or `CLAUDE.md` that is itself a link is
  read, never written through, as before (`contain.go`). A settings file
  is edited only when the edit keeps its formatting. JSON is read and written as
  JavaScript does (`lib/jsjson`), and `config.toml` is judged by
  `internal/toml`, which keeps every value as smol-toml gives it, so a
  change is made only when the parser shows the file then says exactly
  what it said plus the change. The skill is embedded from
  `apps/cli/skill/varlatch` into `skillfiles.gen.go` by `gen_skill.go`
  (`go generate ./...`); `TestSkillFilesCurrent` fails when it is stale,
  and checks it against the TypeScript CLI's own embedded copy. `agents
  hook` (the guardrail hook itself) is slice 5.6a. `internal/cli`'s
  `agentscmd.go` is the commands and `init` with its flags (`--org`,
  `--project`, `--server`, `--default-environment`, `--no-agent-files`);
  `init` on a terminal without them (guided) is slice 5.8a.
- `testdata/vectors/agents.json` (`apps/cli/test/go-vectors-agents.test.ts`):
  the pure edits (the block, the imports, the Gemini CLI's context, 46
  `.aider.conf.yml` layouts, 35 `config.toml` texts through each of the
  four TOML edits, `agents guide`), and 263 projects (files, symbolic and
  hard links, files that are not UTF-8, directories in the way) taken
  through runs of install, check and remove for every coding agent, with
  and without `--guardrails` and `--mcp`, in both scopes: each run's
  result or error, its lines, and the whole tree afterwards
  (`internal/agents`' `TestInstallVectors`).
- Values and import (slice 5.3a): `internal/cli`'s `values.go` (`values
  set`, `list`, `delete`, `rotate`, `rotate-complete`, with assisted mode's
  `--replace` and `--confirm`), `validate.go` (`validate [--json]`, 0
  valid, 1 invalid, 2 incomplete) and `importcmd.go` (`import <file>` with
  `--dry-run`, `--contract`, `--plain`, `--replace`, `--delete-source` and
  `--json`); `internal/secretinput/` is `secretInput.ts` (the value from
  an argument, `--stdin`, `--from-file`, `--generate` or the hidden
  prompt) and `internal/dotenv/` is `dotenv.ts`. Values are secrets: the
  run holds the values in flight (the value `values set` or `values
  rotate` sends, the Secrets `import` reads) and the central fail-safe
  (`RedactDiagnostic`, `RedactOutput`, `RedactValue`) redacts each exact
  occurrence of them, whatever their length, in every output and
  diagnostic; a server's identifiers are shown only of the server's shape,
  and validate and import show only the report's and the Contract's
  documented fields. `TestValuesNeverPrintAValue`,
  `TestShortValuesNeverShown` and `TestServerFieldsNeverPassThrough` take
  canary values through every path, server echoes (in errors and in a
  successful answer's version id), extra fields and parse errors included.
  The hidden prompt installs its signal handler, then puts the terminal in
  raw mode (`golang.org/x/term`), reads keys as `HiddenInput` does, and
  restores the terminal before signal delivery stops, however it ends:
  Enter, Ctrl-D, Ctrl-C (130, nothing stored), a panic, or SIGINT,
  SIGTERM or SIGHUP (the signal then ends the process, as it ends
  Node.js) or SIGQUIT (exit 131). Backspace removes one extended grapheme
  cluster, as `Intl.Segmenter` finds it: `secretinput/graphemes.json`
  holds each code point's segmentation properties as the ICU inside
  Node.js shows them, written by probing the segmenter
  (`apps/cli/test/go-vectors-values.test.ts`). The pseudo-terminal tests
  (`TestHiddenPromptOnATerminal`, `TestHiddenPromptRestoresTheTerminalOnASignal`,
  Linux and macOS) check that nothing typed is echoed, the value sent, and
  the terminal's state afterwards, a signal in the window before the
  question included.
- `testdata/vectors/values.json` (`apps/cli/test/go-vectors-values.test.ts`):
  what `parseDotenv` makes of 68 files, `secretInput.ts`'s checks (the
  generators, the value sources, input bytes, well-formed text, the hidden
  prompt's keys) and 2,022 texts split into grapheme clusters, `validate`'s
  outcome and `--json` document for 17 reports, and import's type
  inference (every semantics version), name checks and strict decoding.
- The process tests of `apps/cli/test` run against a Go binary with
  `VARLATCH_TEST_CLI=<path>` (`cliUnderTest.ts`); `go-cli-files.json` lists
  the files that must pass.
- Conformance: `node scripts/conformance/run.mjs --target <target> --cli
  go:<path to varlatch>` runs the suites with this CLI; the features it
  does not have yet report client-lacks (`scripts/conformance/README.md`).
  The `cli-handover` suite pairs it with the TypeScript CLI 0.22.0
  (`--handover-cli` chooses another) and checks that each uses what the
  other stored (internal `docs/design/go-cli.md`, decision 11).

Text the Go CLI copies byte for byte from the TypeScript CLI's output (the
usage text in `usage.txt`, and the recordings and vectors made from it)
keeps its original characters, the em dash in the usage banner included:
the TypeScript line is frozen to security fixes, and parity needs the bytes
as they are.

### The Go CLI's accepted differences

Where the Go CLI differs from the TypeScript CLI on purpose (internal
`docs/design/go-cli.md`, decision 12). A transcript case names the
difference it relies on (`differences`), and `transcript_test.go` applies
it to the recording.

| Difference | TypeScript | Go | Why |
| --- | --- | --- | --- |
| `version` | `varlatch --version` prints `varlatch <version> (migration <n>)` | `varlatch <version>` | Decision 6: the migration number is the TypeScript release manifest's; every consumer (installers, menu bar app, tray, omarchy plugin, tap) reads the first two words |
| `uncaught`: an error no command handles (for example a `credentials.json` entry or a `.varlatch/local.json` holding `null`, or a `varlatch.toml` that is a directory) | escapes `main()`; Node.js prints the source line, its stack trace and its version, and exits 1 (the recorder keeps `{{uncaught <name>: <message>}}`) | `varlatch: <error>`, one line on stderr, exit 1 | A stack trace is not output anyone parses; the status and stdout are compared as recorded |
| Diagnostics never print credential values | not compared | Every write goes through one fail-safe, so every path is covered by construction. On stdout (`Run.out`: every line, `verify-release`'s results), every text in Varlatch's token format is `[redacted]` (`cli.RedactOutput`), and every string of a `--json` document also has a URL's user name and password masked (`printJSON` through `cli.RedactValue`; keys untouched, the document still valid JSON). On stderr (`cli.RedactDiagnostic`: every failure in `Run.finish`, every other line through `Run.warn`, `verify-release`'s failures), every token is `[redacted]` too, and `clientctx.MaskUserinfoInText`, one linear pass over the whole message, masks from just after the first `:` that follows a letter to the last at-sign (`@`, `\u0040`, `\x40`, `\U00000040`, `%40`; tab, CR and LF ignored in finding them) as `[redacted]@`; failure text may be over-masked, never under-masked. On top of it, a precise layer per value: every server shown, every value a failure echoes (an argument, a command, a topic, an approval id, a path) and every value human output takes from a server's answer is masked on its own with `clientctx.MaskUserinfo` (through `MaskURLInValue`), by the authority `lib/whatwg` parses, so a value without a user name and password, such as `https://example.com\path@segment`, keeps its bytes. The option parser never shows the value of an option it refuses with the value attached (`--name=value`, `-Xvalue`), whatever the option: `--name=[redacted]`, `-X[redacted]`. A header value that cannot be sent is refused before anything is sent, with a message that names the header (`the credential contains a character that is not allowed in an HTTP header`). A failure that echoes a value holding an at-sign puts the value first and its explanation after it, so the fail-safe keeps the explanation: `varlatch server: https://[redacted]@h: unexpected argument`, `varlatch logout: https://[redacted]@h: no credential is stored for this server`, `https://[redacted]@h/v1/meta: a server URL with a user name or password can't be used; remove them and try again`; the usage text appended to a usage error is printed after the fail-safe | Output is printed, logged and pasted into issues: in error text never leaking comes before byte parity, while the precise layer keeps ordinary output, and every value without a user name and password, byte for byte (every recorded transcript replays, two cases through `backslash-path` and one through `option-value`); the exit status is the same. Pinned by `internal/cli`'s `TestServerURLsNeverShowUserinfo`, `TestClientMessagesNeverShowUserinfo`, `TestNotAuthenticatedReadsAfterTheFailSafe`, `TestFailuresNeverEchoUserinfo`, `TestFailuresKeepTextWithoutCredentials`, `TestFailureExplanationsSurvive`, `TestSessionExplanationsSurvive`, `TestRedactDiagnostic`, `TestParserEchoesNoOptionValue`, `internal/clientctx`'s `TestMaskUserinfo`, `TestMaskUserinfoAgreesWithWHATWG` (both ways, over 8,800 texts on which `lib/whatwg` and Node agree), `TestFailSafeMasksEveryReproducer` (every leak found in review, through the fail-safe alone), `TestFailSafeRule`, `TestFailSafeMultiLinePasswords`, `TestFailSafeAgreesWithWHATWG`, `TestHasAtSignIsTheFailSafesDetection`, `TestMaskingIsLinear`, `TestMaskingIsLinearOnLargeMessages` and `FuzzMaskUserinfoInText`, `internal/apiclient`'s `TestRefusalsNeverShowCredentials` and `TestRefusalsReadAfterTheFailSafe`, the process tests `TestDiagnosticsNeverPrintCredentials`, `TestSessionCommandsNeverShowUserinfo` (login, logout and whoami, every WHATWG authority form), `TestLoginNeverShowsTheCredential` (a credential given to `login` never appears in its output, accepted or refused), `TestUsageErrorsNeverEchoACredential`, `TestLoginServerTokenIsNeverEchoed`, `TestOutputNeverShowsAToken` (tokens and URLs in `--json` documents and human output, from the server, the environment and the store) and `TestEveryWriteGoesThroughTheFailSafe` (no write to stdout or stderr, no `log`, and no JSON for stdout outside the fail-safe, across `go/cmd/varlatch`), and `TestVerifyReleaseNeverEchoesUserinfo` |
| `backslash-path`: a special scheme's URL whose at-sign follows a backslash in its path, such as `https://example.com\path@segment` | since 0.22.2, masked to `https://[redacted]@segment`: `maskUserinfo` reads the authority through a backslash | shown as it is: the backslash starts the path, so the URL has no user name or password | Masking reads the authority `lib/whatwg` parses, as `new URL` does (the row above), so a value without a user name and password keeps its bytes; the recording is accepted only where Go's stdout, with the fixture URL shown as TypeScript shows it, is the recording (`TestBackslashPathDifferenceIsExact`) |
| `option-value` (how transcripts and vectors compare, not a behaviour) | not compared | a recorded "unknown option" message is compared with an attached option value shown as `[redacted]` (`cli.OptionValueDifference`) | The Go CLI never shows an option value in a usage error ("Diagnostics never print credential values"); the rest of the message, the status and stdout are compared as recorded |
| `whoami --json` prints only the documented fields | not compared | the schema version, the server it asked (masked; nothing in the answer replaces it), then only the fields of the API's WhoAmI document (`identity`, `organization`, `credential`, `listener`, `tailnet`), each object with only its own documented fields, in the answer's order | A document scripts read holds only what the API defines; for an answer that keeps to the API, the output is the same. Pinned by `TestWhoamiJSONShowsOnlyTheDocumentedFields` |
| The excerpt is left out when the file may hold credentials: a `varlatch.toml` that does not parse and holds an at-sign | smol-toml's message, `Invalid varlatch.toml: Invalid TOML document: <what>` followed by the lines around the error, quoted | `Invalid varlatch.toml: Invalid TOML document: <what>, line <n>, column <n> (the file may hold a URL's user name and password, so its lines are not shown)` when the file holds an at-sign of any form, as the fail-safe detects one (`@`, `\u0040`, `\x40`, `\U00000040`, `%40`, tab, CR and LF ignored; `clientctx.HasAtSign`); a file without one gets smol-toml's message byte for byte | The quoted lines can hold part of a URL's user name and password and end before its at-sign (a string that runs on past them), where neither the precise layer nor the fail-safe sees a URL; a file without an at-sign holds no URL's user name and password. This reaches stderr (`context`, every command that reads `varlatch.toml`) and `server`'s stdout (`Server here: none (...)`). Pinned by `internal/cli`'s `TestTOMLExcerptLeftOutWhenFileMayHoldCredentials` (Sol's reproducer, a credential on the line before the error and several lines after it, every at-sign form, `server`'s stdout) and `TestFailuresKeepTextWithoutCredentials`; the 213 recorded `varlatch.toml` documents (`testdata/vectors/context.json`) and every transcript are unchanged |
| The Node.js version warning | one line on stderr below a Node.js release's security floor (`VARLATCH_NODE_CHECK=off` hides it) | none | No Node.js; the recorder sets `VARLATCH_NODE_CHECK=off` |
| `user-agent` (how transcripts compare, not a behaviour) | `varlatch-cli/0.22.0 (<platform>; <arch>[; assisted])` as recorded | the same format with this build's version, platform and processor | Each CLI names itself; the recording's values belong to the recorder's machine |
| Trust roots | Node.js's bundled Mozilla roots, plus the PEM file `NODE_EXTRA_CA_CERTS` names (Node.js warns once on stderr when it cannot read it) | the system's roots, plus the same file; one it cannot read adds nothing, silently | Decision 4: a self-hosted installation behind a private CA keeps working; the system's roots are where Go and operators keep them |
| Proxies | fetch reads no proxy from the environment, unless Node.js is started with `NODE_USE_ENV_PROXY=1` | never (`Proxy: nil`) | Decision 4; the Go CLI has no Node.js option to honour |
| Runtime error wording: the code in `Cannot reach the Varlatch server (<code>)` | the first code in the `fetch failed` error's causes that `exitCodes.ts` names, else "network error" | the same codes from Go's errors: refused, reset, timed out, unreachable host or network by their errno; NXDOMAIN `ENOTFOUND`; a temporary DNS failure `EAI_AGAIN`; a connect or TLS handshake timeout `UND_ERR_CONNECT_TIMEOUT`; a connection closed before the answer `UND_ERR_SOCKET`; anything else "network error" | Decision 2: the exit status (69) is the same; the code is Node.js's own wording, mapped where Go can tell |
| Request headers decision 2 does not compare | `accept-language: *`, `sec-fetch-mode: cors`, `accept-encoding: gzip, deflate` | none of the first two; `accept-encoding: gzip` (Go decompresses it) | Neither the server nor any consumer reads them |
| `skill-version` (how transcripts compare, not a behaviour) | the skill files `agents install` writes name `varlatch 0.22.0` (`SKILL.md`'s `metadata.generator`, each reference's first line) | this build's version | Each CLI names itself, so `--check` after an upgrade reports the skill as changed; the replay puts this build's version in a case's inputs and expected files alike |
| A system error while `init` writes the agent files (a directory where a file goes, a file it cannot read) | `varlatch: the files for coding agents were not written (<Node.js's message>); run varlatch agents install to try again.`, exit 0 | the same line with Go's message, exit 0 | Decision 2: runtime error wording; what the files are refused for by the CLI itself (a damaged `AGENTS.md`) has the same message in both |
| `agents install` never writes or removes through a symbolic link | not compared | a directory below the project root (or the home directory, for `--scope user`) that is a symbolic link or a Windows junction, on the way to a file the run reads, writes, removes or prunes, refuses the run before anything is touched, `--check` included: `<path> is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed. Replace it with a directory, then run this again`, 78; a refused `--remove` also lists the skill files it would have removed, for removing by hand | Installing agent files never changes anything outside the project or the home directory; `internal/agents` `TestNothingThroughALinkBelowTheRoot` |
| `init` and a server URL with a user name or password | not compared | refused from any source (`--server`, `VARLATCH_SERVER`, the default server, the only stored credential), judged on the server as `varlatch.toml` will give it back: a user name or password as `new URL` reads it, an at-sign in any form in a text that does not parse, or a backslash with an at-sign in any form (`\u0040`, `%40`, ...) after it: `varlatch init: a server URL with a user name or password can't be written to varlatch.toml; give the server's address without them. Nothing was written.`, 64, nothing written and the URL not repeated | `varlatch.toml` is committed; `cmd/varlatch` `TestInitRefusesServerCredentials`, `clientctx` `TestHasUserinfo` |
| `toml-escaped`: how `init` writes `varlatch.toml`'s values | not compared | each value as an escaped TOML basic string (`\"`, `\\`, control characters), so the file reads back as exactly what was given | A value with a quote, a backslash or a control character means what it says; transcripts compare the escaped form (`init.raw-values`); `TestInitValuesReadBackAsGiven` |
| How `agents install` replaces a file | in place (`writeFileSync`) | a temporary file in the same directory, readable by its owner only until it is complete, synced, given the file's mode, then renamed over it; the names of a hard-linked `AGENTS.md`/`CLAUDE.md` pair are each renamed onto the new file; a file with any other name is refused (78) | A crash or a full disk never leaves a settings file empty or half written, and no other file shares the change; bytes and modes are the same |
| No message holds a value: an argument `values set` or `values rotate` refuses (`value-free-usage`) | the option parser's message | never repeated, whatever its spelling: `unexpected argument <n>, not shown since it may be part of a value (a value with spaces goes in quotes)`, `unknown option at argument <n>, not shown since it may be a value (a value that begins with "-" goes after --)`, `--grace needs a whole number of seconds`, `<n>` counting the arguments after `values set` or `values rotate` | Any argument there may be the value or part of it; the status (64) is the same. Accepted only where Go's line is these words for the same command and holds no part of the argument (`TestValueFreeUsageIsExact`) |
| No message holds a value: a value in flight | not compared | each exact occurrence of the value `values set` or `values rotate` sends, and of each Secret (or item of unknown sensitivity) `import` reads, is `[redacted]` in every output and diagnostic, whatever its length, also where a server echoes it in an error or in a successful answer | A server, or anything between it and the CLI, never puts a value back on a terminal or in a log; a very short value may also redact the same characters in the CLI's own words |
| A server's identifier or hash of another shape (`unrecognized-id`) | shown as it is (escaped) | a version or revision id that is not the server's shape (a prefix and 26 characters of lower-case base32) is shown as `an unrecognized id`, a revision's content hash that is not `sha256:` and 64 hex digits as `an unrecognized hash` | A server never puts free text where the CLI shows an id; the status is the same |
| `validate` and `import` show only documented fields | not compared | `validate` shows the report's documented fields only, a requirement or reason outside the protocol's enumerations as `an unrecognized requirement` or `an unrecognized reason`; `import` shows a Contract item's type outside the Contract's types as `an unrecognized type` and its sensitivity as a boolean, in `--json`, human text and `--dry-run` alike | A server never puts an extra field, or a value, into what the CLI prints; a report or Contract of the protocol's shape gives the same bytes (`TestServerFieldsNeverPassThrough`) |
| `import --delete-source` and its source | not compared | the source must be a regular file named directly: a symbolic link (deleting it would leave the values in the file it points to), a directory, a device or a pipe is refused before anything is read or sent (1); the file is opened without following a link and read from what was opened, and deleted only if it still holds those bytes and the path still names that same file, so a file put in its place while importing is never removed; `deleted` is true only when the path is gone | `--delete-source` removes exactly the copy of the values that was imported, or says it did not (`TestDeleteSourceRemovesOnlyTheFileRead`) |
| `generated` (a pattern of the transcripts, not a behaviour) | the value `--generate` made, recorded by its generator as `{{generated <spec>}}` | the value Go sent, recorded the same way when it has exactly the alphabet and length the spec gives and appears nowhere in the output; otherwise a value-free note (`{{generated value of another shape}}`, `{{generated value shown in the output}}`), so neither a recording nor a failing comparison holds the value | Random in both CLIs (`internal/transcript` `TestGeneratedPatternIsExact`) |
| The hidden prompt's Backspace | removes one grapheme cluster as the ICU of the Node.js running the CLI finds it | removes one cluster by the table written from Node.js 26's ICU (Unicode 17), the rules of Unicode Standard Annex #29 | The same answers on 2,022 recorded texts; a TypeScript CLI under another Node.js may segment new characters differently |
| The hidden prompt when the terminal goes away before Enter | not compared | the terminal restored, `varlatch: no value entered; nothing was stored`, exit 1 | Nothing is stored either way; the Go CLI says so |
| A redirect's relative `Location` | resolved by the WHATWG URL parser | resolved by `apiclient`'s own resolver (absolute, `//host`, `/path`, `?query` and path-relative references), then parsed by `lib/whatwg` | varlatchd sends no redirect; a proxy's is absolute or root-relative |
| `login` without `--token` or `--token-stdin` | browser sign-in, `--oidc`, and device sign-in (`--start`, `--wait`, and assisted mode's default) | a usage error (64) saying the method is not in this build of the Go CLI yet (slice 5.2), before anything is read, sent or written | Slice 5.2 ports them; `TestLoginLaterMethodsSayNotYet` |
| `now` (how transcripts compare, not a behaviour) | `login` and `env use` write the time of the run (`issuedAt`, `tierCachedAt`) | the same, at another time | A case that lists the `now` pattern has each ISO 8601 timestamp between its run's start and end written `{{now}}`, in the recording and the replay alike (`goKit.ts` `nowPattern`, `transcript.NowPattern`); a timestamp outside the run is compared as it is |

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
`install/unit_test.go`.

`varlatchd admin bootstrap [--cli-credential]` and `varlatchd admin
recover --identity <id> [--enable] | --new-admin [--cli-credential]`
(with `--config <file>`) print exactly what the TypeScript admin CLI
prints: a one-time enrollment URL, or a CLI credential on the last line.
A build with the `conformance` tag also has `varlatchd admin
conformance-probe` and `conformance-fixture`, the conformance harness's
probes and fixtures; a release has none. The harness seeds through `/v1`.

Host commands write through the daemon (step 4 decision 11,
`server/daemon/control.go`), because the write path's gates live in its
memory (`server/write`):

- `serve` holds an exclusive lock (`flock`) on `varlatchd.lock` in the data
  directory for its whole life; a second `serve` refuses to start, and so
  does a `serve` while an admin command runs offline. The kernel releases
  the lock when the process ends, however it ends.
- `serve` listens on `varlatchd.sock` in the data directory (mode 0600)
  and accepts a connection only from its own user or root (the peer's
  credentials, `SO_PEERCRED`). A command sent there runs inside the
  daemon, with its gates and its writer, and its output and exit status
  come back as if it ran in the caller.
- The data directory holds both, and the database, each opened by path,
  so the path itself must be trusted (`datadir_unix.go`): its last
  component is the directory, never a symbolic link; the path is resolved
  one component at a time, following each symbolic link by hand (at most
  40), and every directory it passes through is owned by root or a
  trusted user and is not writable by its group or others unless its
  sticky bit is set (as `/tmp`'s), and every link it follows, at any hop,
  is owned by root or a trusted user (macOS's `/var` and `/tmp` pass);
  and the directory is owned by the user varlatchd runs as and writable by
  no one else. `serve` refuses to start
  (78) otherwise, and checks after taking the lock and after binding the
  socket that the path still leads to the same directory (device and
  inode). `varlatchd admin` makes the same checks (trusting root, itself
  and the directory's owner; a non-root caller must own the directory),
  refuses a socket file that is not a socket owned by the directory's
  owner, and refuses a server whose peer credentials are not that owner's
  or root's. The shipped unit's directory (`/var/lib/varlatch`,
  `StateDirectoryMode=0700`) passes.
- A command takes the gates of the people and Organizations it writes, from
  the daemon's gate set, before its jobs are queued (`recover --identity`
  its subject, exclusively with `--enable`, as `issueRecoveryGrant` locks
  it; the conformance fixtures as the writers of the same rows would).
- `varlatchd admin ...` tries the socket first. If nothing answers, it
  takes the lock without waiting and runs the same code offline (creating
  the schema and the installation on a fresh data directory, as `serve`
  would); if a daemon holds the lock but its socket does not answer, it
  refuses and writes nothing.

### Backups and maintenance (step 4.14)

`server/backups` takes the installation's backups inside varlatchd
(Decision 7). The TypeScript server's backup socket is not ported: its
commands are host commands on the control socket, so they take the
daemon's maintenance admission and its one backup at a time.

    varlatchd admin backup run [--json]
    varlatchd admin backup status
    varlatchd admin backup test-bucket [--json]
    varlatchd admin backup restore --in <archive> [--backup-key-file <file>]
    varlatchd admin maintenance begin --ttl <duration>
    varlatchd admin maintenance end <lease id>
    varlatchd admin maintenance status
    varlatchd admin kek verify|export|restore|split|combine ...
    varlatchd admin custody attest --key <key> --method <method> | status

- **Settings** (`install/varlatchd.conf.example`): `backup_key_file` (the
  Backup Encryption Key, 32 bytes in hex or base64; without it no
  scheduled backup runs), `backup_interval` (24h by default, `off`, or 1h
  to 744h), `backup_keep` (7 archives on this host), and
  `backup_destinations_file` and `backup_destination` (the bucket, in
  `packages/backup`'s destinations format; without a file, archives stay
  on this host).
- **A run** refuses while a maintenance gate is open, without a BEK, with
  a BEK that is the Root KEK, and when the data directory has less free
  space than `RequiredSpace`: three times the database and its WAL (the
  snapshot, then the archive and its unpacked copy while it is checked)
  plus 64 MiB. It then takes the paced snapshot on the writer's
  connection (`lib/storage` `Snapshot`, with the `TRUNCATE` after it),
  reads the archive's metadata from the snapshot itself (the
  installation, its Root KEK version and canary, the schema version),
  refusing an incomplete Root KEK rotation as `archiveMetadata` does and
  a canary the loaded Root KEK does not open, seals the snapshot and
  `configuration.json` at 32 MiB/s, opens the archive again to record its
  check, uploads it, records the delivery, and removes the archives
  beyond `backup_keep` from this host. A stop ends a run at its next
  snapshot step or sealed MiB, and leaves no archive.
- **The schedule** first looks a minute after start, then takes a backup
  whenever the newest archive is `backup_interval` old (at that first look
  when there is none), retries an hour after a run that made no archive,
  and a minute after maintenance held one back. It goes by the archives'
  age, where the TypeScript host backup's systemd timer runs at a calendar
  time (03:30 UTC, `Persistent=true`), so the wall clock matters in two
  ways: every wait is at most an hour, so a clock moved forward makes an
  overdue backup within the hour; and after a clock moved back, archives
  dated in the future are passed over, the newest one that is not decides,
  and with none recent a backup is taken at once rather than when the
  clock catches up (`TestScheduleUnderClockChanges`).
- **Restore** (`admin backup restore`, offline only: it refuses while a
  varlatchd runs, and takes the data directory's lock) puts an archive's
  installation into a data directory, on a fresh host or over the same
  installation, from the archive and the two keys held apart from it: the
  Backup Encryption Key opens it, and the Root KEK must open its canaries.
  It refuses a TypeScript archive (step 7's migration converts those), an
  archive this release cannot open (another API major or schema), another
  installation's data directory, an open maintenance lease, and an archive
  with active audit exports (whose streams a restore restarts; that comes
  with the audit export's port). It then opens a restore gate, copies the
  snapshot beside the database, removes the old WAL, renames it into
  place, opens it with this release, checks the installation and its
  canary, records `installation.restored` (archive, manifest hash,
  installation) and removes the gate. A restore that fails or is killed
  leaves the gate: a varlatchd that starts then serves 503 MAINTENANCE and
  leaves the database untouched (no schema, installation or canary
  check), and running the restore again with the same archive completes
  it. It prints the archive's settings to compare with `varlatchd.conf`.
- **The bucket test** (`admin backup test-bucket`, G13) seals a test
  archive of this installation (its canary and identity; a marker stands
  in for the database, so no data leaves), uploads it as
  `<prefix>bucket-test/<id>.vltbak`, reads that exact version's retention
  mode and deadline, downloads that version and opens and checks it, then
  tries to delete that version and checks it is still there. Delivery,
  retention and recoverability are reported separately; it passes (exit 0)
  only with all three, and a bucket without versions, without a retention
  or that lets the version be deleted is reported unprotected. Only a
  refused delete counts: a client error (4xx) whatever its code (AWS and
  B2 answer AccessDenied, MinIO InvalidRequest), except 404, 408 and 429;
  a network or server error leaves the retention inconclusive. A test is admitted as a run is (refused during
  maintenance) and works in `backups/.bucket-test-<id>/`, which a run
  removes only when no test is running. Every
  upload sends `Content-MD5`, which B2 requires with Object Lock
  (`packages/backup`'s conditional put notes it; MinIO does not require
  it).
- **Key custody** (`crypto/escrow.ts`, `domain/custody.ts`; ADR-0035 D9):
  `kek export` writes the passphrase escrow blob, `kek restore` reads it
  back, `kek split` prints Shamir shares and `kek combine` joins them;
  restore and combine check the key against the installation's canary
  when there is a database (read-only), and warn on a fresh host. `kek
  verify` checks a key file (or the configured key). Every file they
  write (`--out`) is written as a temporary file of mode 0600 beside it,
  synced and renamed over it, so an existing file never holds the key with
  its old mode and a crash never leaves it truncated. Two consequences
  differ from the TypeScript CLI, which writes through the path: an
  `--out` that is a symbolic link is replaced by the new file (the link's
  target is left as it was), and an `--out` that is a single-file bind
  mount fails with EBUSY (rename cannot replace a mount point) and leaves
  it untouched; write to a directory instead. The passphrase comes
  from `--passphrase-file`, `VARLATCH_KEK_PASSPHRASE`, or the terminal
  without echo. `custody attest` records an
  `installation.custody_attested` audit event (the Root KEK's with its
  version), and `custody status` reads the latest per key, the Root KEK's
  only for its current version. The messages are the TypeScript CLI's. As
  there, `kek` and `custody attest` are refused during maintenance, and
  `custody status` is not.
- **The state** is the TypeScript server's, in the data directory, so
  step 7's migration and the Go CLI's `admin backup` (steps 5 and 6) read
  it as they are:
  - `backups/<archive id>.vltbak`, the archives (mode 0600);
  - `backups/<archive id>.json`, each archive's status record
    (`statusSchema`: identity, `verification`, `delivery`, `capture`),
    kept after local retention removes its archive, since the copy in the
    bucket and its Root KEK version remain. `getInstallationBackups`
    answers them, newest first, with `backupStatus`'s warnings;
  - `backups/.work-<archive id>/`, a run's temporary files, and
    `backups/<archive id>.vltbak.<hex>.partial`, a sealing in progress;
    both are removed by the next run if a run was killed, as is a killed
    bucket test's `backups/.bucket-test-<id>/`;
  - `maintenance.json`, the maintenance gate (`maintenance.ts`'s `Gate`:
    `id`, `kind` capture or restore, `phase`, `expiresAt` in Unix
    milliseconds for a lease, `archiveId`). A lease is a `capture` gate
    with an expiry; a restore's gate (4.14c) has none. A gate holds across
    a restart, and one that cannot be read keeps the installation
    isolated.
- **Maintenance** answers every API route `503 MAINTENANCE` with
  `Retry-After: 5`, as `app.ts` does, before the body limit; `/healthz`
  answers, `/readyz` is not ready, and the dashboard's files are served so
  it shows its maintenance screen. The TypeScript exemption of
  `/.well-known/jwks.json` (the Convex mirror's key fetch) has no Go
  counterpart.
- **Everything else that writes** enters the same admission, and an
  admitted piece of work is counted (`Admission.Busy`) until it ends, so a
  gate can tell when the work it waits for has finished:
  - host commands that write (`bootstrap`, `recover`, `security reset`,
    `unfreeze`, and the conformance build's probes and fixtures), through
    the socket or offline, enter before they take a gate or queue a job;
    under a gate they are refused with the TypeScript admin CLI's
    message, `Installation is in maintenance; ordinary admin operations
    are blocked`, and exit 1. `maintenance begin|end|status` and `backup
    status` stay available;
  - offline, nothing opens the database before a command needs it (its
    first use creates the schema and the installation): the maintenance
    commands and `backup status` work on the data directory's files only
    (`maintenance.json`, `backups/*.json`), and under a gate a command
    that writes, or `backup run`, is refused before the database is
    opened. The data directory's lock is taken first, as the TypeScript
    CLI takes its operator lease before it reads the gate: `flock` needs
    `varlatchd.lock` (an empty file), and a gate read before the lock
    could change before the command runs;
  - a backup run is admitted for its whole length, in one step with the
    check (`Enter`);
  - the Security Control report loop enters for each pass and skips the
    pass under a gate, as `startSecurityReportLoop` does;
  - a passkey-verification report count, which runs after its response,
    enters on its own and is dropped under a gate. The TypeScript server
    runs those counts outside admission;
  - the other loops write nothing: the realtime publisher reads the audit
    log, the trusted-proxy refresh resolves names, and the storage
    engine's checkpoints move no data in or out of the database.
- **An archive** is format 3 (`lib/backup`): `varlatch.db`, the snapshot,
  and `configuration.json`, `{"formatVersion":1,"settings":{...}}` with
  the non-key settings by their `varlatchd.conf` names (paths on this
  host, the data directory and the key files, are left out). Its status
  record's `capture` holds the snapshot's duration (`snapshotHeldMs`),
  the sealing's (`dumpMs`) and the snapshot's size (`dumpBytes`).

### The outbound policy (step 4.7)

`server/outbound` is ADR-0057's outbound policy (`net/outbound.ts`,
`net/outbound-check.ts`). Every request whose destination an Organization
can choose or influence goes through it, and only it.

- **The decision** is the TypeScript server's, held to it by vectors
  (`testdata/ts-vectors.json`, written and checked by
  `services/varlatchd/test/go-outbound-vectors.test.ts`): the class of
  every address form (IPv4, IPv6, mapped, compatible, NAT64, link-local,
  CGNAT, the metadata services, and strings that are not addresses), the
  allow list parser's entries, refusals and doctor's warnings, 705
  decisions, and the refusal sentences.
- **The allow list** is `outbound_allow` in `varlatchd.conf`
  (`VARLATCH_OUTBOUND_ALLOW` today), checked when the file is read. An
  entry's text, warnings and errors are the TypeScript ones, which still
  name `VARLATCH_OUTBOUND_ALLOW`.
- **The connection check** (ADR-0057 Decision 4) is in the dialer: it
  resolves the name once, decides every answer (one refused answer
  refuses the name), and connects only to the addresses it checked, the
  first answer's family first and the other after 300 ms (Happy
  Eyeballs); a literal address is decided as it is and never looked up.
  A resolver whose next answer differs changes nothing for a connection
  already checked, and the socket's own address is checked again as it
  connects (`net.Dialer.Control`). One deadline (10 s) bounds every
  attempt to every checked address together, each attempt taking an
  equal share of what remains (at least 2 s, as Go's own dialer), as
  undici's connect timeout does; a lookup has its own (10 s), and a
  failed one names only the name, never the resolver's address. TLS and
  the Host header use the URL's name. No environment proxy applies,
  redirects are never followed, and a URL carrying credentials is refused.
  The transports are shared by every purpose, pooled per origin.
  `Transport` hands the same round tripper to clients that take one (the
  audit export's S3 client, 4.11); it refuses a redirect itself, so a
  caller's client that would follow one cannot.
- **Refusals** are `RefusedError` (the fixed sentence, never the address)
  and `outbound.refused` audit events within the rate bound: a
  configuration-phase refusal always, a connection-phase one once per
  Organization, purpose, object and reason an hour and at most 100 an hour
  in all, the held-back count carried by the next one.
- **The configured destinations check** (`admin outbound check [--allow
  <value>] [--org <org>] [--json]`, read-only, DNS lookups only, exit 0, 1
  for a refusal, 2 for an unresolved name), and the two pages that show it
  (`getInstallationOutbound` for Installation Admins,
  `refusedDestinations` for an Organization's admins): webhooks, Coolify
  and Convex Connections and OIDC issuers, with the allow list value that
  would open the refused names. Lookups are bounded (8 at once in the
  process, one per name and policy at a time, one per name within a scan),
  and a page's scan is shared while it runs and reused for 30 seconds.
  Rows are ordered by Organization slug in byte order.
- **The structural test** (`structure_test.go`) parses every non-test file
  under `go/server`, `go/cmd/varlatchd` and `go/lib` and fails on a
  request made outside this package: any use of `net.Dial*`, `net.Dialer`,
  `net.Listen{Packet,UDP,IP,MulticastUDP}`, `tls.Dial`,
  `tls.DialWithDialer`, `tls.Dialer`, anything of `net/smtp`, the `Dial`s
  of `net/rpc`, `net/rpc/jsonrpc` and `net/textproto`,
  `http.DefaultClient`, `http.DefaultTransport`, `http.Get`, `Head`,
  `Post`, `PostForm` and `http.ProxyFromEnvironment`; DNS lookups, a
  channel out of their own (`net.Lookup*`, `net.ResolveTCPAddr`,
  `ResolveUDPAddr`, `ResolveIPAddr`, `net.DefaultResolver`,
  `net.Resolver`); httputil's `ReverseProxy` and
  `NewSingleHostReverseProxy` (a nil Transport is the default one); an `http.Client` or `http.Transport` value (a literal,
  `new` or `make`, a variable, a struct field or a declared type, alias or
  defined, of it or of an array, slice, map or channel of it, and a
  pointer element in a composite literal, whose elided `{}` makes one: a
  zero client sends through the default transport); a dot-import of
  `net`, `net/http`, `net/http/httputil`, `crypto/tls`, `net/smtp`,
  `net/rpc`, `net/rpc/jsonrpc` or `net/textproto`; or an S3 client. Imports are
  matched by path. Each reviewed exception names its file, its use and
  how many times: in go/server the daemon's Unix control socket (twice),
  the host's trusted_proxies names and the host's backup destination
  (ADR-0057 Decision 1); in go/lib the backup destination's client and
  Sigstore's TUF repository.
  It is a check of syntax, not of types: a request through a value of
  these types obtained another way (a pointer handed in, returned by a
  function, reached through reflection), or made inside a third-party
  package, is not caught; review covers those.
- `externaleffect.ts` (the effect's deadline and the refusal records kept
  across a rollback) is not ported here: webhooks do not run inside an
  external effect in TypeScript, and in Go a request's deadline is its
  context, which the dialer honours. The effect framework (decision 4)
  lands with its first user (4.9 or 4.10).

### Audit webhooks (step 4.7b)

`server/webhooks` is `domain/webhooks.ts`, with integrationstepup.ts'
webhook bindings: an Organization's endpoints that receive its own audit
events, signed (`X-Varlatch-Signature: t=<seconds>,v1=<hex>`, HMAC-SHA256
of `<seconds>.<body>` with the webhook's secret).

- **Operations.** `listWebhooks` (organization.manage, inspection while
  frozen), `createWebhook`, `updateWebhook` (under an Idempotency-Key) and
  `revokeWebhook`, each a protected operation (admin-step-up's
  `webhook.create`, `.update`, `.delete`), with the TypeScript order of
  refusals: an Organization being deleted, then the URL (WHATWG, http or
  https, no userinfo), then the outbound policy, all before any approval.
  A refused URL answers `VALIDATION_FAILED` with `details.outbound` (the
  reason, never the address) and is recorded as `outbound.refused` in a
  job of its own, which the failed request does not roll back. A name
  that does not resolve is saved. The secret (`vlt_whsec_` and 32 random
  bytes) is sealed under the Organization KEK (`webhook-secret`) and shown
  once. `IdempotentProtected` (the claim inside the approval gate) moved
  from server/access to server/security, which both use.
- **Delivery.** A pass at once, then every 30 seconds
  (feature-parity decision 10), skipped while the maintenance admission
  is closed. Per live webhook of a live Organization, not suspended by a
  deletion: up to 100 events after its cursor, of its filter's types when
  it has one; the deletion lifecycle's events and those of a deleted
  Project (or one of its environments) are left out, and a batch with
  nothing left moves the cursor past it. Right before sending, the
  webhook is read again (not revoked, not suspended, its Organization
  live and without an open deletion) and the KEK with it. One POST
  through the outbound policy's webhook client, 10 seconds in all; the
  cursor moves only on a 2xx, so a failure retries the same batch on the
  next pass. What the row keeps is what the TypeScript server keeps: the
  status code, `outbound_refused` (the refusal recorded, within the rate
  bound), `TimeoutError`, or `TypeError` for any other failure, a
  redirect included. A delivery cut short by a stop records nothing, and
  the next start sends it again.
- **The request is the WHATWG URL's.** The host is the one `new URL`
  gives (`0x7f.1` is `127.0.0.1`), so the policy decides what fetch would
  connect to; the path and query are percent-encoded as fetch sends them
  (`whatwg.URL.RequestTarget`), and the fragment is never sent. Headers
  beyond Content-Type and the signature are Go's, not Node's (no
  `accept-language` or `sec-fetch-mode`); receivers verify the signature
  only.
- **Parity.** `webhooks-v0.22.0.json` and `webhooks-v0.21.0.json`
  (go-webhooks-fixture.test.ts) replay every operation's answers, audit
  events and side rows, then one delivery pass at a fixed second whose
  requests must match byte for byte, signatures included: G3 for webhook
  secrets at the database level from both releases. `TestGoSealedFixture`
  seals the secrets again in Go, and go.yml has the TypeScript server
  deliver with them (the reverse direction). The `webhooks` conformance
  suite runs against a local receiver on every target.

### OIDC workload identity (step 4.8)

`server/oidc` (AGPL) is `auth/oidc.ts` and the exchange of `domain/oidc.ts`;
the bindings' operations are in `server/identities/oidc.go`, beside the
other machine identity step-up operations.

- **Bindings.** `listOidcBindings`, `createOidcBinding` and
  `revokeOidcBinding` bind an issuer, an audience and a subject (and
  optional exact-match claims) to a machine identity: identity.manage,
  existence hidden.
  - The issuer must be a plain https URL. The outbound policy checks it
    (`oidc`, configuration phase, recorded) before anything is held.
  - Creating and revoking are admin-step-up's `oidc_binding.create` and
    `oidc_binding.delete`.
  - Revoking is a recovery operation while frozen.
- **The exchange** (`POST /v1/oidc/token`, no bearer) runs in this order:
  1. the issuer's live bindings in the Organization (by id or slug), for
     identities not disabled;
  2. the token verified against that issuer's keys;
  3. the bindings that match: the audience (or a member of an array), the
     subject (exact, or a prefix when it ends with `*`), every extra claim
     exactly. They must all name one identity;
  4. an oidc credential of that identity, ten minutes by default, at most
     an hour, issued under its live, held Organization.

  Every failure answers 401 `INVALID_CREDENTIAL` alike; the
  `authentication.failed` event keeps the reason.
- **The verifier** (`verify.go`) checks the token as the TypeScript code
  does:
  - RS256 and ES256 only, with 60 seconds of skew on exp and nbf;
  - the issuer's discovery document must name the issuer itself, and its
    `jwks_uri` must be https.

  Its inputs are decoded as Node decodes them, so the reasons match:
  - each segment is base64url decoded leniently (either alphabet,
    characters outside it skipped, stopping at "=");
  - the bytes are decoded as WHATWG UTF-8, then read with `JSON.parse`'s
    rules;
  - a property read of null is a `TypeError`: "verification-error", or
    500 for a null payload, as in TypeScript.

  JWK import is go-jose's (v4, already pinned through tsnet), fed only
  the members a public key is made of. The signature check is the
  standard library's, on exactly the bytes the TypeScript code verifies.
- **The bounds** (ADR-0057 Decision 7), per process:
  - one discovery-and-JWKS operation per issuer at a time, shared by
    concurrent callers;
  - a JWKS kept five minutes;
  - a failure kept 30 seconds, doubling to 10 minutes;
  - a bad token never touches the caches;
  - an unknown key id refreshes at most once a minute;
  - each cache holds at most 1,000 issuers.

  The documents go through the outbound policy's `oidc` client, without
  following redirects, 10 seconds each. A refusal is audited for the
  binding's Organization (connection phase).
- **Parity.**
  - `ts-vectors.json` (`go-oidc-vectors.test.ts`): the TypeScript
    verifier's answers to 67 tokens (reasons and the URLs fetched) and to
    six bounds scenarios.
  - `oidc-v0.22.0.json` (`go-oidc-fixture.test.ts`): 55 requests,
    with the documents each request fetched.
  - The `oidc` conformance suite runs against a local issuer over https on
    every target (the `oidc-issuer` capability).

### Platform Connections (step 4.9b)

`server/syncs` (AGPL) is the Connection part of `domain/sync.ts` and
`integrationstepup.ts`, on the adapters of `lib/sync`; Sync Targets and
the converge engine follow in 4.9c and 4.9d.

- **The operations.** Each needs config.sync.manage, existence hidden.
  - `listPlatformConnections` (inspection while frozen) and
    `getPlatformConnection` (with every Sync Target the Connection feeds,
    each drained or not by its live runs).
  - `createPlatformConnection` (admin-step-up's `connection.create`).
  - `replacePlatformCredential` (`connection.replace_credential`). Each
    live Target's write-time disclosure gate must pass for the requester,
    before an approval is asked for and again in the job. Targets the old
    credential stopped resume, and every Target is queued.
  - `revokePlatformConnection` (`connection.delete`, a recovery operation
    while frozen). Every Target it feeds is disabled and fenced.
  - `checkPlatformAccess` and `listPlatformDestinations`, external effects
    (`write.RunEffect`) that send a credential only to the Connection's
    base identity.

  The writes, the check and the listing need `sync = on`, and an adapter
  `sync_adapters` allows. The credential is sealed under the Organization
  KEK (`platform-credential`).
- **The outbound policy.** A base identity that is an address (Coolify,
  Convex) is checked before anything is held (`sync_check` or
  `sync_listing`, configuration phase, recorded). The platforms' requests
  go through the policy's client for that purpose, and a refusal is noted
  for the effect (connection phase).
- **Expiry.** An expiry a platform reports for a stored credential is
  recorded only while the Connection holds the credential version it was
  read at. A stored credential's recorded expiry stands in when an answer
  says nothing.
- **GitHub App Connections** (ADR-0047 Decisions 2 to 4; step 4.10b):
  - `createPlatformConnection` with `credentialKind: "github-app"`
    (`CreateApp`, `connection.create` bound to the App, the installation
    and the name): an external effect reading the installation as the App,
    which must be this App's and not suspended; its account becomes the
    base identity. Under enforce GitHub is asked only after a precheck
    found an approved intent, and the App must still be live in the final
    job.
  - A check or a listing with one mints an installation token for the use
    (`githubapps.Mint`, narrowed as `domain/githubmint.ts` narrows it,
    never stored); a 422 is explained as TypeScript explains it. A
    Connection whose App was removed answers `credential-rejected`.
  - `rotateGitHubAppKey` (`RotateAppKey`, `github_app.replace_key` bound to
    the App, the key and the version): the new key verified with GET /app
    across the call, then, in the final job, the version checked again,
    every live Target of the App's Connections through the re-authorization
    gate (its decisions in the audit event), the key sealed, the version
    moved and every Target queued.
- **Parity.**
  - `connections-v0.22.0.json` and `connections-v0.21.0.json`
    (`go-connections-fixture.test.ts`): 113 requests on fake GitHub,
    Coolify and Convex servers, with every request each one sent them.
    Those sent with a stored credential carry what its envelope opens to:
    G3 at the database level for Platform Connection credentials, both
    directions (`TestGoSealedFixture`, go.yml).
  - One fixture answer is adjusted in Go: the re-authorization gate's
    `authorization.denied`. The TypeScript server writes it through the
    connection pool, where it commits on PostgreSQL; the fixture's
    single-connection PGlite rolls it back (`gateDenialOnPostgres`).
  - `effect_test.go` holds decision 4's tests for the check and the
    listing.

### Sync Targets (step 4.9c)

`server/syncs` (`targets.go`) and `server/httpserver` (`targets.go`) are
the Target part of `domain/sync.ts` and its routes: a Target maps an
Environment's items onto one destination of a Platform Connection.
Pushing (`pushSyncTarget`) and the converge engine are 4.9d's and answer
501 `NOT_IMPLEMENTED_YET` until then.

- **The operations.** Each needs config.sync.manage on the Environment,
  existence hidden.
  - `listOrgSyncTargets` and `listSyncTargets` (inspection while frozen),
    `getSyncTarget` (with the ledger's per-name state, notes, drift and
    whether a run is live).
  - `createSyncTarget` and `updateSyncTarget`: the body (zod), the
    destination canonicalized by the adapter, the mapping normalized
    against it (wildcard with exclusions, or explicit items with
    renames; duplicates, collisions and names the platform sets or
    refuses are invalid), the write-time disclosure gate for what the
    mapping would push, then the Target in one job. A destination has
    exactly one writer (`VERSION_CONFLICT` when another live Target
    claims it). An update is versioned. A new canonical destination
    (another destination, or a Connection with another base identity)
    fences runs and clears the ledger; re-pointing across platforms is
    refused.
  - `pauseSyncTarget` (a recovery operation while frozen) fences runs;
    with `?wait=true` it answers once no run of the Target is live, for
    at most 30 s. `resumeSyncTarget` refuses a Target whose Connection
    was revoked. `revokeSyncTarget` releases the destination.

  Creating, changing and resuming need `sync = on`; reading, pausing and
  revoking do not, as in TypeScript.
- **Parity.**
  - `targets-v0.22.0.json` (`go-targets-fixture.test.ts`): 83 requests,
    with their audit events and side rows (Targets, ledger, member
    integrations), and no request to a platform.
  - The TypeScript route answers a create body that is not JSON with 500
    `INTERNAL`. Go answers the same, and the fixture holds it.
  - `TestPauseWaitsForALiveRun` and `TestSyncOffRefusesTargetWrites` hold
    the two behaviors the fixture cannot (a run that ends while the pause
    waits; `sync = off`).

### The converge engine (step 4.9d)

`server/syncs/converge.go` is `domain/syncdelivery.ts`: the loop that
converges each Sync Target's destination to its environment's effective
output, and `pushSyncTarget`, which makes a Target due at once.
varlatchd runs it every 30 seconds when `sync = on`.

- **The transaction map first** (feature-parity decision 7):
  `server/syncs/CONVERGE.md` lists every commit the TypeScript engine
  makes, in order, on every path, with the guard it takes and what lies
  between commits (provider calls, the decryption). Go makes each as one
  write job, in that order, and merges none. A merge would need decision
  7's proof.
- **Unchanged:**
  - one `writeValues` and one `deleteNames` per run;
  - the generation guard on every guarded commit;
  - the send check (generation, deadline, freeze) before every write,
    delete and redeploy request inside a batch;
  - the order of audit events.
- **The report:** each run reports its commits, its time queued for the
  writer and in jobs, and its duration (`Service.OnRun`, a debug log
  line).
- **Where Go differs** (CONVERGE.md):
  - the ledger is read in last-write order, which TypeScript leaves
    unspecified.
- **Two TypeScript defects, fixed in Go only** (feature-parity.md; the
  TypeScript line takes security fixes only):
  - **defect 8:** the trigger scan orders its batch by `event_order` as
    text, so it can pass over events. Go orders by number
    (`TestTriggerScanSkipsNoEvent`);
  - **defect 9:** a forced run that adopts a write an earlier run left
    unconfirmed drops its redeploy. Go keeps the debt
    (`TestInterruptedWriteKeepsItsRedeploy`).
- **Parity:**
  - `converge-v0.22.0.json` (`go-converge-fixture.test.ts`): 28 requests,
    ticks of the engine between ordinary requests, against stateful fake
    GitHub, Coolify and Convex services written alike in both languages.
    Every request the engine sends is compared, a GitHub secret by the
    plaintext the fake opens, with every ledger row (fingerprints
    included), every Target column and every audit event.
  - The ticks cover:
    - the first forced pass (read-back, adoption, rewrites, a redeploy, a
      credential's expiry);
    - triggers, and an orphan's deletion;
    - a failed write, its backoff, and `pushSyncTarget`;
    - drift put back;
    - a paused and resumed Target;
    - a new destination;
    - a revoked Connection.
- **G7** (`converge_g7_test.go`), in three scenarios that together make
  every commit CONVERGE.md maps:
  - the first pass;
  - changes to a converged world (deletions, a failed write, a rename,
    drift, an outbound refusal, a trigger);
  - a pass out of budget.

  The tests:
  - a crash right after each commit, and right after a platform accepts
    each request (between its success and the outcome's commit), recovered
    both by the repair pass and by an ordinary triggered run, converges to
    what the uncrashed pass converges to. The fake Coolify tracks what an
    application runs (its values as of its last deploy), and the
    application must run what it stores;
  - a fence (the generation moved) at every request to a platform stops
    the run's writes and records nothing more under its generation.

  Each scenario's start is built once and copied for every point; the
  points run in parallel (one in seven, one at a time, under the race
  detector).
- **Also tested** (`converge_test.go`):
  - a converged run's commits;
  - a refusal by the outbound policy is not a failure;
  - a run out of budget yields;
  - a freeze mid-run yields, and nothing is leased while frozen;
  - App Connection Targets push with a token minted once per run
    (narrowed to the destination, never stored, its expiry never
    recorded); a removed App or a refused mint fails the run as
    `GitHub App: <reason>`;
  - the trigger scan skips no event (defect 8).

### The audit export's configuration (step 4.11a)

`server/auditexport` is the configuration side of `domain/auditexport.ts`
(ADR-0056): an Organization's whole audit log copied to its own
S3-compatible bucket with Object Lock. Its worker, drains and host command
are the next section (4.11b).

- **Operations.** `getAuditExport` (organization.manage, inspection while
  frozen), `createAuditExport`, `checkAuditExport`, `changeAuditExport`,
  `replaceAuditExportCredential` and `removeAuditExport`, each refused to
  a machine credential, while frozen or being deleted, and (all but
  reading and removal) when the host turned the export off
  (`audit_export = off` in `varlatchd.conf`, the TypeScript
  `VARLATCH_AUDIT_EXPORT`). Creating and checking need no approval;
  another destination, a shorter or removed retention, compliance to
  governance, a new key and removal always need the requester's step-up
  approval (`audit_export.change`, `audit_export.remove`), whatever the
  Security Controls' modes.
- **The probe** (Decision 6) writes a test object conditionally, writes it
  again (which must answer 412), reads it back (HEAD: the SHA-256
  metadata the worker's 412 check compares) and, with retention, reads the
  retention back; reading content and retention are recorded separately.
  It goes through `lib/backup`'s S3 client on the outbound policy's
  `audit_export` client, one attempt per request, 30 seconds each; the
  client is a reviewed exception of the structural test.
- **Effects** (decision 4). Creating, checking and a destination change
  run as external effects: the Organization's gate shared and the
  requester's, the checks in one snapshot (the effect's `Checked` part,
  new here, runs after the passkey-verification checkpoint, as the
  TypeScript callbacks do), then the probe, then the final job. A
  destination change also holds the export's gate across its probe, so a
  key replacement or a removal waits for it
  (`TestChangeHoldsTheExportAcrossItsProbe`). A refused endpoint is
  recorded once, whatever the operation answers.
- **Parity.** `audit-export-v0.22.0.json` (go-audit-export-fixture.test.ts)
  replays every operation's answers, audit events and side rows against a
  local S3 server (`auditexport/s3fake`, and its TypeScript twin) reached
  under one fixed endpoint, and each request's exchange with it must be
  the same: G3 for audit export credentials at the database level, both
  directions. The `audit-export` conformance suite runs against MinIO on
  every target (the `object-store` capability).

### Broker Capabilities (step 4.6)

`server/capabilities` (issue, list, revoke) and `server/values`'
`capabilities.go` (exercise, and an issuance's precondition) are
`domain/capabilities.ts` (ADR-0022, ADR-0026, ADR-0038 Decision 7,
ADR-0039): a Broker of an Organization issues, for one of its Agents, a
Capability naming explicit Config Items, destinations and, per item, the
targets its Placeholder may be substituted at. It narrows what the Agent
may use; it never adds to the Agent's Grants.

- **Who.** Only a Broker of the Organization issues and exercises; anyone
  else is told `Not found`, before the body is read. A Broker lists and
  revokes its own; anyone else needs `policy.read` to list an
  environment's and `policy.manage` to revoke one (existence hidden).
  Listing is inspection while frozen, revoking recovery.
- **Issuance.** The items' names, the destination selectors (stored
  canonical), the targets (required; `lib/targets`), the lifetime (1 second
  to a day), then, in a job holding the Organization's, the Broker's and
  the Agent's gates shared: the Agent (an enabled Agent of the
  Organization), the advisory preflight (the Agent's `secret.use` without
  Requirements), the writer's checks, the row and `capability.issued`. The
  secret (`vlt_cap_` and 32 random bytes) is answered once; its SHA-256 is
  stored. With a precondition, its own snapshot first: the state digest
  the operator's preflight saw must still be the state's, else
  `STATE_CHANGED` names the categories that changed; on a match, each
  item's presence as a Secret and the Agent's authorization
  (`preflightItems`).
- **Exercise** is a retrieval. One snapshot: the environment, the Broker,
  the body (read first, parsed once the Broker is known), the Capability,
  the Agent's `secret.use` and `config.value.read` with the
  Organization's Requirements, and the values. Then, in TypeScript's
  order, each refusal recorded as `capability.denied`: unknown, another
  Broker's or a wrong secret (all `Capability not found`), revoked,
  expired, a destination no selector matches, no targets, a placement the
  Capability does not hold, the Agent's authorization. Then
  `capability.exercised` is committed before the placed Secrets are
  decrypted (G7, `TestKillAtCrashPoints` exercises alongside its
  disclosures), and references are resolved or the exercise denied, one
  audited level at a time (`secret.disclosed` and `value.disclosed`, mode
  `reference-expansion`). A rotation's retiring value is returned beside
  the current one, unexpanded. An exercise a Requirement covers is
  `TAILNET_CONTEXT_REQUIRED` without a device: on the ordinary listener,
  always (see "The tailnet listeners").
- **Parity.** `capabilities-v0.22.0.json`
  (go-capabilities-fixture.test.ts) replays 154 requests: issuance in
  every form and refusal (every target rule, every zod issue, the
  precondition's outcomes), listing by each caller, exercise of
  Capabilities live, revoked, expired, without targets and for Agents
  without each permission, references bound, unbound, unknown, cyclic and
  not readable, and revocation, with their audit events and rows. The
  JavaScript behaviour it keeps: a placement named after a member of
  `Object.prototype` (`constructor`) is a 500, as is a refusal whose audit
  event jsonb refuses (U+0000 in the host); a `__proto__` member of
  `targets` is dropped before its value is checked, and one of
  `stateDigests` (enum keys) is an unrecognized key, as zod 4.6.7 does
  each.

### The audit export's worker, drains and host command (step 4.11b)

`server/auditexport/worker.go` and `streams.go` port the rest of
`domain/auditexport.ts`: the worker, stream restarts, the restore step,
the drains and `admin audit-export discard-plan`.

- **The worker** (Decisions 2 to 4). It runs in `serve` while the host
  leaves `audit_export` on: a pass at once, then every minute, paused by
  the maintenance admission. Each pass leases every live export that is
  due, one at a time, for 300 seconds. The lease moves the export's
  generation, so a holder that lost its binding (a change, a new key, a
  removal, a restart) never commits. One lease writes up to 20 objects:
  - **the plan:** a pending plan first, else the next object. That is the
    hour's heartbeat when the hour has none yet; otherwise the next batch
    after the cursor (at most 1,000 events or 8 MiB of NDJSON, gzipped).
    The plan is built outside any job, then stored in one job that checks
    the binding, the cursor and that nothing is pending;
  - **the upload:** exactly the stored bytes, conditionally. A 412 is
    checked with a HEAD: the same SHA-256 means an earlier attempt landed
    (delivered); other content stops the export (`object_conflict`). A key
    that cannot read counts the 412 as delivered;
  - **the commit:** one job that moves the cursor or records the hour, and
    records `audit_export.recovered` after a failing episode;
  - **failures:** a failed upload keeps the plan and records the fixed
    words. Fifteen minutes of failures record `audit_export.failing`,
    once per episode. A plan this release cannot upload stops the export
    (`unsupported_format`).
- **Restarts.** A plan whose retention would end within the hour starts a
  new stream at the committed cursor; its manifest names the dropped batch
  as a possible overlap. `varlatchd admin audit-export discard-plan
  --export <id> --reason <expired|unsupported-format> [--json]` is the
  host's way past a stopped export: the same restart, refused for a plan
  that can still be uploaded. It runs through the daemon's control socket,
  else offline under the lock.
- **Gates** (decision 4). Every job of the worker, the restarts and the
  host command takes the export's gate, as a change, a new key and a
  removal do, so they wait for a destination change's probe
  (`TestWorkerAndHostWaitForAChangesProbe`, `TestAuditExportCommand`).
- **Restore** (Decision 5). `admin backup restore` no longer refuses an
  archive with a live export. In the job that records
  `installation.restored`, every live export continues in a new stream at
  its restored cursor (`audit_export.stream_started`, reason `restored`).
- **Drains** (Decision 10). `RewrapForDrain` seals a deleted
  Organization's export key again under the Root KEK, and the worker reads
  it from there. The batch that holds `organization.deleted` completes the
  drain. A drain still running at its 30-day deadline is abandoned: its key
  and plan are dropped and `audit_export.abandoned` is recorded, by the
  worker or by `AbandonExpiredDrains`. Organization deletion (4.12) calls
  `RewrapForDrain` and runs `AbandonExpiredDrains` in its loop.
- **Parity.** `audit-export-worker-v0.22.0.json`
  (`go-audit-export-worker-fixture.test.ts`) runs 52 steps against the
  TypeScript worker and the Go worker. Each step must give the same
  objects, exchanges with the destination, exports, plans and audit
  events. Batches are compared decompressed: their gzip bytes are zlib's,
  and differ between zlib builds (Node ships Chromium's), so Go's differ
  too. Only the stored bytes are ever uploaded, and a plan keeps them
  across a restart. The fixture's draining export carries a drain copy
  the TypeScript code sealed, and go.yml has the TypeScript worker run the
  steps on Go-sealed rows: G3 for drain copies at the database level, both
  directions. The `audit-export` conformance suite checks the stream the
  worker writes and the host command's refusals on every target (the
  `host-admin` capability).

### The tailnet listeners (step 4.13a)

`server/tailnet` and `server/httpserver/tailnet.go` are the tailnet
listeners' HTTP side (ADR-0014 §7, ADR-0046; `tailnet/whois.ts`,
`tailnet/listener.ts`, `http/tailnet-browser.ts`), on a `tailnet.Node`:
what varlatchd's own node answers about a peer (WhoIs) and about itself.
The node, its pin and the listeners report are step 4.13b, the browser
endpoint's HTTPS with the node's certificate 4.13c (the next two
sections).

- **Listeners.** A tailnet listener is a server of its own
  (`Options.Tailnet`): the API alone, with no nginx in front, no dashboard,
  browser session, enrollment page or public URL, as the TypeScript tailnet
  apps are built. The ordinary listener never has a resolver, so a Tailnet
  Context cannot arise there.
- **The device check** reads the accepted socket's own peer address, never
  what the request says. A shared-in device is refused before its name is
  read, a device of another tailnet (by the pinned MagicDNS suffix) and the
  node itself are refused, and every failure (the node cannot say, a field
  missing, its own identity unknown) refuses as `resolver-unavailable`.
  A tagged device is known by its tags; a user login is kept for an untagged
  one only. The node's own StableID is read fresh for every caller, the
  reads shared and one in flight at most.
- **The request** carries its Tailnet Context (`authz.WithTailnet`): every
  authorization decision evaluates Requirements against it, as are a
  Capability's exercise and an issuance's preflight. A Requirement a device
  does not satisfy is `TAILNET_CONTEXT_UNAVAILABLE`; no device is
  `TAILNET_CONTEXT_REQUIRED`. Audit events record the listener and the
  device or the refusal; `/v1/me` reports both. A recognized device gets a
  request window of its own.
- **The browser endpoint's gate** runs before the device check: only the
  node's own name; a request with `Origin` only from an exactly allowlisted
  origin to the browser read routes, else 403 without CORS headers; a
  preflight answered with the allowed methods and headers
  (`Varlatch-Approval` only when asked for); CORS headers on every allowed
  answer, never `Access-Control-Allow-Credentials`.
- **Operations.** `getTailnetEndpoint` (the browser endpoint's URL, null
  without one, on every listener), `getTailnetContext` (the caller's own
  device, on the browser endpoint only), `getInstallationListeners`
  (Installation Admins; null without a tailnet listener). `/v1/meta` lists
  `tailnet.browser-reads` when a browser endpoint is configured.
- **Parity.** `tailnet-v0.22.0.json` (go-tailnet-fixture.test.ts) replays 40
  requests on the ordinary listener and on tailnet listeners with stand-in
  device checks (tagged, a person's, another tag, shared, unavailable, the
  browser endpoint with and without a device): Requirements met and not,
  reads, disclosures, exercises, the gate's answers with their CORS headers,
  and their audit events with listener and device. The parity kit now sends
  a request to the listener it names (`listener`), and compares the CORS
  headers. `/v1/meta`'s document is the Go server's own, so its tailnet
  capability is a unit test.

### The tailnet node and its pin (step 4.13b)

With `tailnet = on`, varlatchd runs its own Tailscale node in process
(tsnet, `tailscale.com`, BSD-3-Clause; `server/tailnet/node.go`) and
serves the tailnet listener on the node's own addresses
(`server/daemon/tailnet.go`), beside the ordinary listener.

- **Settings** (`varlatchd.conf`): `tailnet = on` needs
  `tailnet_hostname`, `tailnet_tags` (the node is always tagged) and
  `tailnet_port`; `tailnet_auth_key_file` defaults to the
  `tailnet-auth-key` systemd credential. The key is read only while the
  node has no state of its own, to enrol it; after that it is never
  needed. Any `tailnet_*` setting with `tailnet = off` is a configuration
  error. Archives keep the settings, never the node: a restored
  installation's node enrols again.
- **The node** keeps its state (its keys) in `<data_dir>/tailnet`, mode
  0700, never in a backup; it is never ephemeral and never logged out, so
  a restart rejoins as the same device. Nothing goes to Tailscale's log
  service (`TS_NO_LOGS_NO_SUPPORT`, logtail off), and network-namespace
  binding is off (a userspace node has no TUN device). The node joins in
  the background: the ordinary listener serves at once, the tailnet
  listener once the node runs.
- **Coordination server.** This release joins Tailscale's only:
  `tailnet_control_url` other than Tailscale's is refused at startup, and
  the node is always given Tailscale's control URL explicitly (an empty
  one would let tsnet read `TS_CONTROL_URL`). varlatchd refuses to start
  the node while any environment variable tsnet reads in place of its
  settings is set (`TS_CONTROL_URL`, `TS_AUTHKEY`, `TS_AUTH_KEY`,
  `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN`, `TS_AUDIENCE`,
  `TSNET_FORCE_LOGIN`): its control server and enrolment come from
  `varlatchd.conf` alone.
  Decision 5 requires a self-hosted (Headscale) control server's host name
  never to reach Tailscale, and the tsnet release in use always keeps its
  bootstrap DNS fallback (Tailscale's DERP servers resolve the control
  host when the system resolver fails), with no way to turn it off. ADR-0059
  lists a Headscale version as supported only once G10 shows no such
  query, so none is yet. The plan's Headscale end-to-end tests (G10's step
  4 cases against a Headscale 0.29.7 container: WhoIs, tagged peers, a
  changed `base_domain`, a different control URL, and no bootstrap DNS
  query while the control server is down) are deferred until a tsnet
  release can turn the fallback off: the last of them cannot pass before
  then, and the others would test a configuration varlatchd refuses. The
  pin's Headscale rules are in place and unit-tested
  (`TestHeadscalePin`) for that day.
- **The pin** (`<data_dir>/tailnet-pin.json`, `server/tailnet/pin.go`)
  is the control URL, the tailnet's StableID (Tailscale) and its MagicDNS
  suffix (Headscale's `base_domain`), never the display name. It is taken
  at enrolment only: before a node without state of its own starts, the
  pin file is marked as enrolling, and the first tailnet that node runs on
  becomes the pin. A node that has state but no pin file is never pinned
  silently: access stays closed (`pin-missing`) until the host adopts the
  tailnet the node is on.
- **Tailnet access** is open only while the pin is recorded and not
  closed, and the last check of the node (at start, every minute, and
  before any re-pin; checks are serialized) succeeded on the pinned
  tailnet. A check that fails, or finds the node not running or without a
  tailnet, closes access until a check succeeds. A mismatch (a different
  control URL, StableID or suffix) closes it and is latched: written into
  the pin file, it holds across restarts and even if the tailnet changes
  back, until a re-pin.
- **While access is closed** the tailnet listener refuses every request,
  whatever it asks for, with 403 `TAILNET_CONTEXT_UNAVAILABLE`, before the
  peer is looked up (the TypeScript server pins its tailnet in its
  configuration and has no such state). Each open period has a
  generation: when access closes, every request admitted in the period is
  cancelled at once; a peer lookup that was in flight returns no Tailnet
  Context; and a Tailnet Context resolved in the period stops counting at
  the next authorization decision that reads it (`authz.TailnetFrom`), also
  after access reopens. A write a request had already started is stopped
  at the write boundary: its context carries a commit guard
  (`storage.WithCommitGuard`), which the single writer checks after the
  job's function and before its savepoint's release, and which rolls the
  job back (403 `TAILNET_CONTEXT_UNAVAILABLE`) once the request's period
  ended. Closing access waits for any write between that check and its
  release, so each write of the period is either released before access
  closes or refused. Requests on the ordinary listener carry no guard.
- **Re-pin.** `varlatchd admin tailnet repin [--yes [--adopt]] [--json]`
  (host authority, through the running daemon only) runs a fresh check,
  which must succeed, and shows the pin, the observation and the latched
  closure. With `--yes` it pins the observed suffix when the suffix is the
  only change, or reopens access when the tailnet matches the pin again;
  with `--yes --adopt` it pins the tailnet an enrolled node without a pin
  is on. A different StableID or control URL is refused: that means
  enrolling the node again (remove `<data_dir>/tailnet` and the pin, give
  an auth key). Each re-pin is kept in the pin's `history`, with the
  closure it ended, and logged. An audit event for it waits for step 6's
  `varlatch tailnet repin`: the TypeScript server has no event type for
  it, and the Go audit types equal the TypeScript ones.
- **The listeners report** (`getInstallationListeners`, and
  `<data_dir>/tailnet-listeners.json`, rewritten when a check changes and
  at least every 5 minutes) is what varlatchd last observed: the listener
  bound, the node's local API answering, the node running on the pinned
  tailnet, and its name, tailnet, tags and addresses where each passes
  observe.ts's checks. Never reachability, which only a client sees.
- **Tests, with no real tailnet.** Tailscale's own control server
  (`tstest/integration/testcontrol`) and a DERP relay run in process on
  loopback: `TestPeersThroughThePinnedNode` drives every device check
  through a real node (tagged, a person's, shared in, another tailnet,
  itself, unknown) and `TestTailnetListener` runs varlatchd with
  `tailnet = on` (the `tailnetControl` hook points it at the test server):
  a tagged peer's request over the tailnet carries its Tailnet Context
  into the audit; restarted without the auth key it rejoins; a changed
  suffix refuses the whole listener (a write never commits) until `admin
  tailnet repin --yes`; a removed pin file is adopted only with
  `--adopt`. The pin's rules (failed checks, serialized checks, the latch,
  a missing pin, lookups and contexts across a closure, the admission) are
  unit tests in `pin_test.go`. The live checks on a real tailnet are run
  by hand (the PR lists them).

### The browser endpoint over HTTPS (step 4.13c)

With `tailnet_https_port` set, varlatchd serves the browser endpoint
(ADR-0046) on the node's addresses, over HTTPS with the node's own
certificate (`server/tailnet/cert.go`, `cert.ts`; `listener.ts`'s
`serveTailnetHttps`), beside the plain tailnet listener.

- **Settings.** `tailnet_https_port` (not `tailnet_port`) and
  `tailnet_browser_origins`, exact origins as a browser sends them (https,
  or plain http on loopback; never `*`, `null`, a path or a wildcard
  host), checked as `config.ts`'s `tailnetBrowser` checks them (through
  `lib/whatwg`'s URL parser); an https (or loopback http) `public_url`'s
  origin is allowed by default, and at least one origin is required.
- **Its host** is `tailnet_hostname` in the pinned tailnet (the
  TypeScript server's `VARLATCH_TAILNET_MACHINE` and tailnet settings): known
  once the node is enrolled, and following a re-pin.
  `getTailnetEndpoint` answers its URL and `/v1/meta` lists
  `tailnet.browser-reads` from then on (`Options.BrowserEndpoint` and
  `BrowserEndpoint.Host` are functions).
- **The certificate** is the node's Let's Encrypt pair, which tsnet
  obtains through Tailscale's control plane (MagicDNS and HTTPS
  certificates on in the tailnet): fetched at start and daily (hourly in
  its last two days, from 30 seconds doubling to an hour after a
  failure), asking for a third of its lifetime left (at most a week), and
  at once when the host changes (enrolment, a re-pin, an adoption: the
  manager wakes it). A pair whose chain holds a certificate that does not
  parse, whose leaf does not name the host exactly (never a wildcard or
  the subject) or is not valid now, or whose key does not match is never
  used; the last valid one serves until it expires. The certificate's name is
  published in Certificate Transparency logs.
- **TLS.** TLS 1.2 at least; only the host's name (a handshake for another
  name, without SNI, or without a valid certificate is refused), checked
  and its certificate chosen from one reading of the host, and checked
  again once the handshake is done, so a handshake for a name the host no
  longer has (a re-pin meanwhile) never serves a request; no session ever
  resumed (tickets off, and a resumed or certificate-less
  connection fails before a request is read); HTTP/1.1, as Node's server.
- **The same rules as the plain tailnet listener:** the admission (closed
  pin, every request refused), the device check, and the browser gate of
  4.13a (the host, the allowlisted origins, CORS).
- **The report** adds `browserTls` (pass with `certificateNotAfter`, or
  `NO_CERTIFICATE`), both listeners in `listener`, and `NAME_CHANGED` when
  the node's name is no longer the endpoint's host.
- **Tests, with no real tailnet or ACME:** a test CA
  (`server/tailnet/tailnettest`) stands in for Let's Encrypt.
  `TestDecodePair`, `TestCertificateKeepsTheLastValidPair`,
  `TestRefreshesShareAFetch` and `TestBrowserTLS` (SNI, versions, no
  resumption in TLS 1.2 and 1.3) cover `cert.go`;
  `TestReportWithTheBrowserEndpoint` the report; `TestBrowserEndpoint`
  runs varlatchd with the endpoint on testcontrol (the `tailnetCerts`
  hook): a tagged peer reads its own device over HTTPS from an
  allowlisted origin; another origin, name or Host is refused; and with
  tailnet access closed the endpoint refuses too.

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
    `BuiltOperations` lists the ones served (`GET /v1/meta`, and step
    3.4's: who am I, the caller's credentials, passkeys and profile,
    the CLI credential exchange, device sign-in, the caller's
    organizations; step 3.6's read path of values; step 4.1a's creating,
    reading and renaming an Organization); a built operation authenticates its bearer first
    (`authn.go`), unless it authenticates otherwise;
  - the TypeScript server's error envelope, and its two known differences
    (decision 4): an unknown route answers the plain-text `404 Not Found`
    (under `/v1` only after authentication, as the TypeScript server
    orders it: without a bearer credential, `401 AUTHENTICATION_REQUIRED`;
    with an invalid, revoked or expired one, `401 INVALID_CREDENTIAL`; with
    an agent-run credential on a write, `403 PERMISSION_DENIED`), and
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
    Convex in the Go server; with a tailnet browser endpoint, its origin
    too, as `getTailnetEndpoint` answers it now from the pin, so the
    dashboard can Connect to it, as the TypeScript dashboard's container
    adds `VARLATCH_TAILNET_ENDPOINT`). `/v1`, `/auth`, `/enroll`, `/healthz`,
    `/readyz` and `/.well-known` never serve it;
  - the browser session (`browser.go`), generated from the OpenAPI
    document's browser-session section (`server/api/browser`), served at
    `/auth/...` and listed as `auth.session` in `/v1/meta`: its cookies,
    the CSRF and Origin checks on every POST, and the ceremonies; and the
    enrollment page, `/enroll` (the TypeScript server's page, byte for
    byte) with its own script, `/enroll.js`.
- `server/auth`: authentication (ADR-0059 Decision 6): opaque credentials
  stored hashed, setup grants, browser sessions of its own, WebAuthn with
  go-webauthn's `protocol` package (BSD-3-Clause), passkey provenance,
  sign-in evidence and passkey-verification, device sign-in. Its tests are
  G4's server side, with a software authenticator (`auth/authtest`) and a
  v0.22.0 fixture the TypeScript code makes
  (`services/varlatchd/test/go-passkey-fixture.test.ts`).
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
- `server/values` (step 3.6): the read path of values, served as
  `getEffectiveConfiguration` and `discloseSecrets` (ADR-0059
  varlatchd-core decision 2): a snapshot (one read transaction) resolves
  the scope, decides authorization, captures the Contract, the items and
  their ciphertext, and runs passkey-verification's checkpoint; then each
  disclosure's audit events are one write job of the single writer, and
  nothing is decrypted before it committed (Root KEK, Organization KEK,
  DEK, value). References expand only within what the caller receives, one
  audited level at a time. An export while admin-step-up is at enforce
  (step 4.3b, `export.go`, `domain/exportstepup.ts`) consumes its step-up
  approval, bound to the exact set of Secrets disclosed, in the
  disclosure's audit job behind the Organization's and the requester's
  gates, after a freshness check of the capture against the live rows (a
  stale one answers `STATE_CHANGED` and leaves the approval usable).
  `testdata/values-v0.22.0.json`
  and `values-v0.21.0.json` hold a database the TypeScript server built
  through its own `/v1` API (the v0.21.0 file's envelopes sealed by that
  release's code), a table of requests and that server's answers, audit
  events, exposure rows and report counts: the Go tests load the rows
  through the schema mapping and must give the same answers, and the same
  with every Organization KEK and value sealed again by Go, which go.yml
  then hands to the TypeScript server's read path (G3, both directions).
  The rows include the installation's Root KEK canary, which both servers
  open through their readiness check (and varlatchd at startup,
  `server/daemon/canary_test.go`). `testdata/g3-matrix.json` lists every
  encryption class (each envelope purpose `lib/envelope` defines) × fixture
  release × envelope version × direction, at the level it is proven
  (database or envelope) with the tests that prove it; `g3_test.go` fails
  when an entry names a test that does not exist or that CI does not run,
  or when a purpose has no entry.
  Its writes (step 4.1d, `writes.go`): `setValue`, `deleteValue` and
  `applyChangeSet` (`domain/values.ts`), each one job of the single writer
  behind the Organization's and the requester's shared gates, in the
  TypeScript order (the item's name, the environment's expiry, the
  Organization's KEK and the active Contract; the writer's checks and the
  checkpoint; a deletion's value found before the checkpoint; a change
  set's every version guard before any write), with each version sealed
  under the Organization's KEK (a lone surrogate in a value as U+FFFD, as
  Node encodes it; U+0000 kept, since a value is sealed, not stored as
  text). `setValue` and `applyChangeSet` run under an Idempotency-Key
  when the request has one (`write.Idempotent`: the claim, the write and
  the stored response in the same job, so a refused write stores no
  claim), the digest over zod's output in its schema's member order.
  Dual-phase rotation (step 4.2, `rotation.go`; ADR-0027, the grace hint
  of ADR-0053): `beginRotation` writes a new primary version and keeps the
  prior one retiring until a deadline (the request's grace, else the
  Contract's `rotationGraceSeconds`, else a day; at most 30 days; refused
  with `ROTATION_IN_PROGRESS` while one is in flight, a rotation past its
  deadline being over), and `completeRotation` drops the retiring version
  early (a no-op success when none is pinned). A plain write or a deletion
  supersedes a rotation in flight. `rotation_test.go` races begin,
  complete and a plain write on one item: every state is one the
  TypeScript code allows (no rotation, or one in flight whose retiring
  version is the current one's predecessor), and the committed events
  replayed in order give the final row. Rotations in flight are data the
  migration copies as they are (step 7: the retiring version, the
  deadline, the start); the read path already honours them.
  Validation and strict retrieval (step 4.1d, `validate.go`, `strict.go`;
  ADR-0038 Decisions 5 and 6): `validateEnvironment`'s verdicts and
  `strictRetrieval`'s values, manifest, per-category digests, caller view,
  Contract and verdicts, from one snapshot, each class judged only with
  the right to read what it describes, every decryption audited first (a
  validation one event per class and reference level, a preflight's
  Secrets as `secret.validated`); `expandStrict` is
  `expandReferences`' strict mode. `WithReadHook` lets a test commit a
  write between a retrieval's reads: `consistency_test.go` holds
  retrieval-consistency's cases (a parent's write, a Contract activation,
  a grant revocation, change sets committed mid-retrieval in every round,
  and a strict retrieval's values, manifest, digest and verdicts), each
  asserting its hook ran.
  `services/varlatchd/test/go-values-fixture.test.ts` writes them and
  checks the committed files are still that server's answers:

  ```sh
  VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-values-fixture.test.ts
  ```
- `server/jsvalue`: JSON as `JSON.parse` and `JSON.stringify` read and
  write it (member order, numbers, escapes, lone UTF-16 surrogates kept as
  `\udxxx`), and jsonb's key order and refusals; `ToNumber` is
  `Number(string)`.
- `server/custody` (step 4.14): the Root KEK's recovery copies
  (`crypto/escrow.ts`).
  - **The passphrase escrow blob:** scrypt with N 2^17, the KDF's
    parameters bound into the envelope. Weakened parameters are refused,
    and so is any derivation Node's 256 MiB `maxmem` would refuse, with
    OpenSSL's message.
  - **Shamir shares** over GF(2^8) (`vlks1.<x>.<k>.<y>.<fingerprint>`):
    any k of n reconstruct the key, and the fingerprint catches a wrong or
    mixed set.
  - **Vectors in both directions:** `testdata/ts-vectors.json` holds the
    TypeScript code's blobs, splits and refusals (with its messages), and
    go.yml has the TypeScript code restore and combine what
    `TestGoVectors` makes.
- `server/write` (step 4.1a): the write path without row locks (step 4
  decision 4). The TypeScript server orders every row lock by one order
  (`domain/liveness.ts`, ADR-0054 amendment E) and holds some across
  outbound calls; varlatchd has one writer instead, and:
  - `CheckLive` makes the checks the TypeScript code makes under a row lock
    (the Organization live, no deletion open, no incident freeze, the
    Project and environments live) inside the write job that depends on
    them, with the same refusals; `Checkpoint` is passkey-verification's
    `requireOrganizationAccess`;
  - in-process gates replace the advisory locks and the row locks held
    across a call: reader-writer gates with a name and a key, at four
    levels (step 0's singletons, the Organization, people, resources),
    taken all at once in one order (level, name, key), before the job is
    queued and released after its answer. A waiting exclusive taker keeps
    new shared ones out. The tracer refuses a gate taken out of order, and
    in test binaries one taken inside a write job, the counterpart of
    `test/helpers/lock-trace.ts`;
  - `RunEffect` runs an external effect (ADR-0054 Decision 7) in five
    parts: its gates; the authoritative checks in one read snapshot under
    them; a claim, held by its resource gate and written with the outcome;
    the call, with the TypeScript deadline (90 s while passkey-verification
    is at report or enforce); and the final job, which checks the
    Organization again and writes the outcome, with the outbound refusals
    the call noted (written alone if the effect fails). No network call is
    made while the write transaction is held (ADR-0059 Decision 2);
  - `Idempotent`: an Idempotency-Key's claim, the domain write and the
    stored response are one job (ADR-0018 section 8). The stored response
    is jsonb's form, and a replay puts its members in jsonb's order on
    reading, whatever order the stored text has, so a replay's body has
    jsonb's member order, as the TypeScript server's replay has;
    `testdata/ts-vectors.json` holds that server's digests (`bodyHash`)
    and replays (`services/varlatchd/test/go-write-vectors.test.ts`).
    Claims are data the migration copies (step 7): a claim the
    TypeScript server stored replays from its copied row, with the same
    answer, and its digest refuses another body (the core fixture's
    "stored" requests). U+0000 in the endpoint (a path id) or the key
    fails the claim before the write, as the TypeScript claim's INSERT
    fails, whatever the write would have refused.
- `server/orgs` (step 4.1a): creating an Organization (its KEK wrapped
  under the Root KEK, its first admin, `organization.created`) and renaming
  it (the writer's checks and the passkey-verification checkpoint inside
  the job), each one job of the single writer; served as
  `createOrganization`, `getOrganization` and `renameOrganization` by
  `server/httpserver/organizations.go`, which reads their bodies as the
  TypeScript routes do (`c.req.json()` without a fallback: a body that is
  not JSON answers 500 `INTERNAL` there, and here). Body strings are
  measured as zod 4 measures them, in code points (`codePoints`), so a
  name of 200 emoji is accepted.
- `server/contracts` (step 4.1b): a Project's Contract revisions
  (`domain/contracts.ts`, ADR-0013) on `lib/contract`: pushing one
  (normalized before the job; inside it, the writer's checks, the
  passkey-verification checkpoint, an unpinned Contract normalized again
  at the active revision's semantics version, a revision with the same
  content hash answered instead of a new one, `contract.revision_pushed`)
  and activating one (the revision found before the checkpoint, the
  active revision read in the job so concurrent activations each diff
  against what they replace, `contract.activated` with the diff summary),
  each one job behind the Organization's and the requester's shared gates;
  served by `server/httpserver/contracts.go`. A revision is stored as
  jsonb's text and answered in jsonb's member order, as PostgreSQL hands it
  back to the TypeScript server; a Contract jsonb refuses (U+0000, a lone
  surrogate) fails the push with 500, as the insert fails there.
- `server/projects` and `server/environments` (steps 4.1c and 4.12a): an
  Organization's Projects (`domain/projects.ts`: creating, renaming and
  deleting one) and a Project's environments
  (`domain/environments.ts`: creating a root or a derived one, ADR-0012
  and ADR-0020, and removing one, ADR-0025), each write one job behind the
  Organization's and the requester's shared gates, with the writer's
  checks and the passkey-verification checkpoint where the TypeScript code
  runs them (a derived environment's parent before the checkpoint, a
  root's rules before it; an environment's removal checks the active
  Contract's references before the job, as there). Their `created_at` is
  the clock's microseconds, read in the job, not the column default's
  milliseconds: the lists are ordered by `created_at, id`, so Projects and
  environments created within one millisecond still list in creation
  order. An environment's `expiresAt` is stored as PostgreSQL stores it
  (`PostgresTimestamp`: the fraction rounded to microseconds half to even,
  year 0 refused with 500), held to PostgreSQL by
  `testdata/pg-timestamps.json` (`go-timestamp-vectors.test.ts`).
  `audit.ISOTime` writes years past 9999 as `toISOString` does
  (`+010000-…`).
  A Project's deletion (`projects.Delete`, ADR-0051 Decision 2) is
  immediate and final, one job: a protected operation (admin-step-up's
  `project.delete`, bound to the Project by its id with no body, as
  `deletionstepup.ts` binds it; the Project's not-found ahead of the
  passkey-verification checkpoint; `project.manage` checked again once an
  approval was consumed), then every environment tombstoned (derived ones
  first), every value deleted with its version pointers and rotation
  cleared, every version's ciphertext and wrapped key erased, the
  environments' outstanding Capabilities and the Project's Sync Targets
  revoked (a push in progress fenced, the destination claim released),
  the Teams' links removed, the Project tombstoned and `project.deleted`
  recorded with the counts the route answers. Contract Revisions and audit
  events stay. `project-deletion-v0.22.0.json`
  (`go-project-deletion-fixture.test.ts`) replays 23 requests: who may
  delete, a frozen or deleting Organization, the deletion of a Project
  holding every kind of row it ends, what is left (not found, the slug
  free again, the Team link gone), report mode, and enforce (no approval,
  another request's, a malformed one, a machine credential, its own);
  every answer, audit event and changed row equal. The `deletion`
  conformance suite runs it over the API.
  Served by `server/httpserver/projects.go`, with
  `environmentsOut`'s tailnet fields (`tailnetRequired`, and the covering
  Requirements' IDs for a caller holding `policy.read`, decided without a
  record). `server/httpserver/installation.go` answers the two
  installation reads: no release check recorded yet (`varlatch upgrade
  --check` arrives in step 6), and the backup status (`server/backups`,
  step 4.14).
- `server/httpserver/search.go` (step 4.1d): `searchConfigItems`
  (ADR-0030), names only: the candidate environments are those the caller
  may read metadata of (the evaluator with its grants and Organization
  role, no Requirements), a hit is a literal case-insensitive substring of
  an effective name (`toLowerCase` on both sides, `lib/whatwg.ToLower`),
  ordered by project slug, name and project id as JavaScript compares
  strings, with `Number(limit)` and the base64url JSON cursor read as Node
  reads them. Search keeps no derived state (no index or cache): every
  search reads the live rows, so the migration (step 7) has nothing of
  its own to copy.
- `server/security` (step 4.3a): the Organization's Security Controls
  (ADR-0054). A change (`ChangeControl`, `domain/securitycontrols.ts`)
  takes the Organization's gate exclusive, so it waits for every external
  effect of the Organization and every later one sees the new mode, and
  the requester's gate (exclusive when the request carries an approval);
  in its job, the writer's checks (a change is recovery while frozen), the
  passkey-verification checkpoint, `organization.manage` rechecked (a
  denial audited after the job only while a control is on), the expected
  version, then a loosening change consumes the step-up approval bound to
  exactly it (`auth.ConsumeApproval`), or answers `STEP_UP_REQUIRED` with
  a new intent (`WithApproval`, `auth.StepUpRequired`). `Prepare` is the
  protected-operation framework (`protected.ts`) the later slices' writes
  run in their jobs: the controls read in the job, credential-lifetime's
  refusals and default, the existence preflight, the checkpoint, the exact
  binding, consumption, and the report counts (`Prepared.Count`). Report
  counters (`securityreport.ts`) are counted in the counting operation's
  own job, and the summary worker (`RunLoop`, every 60 seconds in the
  daemon, under a singleton gate) turns each hour's rows into
  `security_control.would_block` events once the hour has been over for 10
  minutes, a batch per job, then deletes rows 35 days after their summary.
  Served by `server/httpserver/security.go` (`listSecurityControls`,
  `changeSecurityControl`, `securityControlReport`,
  `securityApprovalKeys`). Approval summaries name things with the labels
  of `labels.go` (`approvallabels.ts`: every name JSON-quoted with the
  characters a reader cannot see escaped, every existing item with its
  id), checked with the canonical JSON and keyed digests an approval binds
  against the TypeScript code's vectors (`testdata/approval-vectors.json`).
  The account writers the TypeScript code runs under the person's row FOR
  UPDATE (starting, approving and cancelling an approval, confirming and
  removing a passkey) take the person's gate exclusive through
  `auth.Options.PersonGate`. Counters, their summaries and open intents are
  data the migration copies (step 7). The approval keys list admins by
  name in byte order. This is an intentional wire difference, not a
  defect: the TypeScript order follows the PostgreSQL database's
  collation (the test databases' C collation is byte order, which the
  security fixture records; a production cluster's may be a locale's).
- `server/freeze` (step 4.3c): the incident freeze (ADR-0055,
  `domain/freeze.ts`). Freezing (a person's credential with
  `organization.manage`, no approval; every open Approval Intent closed),
  lifting (always a step-up approval bound to the freeze id) and the host
  operator's lift (`varlatchd admin unfreeze`, no person, no approval) each
  take the Organization's gate exclusive, so each waits for the
  Organization's external effects; each runs while a deletion is pending
  and leaves it in place. Served by `server/httpserver/freeze.go`
  (`getIncidentFreeze`, `freezeOrganization`, `liftIncidentFreeze`).
- The audit log's reads (step 4.3c): `listAuditEvents` and
  `exportAuditEvents` (`server/httpserver/auditevents.go`), with the
  filters of `server/audit/filters.go` (`audit/filters.ts`; since and until
  read as PostgreSQL reads them, the fraction rounded to microseconds). The
  listing's cursor carries `occurred_at` in PostgreSQL's text form, so a
  cursor either server made reads the same on the other. Its time is read
  as PostgreSQL 17's timestamptz input reads it (`server/pgtime`, a port of
  that input; the TypeScript server hands it to PostgreSQL as
  `$3::timestamptz`): every form it takes, now and today at the time of the
  query, infinity after every event, and the text it refuses answering 500
  `INTERNAL` as it does there. Zone names come from the host's tz database
  (`/usr/share/zoneinfo`), as PostgreSQL's packages read theirs, so for a
  zone name both servers answer as their hosts' databases do. The
  export streams NDJSON a batch of 250 at a time up to the high-water mark.
  `audit.Record` gives the events of one call the clock's time in
  microseconds, as PostgreSQL's `now()` gives one transaction's, so events
  of separate writes list in the order they happened.
- The host operator's commands that write through the Organization's gate
  (feature-parity decision 11): `varlatchd admin security reset` (ADR-0054
  Decision 10, `security.ResetControls`) and `varlatchd admin unfreeze`
  (`freeze.OperatorUnfreeze`), through the daemon's socket or offline under
  its lock. In the daemon they wait for an external effect of the
  Organization and commit after it (`daemon` `TestOperatorCommandsWaitForAnEffect`,
  the commands run as processes of their own). They print the TypeScript
  admin CLI's lines, or the outcome as JSON with `--json`; a refusal prints
  `varlatchd admin <command>: <code>: <message>` and exits 1 (the TypeScript
  CLI prints one generic line), a usage error exits 64. The TypeScript
  code's exclusive takers of the Organization and person gates are
  inventoried by line pattern and each mapped to the Go function meant to
  take the gate (`write` `TestExclusiveTakersAgainstTypeScript`): a new
  taker on either side fails the test, but the mapping is reviewed, not
  proved; the gates the Go functions take are their own tests'.
- `server/orgdeletion` (step 4.12b): deleting an Organization (ADR-0051
  Decisions 4 to 8, `domain/orgdeletion.ts`) and the audit-access
  tombstone (Decision 8). Scheduling (a live built-in admin; admin-step-up's
  `organization.delete`, bound to the Organization and the normalized
  `afterDays`, 1 to 30, 7 by default) freezes the Organization in one job:
  Sync Targets paused with the fence, webhooks and enabled machine
  identities suspended under the request's marker, pending invitations
  revoked and unfinished GitHub App registrations removed. With more than
  one admin, another admin approves; any admin cancels, also while frozen
  for an incident, which restores exactly what the request suspended.
  The deletion loop (`Service.RunLoop`, in every serving varlatchd: a pass
  at once, then every minute, inside the maintenance admission) finalizes
  each due request in one job: claimed only while the Organization is live,
  not frozen for an incident and, when needed, approved by a still-live
  admin; open approvals closed; the readers of the tombstone fixed (the
  enabled members holding Organization-level `audit.read`); every
  membership ended as a removal ends it; Projects, environments, values,
  versions, Capabilities, Sync Targets, Connections, the GitHub App's
  registration, webhooks, machine identities and their credentials and
  OIDC bindings ended; the audit export's key sealed again for its drain;
  report counters removed; the Organization KEK destroyed; then
  `membership.removed` for each member and `organization.deleted`. Each
  pass also abandons audit export drains past their deadline. Schedule,
  cancel and the run take the Organization's gate exclusive and the
  machine identities they change exclusive; the people a job gates are read
  before it and again inside it, and read again if they changed between.
  The GitHub App's part is `server/githubapps`' own
  (`EndRegistrationsForDeletion`, `RemoveForDeletion`; step 4.10a). Served by
  `server/httpserver/orgdeletion.go` (`getOrganizationDeletion`,
  `scheduleOrganizationDeletion`, `approveOrganizationDeletion`,
  `cancelOrganizationDeletion`; and the tombstone's
  `listDeletedOrganizationAuditEvents`,
  `exportDeletedOrganizationAuditEvents`, `listDeletedOrganizations`,
  `removeDeletedOrganizationReader`). `org-deletion-v0.22.0.json`
  (`go-org-deletion-fixture.test.ts`) replays 58 requests, the due run
  among them through the loop's own pass (a path the test answers itself
  on both sides): who may schedule, approve and cancel, the body, a frozen
  Organization, admin-step-up at report and enforce, the run of a deletion
  holding every kind of row it ends (and the ones it must not run: one
  waiting for its approval, one frozen), and the tombstone's readers and
  their removal; every answer, audit event and changed row equal. G7
  (`daemon` `TestKillDuringOrganizationDeletion`, the crashpoint build):
  varlatchd killed before the run's job, inside it, inside the commit of
  its batch and after it ends the Organization exactly once after a
  restart. The `deletion` conformance suite runs it over the API, with a
  second admin enrolled in a browser and the target's `deletion-due`
  probe.
- `server/githubapps` (step 4.10a): the Organization's GitHub App
  (ADR-0047, `domain/githubapps.ts`), registered through GitHub's manifest
  flow, staged as ADR-0054 amendment D stages it:
  - **Start** (not protected): a single-use state (only its SHA-256 kept),
    bound to the person, the Organization and the intended GitHub account,
    and the manifest; ended registrations a day past their expiry go.
  - **The callback** (`Complete`): an external effect (`write.RunEffect`)
    holding the Organization's gate and the person's shared, and the
    registration's resource gate across GitHub's code exchange (decision
    4). A second completion waits on that gate, then reads the first one's
    outcome. The claim is written with GitHub's answer in the final job, so
    a call that got no answer leaves the state free. The owner is checked
    against the intended account; a match is stored as pending (written
    once), its key sealed under the registration's id, then attached in
    the same job while no approval is needed.
  - **Attachment** (`github_app.register`, protected): the pending key
    unwrapped and sealed again for the App row. Terminal refusals (expired,
    ended, another App in the Organization, an App another Organization
    uses) roll the attempt back, then end the registration in a job of
    their own.
  - **Discard** and the **sweep** (`RunSweepLoop`: a pass at once, then
    every minute, in every serving varlatchd) take the registration's gate.
    A completion claims only an unconverted registration, which is never
    the sweep's, so the sweep never waits for GitHub, as TypeScript's
    `SKIP LOCKED` never does.
  - **Import** (`github_app.import`, protected, an external effect without a
    resource gate): GET /app signed with the key as the App id (RS256, an
    App JWT, `jwt.go`), the permissions checked; under enforce GitHub is
    asked only after a precheck found an approved intent
    (`security.Start`), and the approval is consumed in the final job
    (`Started.Finish`).
  - **Removal** (`github_app.remove`, protected, bound to the App and its
    version): its Connections revoked, their Targets disabled and fenced,
    its key deleted.

  Served by `server/httpserver/githubapp.go`. `github-app-v0.22.0.json` and
  `github-app-v0.21.0.json` (`go-github-app-fixture.test.ts`) replay 63
  requests and two sweeps on a fake GitHub that verifies each App JWT's
  signature, with every request each one sent it; an attachment opens a
  pending key the fixture's release sealed, and the stored keys open to the
  PEMs given: G3 at the database level for GitHub App keys, both directions
  (`TestGoSealedFixture`, go.yml), so `TestG3Gate` runs unconditionally.
  Decision 4's tests (`effect_test.go`): two simultaneous completions, a
  completion without an answer, one admitted just before the
  registration's expiry, a discard and the sweep during a blocked call,
  two simultaneous imports, an import without an answer, and a Security
  Control change during a blocked import. An Organization's deletion ends
  its App through this package (`deletion.go`): scheduling deletes its
  unfinished registrations, finalizing removes the App's local
  registration and key, after which the App can be imported elsewhere
  (`TestOrganizationDeletionEndsTheApp`).
  Step 4.10b adds `listGitHubAppInstallations` (`Installations`, an
  external effect signed as the App, audited as a use of its key) and what
  App Connections mint with (`mint.go`, `key.go`; the Connections
  themselves are `server/syncs`'). `github-mint-v0.22.0.json` and
  `github-mint-v0.21.0.json` (`go-github-mint-fixture.test.ts`,
  `TestMintFixtures`) replay 51 requests: installations, App Connections
  created, checked and listed with tokens minted per use, and key
  rotations, with every request sent to GitHub (bodies included, so the
  narrowing is pinned). The rotated keys, sealed by Go, open to the PEM
  given. Decision 4's tests (`syncs/app_effect_test.go`): a Security
  Control change during a blocked creation, the App removed during one,
  and the App re-keyed between a rotation's call and its final job
  (`VERSION_CONFLICT`).
- `server/access` (step 4.4b): the access structure (ADR-0015, ADR-0028,
  ADR-0029; `http/app.ts`, `domain/policy.ts`, `accessstepup.ts`), served
  by `server/httpserver/access.go`: Grants (listed, created, revoked, and
  replaced in one job under an Idempotency-Key), Roles, Groups and Teams
  (created, changed in place under an Idempotency-Key, deleted), their
  memberships and Team-Project links. Every write is a protected operation
  (admin-step-up, with `accessstepup.ts`'s bindings and summaries), with
  `policy.manage` rechecked once an approval is consumed. A Grant's subject
  and a joining member are pinned by their person gate, held shared, so a
  membership's removal (exclusive) either comes first, and they are not in
  the Organization, or after. The Grant declaration is read with a small
  zod 4 (`httpserver/zodschema.go`): its union reports the one option that
  failed only on a size check, or "Invalid input" at its path. The API
  takes any string as an action, which the OpenAPI document's enum does
  not describe. Lists ordered by name use byte order, as the approval keys
  do. A Grant names only its Organization's groups and roles: creating or
  replacing one that names another's is answered as naming one that does
  not exist is (the foreign key's internal error), and `authz.LoadGrants`
  joins only the Organization's own. U+0000 in any string a lookup takes
  from the request answers 500, as PostgreSQL refuses it in a text
  parameter (`pgText`); a role's or group's name or actions that its write
  refuses read as the name taken, as the TypeScript code reads any failure
  there; a scope `jsonb` refuses fails the insert. The fixture
  `access-v0.22.0.json` (`go-access-fixture.test.ts`, 238 requests)
  covers every Grant shape, each control mode, every zod issue of the
  declaration and U+0000 and lone surrogates where they reach a query;
  the authorization vectors carry the write-side checks (`writeChecks`,
  `grantForms`: who a Grant may name, who may join a group, and
  declarations in their bound form). A summary's names are read in chunks
  of 500 ids (a declaration may name more than SQLite binds in one
  statement), with the Organization bound before the list. Adding a
  member or a Project to a group, the job reads the group again: one
  deleted while the job waited is refused.
  Step 4.4c adds Tailnet Requirements (ADR-0014, ADR-0029, ADR-0046's
  data; `requirementprotection.ts`), served by
  `server/httpserver/requirements.go`: listed, created (never protected,
  recovery while frozen), changed in place under an Idempotency-Key and
  revoked, the change and the revocation protected by
  requirement-protection with its bindings and summaries. A target and a
  selector are stored and read back in jsonb's key order; a change whose
  JSON text is unchanged answers the row as it is, and one that means the
  same Requirement is written and counted without an approval, as in
  TypeScript. `loadTailnetRequirements` reads without an ORDER BY, so the
  TypeScript server's order is unspecified: in a small table, PostgreSQL's
  heap order, where an updated row goes last. Go emulates that order: a
  changed Requirement moves to the end of the rowid order
  (`TestUpdatedRequirementMovesToTheEnd`); reach's conditions and an
  authorization event's Requirements follow it. Once the TypeScript line
  is retired (a step 7/8 follow-up), the read can take
  `ORDER BY created_at, id` instead. And the access reports (ADR-0054
  Decision 8): machine reach (`domain/reach.ts`), the credential review
  (`domain/credentialReview.ts`) and the caller's own Organization
  permissions, each from one read snapshot, `Cache-Control: no-store`. The
  fixture `requirements-v0.22.0.json` (`go-requirements-fixture.test.ts`)
  covers Requirements in every control mode and the reports for every
  kind and state; its times keep their meaning whenever it is replayed,
  and `TestCredentialReviewTimeEdges` covers the windows they cannot pin.
- `server/people` (step 4.5a): an Organization's people (ADR-0006,
  ADR-0052; `domain/invitations.ts`, `domain/members.ts`,
  `domain/peoplestepup.ts`, `issueInviteGrant`, the profile update),
  served by `server/httpserver/people.go`. Invitations: listed newest
  first by `(createdAt, id)` with the audit list's cursor (the time read
  as PostgreSQL reads it), issued (inviting an admin is protected,
  member.invite_admin, with `identity.manage` rechecked, and only a live
  built-in admin may: a machine or a person whose Grant holds
  `identity.manage` is refused, `PERMISSION_DENIED`, before an approval is
  asked for and again in the job under the pinned membership, audited as
  `authorization.denied`), revoked while
  pending. Members: the review of what a person set up, role changes
  (member.promote, member.demote), removal (member.remove) and leaving,
  each with the admin check and the last-admin rule before an approval is
  asked for and again in the job, the approval bound to the membership's
  version. A removal records the authority snapshot (`removal_authority`,
  `removal_requirements`, `removal_conditions`), then ends the membership,
  the person's direct Grants, group links and pending invitations
  (`endMembership`, which Organization deletion's finalization will
  call). As in TypeScript, a removal takes the person's gate shared and a
  role change nothing of the target, so a reader with organization.read
  never holds an admin's gate exclusive before the admin check. A Grant
  naming the person, a group they join and an invitation they issue read
  their live membership in their own job and pin it, its version moved on
  (`access.PinLiveMembership`): on the single writer each comes before a
  removal or role change, which revokes it or whose bound version no
  longer holds, or after, and finds the membership gone or changed. An
  admin check's refusal is audited after the job, as a denial. An issued
  invitation's answer, which carries its token, is `Cache-Control:
  no-store`, where the TypeScript route sets none (a deliberate
  difference; the people replay expects it). The review shows a webhook's
  host as `new URL` gives it (`go/lib/whatwg`). The profile: a person's
  name (in `identities` and their account) and image (a `data:image` or
  `https` URL, 100KB at most, matched with JavaScript's ASCII-only case
  folding, so U+017F never stands for `s`). The fixture
  `people-v0.22.0.json` (`go-people-fixture.test.ts`) covers invitations
  in every state (times pinned so a later replay reads them the same),
  every list parameter, members changed and removed with snapshot and
  review, each control mode, the profile, and U+0000 where it reaches a
  query. Step 4.5b adds the exposure report (ADR-0052 Decision 6;
  `domain/exposure.ts`): what a person received, read from the exposure
  index `server/audit` writes (each version's state: current, retiring
  until its deadline, replaced, its value or environment deleted, or
  unknown here; its confirmation and rotation hint), the authority their
  removal recorded, the review, and the coverage of the TypeScript
  backfill, which is not ported (feature-parity decision 10: a Go
  installation starts finished, and step 7's preflight requires it
  finished); and confirmations (Decision 7: `config.value.write` where the
  value lives, a live built-in admin once it is gone; once per version).
  The fixture `exposure-v0.22.0.json` (`go-exposure-fixture.test.ts`)
  covers each version state and way, a former member's report and every
  kind of confirmation; `TestCoverageWhileTheBackfillRuns` the coverage
  of an unfinished backfill.

- `server/tailnet` (steps 4.13a to 4.13c): the tailnet listeners'
  device check, varlatchd's tsnet node, its pin, the listeners report and
  the browser endpoint's certificate (see "The tailnet listeners", "The
  tailnet node and its pin" and "The browser endpoint over HTTPS").
- `server/capabilities` (step 4.6): broker Capabilities' issuance, list
  and revocation; their exercise is `server/values`' (see "Broker
  Capabilities").
- `server/identities` (step 4.4a): an Organization's machine identities
  and their credentials (`domain/identities.ts`, `identitystepup.ts`, the
  issuing side of `auth/credentials.ts`; ADR-0015, ADR-0023, ADR-0034),
  served by `server/httpserver/identities.go`: listing, creating one with
  its first service credential, issuing another, a Broker's short-lived
  agent-run credentials for its Agents, revoking, retiring, reactivating
  and renaming. Creating, issuing and reactivating are protected
  operations (`security.Prepare`: admin-step-up and credential-lifetime,
  with the bindings and summaries of `identitystepup.ts`). Retiring,
  renaming and reactivating take the identity's person gate exclusive,
  where the TypeScript code locks its row for update; issuing takes it
  shared, so a retirement either came first (the identity is not found)
  or comes after and revokes the new credential too
  (`TestRetireWaitsForAnIssuanceAndRevokesItsCredential`). The fixture
  `identities-v0.22.0.json` (`go-identities-fixture.test.ts`, 158
  requests) covers every identity state, credential kind and limit, and
  both controls off, at report and at enforce.
- `server/pgtime` (step 4.3c): PostgreSQL 17's timestamptz input, ported
  (ParseDateTime, DecodeDateTime and tm2timestamp of `datetime.c` and
  `timestamp.c`; `pg_tzset`, `tzload`, `tzparse` and the DST boundary
  search of `src/timezone`; the Default abbreviations), in a UTC session
  with DateStyle ISO, MDY: what the audit cursor's time reads as. Its
  vectors (`testdata/timestamptz-vectors.json`, 4,854 inputs from
  `testdata/gen-vectors.py`) are PostgreSQL 17.6's answers, instant and
  SQLSTATE, read with that server's tz files (`testdata/zoneinfo`);
  `go-timestamptz-vectors.test.ts` checks the same file against PGlite.
  Zones read from the host's files are cached (at most 2,048); POSIX zone
  strings, which any cursor may name, are parsed each time. Leap-second
  corrections (`leapcorr`) apply only to zones from a `right/` directory,
  which the postgres:17.6 image and the vectors do not have; that path is
  ported but not covered by the corpus.
  Ported code is under the PostgreSQL License as well
  (`LICENSE-PostgreSQL`, `scripts/third-party-code.json`).
- `server/paritytest` (step 4.1a): the Go side of the parity kit (step 4
  decision 3). `services/varlatchd/test/go-fixture-kit.ts` has the
  TypeScript server build a database through its own `/v1`, run a table of
  requests and record each answer (status, the headers that matter, the
  body byte for byte), the audit events, the rows each request inserted,
  updated and deleted in the slice's side tables (diffed by primary key),
  and the report counts; a request may be sent several times at once
  (`concurrent`), its answers kept sorted. `Prepare` loads the rows
  through the schema mapping and `Replay` runs the same requests against
  varlatchd and requires the same answers. Rows are compared in
  PostgreSQL's typed form on both sides (Go reads its rows back with the
  column types of `db/testdata/pg-v0.22.0.json`), as one canonical text.
  What a write makes that a file cannot fix is normalized the same way on
  both sides: a new domain ID becomes `{<prefix>#<n>}`, numbered by first
  appearance in the body, then the audit events, then the side rows
  ordered by each table's declared semantic key (`sortBy`; two rows it
  cannot tell apart fail the recording until anchored); a new time
  `{time}`; a new time or envelope in a side table's volatile column
  `{fresh}` (the Go test opens every new Organization KEK with the file's
  Root KEK). Every column a write fills with a new time or envelope must
  be listed as volatile. Each run of the TypeScript test also checks the
  file's requests are the table's, in order, and rebuilds the database to
  check the file's rows are still what the setup makes (new IDs, and the
  values of each table's declared random columns, relabelled one to one in
  a fixed walk, never masked, so a moved foreign key or swapped IDs count
  as a difference). A request may send headers (an Idempotency-Key);
  its placeholders are filled in its body as in its path; and members of
  its answer named in `masked` read `"{masked}"` on both sides (a digest
  over rows earlier requests made, which cannot repeat; a string or a
  flat object). Every answer that carries a `manifest` has its
  `stateDigest` and `stateDigests` recomputed from that manifest, on both
  sides and before any masking (`checkDigests`, `CheckDigests`), so a
  masked digest cannot diverge unseen. A domain ID's prefix has two to
  four letters (a change set's `cs_`). A replay that counts runs its
  server on `HourClock`: the real clock, moved forward to the next hour
  when less than `HourMargin` (30 minutes) of the current one is left, so
  its report counts, kept per hour, fall in one hour, and its times never
  precede the recording's (a list ordered by time keeps the file's rows
  first). `Replay` checks every request's audit events, and the exposure
  times it set, lie between when it was sent and answered, and fails a
  replay on `HourClock` that runs into a second hour.
  `testdata/core-v0.22.0.json` is step 4.1's file (`go-core-fixture.test.ts`,
  regenerated with `VARLATCH_WRITE_GO_VECTORS=1` as the other vectors),
  and `core-v0.21.0.json` the same rows and requests with the canary,
  every Organization KEK and every value version sealed again by
  v0.21.0's code (`resealWith` in the kit, as `values-v0.21.0.json`); the
  Go test replays both. `serverVersion` is the answering server's
  version, which the installation release read reports, and `ref` the
  release that sealed the rows;
  4.1a records the Organization operations in it, 4.1b the Contract
  operations (request paths name rows by placeholders: `{project:SLUG}`,
  and `{rev:KEY}` for the revision holding an item named KEY), 4.1c the
  Projects, environments (`{env:PROJECT/NAME}`) and installation reads,
  and 4.1d the value writes, under Idempotency-Keys too
  (`{ver:PROJECT/ENVIRONMENT/ITEM}`, a value's current version), the
  Go test opening every value version a request wrote and finding a
  value a request sent, then validation, strict retrieval and search
  (`{cursor:PROJECT/ITEM}`, a search cursor after that hit); 4.2 the
  rotations, in acme/rotate (in flight, past their window, completed,
  superseded; the Go test checks each new rotation's window against its
  grace, which the file holds only as `{time}`). Both sides start a fresh
  server before every 500th request (`WINDOW_BATCH`,
  `paritytest.WindowBatch`), so no request meets the request window. Name later files `<area>-v<release>.json` in
  `testdata/` (the secret scan's allow list and `scripts/ci-changes.sh`
  match that). `server/values/valuestest` loads its fixtures with the same
  `Prepare`.
- `server/api/openapicheck` (step 4.1a): the TypeScript tests' OpenAPI
  check (`test/helpers/openapi-check.ts`) for Go tests: the status is
  documented, the content type listed, and a JSON body valid against its
  schema with every object closed, errors included (JSON Schema 2020-12,
  `santhosh-tekuri/jsonschema/v6`); with `Requests`, an accepted request's
  body too. The parity replays (`server/orgs`, `server/values`) check
  every response with it; their requests are outside the document on
  purpose in places, as the TypeScript fixtures run the unchecked app.
- `server/stages` (step 4.1a, step 4 decision 7): per-stage timings of a
  request (admission, authentication, the read snapshot, authorization,
  the write job's wait for the writer and its batch's commit, decryption,
  encoding), summed per request and handed over once. They exist in the
  `g9a` build only: elsewhere the marks are empty functions on an empty
  type, and `server/stages/check-release.sh` (go.yml) checks in the
  assembly that a release build's marked functions read no clock for them.
  The `g9a` build attaches a recorder to every disclosure, writes
  `stages.json` with the run, serves `GET /run/stages`, takes a CPU
  profile from the load's start with `-profile` and on demand at `GET
  /run/profile?seconds=N` (`bench/g9a/README.md`). The storage engine
  reports a job's queue wait and commit through `storage.WithTiming`, also
  in the `g9a` build only: elsewhere a job carries no timing state (its
  size is checked) and the writer does nothing for it. The script also
  checks the storage engine's functions, follows a function the release
  build inlines to its callers, fails on a listed function that is gone,
  and requires the release binary to hold no symbol of the timing code.
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

## Known TypeScript defects

The TypeScript line is frozen (step 4 decision 5). A difference in what
`/v1` says on the wire is kept, as ADR-0059 Decision 3 requires; a defect
of integrity or availability is not reproduced. No conformance check may
assert one of the defects below. A defect that matters for security is
kept out of this repository until the TypeScript release line fixes it.

Kept, because they are on the wire:

| TypeScript | What it does | Go | Shown by |
| --- | --- | --- | --- |
| `http/app.ts`, an unknown `/v1` route | Hono's plain-text `404 Not Found` | the same (step 3 decision 4) | `server/httpserver/testdata/known-differences.json` |
| `http/app.ts`, the request window | `429` with `PERMISSION_DENIED` | the same | the same file |
| `http/app.ts` `withIdempotency` | a replay answers the stored response read back from jsonb, so its members come in jsonb's order (shorter keys first), not the first answer's | the same | `server/write` `TestReplayVectors` |
| `domain/environments.ts` `deleteEnvironment`, an environment with live derived ones | the refusal lists them (its message and `details.children`) from a query without `ORDER BY`: PostgreSQL's heap order, which tuple pruning and space reuse change, so not reproducible | by name, the order the core fixture's case records | the core fixture's "delete a root with derived environments" |
| `http/app.ts` `createEnvironment`, `expiresAt` | zod's `z.string().datetime()` accepts what PostgreSQL's timestamptz refuses (year 0, or a fraction of more than 128 digits, which overflows `timestamptz_in`'s work buffer): the insert fails and the route answers 500 `INTERNAL`, a validation-shaped input with nothing written or counted | the same: `environments.PostgresTimestamp` refuses exactly those, in the job, where the insert would fail | `server/environments` `TestPostgresTimestampVectors` (`testdata/pg-timestamps.json`); the core fixture's "create a preview" requests |
| `http/app.ts` `searchConfigItems`, a hit's environments | listed in the order of a query without `ORDER BY`, so the order is whatever PostgreSQL's plan gives and is not guaranteed: an index scan through `environments_live_name_key` (`project_id`, `name`) gives Project, then name, while a sequential scan of the same rows gives another order | by Project, then name (byte order), chosen on purpose: the index-scan order, which the fixture's TypeScript server used | the core fixture's search requests |
| `http/app.ts` `listAuditEvents`, the `credentials` sidecar | the page's credentials from a query without `ORDER BY` (`id = ANY($1)`), so the object's member order is PostgreSQL's row order | the table's order (`rowid`), which is PostgreSQL's for a table nothing was deleted from, as the security fixture records | the security fixture's audit listings |
| PostgreSQL's text and jsonb, under every route | U+0000 in a string written to a text or jsonb column fails the statement: the transaction rolls back and the route answers 500 `INTERNAL`; a lone surrogate reaches a text column as U+FFFD (Node's UTF-8) and fails in jsonb | the same: `write.Text` for text columns (U+0000 refused, lone surrogates as U+FFFD), `jsvalue.JsonbRefuses` for jsonb (`audit.Record`, `write.Idempotent`). **Every later slice applies them to each text or jsonb value it writes**, at the point the TypeScript statement would fail, and records the case in its parity fixture | `server/write` `TestText`; the core fixture's U+0000 and lone-surrogate requests |
| `domain/oidc.ts` `exchangeOidcToken`, a token whose payload is JSON `null` | `peek.iss` is read outside the try: a `TypeError`, so `POST /v1/oidc/token` answers 500 `INTERNAL` instead of 401 `INVALID_CREDENTIAL`, with no `authentication.failed` event (step 4 defect 5, not a security defect) | the same for now, as the other 500s on bad input; once the TypeScript server is retired (step 7/8), 401 audited as "malformed" | the OIDC fixture's "exchange, a null payload" |
| `apps/cli/src/main.ts` `probeServer`, an answer of another shape (step 5 defect 14, not a security defect) | the `TypeError`'s message becomes the probe's detail on stdout, and V8 names the expression as the release bundle spells it: esbuild renamed `meta` and `credentials` there, so the detail reads `meta3.capabilities.includes is not a function` or `credentials2.items.find is not a function` | the same text, the bundle's names included (`status --probe --json` is parsed by the menu bar app and the tray) | `testdata/transcripts/5.1c-api-client.json`, the `probe.shape.*` cases |

Not reproduced:

| TypeScript | Effect | Go | Shown by | Conformance |
| --- | --- | --- | --- | --- |
| `mirror/publisher.ts:209` orders Convex mirror events by the text form of `event_order` | events after position 9 can be published out of order | nothing to port: there is no Convex in Go | | none |
| `domain/securityreport.ts` `countWouldBlock`, a count whose hour and the current hour are both already summarized (possible only after the clock moved back across a summarized hour) | the count is dropped (an error is logged): the stored total is one short | the count goes to the hour after the last summarized one for its key, which no summary covers yet, so every committed count reaches exactly one summary; with a clock that does not move back nothing differs | `server/security` `TestCountsSurviveAClockMovedBack` | none |
| `domain/retrieval.ts:201` updates `security_control_counters` before `audit/events.ts:221-222` locks the Organization and the exposure identities | under admin-step-up's report mode, repeated exports in one counter bucket can deadlock in PostgreSQL, which aborts one export | the report counter and the export's audit events are one write job on the single writer, and no gate is taken inside a job, so the inversion cannot form | `server/values` `TestConcurrentExportsUnderReportCountExactly`: 24 concurrent named and all-authorized exports in one bucket all succeed and the counter is exact | none |
| `apps/cli/src/options.ts` `parseOptions`, a positional argument named like a property of `Object.prototype` (`constructor`, `toString`, `__proto__`, `hasOwnProperty`) for a command whose options have aliases (step 5 defect 11, not a security defect) | `spec.aliases[arg]` reads the prototype, so `arg` becomes a function and `arg.startsWith` throws a `TypeError`: Node.js prints the stack and exits 1 | an ordinary argument | `internal/cli` `TestPrototypeNamesAreOrdinaryArguments` | none |
| `apps/cli/src/agents/install.ts` `AGENTS`, `skill.ts` `GUIDE_TOPICS` and `mcpConfig.ts` `MCP_FILES_BY_AGENT`, a coding agent or guide topic named like a property of `Object.prototype` (`constructor`, `toString`, `__proto__`, ...) (step 5 defect 15, not a security defect) | the lookups read the prototype, so the name passes as known: `agents install --agent constructor` installs and prints `constructor reads undefined` (in `--json`, an agent without `reads`), with `--mcp` it throws a `TypeError` before writing; `agents guide constructor` throws a `TypeError`: Node.js prints the stack and exits 1 | an unknown coding agent or topic: the usage error every other unknown name gets (64), nothing written | `internal/agents` `TestPrototypeNamesAreUnknown` | none |
| `apps/cli/src/validation.ts` `REQUIRES_HINT`, a requirement named like a property of `Object.prototype` (`constructor`, `toString`, ...) in `validate`'s report (step 5 defect 23, not a security defect) | the lookup reads the prototype, so `validate` prints a function's source as the requirement: `not evaluated: A (function Object() { [native code] })` | a requirement the protocol does not define: `not evaluated: A (an unrecognized requirement)` | `internal/cli` `TestValidationRequiresHintReadsOwnNames` | none |
| `packages/sync` `coolifyCompose.ts` `classifyComposeUsage`, a Compose file with an alias inside its own anchor (step 4 defect 6, not a security defect) | the `yaml` package builds a cyclic object and `scalarsOf` overflows the stack, so the Coolify adapter's `inspectUsage` throws a `RangeError` though it never should: varlatchd's engine catches it (its `usage-unchecked` note says "the destination could not be read"), the CLI's `sync check` fails | `lib/sync` reads the file as unreadable: usage unchecked, every verdict unknown, the note's reason "the service's compose file is too large or could not be read" | `lib/sync` `TestTypeScriptExchanges`, the case "divergence: an alias inside its own anchor" | none |

The TypeScript admin CLI refuses an ordinary command during maintenance
with `Installation is in maintenance; ordinary admin operations are
blocked`, but that error reaches its generic handler, which prints
`Operator command failed; check configuration and maintenance status.`
(exit 1 either way). varlatchd prints the refusal itself.

## Before the first Go release

- G3 at the database level: `go test ./server/values -run TestG3Gate
  -args -g3-gate` passes, so every encryption class in
  `server/values/testdata/g3-matrix.json` but the JWT signing keys (only
  Convex uses them) is proven through both servers' code that reads its
  rows, in both directions. Until step 4 builds the features that store
  them, webhook secrets, Platform credentials, GitHub App keys and audit
  export credentials and drain copies are proven at the envelope level
  only, and the check fails.
- The Go release workflow: binaries named `varlatch-<version>-<os>-<arch>`
  (`.exe` on Windows) and `varlatchd-<version>-linux-<arch>`, plus
  `varlatchd.service`, all in `SHA256SUMS`; `install.sh` attached with
  `@VARLATCH_VERSION@` replaced by the version; varlatch.com serving the
  latest one with a `Content-Length`.
- List the Go module's dependencies (`go list -m all`, modernc.org/sqlite
  and its own) in THIRD-PARTY-NOTICES.md and its generator: the generator
  (`scripts/generate-third-party-notices.mjs`, `pnpm notices:check`)
  covers npm packages only, so no Go binary ships before it lists the
  modules each binary links, go-webauthn and its dependencies
  (fxamacker/cbor, go-webauthn/x, golang-jwt/jwt, google/go-tpm,
  tinylib/msgp, philhofer/fwd, x448/float16) and tailscale.com and its
  dependencies (step 4.13b: BSD-3-Clause, BSD-2-Clause, Apache-2.0, MIT
  and ISC; see its PR) included.
