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
- `lib/keyenv/`: the refusal of a key in the environment, shared by
  `varlatchd serve` and the CLI in the single-container image (slice
  6.10a; see "The single-container image").
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
  - **The seal** of formats 1 and 2 is `packages/backup`'s, byte for byte:
    `VLTBAK01`, a salt and a nonce, then one AES-256-GCM message (the header
    as additional data) over the manifest's length, the manifest and the
    components, under scrypt(BEK, salt), whether the BEK is a 32-byte key
    file or a passphrase.
  - **Format 3 is compressed, then sealed the same way:** `VLTBAK02`, a salt,
    a nonce and the compression's number (1, zstd), all of it additional
    data; in the message, the manifest's length, the manifest (as it is) and
    one zstd frame of the components, which states their size (from 256
    bytes on; a shorter one is held to the manifest's as it is read). The
    manifest's sizes and SHA-256 are the components' before compression.
    Another magic or compression is refused before any key work. Opening
    authenticates the whole archive first, then holds the frame to what
    `Seal` writes without decompressing it (`checkFrame`: one frame, no
    dictionary, a window of at most 8 MiB, the manifest's size, nothing
    after it), and never writes more than the manifest declares. A
    configuration past 16 MiB is neither sealed nor opened. Format 3
    under `VLTBAK01`, not compressed (0.50.0-rc.1 to rc.3, and what their
    converter wrote), still opens; those releases answer a compressed one
    "Unsupported archive format", as the TypeScript CLI does.
  - **A long message.** One GCM message over up to 60 GiB needs a
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
  (`varlatch verify-release`) before anything is put in place. Over the
  TypeScript CLI (slice 6.7a, decision 11): a `varlatch` that is its
  single-file build is kept until the new one runs from its place, then
  removed (both CLIs use one store of sign-ins and settings), or, on a host
  with a Compose installation (`/srv/varlatch` holds `varlatch-install.json`
  or `docker-compose.yml`), kept beside it as `varlatch-ts` for that
  installation's host commands; if the new one does not run there, the
  TypeScript CLI is put back. A serving installation (slice 6.8) stamps
  its address in `ORIGIN`: the CLI then comes from `<origin>/cli/v<version>/`
  over https (or plain http on this machine), with no redirect followed,
  and is checked the same way; `--server` installs from github.com only.
- `install/install.ps1`: the Windows installer (CLI for the current user,
  in `%LOCALAPPDATA%\Programs\Varlatch`, added to the user `PATH`), with
  the same checks as `install.sh` and its G8 tests under PowerShell 5.1 and
  7 (the prefix runner is `install/testdata/ps1prefix.ps1`; the Windows CI
  job runs the end-to-end install). Over the TypeScript CLI in the same
  folder (`varlatch.cmd` starting `varlatch.cjs`, as the documentation and
  the tray app install it): both are removed once the new `varlatch.exe`
  runs from its place; if it does not, it goes and they stay.
- `cmd/varlatch/internal/selfupdate/`: `varlatch self-update` (slice 6.7a,
  decision 11). SHA256SUMS and its signature are downloaded over HTTPS from
  GitHub's hosts only (`api.github.com`, `github.com`, and the release
  files' storage hosts `objects.githubusercontent.com` and
  `release-assets.githubusercontent.com`; a redirect anywhere else, or to
  plain HTTP, is refused) and kept in memory; the signature is verified by
  `lib/release` for the release workflow's identity of that version's tag
  before the binary is even requested; the binary is checked against
  SHA256SUMS in memory, then written to a new file beside the running one,
  made executable, run once (it must report the version), and renamed over
  it. On Windows the running file is renamed aside first, and the next run
  removes it; a rename another process's hold on a file stops is tried
  again for up to 5 seconds, the running file back in its place meanwhile. It never goes to an older release without
  `--allow-downgrade`, to a prerelease unless this binary is one or
  `--prerelease` is given, or to a release before the Go line (0.50.0); a
  copy Homebrew or winget installed (its path is in a Cellar or in WinGet's
  `Packages` or `Links`) is refused with that package manager's command.
  Its tests sign fake releases with a test Sigstore generated in the test
  process (`lib/release/releasetest`; no key is in the repository), and
  `cmd/varlatch`'s `TestSelfUpdateReplacesItself` runs the real CLI,
  built with `-tags selfupdatetest` (the only build that can be pointed at
  another source; `TestSeamIsTestOnly`), on Linux, macOS and Windows. The
  run against a real published prerelease is slice 6.1b's.
- `install/varlatchd.service`: the systemd unit (data in
  `/var/lib/varlatch`, configuration in `/etc/varlatch/varlatchd.conf`, the
  Root KEK and BEK as systemd credentials, user `varlatch`, a strict
  sandbox). CI checks it with `systemd-analyze verify` and `security`, and
  runs `install/unitprobe` under it (`install/test-unit.sh`).
- `release/build-assets.sh` and `release/check-assets.sh` (step 6.1a):
  the Go release assets, built reproducibly from the commit (CGO off,
  `-trimpath`, no VCS stamp or build ID, the version through
  `lib/buildinfo`): `varlatch` for the six platforms, `varlatchd` for Linux
  amd64 and arm64 with the dashboard generated from that commit (a release
  refuses the placeholder, or a dashboard built from changed sources), the
  installers stamped with the version, the unit and its example
  configuration, and `SHA256SUMS`; then checked: exactly the files the
  installers fetch for every platform they accept, each listed once with
  its hash, each binary of its platform's format, the version reported.
  `release.yml` runs both for a tag of 0.50.0 or later, signs
  `SHA256SUMS`, verifies the signature with the release's own `varlatch`,
  and publishes (a prerelease for `-rc.N`); `go.yml`'s conformance job
  runs both on every pull request it selects, signing and publishing
  nothing. `.github/workflows/published-release.yml` (step 6.1b) checks a
  published release of the Go line as people install it, on Linux, macOS
  and Windows (`install/published_test.go`, G8's published-asset half):
  after the Release workflow publishes a release (a prerelease or a final
  one), or by hand for any.
- `image/` (step 6, slice 6.10a): the single-container image, varlatchd
  and the CLI in one distroless image for linux/amd64 and arm64, built by
  `image/build.sh` from the release's own Linux binaries. See "The
  single-container image" below; `image/README.md` is how to run it.
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
  directory). A case may run the CLI on a pseudo-terminal (`terminal`:
  its stdout, its stderr or both, and its stdin): the recorder uses
  util-linux `script`, the replay opens one itself (`creack/pty`, Linux
  and macOS; skipped on Windows), and what the terminal displayed is
  compared as `expect.terminal`, its `\r\n` as `\n`. Regenerate after
  changing the cases with `VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter
  @varlatch/cli exec vitest run test/go-transcripts.test.ts`. A case whose
  outcome names a path below its directory (`{{dir}}/...`) also has a
  Windows expectation, recorded by the TypeScript recorder on Windows
  (`apps/cli/test/goWindows.ts`) into `testdata/transcripts/windows/`,
  which Windows replays it against; so do the agents install and
  find-files vectors (`testdata/vectors/windows/`). The directory inside a
  JSON string is mapped back to `{{dir}}` in its escaped form too
  (`transcript.UnfillDir`), so such a case needs no Windows expectation.
  `TestWindowsExpectationsComplete` fails on every platform when a case
  needs one and has none: label the pull request `record-windows` (the
  windows-expectations workflow) and put its artifact in with
  `scripts/go-windows-expectations.sh <run id>`.
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
  with it and that everything of a built slice has a recorded
  case or a vector: a built command, each of its options, each variable,
  chain and exit status. Missing coverage fails. `TestClientLacksNotStale`
  checks `scripts/conformance/client-go.json` against the built slices.
  Which slices are built is `testdata/built/`: one empty file per built
  slice, named for it (`5.2`), so pull requests that build different slices
  never edit the same line.
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
  hook` (the guardrail hook itself, slice 5.6a) is `hook.go`: the event
  read, the small shell reader, the three denials, and the searches it
  follows (grep and its kin, rg, ag, git grep, jq, the Grep tool). It
  reads an event of any nesting depth (`lib/jsjson`'s `ParseDeep`, which
  keeps its containers on a stack of its own; `Parse` keeps its limit of
  10,000 for every other caller), keeps a word's UTF-8 bytes whole, reads
  in linear time, and turns a panic into no decision. Its globs are
  matched as RE2 regular expressions (Go's `regexp`), compiled once per
  run. On Windows it resolves paths as Node.js's `path.win32` does
  (`win32path.go`, held to Node.js's answers by `TestWin32Paths`): a path
  rooted without a drive (`/home/dev/...`) is absolute, and a UNC path's
  share follows any run of separators after the server. It compares a
  path with the credential store's directories, and with its
  `.config/varlatch` backstop, as Windows names files: without regard to
  case, without a `\\?\` or `\\.\` prefix, and, in a path without one, with
  each component's trailing dots and spaces left out, as Win32 leaves
  them out (`TestHookStoreWindowsForms`); and it reads `.env` names
  without regard to case there (`.ENV` is `.env`,
  `TestHookEnvCaseOnWindows`). Elsewhere byte for byte
  (`TestHookStoreCaseOffWindows`). `TestHookDeniesWithThisPlatformsPaths`
  holds a `.env` read, a search and the store to a denial with the
  platform's own paths. `internal/cli`'s
  `agentscmd.go` is the commands and `init` with its flags (`--org`,
  `--project`, `--server`, `--default-environment`, `--no-agent-files`);
  `init` on a terminal without them (guided) is slice 5.8a's
  (`guidedinit.go`, below).
- Guided `init` (slice 5.8a; ADR-0058 Decision 2) is `internal/cli`'s
  `guidedinit.go` and `prompt.go` (guidedInit.ts and prompt.ts): with a
  terminal on both ends, outside assisted mode, when `--org` or
  `--project` is missing, `init` asks only for what is missing: the
  installation's address (setup.ts's rule: an origin, https, or http on a
  loopback host; what was typed is never echoed), signing in (the stored
  credential when the server accepts it, else `login`'s browser hand-off,
  printing nothing a server sent; every bearer it reads or obtains, the
  hand-off's and the issued one, is held from that moment, as `login`
  holds them), the Organization and the Project
  (each listed, or created after asking), the environments (development
  and production offered when there are none) and the default one. It
  writes `varlatch.toml` and the agent files as `init` with flags does,
  then plans every `.env` file it finds (examples and schemas left out,
  `.env` first and the rest in locale order) before writing anything:
  where each goes (one file per environment), what each environment
  already has (a replacement asked for, a production one only after its
  name is typed), one Contract revision for every new item of every file
  (a type the files disagree on chosen, the items that are not secret
  named), activation asked for on its own, and a file deleted last, only
  when asked and only when every value is stored and every item is in the
  active Contract. Every step prints the command it stands for; a failure
  names the step and an API error's code or a network failure's name,
  never a server's text, and every `.env` file is kept. The questions are
  plain lines (a number, y or n, text with a default in brackets), as
  prompt.ts asks them; none takes a secret. The values it reads are held
  in flight as `import` holds them. Off a terminal or in assisted mode,
  `init` is the flags path (a usage error without `--org` and
  `--project`).
- `testdata/vectors/guided-init.json`
  (`apps/cli/test/go-vectors-guided-init.test.ts`): every case of
  guided-init.test.ts and more (40 runs: the paths through each step,
  refusals, re-asks, failures at each call, codes a server should not
  send, names with control characters), each through guidedInit.ts with
  that test's fake and a scripted prompter: the status, every line, the
  questions and options, the configuration written, every API call, the
  fake's state and the files left (`internal/cli`'s
  `TestGuidedInitVectors`, with a port of the fake); and the terminal
  prompter's own text, byte for byte, for 15 inputs (`TestPrompterVectors`).
  The `5.8a-guided-init` transcripts hold `init` off a terminal; the
  pseudo-terminal tests (`guided_pty_test.go`) run the whole guided path,
  assisted mode on a terminal, and the input ending at a question.
- `testdata/vectors/agents.json` (`apps/cli/test/go-vectors-agents.test.ts`):
  the pure edits (the block, the imports, the Gemini CLI's context, 46
  `.aider.conf.yml` layouts, 35 `config.toml` texts through each of the
  four TOML edits, `agents guide`), and 263 projects (files, symbolic and
  hard links, files that are not UTF-8, directories in the way) taken
  through runs of install, check and remove for every coding agent, with
  and without `--guardrails` and `--mcp`, in both scopes: each run's
  result or error, its lines, and the whole tree afterwards
  (`internal/agents`' `TestInstallVectors`).
- `testdata/vectors/hook.json` (`apps/cli/test/go-vectors-hook.test.ts`):
  1,439 pre-tool-use events through `hook.ts`'s `runHook`, each with its
  answer's exact bytes: every event of `agents-hook.test.ts` and
  `agents-guardrails.test.ts`, projects (files, a directory called
  `.env`, git repositories with ignored and tracked files, directories
  named `café` and `日本`, quoted and not, and names holding a lone
  surrogate) for the globs and recursive
  searches, events padded with arrays nested 10,001 and 100,000 deep
  (inside `tool_input` and at the top level; the case's `nest` keeps the
  padding out of the file), UNC-shaped store paths (only names on POSIX;
  skipped on Windows, which reads them as UNC paths), and a command for
  each option of another program the inventory lists for the hook, and for the six options
  `hook.ts` reads that the inventory files under another kind
  (`internal/agents`' `TestHookVectors`; `TestInventoryCoverage` checks
  that a vector uses each). `TestHookLinearTime` holds a long word in
  every shape, many keys, deep nesting and a long filter in a walked
  search to linear growth: eight times the input in at most 24 times the
  time (plus 20 ms), each size timed interleaved with the other after a
  warm-up, never against a clock; `TestTheLinearityCriterion` checks that
  a quadratic merge fails it.
- `varlatch mcp` (slice 5.6b; ADR-0043 Decision 9) is `internal/mcp`: the
  Model Context Protocol over stdio, newline-delimited JSON-RPC, written
  directly rather than with an MCP library and held to what
  `packages/mcp-server` does over `@modelcontextprotocol/sdk` 1.32.2
  (`protocol.go`: which lines are messages, the methods it answers
  (`initialize`, `ping`, `tools/list`, `tools/call`; any other is -32601),
  cancellation, and task creation refused; `schema.go`: each method's
  request checks and each tool's input checks, with zod's issues in its
  order and words; `tools.go`: the eight read tools, and with
  `--allow-writes` `varlatch_set_value`, which never writes a Secret's
  value, and `varlatch_delete_value`, which needs the item named again as
  `confirm`). No tool returns a Secret's value, and every line it writes
  goes through the CLI's fail-safe. `internal/cli`'s `mcpcmd.go` starts it
  as `run.ts` does: the flags and `VARLATCH_MCP_ALLOW_WRITES`,
  `--allow-disclose` and `VARLATCH_MCP_ALLOW_DISCLOSE` refused (64), the
  server and defaults from the flags and the repository's context, the
  credential (never the operator's inside an agent-safe run, where
  `--allow-writes` is refused), and its own User-Agent,
  `varlatch-mcp/<version> (<platform>; <arch>)`. It serves until standard
  input ends, answers what it holds, and exits 0 once the requests in
  flight have finished: a request still waiting on a server that never
  answers keeps it running, and the host may kill it then. A handler that
  panics is answered as the SDK answers one that throws, -32603 with what
  happened, and the server serves on (`TestAHandlerThatPanicsIsAnInternalError`).
- `testdata/vectors/mcp.json` (`apps/cli/test/go-vectors-mcp.test.ts`):
  574 inputs through the TypeScript server and the SDK's own stdio
  transport, each with the lines it writes: what is a message and what is
  dropped, request ids, every method, each request schema's issues, every
  tool's arguments and checks before a request, and each tool's answer for
  a client that fails, answers nothing, answers null, or answers with an
  API error (`internal/mcp`'s `TestVectors`). The transcripts (`5.6b-mcp`,
  70 cases) hold the server end to end with the fake server: the startup
  refusals, the protocol, every tool, the write checks, a cancellation,
  and malformed answers. `internal/mcp`'s and `internal/cli`'s tests port
  `packages/mcp-server`'s `server.test.ts` and `run.test.ts`, and
  `mcp-cli.test.ts` runs against Go.
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
- Contracts (slice 5.3b): `internal/cli`'s `contract.go` (`contract push
  --schema <.env.schema> | --file <contract.json> [--semantics
  <version|latest>] [--json]`, `contract activate <revision-id>`, `contract
  show`), on `lib/contract`: `--file` sends the file as `JSON.parse` reads
  it, `--schema` the Contract `internal/envschema` resolves, and a type newer
  than the version the revision will get (integer needs version 3) is
  refused before anything is sent. `internal/envschema/` is
  `packages/env-schema`'s `.env.schema` parser and resolver in Go (decision
  8, ADR-0059 amendment 7), JavaScript's whitespace, `.` and `trim()`
  included; `testdata/vectors/envschema.json`
  (`apps/cli/test/go-vectors-envschema.test.ts`) holds both to 115 schemas
  (the draft, the resolved Contract's canonical bytes and hash, or the
  error) and every valid Contract of `lib/contract`'s normalization vectors
  pushed with `--file` (`TestContractPushSendsTheSameRevision`).
- Types (slice 5.3c): `internal/cli`'s `types.go` (`types --out
  <file.ts|.mts|.cts|.py> [--revision <id>] [--check]`, typesCommand.ts:
  one fetch, the module written only if its bytes changed, never through a
  symbolic link, by a fresh file in the same directory renamed over the old
  one with its mode kept; a file another release generated is current when
  only its Generator lines differ) and `internal/typegen` (typegen.ts and
  typegenPython.ts, decision 7). The modules embed the Typed Accessor
  runtimes the TypeScript CLI embeds, byte for byte:
  `internal/typegen/embedded/` holds `ACCESSOR_RUNTIME_SOURCE` and
  `PYTHON_RUNTIME_SOURCE` with the runtime's function name, schema format
  and semantics versions, copied by `embed-runtimes.mjs` (`go generate`)
  from the packages' own build scripts; go.yml's "Generated code is
  current" fails on a stale copy, and the packages' sources are in its path
  filter. `testdata/vectors/types.json`
  (`apps/cli/test/go-vectors-types.test.ts`) holds both generators to 120
  revisions (every valid Contract of `lib/contract`'s normalization vectors
  at its own semantics version and at 2 and 3, one Contract per Contract
  Semantics vector file, every input of `typegen.test.ts` and
  `typegenPython.test.ts`, and answers of the wrong shape): the whole
  module, byte for byte as the file holds it (UTF-8 as Node.js writes it:
  a lone surrogate from the Contract's text as U+FFFD, `typegen.Encode`),
  or the same `TypesError` message (`TestTypesVectors`).
- The matcher and the redaction engine (slice 5.4a, decision 10):
  `internal/matcher` is `packages/matcher` (the forms of a value, the
  byte-level Aho-Corasick automaton with its hold-back, `StreamMatcher`,
  which replaces each overlap region once, `StreamScanner`, and the
  whole-input references) and `redact.ts`'s `OutputRedaction` (its
  notices, and the relay of the child's two streams, which never releases
  held bytes on a timer and discards them after an interrupt, a failed
  read or a failed destination). No command uses it yet (5.4b).
  `testdata/vectors/matcher.json` (`apps/cli/test/go-vectors-matcher.test.ts`)
  holds both to 364 streams: every case of `packages/matcher`'s tests and of
  `redact.test.ts`, seeded overlaps, every encoded form at every base64
  alignment, multi-byte, lone-surrogate and binary text, 400 Secrets, and
  long inputs. Go replays each at every byte split, byte by byte and at
  random chunkings against the recorded output, and each recorded chunking
  push by push (what was emitted, held and pending); the scanner's
  occurrences likewise, and 12 relays. Matching is linear in the input,
  however many matches one chunk holds (`TestMatcherIsLinear`; the
  TypeScript merge is quadratic per chunk, step 5 defect 29).
- `run` (slice 5.4b): `internal/cli`'s `run.go`, `runchild.go`,
  `exportcontext.go` and `assistedrun.go` (main.ts's `run` case,
  `inject.ts`, `exportContext.ts`, `assistedRun.ts`):
  - **A default run.** The command gets this process's environment with
    every delivered value over it. An inherited `VARLATCH_RUN_CONTEXT` is
    removed. `--omit` leaves items out, delivered or inherited, and is
    checked before any Secret is disclosed. A disclosure refused for
    permission or the tailnet continues with the plain values, and says so.
  - **`--export-context`.** The run context, after the two reads agree on
    their state digest (three attempts).
  - **Assisted mode.** The command's stdout and stderr go through
    `internal/matcher`. A Secret too short to mask stops the run (78), with
    its remedies. `--allow-unmasked` and `--no-redact` are refused there.
  - **The human's override.** `--allow-unmasked NAME`, outside assisted
    mode.
  - **Signals.** `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`, `SIGUSR1` and
    `SIGUSR2` are forwarded to the command; Windows has only Ctrl-C and a
    stop. An interrupting one makes the relay discard what it holds. The
    status is the command's own, or 128 plus the number of the signal that
    ended it.
  - **Held output.** A clean end of the command's stream releases the bytes
    held as a possible start of a value unchanged, as TypeScript does: they
    can no longer complete a match.
  - **A closed stdout or stderr.** It fails the relay's write (EPIPE)
    instead of ending the CLI: SIGPIPE is handled while the relay runs, and
    the command starts with SIGPIPE's default
    (`TestRunSurvivesAClosedStdout`).
  - **The command's environment** is encoded as Node.js's spawn encodes
    it: a stored value's unpaired surrogate (kept as WTF-8 bytes by
    `lib/jsjson`) reaches the command as one U+FFFD, the form the matcher
    masks (`run.surrogate`, `assisted.surrogate`).
  - **Finding the command.** As libuv does: in the command's own `PATH` on
    POSIX; on Windows, `.com` or `.exe` only, a `.bat` or `.cmd` file
    refused (decision 4, `TestLookCommandAsLibuv`).
  - **`--redact` (slice 5.4c).** Outside assisted mode, the command's
    stdout and stderr go through `internal/matcher` too, masking the
    Secrets this run delivered (`redact.ts`, ADR-0038 Decision 10); a
    shorter one passes unchanged and is named. It is refused (64), before
    anything is fetched, when stdout or stderr is a terminal (outside
    assisted mode, which gives the command pipes) and in an agent-safe run.
    `testdata/transcripts/5.4c-redact.json` records every combination, the
    terminal refusals under a pseudo-terminal (`terminal` cases), and
    `redact-run.test.ts` runs against Go.
  - **`--strict` (slice 5.4f, `strictRun.ts`).** One strict retrieval
    (`POST .../retrievals`, retried once after a server failure or a lost
    connection) gives the values, the manifest and the Contract Revision.
    The environment the command would receive is resolved and validated
    against that revision (`lib/contract`'s semantics); `--allow-inherited`
    accepts a parent's value, validated, and must name Contract items;
    `--omit` of a required item is a violation. Every violation is printed
    at once, names, classes and reasons, never a value, and the run ends
    with 78 before the command starts (`5.4f-strict.json`, one case per
    kind). A server without strict retrieval gets 78, never a default run.
    The checks come after the strict retrieval, whose one answer holds the
    Contract and the values: an `--allow-inherited` or `--omit` name that
    is refused, or a violation, ends a run whose values were already
    disclosed to the CLI process (and recorded as a disclosure); nothing
    reaches the command before every check.
  - **`--agent-safe` (slice 5.5b, `agentrun.go`, `nestedrun.go`).** Runs
    the Agent with non-sensitive values, Placeholders for Secrets, a local
    Broker (`internal/broker`), and a fresh private `VARLATCH_CONFIG_DIR`
    with `VARLATCH_AGENT_RUN`, never a Secret value or reusable bearer.
    `--agent-safe --strict` runs preflight strict retrieval and binds
    Capability issuance to its state precondition (retrying once on
    `STATE_CHANGED`). A nested `varlatch run` inside an agent-safe run
    keeps the Agent isolated and adds Broker tunnel notes.
- The local Broker (slice 5.5a; ADR-0022, ADR-0039 Decisions 1 to 37):
  `internal/broker` is `broker.ts`, `placement.ts` and `scrub.ts`. It
  listens on 127.0.0.1 only and answers nothing without the per-run proxy
  credential, compared in constant time once the request's line and
  headers are read and before any byte of its body. Placement decides,
  before anything is exercised, where each Placeholder may be substituted
  and blocks the rest; a substituted request goes out over Go's stock TLS
  verification to an allowlisted destination only, its values held for
  that request and its response and cleared after; the response passes
  the scrubber (gzip, deflate, and Brotli through
  `github.com/andybalholm/brotli`, MIT), whose decoders are bounded by
  `MaxDecodedBytes` (a decompression bomb in each coding is cut off at 64
  MiB, `limit.bomb-*`). A CONNECT to a destination that uses Secrets is
  refused with its diagnostic; strict mode blocks every other destination.
  The Agent's side speaks HTTP/1.1 through a reader and writer of its own
  (`httpwire.go`), which refuses rather than guesses: see "The Broker's
  HTTP/1.1 reader" below, and `FuzzReadHead`. Vectors:
  `testdata/vectors/placement.json` (86 requests through the planner),
  `broker-wire.json` (66 raw requests and every byte the Broker answered)
  and `broker.json` (53 scenarios through a scripted TLS destination: the
  request it received, the Agent's response, the events, nothing held
  after), all recorded from the TypeScript Broker.
- Agent-safe runs and `request` (slice 5.5b; ADR-0022, ADR-0039,
  ADR-0043 Decisions 5 and 6): `internal/cli`'s `agentrun.go`,
  `nestedrun.go` and `request.go` (`agentRun.ts`, `request.ts`, main.ts's
  `run` and `request` cases):
  - **`run --agent-safe`.** Every stored Secret is targeted or omitted, and
    a flag naming anything else is refused, before anything is issued. The
    Capability is issued with the Broker credential (`--broker-credential-file`
    or `VARLATCH_BROKER_CREDENTIAL`) and refused unless the server recorded
    exactly the targets asked for. The Agent starts with the plain values,
    a Placeholder for each Secret, and every spelling of the proxy
    variables naming the Broker (`NODE_USE_ENV_PROXY=1`; each no-proxy
    spelling keeps what it inherited but an entry that exempts every
    host, and gains the Broker's address). It never gets a Secret's value,
    the Broker credential or the operator's bearer; Secrets inherited from
    the shell under a stored or Contract name are removed and named. It
    gets a configuration directory of its own (mode 0700, removed at exit)
    and `VARLATCH_AGENT_RUN`. The per-run proxy credential is only in the
    Agent's proxy URLs, never printed. `--agent-metadata` mints a
    read-only agent-run credential after the Broker starts; it and the
    Capability are revoked when the Agent exits. The Broker's diagnostics
    are names, rules and counts only.
  - **A run inside an agent-safe run** never discloses and never uses the
    operator's credential: the command gets this run's environment (less
    `--omit`), the run's own credentials masked in its output, and a note
    naming any tunnel the Broker refused meanwhile.
  - **`varlatch request`** sends one request to the run's Broker with the
    absolute URI and the per-run credential, and relays the response (with
    `-o`, to a file replaced only when the whole response arrived). Its
    statuses: 0 when the destination answered, 1 for a Broker refusal or
    a cut-off response, 77 when the Broker refused the credential, 69 when
    the Broker cannot be reached or answers 503, 64 for the command line
    or no Broker to send through.
  - Transcripts `5.5b-agent-run` and `5.5b-request`; the `agent-isolation`,
    `broker-connect-errors`, `request-e2e` and `request-failures` process
    tests; the conformance suite `broker` on the Go client.
- `testdata/vectors/values.json` (`apps/cli/test/go-vectors-values.test.ts`):
  what `parseDotenv` makes of 68 files, `secretInput.ts`'s checks (the
  generators, the value sources, input bytes, well-formed text, the hidden
  prompt's keys) and 2,022 texts split into grapheme clusters, `validate`'s
  outcome and `--json` document for 17 reports, and import's type
  inference (every semantics version), name checks and strict decoding.
- Scan (slice 5.4d; ADR-0038 Decision 14): `scan (--staged | <path>...)
  [-e <env>] [--json] [--baseline <file>] [--write-baseline]
  [--max-file-size <size>] [--max-total-size <size>]` and `scan
  --install-hook [-e <env>]` are `internal/scan` (`engine.go`,
  `baseline.go`, `sources.go`: scan.ts and scanSources.ts) and
  `internal/cli`'s `scancmd.go` (scanCommand.ts and main.ts's case, with
  `--find-files`). Listing comes first and reads no content: `--staged`
  takes the blobs the index records for every path the next commit adds or
  changes (`git diff --cached --raw -z`, sizes from `git cat-file
  --batch-check`, content from one `git cat-file --batch`, never the
  working tree; inside a hook, Git's own environment as it is), and paths
  are walked without following a symbolic link, in byte order of their
  names. A file over `--max-file-size` (64 MiB) or past `--max-total-size`
  (1 GiB) is refused by its listed size before it is opened, and every file
  is read in chunks of 64 KiB, so memory stays bounded. Only when a file
  will be read is there one disclosure, `scope: "all-authorized-secrets"`
  with `purpose: "scan"` (a server without `secrets.disclosure-purpose` is
  named), and the values (current and retiring) go to `internal/matcher`'s
  `StreamScanner`, binary files as bytes; each value long enough to mask
  is a value in flight, so no output or diagnostic shows one. A finding
  names the path, line, byte column, item, version and form, never the
  value or the line; a file ending with a value's start is counted, never
  a finding; `varlatch:allow NAME` on a line the occurrence touches and a
  baseline entry (path, item, version: nothing else is accepted) allow
  one; past 1,000 findings a file's occurrences are counted by item and
  version. `--install-hook` writes `.git/hooks/pre-commit` (Git's
  `--git-path`) to run `varlatch scan --staged` from the project directory,
  and never replaces a hook it did not write (it names the line to add
  instead). Statuses: 1 for findings, 2 when nothing is found but a file
  was not scanned, 0 otherwise, and 1 for every failure (usage, a refused
  credential, a server that cannot be reached).
  `testdata/vectors/scan.json` (`apps/cli/test/go-vectors-scan.test.ts`)
  holds 33 engine cases (locations, forms, markers, bounds, baselines,
  listing limits, incomplete starts; `internal/scan`'s `TestEngineVectors`
  also feeds each in every chunk size up to 97 bytes), 26 trees scanned as
  `--staged` or paths with real Git (`TestSourceVectors`), and
  `parseSize`, `formatBytes`, the baseline's reading and writing, the
  option parser and the hook's text; the transcripts (`5.4d-scan`, 38
  cases) hold the command end to end against the fake server, a transcript
  per failure class included. `scan-cli.test.ts` runs against Go (the
  hook blocks real commits), and `TestScanIsLinear` holds every
  adversarial shape to the shared growth rule.
- Find files (slice 5.4e): `scan --find-files [<dir>] [--json]` is
  `internal/findfiles`, run from `internal/cli`'s `scancmd.go`. It lists
  the files whose names look like copies of secrets
  (`.env`, `.env.*` but the two templates, `*.pem`, `*.key`) by names and
  `lstat` alone: it never reads a candidate, never follows a symbolic link
  (one is listed by its own name), skips `.git`, `.hg`, `.svn` and
  `node_modules`, and stops at 200,000 entries or 20 directory levels,
  naming what it did not search. Git's own ignore rules decide each
  file's state: one `git check-ignore --no-index` per repository, with no
  system or global configuration and none of the caller's `GIT_*`
  variables, given the excludes file read here (the repository's
  `core.excludesFile`, else the global one from `GIT_CONFIG_GLOBAL`, or
  `$XDG_CONFIG_HOME/git/config` then `~/.gitconfig`, else
  `$XDG_CONFIG_HOME/git/ignore`). Before Git runs, the repository is found
  by name and looked at: a linked `.git`, a bare repository, an include,
  `core.worktree`, an alternate object store, a `.gitignore` or excludes
  file that is a link, a hard link or not a regular file, or one named
  like a secret copy, makes the state unknown, with why. Names are bytes
  (`internal/termtext` shows them as `scan` shows text); statuses 1 (a
  file found), 2 (none found, the search incomplete), 0, and 1 for every
  failure, as for all of `scan` (a status the command sets itself is
  kept). `testdata/vectors/findfiles.json`
  (`apps/cli/test/go-vectors-findfiles.test.ts`) holds 79 trees (names,
  links, bounds, Git's rules, global and XDG configuration, repositories
  and their unusual forms) to findFiles.ts's report, human and `--json`
  (`internal/findfiles`' `TestVectors`); `TestNeverReadsACandidate` and
  `TestFindIsLinear` (eight times the tree in at most 24 times the time).
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
| The Broker's HTTP/1.1 reader (`internal/broker`, `broker-wire.json`) | Node.js's parser takes a request line split by two spaces, one without a version, and one naming HTTP/2.0, and drops header fields after the 2,000th | each is refused: 400 for the request lines, 431 past 2,000 fields; a request-target with a byte outside visible ASCII is 400 too, a chunk-size line over 4 KiB 400. Every other refusal (obs-fold, a bare LF or CR, Content-Length with Transfer-Encoding, a repeated Content-Length, a Transfer-Encoding other than chunked, a control character in a value, a head over 16 KiB, a timeout) is Node.js's, byte for byte | A request a destination could read two ways is never inspected one way and forwarded the other |
| The Broker's own requests and relays (`broker.json`) | headers to the destination in the Agent's order and spelling, `Connection: keep-alive`; a relayed response's headers in the destination's order; the Agent's connection kept alive after a substituted request | headers to the destination in net/http's order and spelling, `Connection: close`, no `User-Agent` added; relayed headers sorted by name (a pass-through response's names lower-cased, as Node.js writes them); the Agent's connection closed after a substituted request | Header order and spelling carry no meaning; net/http owns its connection. Closing after a substituted response leaves no state between it and the next request |
| A 101 Switching Protocols to a request the Broker passes through (`broker.json`, `pass.upgrade`) | no answer: the Agent's request waits until it gives up (step 5 defect 43, below) | 502, `the destination switched protocols; the Broker relays HTTP only` | The Agent hears at once that the Broker relays HTTP only; a substituted request's switch is refused the same way |
| An aborted response's body (`broker.json`) | the bytes relayed before the abort are those its reads happened to get | the same rule, so an aborted body may stop at another byte; both stop without a terminating chunk and release nothing held | Where the destination's bytes arrive in pieces is the network's |
| An agent-safe run that stops after its Capability was issued | the Capability is left to its lifetime when the server's targets cannot be put in canonical form, the Broker cannot start, or the `--agent-metadata` credential cannot be minted | revoked in each case before the run is refused | A refused run leaves nothing usable behind (`internal/cli` `TestRefusedRunRevokesItsCapability`) |
| `broker-reply-once`: a reply the Broker generated itself, as `varlatch request` prints it | its text twice (step 5 defect 44, below), then the closing line | its text once, then the closing line | Each line of the Broker's refusal is said once; the status is the same |
| The Broker's events on an abort after the headers | (step 5 defect 42, below) | one `aborted` event per abort; a destination that resets the connection after the headers is an abort (`the destination's response failed mid-stream`), its held bytes discarded | Diagnostics count each abort once and name its cause |
| `version` | `varlatch --version` prints `varlatch <version> (migration <n>)` | `varlatch <version>` | Decision 6: the migration number is the TypeScript release manifest's; every consumer (installers, menu bar app, tray, omarchy plugin, tap) reads the first two words |
| `uncaught`: an error no command handles (for example a `credentials.json` entry or a `.varlatch/local.json` holding `null`, or a `varlatch.toml` that is a directory) | escapes `main()`; Node.js prints the source line, its stack trace and its version, and exits 1 (the recorder keeps `{{uncaught <name>: <message>}}`) | `varlatch: <error>`, one line on stderr, exit 1 | A stack trace is not output anyone parses; the status and stdout are compared as recorded |
| Diagnostics never print credential values | not compared | Every write goes through one fail-safe, so every path is covered by construction. On stdout (`Run.out`: every line, `verify-release`'s results), every text in Varlatch's token format is `[redacted]` (`cli.RedactOutput`), and so is the bearer the run sends, whatever its shape: every API client is made by `Run.newClient`, which holds its bearer first (`Run.holdCredential`; `TestEveryClientHoldsItsBearer` fails on any other `apiclient.New`, and on the package imported under another name), so a server that echoes a bearer in an answer `whoami`, `env list`, `env use` or an MCP tool prints never gets it shown, and `env use` keeps the tier it caches in `.varlatch/local.json` masked, while `status` and `context` mask a cached tier again as they read it (one an older CLI stored included) with every credential the run knows, stored ones too (`TestPoisonedTierNeverShown`), so a later run, offline, cannot print it either. A bearer the person gave (`--token`, `--token-stdin`, or `VARLATCH_TOKEN`, held from the start of every run) is held whatever its length; any other from 8 characters on, since a shorter one would match ordinary words, and every string value of a `--json` document has every URL's user name and password masked and every token redacted (`printJSON` through `cli.RedactValue`, then straight to stdout); keys are left alone, never redacted, since they come from the API's schema and the CLI's own documents, so the document stays valid JSON with the keys it had. On stderr (`cli.RedactDiagnostic`: every failure in `Run.finish`, every other line through `Run.warn`, `verify-release`'s failures), every token is `[redacted]` too, and `clientctx.MaskUserinfoInText`, one linear pass over the whole message (at-signs `@`, `\u0040`, `\x40`, `\U00000040`, `%40`; tab, CR and LF ignored in finding them), masks the union of two kinds of span as `[redacted]@`: for each at-sign whose run (a run ends at whitespace or a quote) holds any colon before it, from just after the nearest preceding `//`, or the run's start when there is none, up to the at-sign; and from just after the first colon of the text, whatever precedes it, to its last at-sign. An at-sign in a URL's path, query or fragment is not a credential's and is passed over by both (a release workflow's identity, `.../release.yml@refs/tags/v<version>`, reads as it is), but only when nothing is ambiguous: a literal `@`, after a "//" and an authority that is not empty (slashes after "//" skipped) and has ended at `/`, `?` or `#`, whose host part after its last at-sign is a host, a numeric `host:port` or a bracketed address, with no colon, `%3A` or `%2F` between the authority's end and the at-sign; anything else may end a credential, as before (`alice:fake/x@h`, a percent-encoded URL in a query or fragment, `https:///u@h`). The TypeScript CLI's fail-safe passes over such an at-sign as well: the two CLIs read a release workflow's identity the same way, and Go still masks every ambiguous shape that TypeScript's masker would show; neither shows a credential. No character class decides what precedes a colon; an email or `@AGENTS.md` (no colon before the at-sign) keeps its bytes, and text may be over-masked, never under-masked. On top of it, a precise layer per value (every server URL shown is its display form instead: `server-display`, below): every value a failure echoes (an argument, a command, a topic, an approval id, a path) and every value human output takes from a server's answer, the tier cache, stored metadata, the repository's files or the environment (an Environment name, the Organization and Project, an agent run id) is masked with `clientctx.MaskURLInValue`: which composes both maskers on the original value, never one on the other's output: the precise authority span (`clientctx.MaskUserinfo`'s, by the authority `lib/whatwg` parses, when the value, its leading and trailing whitespace trimmed, parses as a URL or is scheme-relative) and the whole-text fail-safe's span, their union replaced once with `[redacted]`, so a credentialed URL in a query, a fragment or surrounding text is masked whatever the other masker removed; an API client's refusal names the refused URL by its display form; already-masked text may read `https:[redacted]@h` (cosmetic, never a leak), and a value without a user name and password keeps its bytes. The option parser never shows the value of an option it refuses with the value attached (`--name=value`, `-Xvalue`), whatever the option: `--name=[redacted]`, `-X[redacted]`. A header value that cannot be sent is refused before anything is sent, with a message that names the header (`the credential contains a character that is not allowed in an HTTP header`). A failure that echoes a value holding an at-sign puts the value first and its explanation after it, so the fail-safe keeps the explanation: `varlatch server: https://[redacted]@h: unexpected argument`; a message naming a server shows its display form, which holds no at-sign, in the wording the recordings hold; the usage text of a usage error, alone or after a message, is printed after the fail-safe, never masked, byte for byte as TypeScript prints it (`UsageErrorWithUsage`, `UsageOnly`) | Output is printed, logged and pasted into issues: in error text never leaking comes before byte parity, while the precise layer keeps ordinary output, and every value without a user name and password, byte for byte (every recorded transcript replays, the cases showing a server Go displays differently through `server-display` and one through `option-value`); the exit status is the same. Pinned by `internal/cli`'s `TestServerURLsNeverShowUserinfo`, `TestClientMessagesNeverShowUserinfo`, `TestNotAuthenticatedReadsAfterTheFailSafe`, `TestFailuresNeverEchoUserinfo`, `TestFailuresKeepTextWithoutCredentials`, `TestFailureExplanationsSurvive`, `TestSessionExplanationsSurvive`, `TestRedactDiagnostic`, `TestParserEchoesNoOptionValue`, `internal/clientctx`'s `TestMaskUserinfo`, `TestMaskURLInValueNeverShowsUserinfo`, `TestMaskURLInValueTrustsNoContent`, `TestMaskURLInValueComposes`, `TestMaskURLInValueUnionOfSpans`, `TestNoPasswordEverShows` (a property test: thousands of generated secrets, a token as the user name with no colon included, in every context, percent-encoded and nested, through `DisplayServer` and the free-text maskers), `TestDisplayServer`, `TestMaskUserinfoAgreesWithWHATWG` (both ways, over 8,800 texts on which `lib/whatwg` and Node agree), `TestFailSafeMasksEveryReproducer` (every leak found in review, through the fail-safe alone), `TestFailSafeRule`, `TestFailSafeAtSignsInAPath`, `TestFailSafeMultiLinePasswords`, `TestFailSafeAgreesWithWHATWG`, `TestHasAtSignIsTheFailSafesDetection`, `TestMaskingIsLinear`, `TestMaskingIsLinearOnLargeMessages` and `FuzzMaskUserinfoInText`, `internal/apiclient`'s `TestRefusalsNeverShowCredentials` and `TestRefusalsReadAfterTheFailSafe`, the process tests `TestDiagnosticsNeverPrintCredentials`, `TestSessionCommandsNeverShowUserinfo` (login, logout and whoami, every WHATWG authority form), `TestLoginNeverShowsTheCredential` (a credential given to `login` never appears in its output, accepted or refused), `TestUsageErrorsNeverEchoACredential`, `TestLoginServerTokenIsNeverEchoed`, `TestStatusProbeMasksNestedCredentials`, `TestNestedCredentialsBehindOuterOnes`, `TestOutputNeverShowsAToken` (tokens and URLs in `--json` documents and human output, from the server, the environment and the store), `TestEchoedBearerNeverReachesStdout`, `TestEveryClientHoldsItsBearer` and `internal/cli`'s `TestMcpNeverShowsTheCredential` (a bearer that is not in Varlatch's format, echoed in answers) and `TestEveryWriteGoesThroughTheFailSafe` (a `go/ast` check across `go/cmd/varlatch`: no reference to a stream, no `fmt.Print*`, no `log`, no `json.NewEncoder` outside the fail-safe's writers), `TestJSONKeysAreLeftAlone`, `TestNoPasswordInOutput`, `TestUsageTextIsNeverMasked` (every usage error's usage text, after a message echoing a credentialed URL too), `TestHelpIsTheUsageText`, `TestNoUsageTextThroughTheFailSafe` (a `go/ast` check: no usage text in a message the fail-safe masks), `TestOutJSONTakesOnlyARedactedDocument`, `TestEchoedNamesAreMasked`, and `TestVerifyReleaseNeverEchoesUserinfo` |
| `server-display`: every server URL the CLI shows (a stored server, a `--server` or `VARLATCH_SERVER` value, a local override, the remembered default, a refused URL), in `context`, `status`, `server`, `whoami`, `login` (every method, device sign-in's messages included), `logout`, `init` and `mcp`, their `--json` documents and their messages | as recorded | its display form (`clientctx.DisplayServer`), an allow-list of its parts, each keeping its bytes: the scheme and the slashes or backslashes after it (`//` for a scheme-relative URL), the host and port, and the path when it holds only RFC 3986's unreserved characters and `/` (ASCII letters and digits and `/-._~`; otherwise its leading segments that do, then `/[redacted]`: `/api/v1;token=x` reads `/api/[redacted]`), so an ordinary URL (`http://127.0.0.1:1234`, `https://h.example/varlatch/`) is shown as it is. A user name and password are never shown; a query is shown as `?[redacted]`, a fragment as `#[redacted]`, a path outside the allow-list as `/[redacted]`; leading and trailing spaces are left out. A value that does not parse as a URL (`lib/whatwg`, against `https:` for a scheme-relative one), holds a space or a control character, has no authority, has a host and port outside their allow-list (letters, digits and marks of any script, `.-_~[]:`), or whose authority ends at a backslash with an at-sign of any form after it, is shown as `[unrecognised server URL]`. A message that would name the server in a command to run says `this server's URL` where the display form differs from the value, and names it as one POSIX shell word otherwise (`'http://[::1]:8080'`, single-quoted when it holds a character a shell would read). An address the server gives for the person to open (a device sign-in's verification address, an approval's address, a redirect's target) is free text, shown with the masking above | A server URL is a value of known shape, so it is shown by what is allowed rather than by what a masker detects: no user name, password, token, nested or percent-encoded URL in a query, fragment or path can reach output, whatever its form (Sol, #278 rounds 1 to 6). Free text (a server's answer, an echoed argument) keeps the masking above. Every recorded transcript replays; a case showing a server differently is accepted only where Go's output is the recording with each fixture server shown through `DisplayServer` (`TestServerDisplayDifferenceIsExact`). Pinned by `internal/clientctx`'s `TestDisplayServer` and `TestNoPasswordEverShows`, and the process tests `TestNestedCredentialsBehindOuterOnes` (Sol's round-6 canaries through `server`, `context`, `status --probe` and `logout --all`), `TestStatusProbeMasksNestedCredentials`, `TestDiagnosticsNeverPrintCredentials` and `TestSessionCommandsNeverShowUserinfo` |
| `option-value` (how transcripts and vectors compare, not a behaviour) | not compared | a recorded "unknown option" message is compared with an attached option value shown as `[redacted]` (`cli.OptionValueDifference`) | The Go CLI never shows an option value in a usage error ("Diagnostics never print credential values"); the rest of the message, the status and stdout are compared as recorded |
| `--json` documents hold only scalars where the API defines them | not compared | `env list --json`'s `name`, `tier` and `kind`, `whoami --json`'s documented fields (`tags` a list of scalars), and `status --probe --json`'s identity and organization fields: an object or array a server sends where the API defines a scalar is left out | A document scripts read never passes a server's nested value through. Pinned by `TestJSONScalarsOnly` |
| `json-scalars` (how transcripts compare, not a behaviour) | not compared | a recorded `env list --json` or `status --probe --json` document is compared with an object or array removed where the API defines a scalar | Two recorded cases (`probe.whoami.odd-shapes`, `env.list.odd-marks.json`) hold such values |
| `whoami --json` prints only the documented fields | not compared | the schema version, the server it asked (masked; nothing in the answer replaces it), then only the fields of the API's WhoAmI document (`identity`, `organization`, `credential`, `listener`, `tailnet`), each object with only its own documented fields, in the answer's order | A document scripts read holds only what the API defines; for an answer that keeps to the API, the output is the same. Pinned by `TestWhoamiJSONShowsOnlyTheDocumentedFields` |
| The excerpt is left out when the file may hold credentials: a `varlatch.toml` that does not parse and holds an at-sign | smol-toml's message, `Invalid varlatch.toml: Invalid TOML document: <what>` followed by the lines around the error, quoted | `Invalid varlatch.toml: Invalid TOML document: <what>, line <n>, column <n> (the file may hold a URL's user name and password, so its lines are not shown)` when the file holds an at-sign of any form, as the fail-safe detects one (`@`, `\u0040`, `\x40`, `\U00000040`, `%40`, tab, CR and LF ignored; `clientctx.HasAtSign`); a file without one gets smol-toml's message byte for byte | The quoted lines can hold part of a URL's user name and password and end before its at-sign (a string that runs on past them), where neither the precise layer nor the fail-safe sees a URL; a file without an at-sign holds no URL's user name and password. This reaches stderr (`context`, every command that reads `varlatch.toml`) and `server`'s stdout (`Server here: none (...)`). Pinned by `internal/cli`'s `TestTOMLExcerptLeftOutWhenFileMayHoldCredentials` (Sol's reproducer, a credential on the line before the error and several lines after it, every at-sign form, `server`'s stdout) and `TestFailuresKeepTextWithoutCredentials`; the 213 recorded `varlatch.toml` documents (`testdata/vectors/context.json`) and every transcript are unchanged |
| The Node.js version warning | one line on stderr below a Node.js release's security floor (`VARLATCH_NODE_CHECK=off` hides it) | none | No Node.js; the recorder sets `VARLATCH_NODE_CHECK=off` |
| `user-agent` (how transcripts compare, not a behaviour) | `varlatch-cli/0.22.0 (<platform>; <arch>[; assisted])` as recorded | the same format with this build's version, platform and processor | Each CLI names itself; the recording's values belong to the recorder's machine |
| Trust roots | Node.js's bundled Mozilla roots, plus the PEM file `NODE_EXTRA_CA_CERTS` names (Node.js warns once on stderr when it cannot read it) | the system's roots, plus the same file; one it cannot read adds nothing, silently | Decision 4: a self-hosted installation behind a private CA keeps working; the system's roots are where Go and operators keep them |
| Proxies | fetch reads no proxy from the environment, unless Node.js is started with `NODE_USE_ENV_PROXY=1` | never (`Proxy: nil`) | Decision 4; the Go CLI has no Node.js option to honour |
| Runtime error wording: the code in `Cannot reach the Varlatch server (<code>)` | the first code in the `fetch failed` error's causes that `exitCodes.ts` names, else "network error" | the same codes from Go's errors: refused, reset, timed out, unreachable host or network by their errno; NXDOMAIN `ENOTFOUND`; a temporary DNS failure `EAI_AGAIN`; a connect or TLS handshake timeout `UND_ERR_CONNECT_TIMEOUT`; a connection closed before the answer `UND_ERR_SOCKET`; anything else "network error" | Decision 2: the exit status (69) is the same; the code is Node.js's own wording, mapped where Go can tell |
| Request headers decision 2 does not compare | `accept-language: *`, `sec-fetch-mode: cors`, `accept-encoding: gzip, deflate` | none of the first two; `accept-encoding: gzip` (Go decompresses it) | Neither the server nor any consumer reads them |
| `self-update` (slice 6.7a of internal docs/design/go-step6.md) | replaces its `.cjs` with `varlatch-cli-<version>.cjs`; the newest release is GitHub's latest; the signature is checked only when cosign is installed and the release carries one, and `--allow-unverified` (with `--yes`) installs without it; `--repo` and `VARLATCH_RELEASE_REPO` choose another repository | replaces its own binary with the release's `varlatch-<version>-<os>-<arch>[.exe]`, always verifying SHA256SUMS's signature with the embedded verifier first (`--allow-unverified` changes nothing); the newest release is the newest of the Go line (0.50.0 or later), a prerelease only from a prerelease or with `--prerelease`; an older release only with `--allow-downgrade` (64 otherwise); `--repo` and `VARLATCH_RELEASE_REPO` other than `varlatch/varlatch` are refused (64); a Homebrew or winget copy is refused (1) with that package manager's command; `--check --json` reports `install` as `release`, `homebrew` or `winget`; 69 when GitHub cannot be reached, 1 for a release that does not verify | Decision 11: the Go CLI is a native binary from the Go line's releases, and fails closed (Decision 8). Pinned by `internal/selfupdate`'s tests and `TestSelfUpdateReplacesItself`, `TestSelfUpdateRefuses` |
| `self-update-usage` | `varlatch help self-update`, `self-update --help` and `self-update -h` print the TypeScript CLI's form | the Go CLI's: `[<version>] [--check [--json]] [--yes] [--prerelease] [--allow-downgrade]`, with what it checks; `varlatch --help` has it too (`host-usage`) | `self-update`. Transcript cases `help.self-update`, `help.self-update.option` and `help.self-update.short` name it; pinned by `TestHelpIsTheUsageText` |
| `host-usage` | `varlatch`, `--help`, `-h`, `help`, and an unknown command print the whole usage with a Compose installation's host commands (`admin` with `--dir`, `setup`, `adopt`, `move`, `doctor`, `self-update`, `upgrade`) | the same text, its title without the dash, with a Go installation's in their place (`setup`, `move`, `doctor`, `admin`; `self-update`, `upgrade`, `migrate`), as each command's own help prints them, without `adopt`, and with `tailnet repin`; `varlatch help migrate` prints `migrate`'s | A release whose help names commands it refuses, and not the ones it has, sends people to the wrong ones (the audit of 2026-11-24). Transcript cases of area 5.1a name it; the text is made from the TypeScript one (`hostUsage`), and `TestUsageIsAGoInstallations` holds the rest to it |
| `tailnet-usage` | `varlatch help tailnet`, `tailnet --help` and `tailnet -h` print `require`, `requirements` and `remove` | the same, and `repin` | Only the Go CLI has `tailnet repin`. Transcript cases `help.tailnet`, `help.tailnet.option` and `help.tailnet.short` name it |
| `skill-version` (how transcripts compare, not a behaviour) | the skill files `agents install` writes name `varlatch 0.22.0` (`SKILL.md`'s `metadata.generator`, each reference's first line) | this build's version | Each CLI names itself, so `--check` after an upgrade reports the skill as changed; the replay puts this build's version in a case's inputs and expected files alike |
| `host-admin`: `varlatch admin backup`, `security reset`, `unfreeze`, `outbound check` and `maintenance` (slice 6.2a of internal docs/design/go-step6.md) | a Compose installation's: `docker compose exec -T varlatchd node dist/cli.js admin ...` in the `--dir` directory (or the working directory); `backup create\|verify\|restore\|status` through Compose and pg_dump; no `maintenance` | a Go installation's: runs `varlatchd admin <the same words and options> [--config <file>]` as a separate process (decision 2), the `varlatchd` beside this `varlatch` (a symbolic link to `varlatch` followed; an executable file) or else the first on `PATH` (69 when there is none); (Unix) as root, one on `PATH` is run only when root alone can change it, the directory it is in and the `PATH` entry (not writable by group or others, owned by root), else 78 naming the path; `VARLATCH_*` variables holding a credential (`VARLATCH_TOKEN`, `VARLATCH_OIDC_TOKEN`, `VARLATCH_KEK_PASSPHRASE`, any named for a token, passphrase, password, secret, credential or key) are left out of its environment, as no fronted form reads one; the forms are `varlatchd`'s (`backup run\|status\|test-bucket\|restore --in`, `maintenance begin\|end\|status`); `--config` names the installation's `varlatchd.conf` (default `/etc/varlatch/varlatchd.conf`); a JSON answer is printed again as `JSON.stringify(doc, null, 2)` after the fail-safe, any other answer and every line on stderr through the fail-safe; the exit status is `varlatchd`'s (78 adds a line saying to run it as root when not root; Unix only). `--dir` names a Compose installation and is refused (64), naming `varlatch-ts` (decision 11); `backup create` and `backup verify` are refused (64) naming `backup run`; `admin reenroll` is slice 6.9 | The Go installation has no Compose stack, and every database or key operation is `varlatchd`'s, routed through its control socket or run offline under its lock (step 4's decision 11). Pinned by `internal/cli`'s `TestAdminFrontsRunVarlatchd` and `TestAdminRefusals` (a fake `varlatchd` on `PATH`) and `TestAdminWithTheRealVarlatchd` (the real one, built from this checkout, in a temporary installation), `TestFindVarlatchdBesideFirst`, `TestFindVarlatchdAsRoot` and `TestAdminLeavesCredentialsOut` |
| `admin-usage` | `varlatch help admin`, `admin --help` and `admin -h` print a Compose installation's `admin` forms (`backup create\|verify\|restore\|status`, `reenroll`, `security reset`, `unfreeze`, `outbound check`, each with `--dir`) | a Go installation's: `backup run\|status\|test-bucket\|restore`, `security reset`, `unfreeze`, `outbound check`, `maintenance begin\|end\|status`, `reenroll`, each also taking `--config` (the text a usage error adds); `varlatch --help` has it too (`host-usage`) | The Go CLI runs a Go installation's host commands (`host-admin`); a Compose installation's stay the TypeScript CLI's (decision 11). Transcript cases `help.admin`, `help.admin.option` and `help.admin.short` name it; pinned by `TestHelpAdminIsTheGoUsage` |
| `doctor-usage` | `varlatch help doctor`, `doctor --help` and `doctor -h` print a Compose installation's doctor (`--dir`, `--wait`, `--gate`) | a Go installation's: `varlatch doctor [--json] [--config <file>]` | The Go CLI runs a Go installation's doctor (`doctor`); a Compose installation's stays the TypeScript CLI's (decision 11). Transcript cases `help.doctor`, `help.doctor.option` and `help.doctor.short` name it |
| `setup-usage` | `varlatch help setup`, `setup --help` and `setup -h` print a Compose installation's setup (`--dir`, `--escrow`, Docker) | a Go installation's: `sudo varlatch setup` with every question's flag (`--name value` or `--name=value`), `--answers`, `--root-kek-out`/`--backup-key-out`, `--accept-slow-disk` and `--accept-existing-user` | The Go CLI sets up a Go installation (`setup`); a Compose installation's stays the TypeScript CLI's (decision 11). Transcript cases `help.setup`, `help.setup.option` and `help.setup.short` name it |
| `setup`: `sudo varlatch setup [flags]` (slices 6.4a, 6.4b and 6.4c of internal docs/design/go-step6.md) | a Compose installation: `.env`, images, Convex, the first administrator, escrow, `doctor`, in the `--dir` directory | a Go installation on a systemd host (as root, said before anything): the questions (ingress public, proxy, localhost or tailnet, with what each needs, localhost refusing a non-loopback `--listen` and any `--trusted-proxies`; where backups go: this host, or a bucket through a destinations file; Varlatch's hosted backups shown as not available yet), each with its flag and the answers file's name (`--answers <file>`, a JSON object: a flag that disagrees with it is refused); the `varlatch` system user (one that exists already must be a system account, a `nologin` or `false` shell and a uid within `SYS_UID_MAX`, or setup refuses, saying what it found, unless `--accept-existing-user`; uid 0 always refused); `/var/lib/varlatch` (0700, the user's) and the fsync probe of its disk before the database is placed (a slow disk said with its p99; setup goes on only when accepted: `--accept-slow-disk` or the question); the Root KEK and the backup key made with crypto/rand and written straight into `/etc/varlatch` (root, 0600, linked into place, never replaced; one there that no run in the journal made is kept and said; the temporary files a run that ended mid-write left in `/etc/varlatch`, exactly setup's own `.<name>.<12 hex>.tmp`, are removed and counted), never in an argument, the environment, the journal, a log or a temporary file outside `/etc/varlatch`, shown once on a terminal or, without one, written to `--root-kek-out`/`--backup-key-out` (0600, never over another file); `varlatchd.conf` (0640, root:varlatch, in `/etc/varlatch` 0750 root:varlatch), naming no key (the unit's credentials are the keys: `backup_key_file` now defaults to the `backup-key` credential as `root_kek_file` does), checked by `varlatchd admin config check` before it is put in place, an existing one kept; the unit enabled and started; `/readyz` awaited. A journal (`/etc/varlatch/setup.json`, 0600: the answers, the steps done, the probe's measure, never a key) makes a rerun continue where setup stopped and change nothing once done (no file written, nothing restarted); an answer given differently is refused (moving is `varlatch move`). `--dir` names `varlatch-ts setup`; (6.4c) `setup --restore <archive> --root-kek-file <file> --backup-key-file <file>` onto a fresh host (G13 through setup; refused onto a host whose setup has steps done, or for another archive than the journal's): the operator's two keys checked as keys, different from each other, and installed in `/etc/varlatch` in place of new ones (root, 0600, linked into place, never over another key, never shown, copied or said), then `varlatchd admin backup restore` before the unit first starts (the archive, its release and the Root KEK checked by varlatchd; resumable), the archive's `public_url` required to be the answers' (its passkeys belong to it: refused before the unit starts, with what to do), the restored files made the unit's; with tailnet ingress, before the restored node first enrols, `varlatchd admin tailnet probe-name --json` (decision 16): a short-lived ephemeral probe node joins with the auth key under a name of its own, reads the peers it can see, logs out (an ephemeral node logged out is deleted) and leaves no state, then a second one joins to show the key is reusable; a peer under the configured name (any case) stops setup before enrolment (delete the old node first), and so does a single-use key, which the probe spent (setup says how to make a reusable one with the node's tags; the probe uses the key twice more than the enrolment, and the operator can revoke it after the restore); a name not seen is not taken as free (the tailnet's access rules may hide nodes): varlatchd reads its name back after enrolment, and a name the control plane suffixed (`<hostname>-<n>`) keeps tailnet access closed, latched as `name-suffixed`, with the remedy in the log (delete the old node, rename this one, then re-pin; a re-pin is refused while the suffix stays); step 7's OAuth client (`devices:core`, O4) may later replace the probe where present; the restored administrators keep their passkeys, so no link is issued, and the first backup proves the restored installation; then (6.4b) the first administrator's passkey: `varlatchd admin bootstrap` (or `recover` for an administrator made but never enrolled, as `admin bootstrap-status` says) gives a one-time link with `--revoke-unused` (the links setup issued before and never used are revoked in the same write job, counted in the issued event's `revokedUnused`), shown on a terminal or, without one, written to `--admin-link-out` (0600, a new file or an earlier link's, never through a symbolic link; never in the output or the journal; removed once the passkey is in), and setup waits `--admin-wait` (default 15m; `0s` stops, exit 75, for a rerun); the keys shown once on a terminal, each pasted back without echo and checked (a wrong copy refused, three tries a key, what was typed never shown), or without one written to `--root-kek-out`/`--backup-key-out`; the Custody Attestation (`varlatchd admin custody attest`, method `copy`, for both keys), asked on a terminal or `--attest` without one (without it, exit 75); the first backup (`varlatchd admin backup run --json`) verified (integrity, compatibility, the Root KEK; with a bucket, delivered) and its id journaled; then `varlatch doctor`'s report (a failing mandatory check: exit 1, setup otherwise done, and a rerun runs doctor again). Host commands run as root outside the unit (`varlatch admin ...`, and `varlatchd admin ...` by hand, as doctor's remedies give them) read the keys where the unit's `LoadCredential` does: with no `CREDENTIALS_DIRECTORY` and no `root_kek_file`, the configuration's directory stands for it when the Root KEK is there, so the configuration loads as under the unit (the keys read in place under their own modes, never copied, no key put in the environment); only as root, since a member of the `varlatch` group can see that `root-kek` is there; without a Root KEK, a run by hand is told to set `root_kek_file` or run as root with `root-kek` beside the configuration; in the single-container image, the keys found so are among those `lib/keyenv` refuses in the environment | Decision 7 and ADR-0059 Decision 8. Pinned by `internal/setup`'s tests (a fake host under a temporary root: every step, the modes, a rerun changing nothing, stopped after each step and resumed, answers final, missing answers named before anything changes, the slow disk, keys never replaced and never anywhere but their files, an existing user, an interrupted run's leftovers), `internal/setup`'s `TestRestore`, `TestRestoreRefusals`, `TestRestoreChecksTheTailnetName`, `server/tailnet`'s `TestTheProbeSeesAHeldName`, `TestTheProbeFindsASingleUseKey`, `TestASuffixedNameKeepsAccessClosed` and `TestTheReadBackOnTheControlPlane` (testcontrol), `TestFirstAdministrator`, `TestPasteBack`, `TestCustodyAttestation`, `TestFirstBackup` and `TestDoctorStep`, `server/daemon`'s `TestBootstrapStatus`, `TestAdminFindsTheKeysBesideTheConfiguration` and `TestAdminRefusesAKeyFoundBesideTheConfigurationInTheImage`, `lib/keyenv`'s `TestConfigured`, `server/config`'s `TestLoadHost`, `internal/cli`'s `TestSetupRefusals`, `TestSetupFlagValueForms` and `TestAdminFindsTheUnitsCredentials`, and `go/install/test-setup.sh` on go.yml's runner (its own systemd, no container: localhost, own proxy and public against Pebble, the passkey enrolled from the link's file by `enrollpasskey`, a test tool with `authtest`'s software authenticator, the custody attested and the first backup verified, G13: the localhost installation's archive and its two keys restored by `setup --restore` onto the host emptied again, the administrator and their passkey back, no link, a backup verified, stopped after each step and resumed, no key in setup's output, its journal, the configuration, the unit's journal or a backup) |
| `doctor`: `varlatch doctor [--json] [--config <file>]` (slice 6.5 of internal docs/design/go-step6.md) | a Compose installation's (`--dir`, Docker, Convex): the TypeScript CLI's checks and the server's (`varlatchd admin doctor --wait` in the container) | a Go installation's: runs `varlatchd admin doctor --json` (as `host-admin`), which reads the host itself (the configuration; the data directory's and the key files' modes, by `stat` only, never opening a key file; free space against the database plus a snapshot; the disk's fsync p99 against Decision 2's 10 ms, through a file without a name (`O_TMPFILE`) that never appears in the data directory; the clock; the backups' status files) and asks the running varlatchd through its control socket for the rest (readiness, the WAL against twice its bound, the TRUNCATE checkpoints against 1 s, the public certificate, the tailnet pin, custody attestations); without a running varlatchd those are unknown, and nothing takes the lock or opens the database. The CLI adds `services.running` (varlatchd answered) and `release.pending-upgrade` (one release). Each check is pass, fail or unknown, mandatory or advisory, with what to do; exit 1 on a mandatory failure; `--json` for scripts; a URL's user name and password never shown. `--dir` is refused (64) naming `varlatch-ts doctor` | Decision 8: doctor reads, never writes. Pinned by `server/doctor`'s tests (a case for each failing check), `daemon`'s `TestDoctorNeverWrites` (the data directory and the configuration's directory unchanged, daemon running and stopped, no audit event), `TestDoctorShowsNoKey`, `internal/cli`'s `TestDoctor*` (the real varlatchd too), and the conformance suite `go-doctor` (the TypeScript doctor suite's replacements) |
| `host-settings` | `security report`, `security status`, `audit-export show`, and the server's refusals, messages and report tell the host operator about `VARLATCH_OUTBOUND_ALLOW`, `VARLATCH_AUDIT_EXPORT=off` and `VARLATCH_PUBLIC_URL` | `outbound_allow`, `audit_export = off` and `public_url`, in `varlatchd.conf` | A Go installation has no such variables. The CLI says it whatever the server: 0.23.0's own messages name its variables. Transcript cases `report.human`, `status.audit-off`, `status.audit-draining` and `ae.show.stopped` name it; the server's replays and outbound vectors are read with the names replaced (`paritytest.GoSettings`, `server/outbound`'s vectors test) |
| `move-usage` | `varlatch help move`, `move --help` and `move -h` print a Compose installation's `move` (`--dir`, `--bek-file`, `--kek-file`) | a Go installation's: `--public-url`, `--ingress public\|external`, `--listen-https`, `--reenroll-hours`, `--yes`, `--no-wait`, `--abandon`, each with `--config`; `varlatch --help` has it too (`host-usage`) | A Go installation's move rewrites `varlatchd.conf` and restarts `varlatchd.service` (slice 6.9); a Compose installation's stays the TypeScript CLI's (decision 11). Transcript cases `help.move`, `help.move.option` and `help.move.short` name it |
| `upgrade`: `varlatch upgrade [<version>]` and `upgrade --check` (slice 6.6b of internal docs/design/go-step6.md) | a Compose installation's: pulls the release set's images, backs up, restarts the stack, gates on `doctor --gate`; `--check` records the newest release through the backup control | a Go installation's, on its host, as root (`--check` as root, or as the user varlatchd runs as where the configuration names `root_kek_file`: outside the unit, only root finds the Root KEK beside the configuration): the release's `varlatch`, `varlatchd` and `release.json` verified against its signed `SHA256SUMS` (fail closed); a release whose manifest's `compatibleFrom` is above the installed schema is refused unless `--accept-not-rollback-safe` (or yes at a prompt); then decision 6's steps, each journaled durably before the next in `/etc/varlatch/upgrade.json` (`go/lib/upgradejournal`, format 2; format 1, which 0.50.0-rc.2 and rc.3 wrote, is still read and undone): the binaries of both releases kept in `lib/varlatch/releases/<version>` beside the binaries (directories only root may write, each binary's SHA-256 in the journal and checked before it is run or put in place); the encrypted snapshot (`admin backup run`, copied into root's `lib/varlatch/snapshots/<id>`, kept 30 days, its SHA-256 in the journal); stop; the schema update on a copy (`admin schema upgrade --database`); the original database and its log under second names (hard links, or synced copies where the file system has none), a set that stays whole until the upgrade's end is recorded; the new binaries; the copy in the database's place, by one rename; start; and the health checks (`admin status`: the release, its schema, serving, schema, Root KEK and installation ready). Any failure stops varlatchd, puts the original database back from its set, then the previous binaries, each recorded, and starts and checks the previous release; the next run finishes (after the checks) or undoes (before) an interrupted one, an undo going on from where it got; after the checks nothing is undone. What is done in the data directory is done as its owner, in a child of the program without root's rights, under the data directory's lock, and not at all once the installation was restored from an archive since. From the stop until the upgrade is over no varlatchd starts but the one the journal allows (its `start`: the release and the boot), and that one is held: 503 on every listener, nothing in the background, the real readiness on the control socket, which the health checks read. It opens once the journal says the upgrade is over, written only after the record of the checks was made durable, or when that record was read back after a reboot. A record that cannot be made durable ends the run there; a recovery makes what it read durable first. What the engine started holds the upgrade lock until it has ended, killed or not. A pending upgrade of rc.2's or rc.3's engine with another database than the original in place is finished when that is the original's upgraded copy (the same installation, with at least its history: `varlatchd admin schema identity`) and the new release's checks pass, or stopped with both databases kept and the commands for either way, never undone by itself. The installed varlatch can always read the journal: it goes in before varlatchd, and, from a release before 0.50.0-rc.4, before the first record. Before anything is run or made as root, the journal's directory, the binaries and the releases' are only root's to change; before anything is changed, the configuration is the one the unit starts varlatchd with, the boot id can be read, and those directories and the data directory can be made durable. A journal that cannot be read is not gone on from: `varlatch upgrade` prints the ways out (how to ask whose each database is, then going on with the one in place, then going back to each that is kept, with its date; nothing is overwritten), and a held varlatchd whose journal is gone or unreadable says so in its log, on `/readyz` and in `doctor`. Never remove the journal of an upgrade that is not over but as a printed step says. An upgrade from a release before 0.50.0-rc.4, undone, sets its journal aside (`upgrade-<id>.json`), which that release would refuse. `--check` records the newest release in `release-check.json` (`admin release-check record`), which `GET /v1/installation/release` reads. `--rollback` (slice 6.6c) returns to the release the last upgrade came from, with its kept binaries, journaled the same way (`kind: rollback`, with the upgrade's own record inside) and undone and recovered the same way; undone, it leaves the upgrade's record again (with its `lastRollback`), so it can be run again. When both hold, that the upgraded release's `release.json` declared itself rollback-safe for that release, and that this release opens the database as it is (`admin schema status`), only the binaries go back and every change stays; otherwise the pre-upgrade snapshot is restored (`admin backup restore`, with the release returned to), after listing what is lost (`admin changes`, no value: first the revocations, removals, rotations, replacements, deletions and freezes the restore takes back, with their resources, then the audit events after the snapshot's last one, by position and type, and how many browser sessions are valid again; and that sign-ins and sign-outs, pending approvals and delivery and sync cursors are not counted but revert too) and only with `--accept-data-loss` (or yes at a prompt; `--yes` alone is not enough); the list is made again after the stop, and when it grew, asked again, or refused and undone without a terminal. Before the stop: the kept binaries and the snapshot are the recorded ones (SHA-256, root's directories), the snapshot opens with the host's keys in the release that restores it (`admin backup restore --check`), the database is the upgrade's (its data directory, its installation, there), and the disks hold the rollback; the database is looked at again after the stop, and the health checks compare the installation. After it, what to do again (revoke, retire, rotate, sign out: the release has no command that signs everyone out), and that a held installation is resumed (`varlatch admin restore resume`); the database it replaces is kept with the rollback, 30 days. Refused with nothing recorded to roll back, an upgrade not over, a rollback or an undone upgrade last, another varlatchd installed than the upgrade's, no database, the previous binaries or (to restore) the snapshot gone or not the recorded ones; a release before 0.50.0-rc.4, whose varlatch cannot read a rollback's journal, with the commands by hand, the unit disabled first, and how to go back on each; a maintenance gate in the data directory; an installation held after a restore; (and a restore by hand is refused while an upgrade or a rollback is not over); and a migration not open or finished, or that switched after the upgrade began. After an open migration it says whether the migration's own rollback window stays as it is or was ended by the upgrade. `--dir` and the Compose options are refused (64), naming `varlatch-ts upgrade` | ADR-0059 Decision 8 for a Go installation; a Compose installation's upgrade stays the TypeScript CLI's. Pinned by `internal/upgrade`'s tests (a fixed part of the interruptions on a pull request; every one with `VARLATCH_UPGRADE_TESTS=all`, which the nightly and dispatched Go workflow and the release set; two prereleases built from this checkout, a kill at each step and in the undo, as root with varlatchd another user's; with stand-ins for the releases, a kill and a power cut after every change it makes, in the undo too, every directory sync failing, with and without hard links, with the reboot's start between and a client writing whenever it can; a full disk, a failed health check, a bad signature, a wrong identity, the snapshot restored; for `--rollback`, both paths, every refusal, and the same kills and power cuts) and `internal/cli`'s `TestUpgrade*` |
| `upgrade-usage` | `varlatch help upgrade`, `upgrade --help` and `upgrade -h` print a Compose installation's `upgrade` form | a Go installation's: `[<version>] [--prerelease] [--accept-not-rollback-safe] [--end-rollback-window] [--yes]`, `--check [--prerelease] [--json]` and `--rollback [--yes] [--accept-data-loss]`, each with `--config` | The Go CLI upgrades a Go installation; a Compose installation's upgrade is `varlatch-ts upgrade` |
| `skill-order` (how Windows compares a Linux recording, not a behaviour) | walks the skill directories in the file system's order: sorted on Linux and macOS, NTFS's case-insensitive order on Windows (`references/` before `SKILL.md`), which orders `agents install`'s changes and decides which files a removal reaches before a link stops it | the same: the skill directories and empty-directory pruning are read in the system's order on Windows and sorted elsewhere (`internal/agents`' `readDir`); the guardrail hook's reads, whose answers do not depend on order, stay sorted | A case recorded on Windows compares exactly. A case replayed on Windows against its Linux recording (it names no path below its directory, so it has no Windows expectation) compares each run of consecutive skill-file entries as a multiset (`transcript.SkillOrderFree`): in a `--json` document the runs of `changes` entries whose path is a skill file, in human output the runs of lines that name one, in the install vectors both. Nothing is added or dropped and everything else keeps its bytes and place (`TestSkillOrderFree`) |
| `tailnet-repin`: `varlatch tailnet repin [--yes] [--adopt] [--json] [--config <file>]` (slice 6.2b) | no such command (`tailnet` has `require`, `requirements` and `remove`); the TypeScript server keeps no tailnet pin | runs `varlatchd admin tailnet repin --json [--yes [--adopt]] [--config <file>]` (as `host-admin`) and shows `varlatchd`'s text from its answer: the pinned and the observed tailnet, then what it did or offers, on stderr with `varlatchd`'s status when it refuses. On a terminal, without `--yes`, an offered re-pin (or, with `--adopt`, an adoption) is asked for (`[y/N]`), then done with `--yes --offer <the offer shown>`: `varlatchd` acts only while the pin and the observed tailnet are still what was shown, and otherwise changes nothing and answers `offer-changed` (status 1) with the new view, which is shown and asked about once more (a second change stops, nothing re-pinned). `varlatch tailnet repin --yes` (scripted use) passes no offer and acts on the observation at that moment. `--json` prints `varlatchd`'s answer. `varlatchd admin tailnet repin --json` gives stable names (the view's `pinned`, `observed`, `reason`, `closed`, `missing`, `offered`, `offer` (a value-free token: 128 bits of a SHA-256 over what is offered, the pin and the observation; empty when nothing is offered), and `pinnedText`, `observedText`, `outcome`, `message`, `pin`) with or without `--yes`; `varlatchd`'s 78 adds a line saying to run it as root (`sudo varlatch tailnet repin`; Unix), as `host-admin`'s; its text is unchanged | The tailnet pin is the Go server's (step 4.13); a re-pin changes what the tailnet listener trusts, so it is the host's and is confirmed. Pinned by `internal/cli`'s `TestTailnetRepinFront` and `daemon`'s `TestTailnetListener` |
| `installation.migrated` (an audit event only Go records, until the last TypeScript release) | not recorded by v0.22 | appended by `varlatchd admin migrate import` and `export --reverse` (step 7.3a) after the source's events and the revocations of the sessions the migration ended: no Organization and no actor identity, metadata `direction`, `sourceRelease`, `manifestVersion`, `frozenPoint` (`auditPosition`, and `snapshot` for a forward import), `sessionsEnded`, `credentialsRevoked` | Decision 9's audit-append transformation (internal docs/design/go-step7.md decision 5); the last TypeScript release (0.23.0) records and lists it too (slice 7.2a). Pinned by `server/migration/migrate`'s `TestRoundTrip` |
| `restore-hold`: a completed `admin backup restore` (so `setup --restore`, the image's restore and a restored `move --abandon` too) holds the installation; `varlatchd admin restore status` and `restore resume`; the audit event `installation.restore_resumed` | a restore serves, delivers and deletes at once | `restore-hold.json` in the data directory (the archive and the time), durable before the restore's gate goes. While it stands `varlatchd` serves as normal, requests that send or erase included, but its background work does not run: no sync, webhook, audit export, organization deletion (or drain) or GitHub App sweep pass (`maintenance.EnterWork`); scheduled backups remove nothing from this host, `/readyz` answers 200 with `"held":true`, `doctor` has the advisory check `restore.hold`, and `varlatch upgrade`, the reverse migration's barrier and its export are refused. An upgrade left pending is refused too, before it is undone over the restored database: its journal is moved away first, then the hold resumed. Whatever has the file's name and is no hold of root's or the directory owner's (a link, a pipe) holds. Deadlines go on while held, as on a stopped server: at the resume a drain past its deadline is given up, due deletions run, and webhooks may repeat what they delivered after the archive. `restore resume` (one at a time; killed between its event and the removal it records again) records `installation.restore_resumed` (no Organization, no actor, the archive) and then ends it, in the running `varlatchd` or with it stopped; behind a maintenance gate it is refused, and without a database it only removes the file. `migrate`'s import and `upgrade`'s undo leave no hold | An archive brings back what was changed since: a cancelled deletion that is due would destroy an Organization's key at the first start. Requests by credentials the archive brings back are not refused. Pinned by `lib/backup`'s `TestHoldIsNeverMistaken`, `server/maintenance`'s and `server/doctor`'s `TestRestoreHold`, `server/backups`' `TestRestore` and `TestHeldKeepsEveryArchive`, `server/daemon`'s `TestRestoreHoldsWork` and `TestStaleHold`, `go/bench/restore-drill.sh`, `go/image/check-image.mjs` and `go/install/test-setup.sh` |
| `tailnet.repinned` (an audit event only Go records) | not recorded | each re-pin, reopening or adoption by `varlatchd admin tailnet repin --yes`: no Organization and no actor identity (the host operator: the control socket's peer is the data directory's owner or root), metadata `action` (`repinned`, `reopened`, `adopted`), `fromSuffix`, `toSuffix`, `tailnetId`, `reason` (what the re-pin's own check found), `operator: true`, never the control server's URL. Committed before the pin changes: a re-pin whose event cannot be recorded does not happen (`audit.GoOnlyEventTypes`) | The TypeScript server's event list is frozen; ADR-0059 step 6's G10 asks for the re-pin to be audited. Pinned by `daemon`'s `TestTailnetListener` (both events, read from the database) and `audit`'s `TestGoOnlyEventTypes` |
| `public-https`: `listen_https`, `listen_http_redirect`, `acme_email`, `acme_ca`, `acme_ca_root` (step 6, slice 6.3a) | public HTTPS is Caddy's, in the Compose stack (`--ingress public`; `VARLATCH_ACME_CA`) | `varlatchd` serves HTTPS itself on `listen_https`, with a certificate for `public_url`'s host obtained and renewed over ACME (HTTP-01 on `listen_http_redirect`, default port 80 on the same address; TLS-ALPN-01 on `listen_https`) through certmagic; nothing is served over HTTPS before a certificate exists, a handshake for another name (or none) is refused, a request for another `Host` is 421, no `X-Forwarded-For` is believed on it, and `listen` must then be a loopback address, TLS 1.2 at least with ECDHE and AEAD suites, HTTP/2 and HTTP/1.1; the plain listener answers a pending HTTP-01 challenge for the host and redirects everything else (308) to `public_url`, never a page; no `Strict-Transport-Security` header (an operator adds one at their own proxy or CDN); `GET /v1/installation/listeners` gains `public` (configuration, status, the certificate's dates and issuer, the last attempt, failures, the next attempt) only when it is on. Off (unset), nothing changes. The certificate and the ACME account key are in `<data_dir>/acme` (0700, files 0600), never logged and never in a backup archive | Decision 5 builds certificates into `varlatchd` (owner, O1); the Go installation has no Compose stack. Pinned by `publictls`'s tests and `daemon`'s `TestPublicHTTPSAgainstPebble` (Pebble in go.yml), `backups`' `TestRunLeavesTheACMEStoreOut`, `config`'s `TestParsePublicHTTPS` |
| A system error while `init` writes the agent files (a directory where a file goes, a file it cannot read) | `varlatch: the files for coding agents were not written (<Node.js's message>); run varlatch agents install to try again.`, exit 0 | the same line with Go's message, exit 0 | Decision 2: runtime error wording; what the files are refused for by the CLI itself (a damaged `AGENTS.md`) has the same message in both |
| `agents install` never writes or removes through a symbolic link | not compared | a directory below the project root (or the home directory, for `--scope user`) that is a symbolic link or a Windows junction, on the way to a file the run reads, writes, removes or prunes, refuses the run before anything is touched, `--check` included: `<path> is a symbolic link, so the CLI does not read, write or remove anything through it; nothing was changed. Replace it with a directory, then run this again`, 78; a refused `--remove` also lists the skill files it would have removed, for removing by hand | Installing agent files never changes anything outside the project or the home directory; `internal/agents` `TestNothingThroughALinkBelowTheRoot` |
| The guardrail hook reads every command alike | not compared | `agents hook` reads each word of a command line the same way: a command named like a property every JavaScript object has (`toString`, `constructor`, `valueOf`) and a glob whose class is no regular expression (`[z-a]`) are words like any other, and the rest of the line is checked: `toString x; cat .env` is denied | The hook reads a whole command line, and no word ends the reading early. Pinned by `internal/agents`' `TestHookReadsEveryCommandAlike` |
| Hook globs are RE2 classes | not compared | `agents hook` reads a glob's bracket class as an RE2 class, so a POSIX class inside it is a class of characters: `cat .e[[:alpha:]]v` names `.env` and is denied | Go's regular expressions are RE2; the hook denies more, never less. Pinned by `internal/agents`' `TestHookStricterReadings` |
| A surrogate pair split by a quote | not compared | `agents hook` reads a lone UTF-16 surrogate in a tool call's strings (which JSON can carry) as U+FFFD, as a command or the file system receives it. A surrogate pair that a shell quote splits (`.en'v\ud83d'\ude00`) is two lone surrogates, so the hook checks `.env` followed by two U+FFFD, the name a shell given that command line reads, not `.env😀` | The hook checks the file the command would read. Pinned by `internal/agents`' `TestHookSplitSurrogatePair`; the lone surrogates themselves by hook vectors |
| MCP answers in a chunk's order | not compared | `varlatch mcp` handles the lines of one read of standard input in order: it registers each request (answering a method it lacks at once), applies the read's cancellations, then starts the handlers one at a time, each until it answers or waits on the server. An answer that needs no request goes out in the order of the lines; one that waits on the server goes out when the server answers | The order of the answers is the protocol's to leave open (each names its request), and a host reads them by id. Within one read, a cancellation reaches a request on a later line. Pinned by `internal/mcp`'s `TestVectors` and the `5.6b-mcp` transcripts |
| A line of more than 10 MiB closes the MCP connection | not compared | `varlatch mcp` reads standard input in reads of up to 64 KiB; when the unread input would pass 10 MiB, it stops reading, gives no answer to the requests it holds, and exits 0 once they are done | The limit is the SDK transport's (`ReadBuffer`); where a read ends depends on the pipe, so no transcript compares it. |
| A name ending in a line break after `.env.` | not compared | `agents hook` treats `.env.` followed only by a carriage return, U+2028 or U+2029 as a .env file, and denies reading it | RE2's `.` matches every character but a newline; the hook denies more, never less. Pinned by `TestHookStricterReadings` |
| `init` and a server URL with a user name or password | not compared | refused from any source (`--server`, `VARLATCH_SERVER`, the default server, the only stored credential), judged on the server as `varlatch.toml` will give it back: a user name or password as `new URL` reads it, an at-sign in any form in a text that does not parse, or a backslash with an at-sign in any form (`\u0040`, `%40`, ...) after it: `varlatch init: a server URL with a user name or password can't be written to varlatch.toml; give the server's address without them. Nothing was written.`, 64, nothing written and the URL not repeated | `varlatch.toml` is committed; `cmd/varlatch` `TestInitRefusesServerCredentials`, `clientctx` `TestHasUserinfo` |
| `toml-escaped`: how `init` writes `varlatch.toml`'s values | not compared | each value as an escaped TOML basic string (`\"`, `\\`, control characters), so the file reads back as exactly what was given | A value with a quote, a backslash or a control character means what it says; transcripts compare the escaped form (`init.raw-values`); `TestInitValuesReadBackAsGiven` |
| How `agents install` replaces a file | in place (`writeFileSync`) | a temporary file in the same directory, readable by its owner only until it is complete, synced, given the file's mode, then renamed over it; the names of a hard-linked `AGENTS.md`/`CLAUDE.md` pair are each renamed onto the new file; a file with any other name is refused (78) | A crash or a full disk never leaves a settings file empty or half written, and no other file shares the change; bytes and modes are the same |
| No message holds a value: an argument `values set` or `values rotate` refuses (`value-free-usage`) | the option parser's message | never repeated, whatever its spelling: `unexpected argument <n>, not shown since it may be part of a value (a value with spaces goes in quotes)`, `unknown option at argument <n>, not shown since it may be a value (a value that begins with "-" goes after --)`, `--grace needs a whole number of seconds`, `--replace names another item, but this command sets <ITEM>; ...`, `<n>` counting the arguments after `values set` or `values rotate` | Any argument there may be the value or part of it; the status (64) is the same. Accepted only where Go's line is these words for the same command and holds no part of the argument (`TestValueFreeUsageIsExact`) |
| No message holds a value: a value in flight | not compared | each exact occurrence of the value `values set` or `values rotate` sends, and of each value `import` (or guided `init`) reads unless the active Contract marks its item `sensitive: false` (a boolean; a missing or malformed field, or an item `--contract --plain` only proposes, keeps the value held), is `[redacted]` in every output and diagnostic, whatever its length, also where a server echoes it in an error or in a successful answer. The fail-safe finds every sensitive span in the original text first (a URL's user name and password, every token, each value in flight), merges the spans that overlap, and replaces them in one pass, so a value such as `@`, `:` or a token's prefix never hides the credential another detection marks | A server, or anything between it and the CLI, never puts a value back on a terminal or in a log; a very short value may also redact the same characters in the CLI's own words (`TestInFlightValuesNeverDisableTheFailSafe`, `TestPlainOnlyOnTheContractsExplicitFalse`) |
| `contract` and secret values (`contract-show-sensitive-default`, `unrecognized-id`) | not compared | the default of each item a Contract does not mark `sensitive: false`, in a pushed Contract or the one `contract show` prints, is a value in flight (redacted wherever output repeats it), and `contract show` prints it as `[redacted]`, every string and every object key of the document through the composed masker (the bearer, the run's secrets, token formats; a masked key kept unique as `[redacted] (2)`, ...); a sensitive default of a `--schema` file is in flight from the moment it is parsed; `contract activate` repeats the id only when it has the server's shape, else `Activated the revision.`; a push answer's `active` counts only as a boolean, and an environment list whose items lack a string id or name is refused before the push (status 1) | A Contract's sensitive default is a Secret; a server or a mistyped argument never puts one on the terminal (`TestContractNeverShowsASecret`, `TestContractPushReadsTheProtocolsTypes`) |
| `.env.schema` errors never quote the file (`env-schema-value-free`) | the package's message, with part of the line it cannot read | `.env.schema line <n>: Unrecognized line (not shown, since it may hold a value)`, and the same for text after a value, a malformed decorator, and an unsupported `@required`, `@sensitive` or `@type` form; every other message as the package words it, except that a reason holding a decorator (`@rotationGrace appears twice for this item`) is put before the line's place, `<reason> (.env.schema line <n>)`, and two reasons say "as in" where the package puts a colon before a decorator, so the fail-safe never reads the colon and the at-sign as a password (`TestErrorsReadAfterTheFailSafe`) | A file given as `--schema` by mistake may be a `.env` holding values; the status (1) is the same (`internal/envschema` `TestErrorsNeverQuoteTheFile`, and the vectors with these six messages mapped) |
| A server's identifier or hash of another shape (`unrecognized-id`) | shown as it is (escaped) | a version or revision id that is not the server's shape (a prefix and 26 characters of lower-case base32) is shown in text as `an unrecognized id`, and a revision's content hash that is not `sha256:` and 64 hex digits as `an unrecognized hash`. An id or hash that holds a value in flight is not shown either, since redaction would rewrite it. `contract push` treats its answer's id and hash alike, whichever the reason: in text the placeholder, with no activation hint without an id; in `--json` `null` (never the placeholder); in both, one note on stderr. Its answer's semantics version, when it is not a whole number from 1 to 999, is `an unrecognized version` in text and in `--json`. `values set`/`rotate` and `import` show the placeholder for an id that holds a value in flight (`TestContractIdentifiersAreNeverRewritten`) | A server never puts free text where the CLI shows an id; the status is the same |
| `types` names a revision only by an id of the server's shape (`unrecognized-id`) | the id as the server or `--revision` gave it | a revision id that is not the server's shape (`rev_` and 26 characters of lower-case base32), from the answer or from `--revision`, is `an unrecognized id` in every message (`Wrote <file> from Contract Revision an unrecognized id (...)`, a 404 for `--revision`, every refusal of the revision), and `--check`'s hint gives `--revision <revision-id>` for such an argument; the module itself always holds the server's id, byte for byte | A mistyped argument or a server's free text never reaches the terminal (as `contract activate`); real revision ids keep their bytes |
| `types` shows the server's text safely (`types-printable`) | not compared | a refusal of the revision has its control characters and bidirectional overrides escaped as `\uXXXX` (a Contract's unrecognized key, quoted in the validation issue, included), and the semantics version is shown only as a whole number from 1 to 999, else as `an unrecognized version` | A server's answer never drives the terminal (`TestTypesShowsTheServersVersionSafely`) |
| `release` (a pattern of the transcripts, not a behaviour) | a module `types` writes names `varlatch 0.22.0` (its Generator lines, `generatedFrom` and the accessor schema) | this build's release | Each CLI names itself, and a module is current for another release when only those lines differ; a case that lists the `release` pattern has `varlatch <the CLI's release>` written `varlatch {{release}}` in the recording and the replay alike, and `{{release}}` in its files is the running CLI's release (`goKit.ts` `releasePattern`, `transcript.ReleaseFill`); another release a case names (`0.13.0`) is compared as it is |
| `spawn-error`: a command `run` cannot start | Node's error escapes: its stack trace, exit 1 | `varlatch: spawn <command> <errno>`, exit 1: `ENOENT` when PATH has no such file, `EACCES` when a file there may not be executed and no later one may (libuv's execvp), `ENOEXEC` for one the system cannot execute, `EINVAL` for a Windows `.bat` or `.cmd` file | Node's own message without the stack (`run.no-command`, `TestLookCommandRemembersEACCES`, `TestSpawnExecFormatError`) |
| `run --strict` and an item type outside the Contract's eight | a value of an item whose `type` the CLI does not know passes, and the command starts | an `invalid` violation, `has a type this Contract Semantics version does not define`, and 78: nothing starts | A conforming server sends only the Contract's types; a type the CLI cannot validate is never taken as valid |
| `run --strict`'s refusals of `--allow-inherited` and `--omit` names | the names echoed as given | the names escaped as `Printable` escapes server and user text (controls and bidirectional overrides as `\uXXXX`), as `run`'s other refusals do | A name the person typed never drives the terminal |
| The order of the command's environment (`run`) | the parent's variables in the order the process got them, then the delivered ones | the parent's variables sorted by name, then the delivered ones (a variable set again keeps its place) | No program reads its environment's order; the values are the same (`5.4b-run` transcripts) |
| `validate` and `import` show only documented fields | not compared | `validate` refuses a report whose lists are not the protocol's shape (each an array of names, or of objects whose documented members are strings; `valid` and `complete` booleans; a present `null` for any of them is not that shape, while an omitted `complete` or list, from a server before it, keeps its fallback) before judging or printing anything: `varlatch validate: the server's answer is not a validation report (<where> has an unexpected shape); nothing was judged.`, status 1; of a report of that shape it shows the documented members only, a requirement or reason outside the protocol's enumerations as `an unrecognized requirement` or `an unrecognized reason`; `import` shows a Contract item's type outside the Contract's types as `an unrecognized type` and its sensitivity as a boolean, in `--json`, human text and `--dry-run` alike | A server never puts an extra field, or a value, into what the CLI prints; a report or Contract of the protocol's shape gives the same bytes (`TestServerFieldsNeverPassThrough`, `TestValidateRefusesAReportOfAnotherShape`) |
| `init-delete-link`: guided `init` and a `.env` that is a symbolic link | not compared | asked to delete it, guided `init` keeps a link and says so (`<file> is a symbolic link, so it was not deleted: deleting the link would leave the values in the file it points to.`), and deletes a regular file only if it still holds what was read and the path still names it (`TestGuidedDeleteNeverRemovesALink`) | Deleting the plaintext copy must not leave it in the file the link points to |
| `import --delete-source` and its source | not compared | the source must be a regular file named directly: a symbolic link (deleting it would leave the values in the file it points to), a directory, a device or a pipe is refused before anything is read or sent (1); the file is opened without following a link and read from what was opened, and deleted only if it still holds those bytes and the path still names that same file, so a file put in its place while importing is never removed; `deleted` is true only when the path is gone | `--delete-source` removes exactly the copy of the values that was imported, or says it did not (`TestDeleteSourceRemovesOnlyTheFileRead`) |
| `generated` (a pattern of the transcripts, not a behaviour) | the value `--generate` made, recorded by its generator as `{{generated <spec>}}` | the value Go sent, recorded the same way when it has exactly the alphabet and length the spec gives and appears nowhere in the output; otherwise a value-free note (`{{generated value of another shape}}`, `{{generated value shown in the output}}`), so neither a recording nor a failing comparison holds the value | Random in both CLIs (`internal/transcript` `TestGeneratedPatternIsExact`) |
| The hidden prompt's Backspace | removes one grapheme cluster as the ICU of the Node.js running the CLI finds it | removes one cluster by the table written from Node.js 26's ICU (Unicode 17), the rules of Unicode Standard Annex #29 | The same answers on 2,022 recorded texts; a TypeScript CLI under another Node.js may segment new characters differently |
| The hidden prompt when the terminal goes away before Enter | not compared | the terminal restored, `varlatch: no value entered; nothing was stored`, exit 1 | Nothing is stored either way; the Go CLI says so |
| A redirect's relative `Location` | resolved by the WHATWG URL parser | resolved by `apiclient`'s own resolver (absolute, `//host`, `/path`, `?query` and path-relative references), then parsed by `lib/whatwg` | varlatchd sends no redirect; a proxy's is absolute or root-relative |
| `loopback-nonce`: the browser sign-in's loopback callback | `http://127.0.0.1:<port>/` | `http://127.0.0.1:<port>/<32 random characters>`: only a POST to exactly that path (compared in constant time), with the listener's own address as its Host (`127.0.0.1:<port>` or `localhost:<port>`), delivers the bearer, and only once (the listener closes before it answers); any other request gets 404 (a GET on the path 405, a preflight 204) and the sign-in goes on waiting. Bound to 127.0.0.1 only, given up after 5 minutes | Delivering a bearer takes the random path as well as the port. The path is in the printed address and, while the browser runs, in its command line, so it keeps out what can read neither (a web page in the browser, a name another host resolves to 127.0.0.1), not another process of the same machine that can read the browser's command line. The sign-in page posts to the callback as given, path included, so neither server's page changes. Accepted only where Go's stdout, the path taken out of the printed address, is the recording; pinned by `internal/cli`'s `TestBrowserCallbackTakesOnlyItsPath` and the `browser-login` process tests, which require the 32-character path from the Go CLI |
| `compose-usage-unchecked`: `sync check` on a Coolify service whose compose file has an alias inside its own anchor (step 4 defect 6) | the `yaml` package builds a cyclic object and `scalarsOf` overflows the stack: `sync check` dies with a `RangeError` (exit 1), before any Secret is disclosed | `lib/sync` reads the file as unreadable: `varlatch: usage: usage not checked: the service's compose file is too large or could not be read`, and the check finishes, disclosing the Secrets it compares as any check does, with its verdict and exit status | The adapter's `inspectUsage` never fails by design (varlatchd's engine catches the same `RangeError` and says the destination could not be read). Accepted only where the recording is that `RangeError`, Go's stderr has that line, its stdout ends with a verdict, and its requests are the recorded ones and one disclosure (`TestComposeUsageUncheckedIsExact`) |
| `invite` prints only an invitation token | not compared | the enrollment link's token is printed only when it is an invitation token in the servers' format (`vlt_invite_` and 43 base64url characters) that neither holds nor is part of a credential or value the run knows (its bearer, `VARLATCH_TOKEN`, a stored credential, a value in flight); otherwise the first line, then `varlatch invite: the server's answer holds no invitation token in Varlatch's format, or holds a credential or value this run knows, so no link is printed. The server may have created the invitation anyway: revoke it under Pending invitations in the dashboard.`, exit 1 | The fail-safe redacts every token on stdout, and the link is the one token a command prints on purpose: its writer (`outShowing`, reachable only from `inviteCommand`; `failsafe_test.go`) keeps exactly that token, and only one that is what the link is for (`TestInviteShowsOnlyAnInvitationToken`, `TestInviteNeverPrintsAnotherSecret`) |
| `credential issue --out` on Windows | the file is created with mode 0600, of which Windows reads only the write bit; the line `The token is in <file>, readable by you only, ...` is printed on every platform | the same | On Windows the new file takes its directory's access control list, so who can read it is who that directory lets read it; both CLIs print the same line, and `--out` belongs in a directory only its owner can read |
| `pending-sign-ins.json` and runs at the same time | not compared | not locked across processes, as in TypeScript: each run reads the file, changes its entry and replaces the file atomically, so of two runs that change it at once the later write wins (a `--start` replacing an entry another run's `--wait` is keeping, for example) | Parity: both CLIs share the file (decision 11), and a lock one of them does not take would not hold. A lost update costs at most a sign-in to start again |
| Secrets in flight never show | not compared | a credential given or issued, a device code, a sign-in hand-off bearer, an OIDC ID token and the GitHub Actions request token are held for the run (`Run.holdValue`): every exact occurrence, and its escaped form, is `[redacted]` on stdout, in every `--json` document and on stderr, whatever their length or format, as well as in a server's free text | A server's answer or an error could echo one, and only Varlatch's own token formats are caught by shape. Pinned by `internal/cli`'s `TestInFlightSecretsNeverShow` and every 5.2 transcript, whose canaries appear in no output |
| `now` (how transcripts compare, not a behaviour) | `login` and `env use` write the time of the run (`issuedAt`, `tierCachedAt`) | the same, at another time | A case that lists the `now` pattern has each ISO 8601 timestamp between its run's start and end written `{{now}}`, in the recording and the replay alike (`goKit.ts` `nowPattern`, `transcript.NowPattern`); a timestamp outside the run is compared as it is |
| `scan-staged-total`: `--max-total-size` with `--staged` | not compared | each staged file is admitted with the sizes of the files admitted before it counted, as a path scan admits each file just before it reads it, so the staged content read in all stays within the bound; a file past it is named `over the total size bound of <size>` and not read | The bound limits how much one scan reads; the scan vectors' `staged.total-bound` case is compared through this difference (`internal/scan`'s `TestSourceVectors`, `TestStagedTotalBound`) |
| `scan-values-in-flight`: a value `scan` holds | not compared | each disclosed value long enough to mask (8 characters or more) is a value in flight: a path, an item name or any other text that holds one is shown with it `[redacted]`, on stdout and stderr alike; the baseline file keeps paths as they are, since it must match them again (`TestScanNeverShowsAValue`) | A scan never puts a value on the terminal, whatever a file is named |
| `scan-hook-link`: `scan --install-hook` where the pre-commit hook (its `git rev-parse --git-path hooks/pre-commit`, `core.hooksPath` honoured) is a symbolic link | not compared (TypeScript writes through the link, wherever it points) | refused, 1: `<hook> is a symbolic link; it was left unchanged, since varlatch does not write a hook through a link. Replace it with a file, or add "varlatch scan --staged \|\| exit 1" to the hook it points to yourself.`, the link and what it points to unchanged, a dangling link's target not created, and the target never named. The check is `Lstat` before anything is read, and the write itself never follows a link (`O_NOFOLLOW`; on Windows the reparse point is opened and seen) | A hook location that is a link can point anywhere outside `.git/hooks`, so writing through it could change a file the person never meant to give the hook. Pinned by `internal/cli`'s `TestInstallHookRefusesALink` and `TestWriteHookNeverFollowsALink` |
| `scan-disclosure-shape`: a disclosure answer of another shape | not compared | an item whose `name`, `versionId` or `value` (or its retiring version's) is not a string, an item that is not an object, or `items` that cannot be iterated ends the scan with 1 before any file is read, the reason in Go's words and nothing of the answer shown (`TestScanRefusesADisclosureOfAnotherShape`) | A scan looks only for values it can name |
| `baseline-json-syntax`: a baseline that is not JSON | `invalid baseline <path>: not valid JSON (<V8's message>)` | `invalid baseline <path>: not valid JSON (Unexpected end of JSON input)` for an empty file, `(Unexpected token in JSON)` otherwise | V8's wording quotes the text it stopped at; the scan vectors compare such a baseline by the start of the message |

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
`--revoke-unused` (Go only; what setup runs) first revokes the bootstrap and recovery links issued before and never used, in the same write job, and adds their count to the issued event's metadata (`revokedUnused`; `TestReissueRevokesUnusedLinks`).
`varlatchd admin bootstrap-status` prints the TypeScript server's JSON,
`{"initialized","bootstrapped","admins":[{"id","enabled","hasPasskey"}]}`,
read-only (the database opened read-only, beside a running daemon or
without one; `TestBootstrapStatus`): what `varlatch setup` waits on for the
first administrator's passkey (slice 6.4b). A build with the `conformance` tag also has `varlatchd admin
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
- Run as root, `varlatchd admin` works in the data directory as its owner
  (`privileges.go`): with the directory's path checked and the directory
  held by its descriptor, it opens what only root may read (the two keys, a
  backup's destination and credentials, a restore's archive, a migration's
  bundle, the tailnet's key and authority files; `lib/preread`), loads the
  trusted certificates (`SSL_CERT_FILE` may be root's), gives the owner what
  an earlier release's commands left there as root's (below that descriptor
  only, no link followed, no file with another name, no other file system),
  then becomes the owner and the directory's group for good, on every
  thread, with no other group, no capability, not dumpable, umask 077. So a
  link in that directory, which its owner may write, leads root nowhere, and
  nothing a command makes there is root's. `kek`, `config check`, `doctor`,
  `outbound check`, `tailnet reaches`, `schema upgrade` of a database
  elsewhere and `migrate keys` stay root's: they write nothing there.
  `varlatch migrate` stages its bundles and scratch databases for that
  user, and `setup --restore` refuses a `varlatchd` whose `config check`
  does not answer `actsAsOwner`. A data directory of root's keeps root.

### Backups and maintenance (step 4.14)

`server/backups` takes the installation's backups inside varlatchd
(Decision 7). The TypeScript server's backup socket is not ported: its
commands are host commands on the control socket, so they take the
daemon's maintenance admission and its one backup at a time.

    varlatchd admin backup run [--json]
    varlatchd admin backup status
    varlatchd admin backup test-bucket [--json]
    varlatchd admin backup restore --in <archive> [--backup-key-file <file>] [--check]
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
  plus 64 MiB. It then takes the paced snapshot (256 pages every 100 ms)
  on the writer's connection (`lib/storage` `Snapshot`, with the
  `TRUNCATE` after it),
  reads the archive's metadata from the snapshot itself (the
  installation, its Root KEK version and canary, the schema version),
  refusing an incomplete Root KEK rotation as `archiveMetadata` does and
  a canary the loaded Root KEK does not open, hashes the components for
  the manifest, seals the snapshot and `configuration.json`, and opens the
  archive again to record its check, each at 16 MiB/s and with the archive
  key derived once for the run, then uploads it, records the delivery, and
  removes the archives beyond `backup_keep` from this host. Retention
  counts and removes only Go's own archives, those whose status record
  names a Go release (0.50 and later): never a TypeScript-format archive,
  nor an archive without a readable record. A stop ends a run at its next
  snapshot step or paced MiB, and leaves no archive.
- **TypeScript-format archives** (format 1 or 2, step 7 decision 18) stay
  where they are. A status record whose release is below 0.50 is one: the
  status (`admin backup status`, `GET /v1/installation/backups`) lists
  them apart, newest first, in `typescriptArchives` (left out when there
  are none, so the status is then exactly the TypeScript server's), as restorable through
  the converter (`varlatch migrate --from-archive`), and none of the
  warnings about Go's own archives counts them (the Root KEK's does:
  converting one needs its key). `retainUntil` is when one's retention
  ends, when that is known (the migration records it: an Object Lock
  retain-until date, or the operator's); without it the bucket's lifecycle
  rule decides, which Varlatch does not read. The TypeScript server sends
  neither member; the dashboard reads neither.
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
  with the audit export's port). In the copy unpacked from the archive it
  opens the database with this release, checks the installation and its
  canary and records `installation.restored` (archive, manifest hash,
  installation): a failure up to here changed nothing, and `--check` and
  `--verify-remote` make the same writes in a copy they throw away. It
  then opens a restore gate, copies that database beside the one that is
  there, removes the old WAL, renames it into place, leaves the restore hold
  and removes the gate. A restore that fails or is killed from the gate on
  leaves it: a varlatchd that starts then serves 503 MAINTENANCE and
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
    answers them, newest first, with `backupStatus`'s warnings, without
    "No remote copy has passed retrieval and verification within the last 30
    days" while no remote copy was ever checked (a difference from the
    TypeScript server: an upload-only key can never clear it; doctor's
    `backups.status` says none was checked; `TestUpload`,
    `TestRemoteCopyUnchecked`);
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

### The single-container image (step 6, slice 6.10a)

`image/Dockerfile` is one image with `varlatchd` and `varlatch`
(`/opt/varlatch/`, where the host backup job finds the CLI), distroless
static, run as uid and gid 65532, the data directory `/var/lib/varlatch`
a volume (a new one starts the image user's, mode 0700), the
configuration at `/etc/varlatch/varlatchd.conf`, the keys mounted as files
under `/keys`. `image/build.sh` builds it with buildx from a directory of
release assets (the named build context `assets`), for both platforms,
and never pushes: `release.yml` publishes it, from the same assets.

Keys reach varlatchd only as files. `varlatchd serve` refuses to start
(exit 78) when its environment holds the Root KEK or the Backup
Encryption Key, as hex in either case or base64 with or without padding,
standard or URL-safe, anywhere in a value; or has a key or passphrase
variable name, whatever its value: `VARLATCH_KEK`,
`VARLATCH_KEK_PASSPHRASE`, `VARLATCH_ROOT_KEK`, `VARLATCH_BEK`,
`VARLATCH_BEK_PASSPHRASE` and `VARLATCH_BACKUP_KEY` (in any case; the
TypeScript line used the first two). It checks names and the configured
keys' own values only, never a guess at what looks like a key; when
`backup_key_file` cannot be read at the check, only the Root KEK's value
and the names are checked. The refusal names the variable and never its
value. In the image (`VARLATCH_IMAGE`), `varlatchd admin` and the CLI
refuse to run the same way, against the keys the image's configuration
names that they can read. `lib/keyenv` is the check; `keyenv_test.go`,
`daemon.TestServeRefusesAKeyInItsEnvironment`,
`daemon.TestAdminRefusesAKeyInTheImage` and the CLI's
`TestImageRefusesAKeyInTheEnvironment` test it, each checking the value is
never in the message.

`image/check-image.mjs` runs the image as an operator would (the
replacement of `test-backup-compose.mjs`): its configuration, the refusal
by both commands, a new installation on a new volume as the image user
with a read-only root filesystem,
no key in `docker inspect` or `/proc/1/environ`, the recovery gate held in
the volume across containers, and a backup restored into a new volume
through the image alone. Then it uses an installation, with a read-only
root filesystem and no tmpfs: the first passkey, values set, replaced,
rotated and deleted, imports larger than SQLite keeps in memory, a deleted
project, a backup and its restore; as `docker run`, as
`infra/coolify/varlatchd.compose.yml` itself, and without `SQLITE_TMPDIR`;
and serve refuses to start with nowhere to write (`lib/storage/temp.go`).
go.yml's `go-image` job builds the image for
both platforms and runs it on every pull request that touches it;
`go-container` runs the conformance suites against it nightly (target
`go-container:<image>`, which runs as go-binary with its expectations).

### Public HTTPS (step 6, slice 6.3a)

`server/publictls` is `varlatchd`'s own public HTTPS (ADR-0059 Decision 5;
step 6's decision 4), on when `listen_https` is set. certmagic is the ACME
client and the store; the schedule is `publictls`'s, so that what it
reports is what it does:

- **Obtaining and renewing.** At start, a certificate in the store for
  `public_url`'s host is served at once; otherwise one is obtained. It is
  renewed in the last third of its lifetime. A failed attempt is retried
  after 1, 2, 5, 10, 20 and 30 minutes, then 1, 2 and 6 hours (the last
  repeating), each failure logged and reported; certmagic's own retries,
  cache maintenance, on-demand issuance, OCSP stapling and ARI are not
  used. Nothing is ever asked: without `acme_email` the account is
  registered without a contact (said once in the log), and certmagic's
  prompt for an address never runs. Both listeners need a real port (not
  0): the CA connects to them.
- **What is served.** The HTTPS listener serves the same handler as the
  plain listener, with the one certificate, for the host only; before a
  certificate exists, and once it expired, every handshake is refused. A
  TLS-ALPN-01 handshake (ALPN `acme-tls/1` alone, for the host) gets
  certmagic's challenge certificate while a challenge is pending, and the
  connection serves no request. The plain listener answers a pending
  HTTP-01 challenge from memory (never from the store, never blindly) and
  redirects everything else to `public_url`. No `Strict-Transport-Security`
  header is sent, as the TypeScript stack's Caddy sends none (and a
  long-lived one would hold browsers to a name a move may leave); an
  operator who wants it adds it at their own proxy or CDN.
- **What stays private.** `<data_dir>/acme` is made 0700 (a store others
  can enter, or a symbolic link, stops the start); certmagic writes its
  files 0600. Neither key is logged, put in the environment or archived:
  a backup holds the database and the settings (`listen_https`,
  `listen_http_redirect`, `acme_ca`, `acme_email`; not `acme_ca_root`, a
  path on the host), and a restored installation obtains its certificate
  again.
- **Tests.** `go/server/publictls/testdata/pebble.sh` starts Pebble and its
  mock DNS server (pinned by digest, on the host's network, every name at
  127.0.0.1, 45-second certificates); go.yml's `go` job runs the Pebble
  tests with `VARLATCH_REQUIRE_PEBBLE=1`. Let's Encrypt's staging is run
  only by hand, with the owner; Let's Encrypt itself never from CI.
### The ingress modes side by side (step 6, slice 6.3b)

An installation has one relying party, its public URL's (ADR-0059
Decision 6): the RP ID is `public_url`'s host, and a passkey ceremony
(registration and sign-in), like every state-changing browser request,
is accepted only from `public_url`'s exact origin, scheme and port
included. The Origin header is checked before the body is read, and the
origin the authenticator signed (`clientDataJSON`) and the RP ID hash
are checked again by go-webauthn. The listeners serve that one origin in
their own ways:

| Ingress | Listener | `public_url` | Ceremonies | Client address |
| --- | --- | --- | --- | --- |
| This machine | `listen` (loopback) | `http://localhost:<port>` | from `http://localhost:<port>` | the connection |
| Own reverse proxy | `listen`, behind the proxy | `https://<name>` | from `https://<name>`, through the proxy | `X-Forwarded-For` from `trusted_proxies` |
| Public HTTPS | `listen_https` (and `listen_http_redirect`) | `https://<name>[:port]` | from `https://<name>[:port]` | the connection: no `X-Forwarded-For` is believed, whatever `trusted_proxies` says |
| Tailnet | `tailnet_port`, and the browser endpoint on `tailnet_https_port` | (any) | none: no `/auth`, no dashboard, no enrollment page; the browser endpoint reads cross-origin for the listed dashboard origins, with a bearer | the node's WhoIs |

Side by side: with public HTTPS on, the plain listener stays on a
loopback address (`listen` elsewhere is refused at start), so nothing is
served in plain text beyond the machine; it still serves the API to the
host (and to a proxy there, with `trusted_proxies`), but a ceremony from
its own origin is refused, as is one from any origin but `public_url`'s.
The HTTPS listener answers 421 to a `Host` other than `public_url`'s host, logged in the access log (and, on the API, charged to the request window) like any other request.
A `public_url` naming an IP address starts with a warning: browsers refuse
an IP address as an RP ID, so the dashboard cannot sign in there (use
`http://localhost` on one machine). Pinned by `httpserver`'s
`TestIngressOriginsAndRPID` (each mode against every other ingress's
origin, by Origin header, by signed origin and by RP ID) and
`TestTailnetListenerRunsNoCeremony`, and `daemon`'s
`TestIngressModesSideBySide` (against Pebble).

### Moving an installation (step 6, slice 6.9)

The public URL is the passkeys' relying party (Decision 6), so moving an
installation to another address is a re-enrollment event (decision 13,
the TypeScript flow's semantics). `varlatch move --public-url <url>`, on
the host as root:

1. reads the installation through varlatchd (`varlatchd admin config
   check`, which parses `varlatchd.conf` and nothing else, and `admin
   move-facts`), shows what the move does (passkeys, sessions, people,
   open invitations) and asks before anything changes (`--yes` outside a
   terminal);
2. takes and verifies an archive (`admin backup run`), the way back;
3. writes the move's journal, `move.json` beside `varlatchd.conf` (0600:
   the addresses, the archive's path, times, and the configuration before
   and after; never a link or a key), then the new `public_url` (and, from
   one ingress to the other, `listen_https` set or the public HTTPS
   settings taken out), which varlatchd checks first; restarts
   `varlatchd.service` and waits for `/readyz` and, on the public ingress,
   for the new name's certificate;
4. removes the old address's passkeys once (`varlatchd admin
   public-url-changed --from <old>`: every passkey, every browser session
   and the dashboard credentials minted from them; CLI, agent and machine
   credentials keep working), and records it;
5. prints one re-enrollment link per person (`admin reenroll --all`), and
   waits for an Installation Admin to enroll (`--no-wait`: exit 75, rerun
   to finish).

A rerun continues where it stopped (no second archive, no second removal,
no second set of links, no restart when varlatchd already serves the new
address); `--abandon` puts the old configuration back and restarts
varlatchd, naming the archive when the old passkeys were already removed.
The tailnet node is never touched: a move to the tailnet ingress is
refused (the node keeps its own name and state), and its settings, pin and
state stay as they were. `varlatch admin reenroll (--all | --identity
<id>...) [--hours <1-168>]` issues links on its own: one live link per
person (a new one revokes the unused ones), a day by default, a week at
most, each `reenrollment.grant_issued` without the token.

**If the move stops**, rerun `varlatch move` (no `--public-url`): the
journal says where it stands. `move.json` holds `from` and `fromIngress`,
`to` and `toIngress`, `archive` (the archive taken first), `startedAt`,
`passkeysRetiredAt` and `linksIssuedAt` once those steps are done, and
`previousConfig` and `config`, `varlatchd.conf` before and after the move.
A rerun puts `config` back if the move stopped before writing it, restarts
varlatchd only when it does not serve the new address yet, and treats a
removal that committed before the journal recorded it as done. A
`varlatchd.conf` that is neither of the two is refused: put one back, or
`varlatch move --abandon` (which writes `previousConfig` and restarts
varlatchd). An unreadable journal stops the command with nothing changed:
put the configuration varlatchd should run in place from the journal's
text, restart varlatchd, and remove the journal. If the old passkeys were
removed, only restoring `archive` brings them back.

The links are the one credential a move prints. They go to the terminal
only, through the fail-safe's one exception for them
(`showReenrollLinks`, beside `invite`'s link): never to the journal, a log,
an audit event or `--json`. Assisted mode refuses `move` and `admin
reenroll` (78): a coding agent reads the output, and a link adds a passkey
to a person's identity. In the container (`VARLATCH_IMAGE`), `move` is
refused with the manual steps (an archive, the new `public_url` in the
mounted configuration and the container recreated, then `varlatchd admin
public-url-changed` and `varlatch admin reenroll --all` in it). The
replacement of the `move` external suite: `daemon`'s
`TestPublicHTTPSMoveAgainstPebble` (go.yml's Pebble step) and
`TestMoveKeepsTheTailnetNode`, `TestMoveCommands`, `httpserver`'s
`TestMoveReenrollsAtTheNewRelyingParty`, and the CLI's `TestMoveRefusals`,
`TestMovedConfig` and `TestAdminReenroll`.

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
- **No network map read from disk.** tsnet writes the node's own map to its
  state directory and, by default, is Running on it at the next start before
  it has spoken to the control plane (`TS_USE_CACHED_NETMAP`). varlatchd
  turns that off for every node it starts, whatever its environment says: no
  map is read from disk. tsnet still writes the node's own (its name, tags
  and addresses, no peers) at a change of its home DERP region, and has no
  switch for that; `profile-data/*/netmap-cache` is removed when the node
  starts and when it closes. The node's name, tags and tailnet, and so the
  pin's and the tags' checks, are what the control plane answers this start.
- **Until it joins.** While the control plane does not answer, or puts the
  node off (a rate limit), the node is not up and the tailnet listener does
  not open; varlatchd waits for it without end, and the listener opens when
  the node joins, with no restart. The log, doctor and the report's
  `warnings` say what it waits for (`waiting-for-control`, or `login-needed`
  when it must be logged in or approved there). A control plane that refuses
  the node (`join-refused`: an auth key it does not take) ends the wait: the
  listener stays closed, and doctor says so, until varlatchd is restarted,
  though tsnet goes on and the node may come to run. The refusal's own words,
  which may repeat the auth key, are shown nowhere: not in the log, the
  report, or a host command's answer; a message of tsnet's own log with the
  key in it, percent-escaped or not, is not logged. A control server that answers a registration with a plain HTTP error (a 403) is not
  told from one that does not answer.
- **Coordination server.** Tailscale's by default (`tailnet_control_url`
  unset, or Tailscale's own URL), and the node is always given its control
  URL explicitly (an empty one would let tsnet read `TS_CONTROL_URL`).
  varlatchd refuses to start the node while any environment variable
  tsnet reads in place of its settings is set (`TS_CONTROL_URL`,
  `TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`,
  `TS_ID_TOKEN`, `TS_AUDIENCE`, `TSNET_FORCE_LOGIN`): its control server
  and enrolment come from `varlatchd.conf` alone.
  - **A self-hosted control server (Headscale)** is given as
    `https://<its IP address>[:port]` only (step 7.5c; ADR-0059 Decision 5
    as amended). Decision 5 requires a self-hosted server's host name
    never to reach Tailscale. tsnet looks a control server's host name up
    through Tailscale's DERP servers whenever the ordinary lookup fails
    (its bootstrap DNS fallback), and no tailscale.com release can turn
    that off (checked up to v1.105.0-pre: `controlclient/direct.go` and
    `controlhttp/client.go` always install it). An IP address is never
    looked up, so a host-name URL other than Tailscale's is refused, with
    a message naming the IP form and why. The URL is kept canonical
    (`https://192.0.2.10:8443`, `https://[2001:db8::10]`; `:443` dropped),
    as the pin compares it; plain http, a user, a path, a query, an
    unspecified, multicast, link-local, broadcast or zoned address
    (judged after an IPv4-mapped address is unmapped) are refused. The server's
    certificate must be valid for that address and trusted by the host
    (the system's roots, or `SSL_CERT_FILE`).
  - **Tags** come from the auth key there: Headscale refuses a node that
    registers with a pre-auth key and advertises tags (0.29.7), so the
    node advertises none, and its key must be a tagged pre-auth key
    (`headscale preauthkeys create --tags <tailnet_tags>`). The node's
    tags must then be exactly `tailnet_tags` (step 7.5c c3): any other
    set, none included (an untagged key), closes tailnet access (fail
    closed, never latched) until they match. The listeners report says
    `TAGS_DIFFER` with both sets in `observed.warnings` (the dashboard's
    Tailnet tab), and doctor's `tailnet.pin` names them, with the remedy:
    give the node `tailnet_tags` in Headscale (`headscale nodes tag -i
    <node id> -t <tailnet_tags>`), or enrol it again with a tagged key;
    access opens at the next check (60 seconds). `admin tailnet enroll`
    refuses such a node before the handoff goes on (the node stays held,
    so enroll runs again once it is tagged).
  - **DERP.** The node uses the DERP map its control server sends. One
    that lists Tailscale's DERP servers (Headscale's default `derp.urls`)
    sends the node's netcheck, STUN and relayed traffic to Tailscale:
    doctor's advisory `tailnet.control` fails, naming them, and the
    listeners report's `observed.warnings` carries the same; access stays
    open (Headscale's configuration is the operator's). Keep `derp.urls`
    and `derp.paths` to your own DERP servers.
  - **No browser endpoint** with it: `tailnet_https_port` serves the
    node's Tailscale certificate, which a self-hosted server does not
    issue, so the two together are refused.
  - The listeners report (`GET /v1/installation/listeners`, the
    dashboard's Tailnet tab) names a self-hosted control server
    (`configured.controlUrl`); it is absent for Tailscale's.
  - Tested against Headscale 0.29.7 in a container (build tag
    `headscale`, its own step in `go.yml`;
    `server/tailnet/headscaletest`): the node joins on an IP address,
    tagged by its key, is pinned to the control URL and `base_domain`
    with no tailnet StableID, and while Headscale is unreachable makes no
    bootstrap DNS query; another configured control URL closes access.
    The identity cases (c3): a node's StableID on Headscale is its node id
    (`headscale nodes list`'s, a number per database, never a pin); over
    the tailnet listener a tagged peer is known by its tags and Headscale
    node id, a user's device by its user's login (Headscale's user name),
    the node itself is refused (self) and an address no device has
    (unrecognized); the node retagged in Headscale closes access and
    reopens once tagged again; a handoff's node enrols, is held, is shown
    reaching its name from a probe, and opens (`server/daemon`'s
    `TestHeadscaleHandoffNode`). Migrate's Headscale authority and the
    restore handoff are step 7.5c's other slices.
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
- **Re-pin.** `varlatchd admin tailnet repin [--yes [--adopt] [--offer <token>]] [--json]`
  (host authority, through the running daemon only) runs a fresh check,
  which must succeed, and shows the pin, the observation and the latched
  closure. With `--yes` it pins the observed suffix when the suffix is the
  only change, or reopens access when the tailnet matches the pin again;
  with `--yes --adopt` it pins the tailnet an enrolled node without a pin
  is on. With `--offer`, the token of the view a confirmation was given
  for, it acts only while the view's offer is still that one, decided
  under the same locks as the re-pin; otherwise nothing changes
  (`offer-changed`). A different StableID or control URL is refused: that means
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
- **The node's side of a tailnet handoff** (step 7, slice 7.5b part 2;
  internal docs/design/go-step7.md decision 11; `daemon/tailnetnode.go`,
  `tailnet/hold.go`). These host commands are what `varlatch migrate` and
  the restore ask of this installation's node.
  - **None opens the database.** So they run on the empty data directory a
    migration imports into, and under the migration's gate: the
    maintenance admission does not refuse them.
  - **Files made as root.** The node's files a command creates as root go
    to the data directory's owner: the state directory, the pin, the
    hold, the listeners report and the lock.
  - `varlatchd admin tailnet enroll --hostname <temporary name>
    [--certificate] [--timeout <d>] [--json]` runs offline, under the
    data directory's lock, before varlatchd first starts:
    - it writes the hold first (`tailnet-handoff.json`, 0600), so a crash
      after the join leaves the node held;
    - the node then joins with the auth key under the temporary name, and
      its tailnet is pinned from what it observes;
    - with `--certificate`, it gets a certificate for that name, which
      proves issuance works now;
    - it reports the node's StableID, MagicDNS name, suffix, tailnet and
      control server.

    It refuses the configured name, a name shaped like the control
    plane's collision suffix of it (`vault-1` for `vault`, which would
    latch the tailnet closed), a name the control plane changed, a data
    directory setup has not made, and a name other than the one a hold
    already names, enrolled or not. Run again for the same name, it
    reports the same node; an enrolled node no handoff holds is held again
    only while the control plane names it exactly the temporary name.

    The node's name and, on a self-hosted control server, its tags are what
    the control plane sends this start (never a map read from disk), and
    waited for, together, up to 30 seconds, since a rename just made reaches
    the node a moment after the control plane records it. One reading of the
    node must show all of it, with one StableID throughout, and that reading
    is what is pinned and reported. What is expected is never relaxed: past
    the wait it is refused, naming both.
  - **A varlatchd started under the hold** joins under the hold's
    temporary name, never announcing the configured one, which another
    node holds, and reads its name back as the hold's (open sets the
    configured one again). Nothing listens on the tailnet until `varlatchd admin
    tailnet open [--json]`, which:
    - removes the hold first;
    - then, through the control socket, starts the tailnet listener and
      waits for it. An error means it is not listening.

    Offline, `open` only removes the hold. With no hold it does nothing:
    a resumed handoff calls it again.
  - `varlatchd admin tailnet certificate obtain|expiry --name <name>
    [--json]` works on `<name>.<pinned suffix>`:
    - `obtain` is one attempt, through the running varlatchd's node or
      offline through the enrolled node, started for it, once the node's
      own map names it that and lists exactly that among its certificate
      domains (up to 30 seconds: before, the node itself refuses the name).
      A refusal for the authority's rate limit is answered as `refusal: "rate-limited"`.
    - `expiry` reads the node's cached certificate (`tailnet/certs/`,
      tsnet's ACME store) and never issues one.
  - `varlatchd admin tailnet reaches --name <name> --stable-id <id>
    [--wait <d>] [--json]` is the final check, from a client node:
    - an ephemeral probe node joins with the auth key, as the restore's
      probe does, so the key must be reusable;
    - it looks among its peers, every second until `--wait` has passed,
      for the name to be held by exactly the node with that StableID;
    - it logs out and leaves no state, on SIGINT or SIGTERM too; a
      killed probe's directory (`varlatchd-reach-*` in the system's
      temporary directory, this user's, older than 10 minutes) is swept
      by the next probe.

    The tailnet's access rules must let the node's tags see each other,
    or the probe sees nothing and the check fails closed: the answer then
    says so and names the tags.
  - `varlatchd admin tailnet take-name (--oauth-client-file <file> | --headscale-url <https://IP[:port]> --headscale-api-key-file <file>) [--json]`
    is the restore's handoff (step 7, slices 7.5b part 2c and 7.5c c4;
    decision 11, in place of step 6 decision 16's interim rule). A restore
    onto a fresh host takes the dead installation's name over, by rename,
    rather than waiting for its node to be deleted. It runs offline, under
    the lock, after `enroll` held the restored node under
    `<name>-vl-<op>-n`, and before varlatchd first starts:
    - on Tailscale (`tailnet_control_url` unset), the control plane is
      Tailscale's API with the operator's OAuth client (`devices:core`
      only), read from its file (an absolute path, regular file, mode 0600
      or tighter, never printed);
    - on a self-hosted Headscale (`tailnet_control_url` set), the control
      plane is Headscale's API (`--headscale-url`, canonicalised by
      `tailcontrol.CanonicalControlURL` and required to equal
      `tailnet_control_url`, and `--headscale-api-key-file`, read with the
      same secret-file checks). The key must expire within the hour and is
      expired however `take-name` ends after its first checks (the tailnet
      off, an authority that does not match `tailnet_control_url`, an
      authority file refused: those leave the key to expire by itself
      within the hour), a refusal before the handoff included; when it
      cannot be expired that way (Headscale unreachable, the outbound
      policy refused it, or the key refused for expiring too late), the
      answer says why and names the command that does it on the control
      server (`headscale apikeys expire --prefix hskey-api-<12>`), and a
      run killed outright leaves its key to expire by itself within the
      hour. The authority's file is checked before anything starts. A
      handoff under way goes on only against the control server it began
      on (its journal records `tailnet_control_url`) and only for the node
      it planned for: Headscale's node ids are small integers that
      another server, or another node, can carry. `--headscale-cli` is
      refused because Headscale's CLI listing carries no HTTP `Date` header
      by which to judge liveness against `deadGrace`;
    - both go through the outbound policy's client (purpose
      `tailnet_control`, `outbound_allow` as configured). Because a
      self-hosted Headscale usually listens on a private or host-only IP,
      add it to `outbound_allow` in `varlatchd.conf` (for example
      `outbound_allow = 192.0.2.10/32:8443`, `192.0.2.10/32` for port 443,
      or `[fd00::10/128]:8443` for IPv6); when refused, `take-name` prints
      the exact `outbound_allow = ...` line to add;
    - the one device under the configured name, the dead node, is judged
      dead by the control plane's `Date` header (not online, `lastSeen`
      known and older than `deadGrace`, `Date` within 1 hour of the host
      clock, re-checked right before the first rename), renamed
      `<name>-vl-<op>-o`, and the restored node renamed to the name, each
      read back; the dead node is never closed or reopened; on Tailscale
      with tailnet HTTPS the name's certificate is obtained, counted in
      `tailnet-issuances.json` (skipped on Headscale, which has no
      certificates); the reach probe must see the name reach the restored
      node; then the hold is removed, so varlatchd listens when it starts;
    - the state is journalled in `tailnet-takeover.json` (0600) before each
      act. Run again, it resumes: an unfinished switch is undone (the dead
      node takes its name back), then done again; once done, it changes
      nothing.

    `varlatch setup --restore ... --tailscale-oauth-client-file <file>`
    (ingress tailnet) runs it in place of the name probe: the operation
    journalled first, then `enroll` and `take-name`, before the unit. On a
    self-hosted control server the restore answers
    `--tailnet-control-url <https://IP[:port]>` (canonical, written as
    `tailnet_control_url`) and `--headscale-api-key-file <file>` instead,
    and `take-name` gets `--headscale-url` (that same URL) and the key file;
    both files' modes are checked at the answers step, before anything is
    made (while the takeover is still to do), and the answers are
    journalled, so a rerun takes the same authority and one naming another
    control server is refused (Tailscale's, answered as no URL, included).
    A rerun reads where the takeover got to, never by trying `take-name`
    (on Headscale it expires its key every time): enrolled only when
    setup's journal records the enrolment succeeded (or this takeover's own
    journal exists), held only under this operation's temporary name, done
    only when varlatchd's takeover journal is this operation's (its
    operation, name and control server) and says done; any other node or
    record in the data directory is refused, with nothing run against it.
    A `varlatchd.conf` whose `tailnet_control_url` is not the answered one
    is refused before anything is recorded or enrolled. A fresh
    setup on a self-hosted control server is not built yet: setup refuses
    `--tailnet-control-url` without `--restore`
    (`TestRestoreTakesTheTailnetNameOverOnHeadscale`,
    `TestHeadscaleRestoreAnswersRefused`).
    Tests: `daemon`'s `TestTheRestoreTakesTheName` (testcontrol and a fake
    of Tailscale's API over it, a rename the control server's: the dead
    node offline under the name, the takeover through the outbound policy,
    varlatchd serving under the name, a client node's map),
    `TestATakeoverCutShortIsResumed` (the control plane lost after the
    first rename), `TestTakeNameRefusals`, `TestHeadscaleTakeNameFakes`,
    `TestHeadscaleOutboundAllowEntry`, in a crashpoint build
    `TestKillTheTakeoverAtEveryStep` (killed at each journalled step in a
    process of its own, then resumed), and against a real Headscale 0.29.7
    container (`headscale` build tag) `TestHeadscaleTakeNameDeadHolder`,
    `TestHeadscaleTakeNameLiveHolderRefused`,
    `TestHeadscaleTakeNameHolderReturnsBeforeRename`, and (`headscale &&
    crashpoint`) `TestKillTheHeadscaleTakeoverAtEveryStep`; `setup`'s
    `TestRestoreTakesTheTailnetNameOver`.
  - **Tests.** `daemon`'s `TestTheHandoffNode` uses testcontrol and a
    test CA: enrolment, held, pinned and certified, run again, refusals,
    the expiry read without an issuance, varlatchd started held, silent on
    the tailnet, the reach check, obtain through the running node, and the
    live open answering at once. `tailnet`'s `TestReaches`, `TestTheHold`
    and `TestCachedNotAfter` cover the rest.

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
- `server/servecli` (step 6.8; ADR-0058 Decision 3, internal
  docs/design/go-step6.md decision 12): `serve_cli = on` serves this
  release's `varlatch` for Linux, macOS and Windows and the installers,
  stamped with the public URL's origin (required, without a path; https,
  or http on this machine). Sigstore's TUF repository is read through the
  policy's client, which follows no redirect: its CDN answers directly,
  and a redirect makes the attempt fail and retry, never a stale root
  used. `go/server/stages/check-release.sh` holds release binaries to none
  of the conformance-only parts below. In the background, varlatchd downloads the release's
  `SHA256SUMS` and its signature from github.com through the outbound
  policy (`lib/release`'s `Downloader`: github.com and its storage hosts
  only, sizes bounded; it follows github.com's redirect to storage
  itself, each Location checked and fetched as a request of its own
  through the policy, at most five), verifies the signature
  for the release workflow's identity of its own version (Sigstore's
  trusted root through its TUF repository, cached in `<data_dir>/sigstore`)
  before anything else is downloaded, checks each file against its line,
  and caches the set in `<data_dir>/cli/v<version>` only when all of it
  checks; at every start the cache is verified again (signature and every
  file) before anything is served, and other versions are removed. A
  failure is retried (a minute, doubling to an hour); until a release is
  ready, `/install.sh`, `/install.ps1` and `/cli/` answer 404 and
  `/v1/meta` does not list `cli.download`. Requests name a file by its
  exact name in the verified set, under `/cli/v<version>/` of this
  version only: nothing of a request reaches the file system. Served on
  the public listener only. With serving off, the paths answer as the
  TypeScript server's. In a conformance build only,
  `VARLATCH_CONFORMANCE_CLI_RELEASE` names a directory the harness signed
  with a test Sigstore (`varlatchd admin conformance-sign-release`), and
  the CLI built for it reads that Sigstore's trusted root
  (`main.conformanceTrustedRoot`, set at link time); go-binary's
  `cli-download-on` suite runs against it.
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

### The tailnet's control plane (step 7, slice 7.5a)

`lib/tailcontrol` is what a tailnet handoff asks of the control plane.
The handoffs themselves (internal docs/design/go-step7.md decision 11) are
slice 7.5b.

- **One interface, two backends.** Each lists the devices, offline and
  expired ones included, and renames one.
  - `Tailscale` uses the API with an OAuth client that has the
    `devices:core` scope and no other (O4); any other scope is refused
    before a token is used. Each operation exchanges the client for a
    token of its own, and nothing keeps one.
  - `HeadscaleAPI` uses a key that `Open` checks expires within the hour
    (every Headscale key is a full administrator); `Close` expires it.
  - `HeadscaleCLI` runs `headscale` on the control server (an absolute
    path when named), with the new name after `--`.
  - Both APIs are https only, and are built with a constructor that
    keeps the credential in a closure, so printing a control plane shows
    none. The constructor requires the caller's `*http.Client` and never
    makes one: `varlatch migrate` passes its own; varlatchd's restore
    handoff (7.5b) passes the outbound policy's (`go/server/outbound`),
    so the guard there needs no exception for `lib/tailcontrol`.
- **Names.**
  - `TempName` is a handoff's temporary name, `<name>-vl-<operation
    id>-n|o`, in canonical form within 63 bytes; when too long, the name
    is cut, never the operation id.
  - `CheckNames` compares a plan with every device case-insensitively.
    The name must be held by exactly the expected device, and every
    temporary name must be free, whoever holds it, online, offline or
    expired.
  - Every backend refuses a name not in canonical form.
    `RenameAndReadBack` counts a rename only once the control plane lists
    the device under exactly that name, reading it again once, a second
    later, before it calls a difference a failure.
- **Errors** name the operation and the device. Every credential is
  scrubbed from them before any cut, in every form an answer could echo
  (as sent, escaped, base64), even when the control plane echoes it. A
  transport error still answers `errors.Is` (a passed deadline stays
  `context.DeadlineExceeded`).
- **Testing.** `tailcontroltest` fakes both control planes, with the
  behaviour ADR-0059 Decision 9 records:
  - Tailscale rewrites non-canonical names and refuses a taken one;
  - Headscale keeps a case variant and refuses only the exact name.

  The real APIs are checked by hand against the owner's throwaway tailnet
  and a Headscale server (O6) in 7.5b.

### The tailnet handoff (step 7, slice 7.5b, part 1)

`lib/tailhandoff` moves a tailnet name from the node serving it to
another, and back if anything fails. It covers three handoffs (internal
docs/design/go-step7.md decision 11): the forward handoff of a migration,
its reverse, and the restore handoff of a restore onto a new host. It is
not wired into `varlatch migrate` or varlatchd's restore yet: that is part
2.

- **Prepare** runs before any barrier and changes nothing:
  - It checks the names case-insensitively against every device: the
    name held by exactly the serving node, the incoming node under exactly
    its temporary name (an enrolment under a taken name comes back
    suffixed and is refused), and the serving node's temporary name free.
  - It checks the issuance count.
  - On the Tailscale certificate path:
    - the incoming node proves it can obtain a certificate now;
    - the serving node's certificate must last through the rollback
      window plus seven days, or be renewed now, or the operator accepts
      a new certificate on a rollback.
- **Switch** runs under the barrier, and everything from its first change
  sits under one deadline (180 s):
  1. The serving installation closes its tailnet listener.
  2. The two renames, back to back, each read back.
  3. The name's certificate: at most three attempts for fast server
     errors, each counted before it is made. A rate-limit refusal ends the
     wait at once, and a timed-out attempt stays counted.
  4. A client must reach the incoming node by the name.
  5. Then the incoming installation opens.
- **The undo** runs on any failure after the first change, reading the
  control plane's own listing. The incoming node gives the name back, the
  serving node takes it again (read back), and only then does the serving
  installation reopen.
  - When the control plane can't be reached, the undo stays pending, and
    neither installation is opened on the tailnet. `Resume` finishes it
    later.
  - A restore's serving node is dead, so its listener is never closed or
    reopened.
  - `Resume` also finishes a switch that crashed while opening the
    incoming installation, once the name, the certificate and a client's
    reach hold again; otherwise it undoes it.
- **What the callers supply:** the journal, the certificates, the issuance
  count (the installation's `certificate_issuances`, #344), the
  installations' listeners, the check from a client node, and a control
  plane built with their own `*http.Client`.

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
- The migration manifest and its encoding (step 7, slice 7.1):
  - `server/migration/manifest/v1.json` lists every PostgreSQL table
    and column, in the source's column order with its type: copied (to
    its SQLite table and column), transformed (`session`: browser
    sessions end), or left out with the reason (`account`, `verification`,
    `audit_position`, `varlatch_migrations`). It also lists the two
    transformations and what lives outside the database (Convex, the
    keys, the tailnet node).
  - `manifest_test.go` holds the manifest to `testdata/pg-v0.22.0.json`,
    `mapping.json` and the schema `Init` creates. A column or table added
    on either side fails until the manifest accounts for it.
  - `server/migration/canonical` is the canonical encoding
    (`CANONICAL.md`) of values, rows and decision 7's digest input.
    `testdata/vectors.json` holds the cases, and the TypeScript server's
    encoder reproduces them on the 0.22 line.
  - **Accepted difference:** after a migration, Requirements are read in
    rowid order, the order the migration inserts them in (the source's
    physical order). That order is now defined. The TypeScript server's
    heap order depended on PostgreSQL's planner.
- The import and the reverse export (step 7, slice 7.3a; internal
  docs/design/go-step7.md decisions 2 to 5 and 16):
  - `server/migration/bundle` is the bundle (`BUNDLE.md`, bundle-v1): one
    JSON Lines stream, a header (format, manifest, encoding, direction,
    release, frozen point, an empty `sequences` list), each table the
    manifest copies or transforms in its order with its canonical rows,
    and an end line with the counts and the stream's SHA-256, so a stream
    cut short or damaged is refused whole. `testdata/small.jsonl` and
    `testdata/refused.json` are the shared vectors the TypeScript export
    reproduces. Rows sort as SQLite does: NULL first, text by its bytes.
  - `canonical.DecodeRow` reads a canonical row back into the forms
    varlatchd writes, and accepts it only when writing it again gives the
    same bytes: a value written any other way is refused, never
    normalized.
  - `varlatchd admin migrate import --in <bundle> [--json]` (offline, the
    data directory held and empty, `server/migration/migrate`): the bundle
    is read whole first (counts and SHA-256), then into a fresh database
    under a temporary name in the data directory (`.migrate-import-*`,
    renamed to `varlatch.db` once committed, synced; what an import or a
    reverse export that was killed left under its temporary name is
    removed by the next import, a look-alike refused) in one write job, foreign keys
    deferred to the commit (`PRAGMA defer_foreign_keys`, ON only, the one
    assignment a job may make, and only on a database opened with
    `storage.Options.DeferForeignKeys`, as the import's is: the schema's
    tables refer to each other in a cycle), every copied row inserted as it is (ciphertexts byte for
    byte; a left-out column, the session's token, must be null: the
    export never reads it), and before the commit every foreign key checked
    (`foreign_key_check`, the broken ones named), no sequence present, and
    the Root KEK checked against the installation's canary. Anything that
    fails keeps nothing.
  - The transformations: each source session is inserted and deleted at
    once, so `session_end_revokes_browser_credentials` revokes its browser
    credentials and writes their `credential.revoked` events exactly as a
    sign-out does (CLI hand-off credentials stay); the session itself is
    never kept. Then `installation.migrated` is appended, carrying the
    direction, the source release, the manifest version, the frozen point
    and how many sessions ended and credentials the trigger revoked
    (counted from the `credential.revoked` events it wrote, so an expired
    browser credential, which it leaves as it is, is not counted), which
    attributes those revocations to the migration.
  - `varlatchd admin migrate export --reverse --out <bundle> [--json]`
    writes the reverse bundle for the last TypeScript release's import
    from a snapshot copy of the database: every Go browser session ended
    and `installation.migrated` appended on the copy only, the database
    itself unchanged. The bundle is a new file, mode 0600.
  - Round trip (`TestRoundTrip`): twelve v0.22.0 parity fixtures' TypeScript
    rows (47 tables with rows, among them the audit log, audit export plans'
    `bytea`, webhooks, platform connections, the sync cursor, passkeys and a
    signing key) imported and exported back are the same rows, byte for
    byte, but for the documented transformations.
  - **Accepted difference:** `installation.migrated` is an audit event of
    the Go server (`GoOnlyEventTypes`); the last TypeScript release
    (0.23.0, slice 7.2a) knows it too.
- The migration's checks (step 7, slice 7.3b; ADR-0059 Decision 9 phase 4;
  internal docs/design/go-step7.md decisions 7 and 8;
  `server/migration/check/CHECKS.md`):
  - The bundle gains two sections after the tables: the writer's keyed
    digest of every encrypted item (HMAC-SHA256 under the migration's run
    key over `canonical.DigestInput`; the key itself never in the bundle)
    and its decision table (credential, credential state, resource,
    action, Tailnet Context, answer). The end line counts both. An import
    reads them past; a reverse bundle carries them empty until slice 7.6.
  - `varlatchd admin migrate check --in <bundle> [--json]` (offline, the
    data directory held, the database opened read-only; the run key, 64 hex
    digits on one line, on standard input) holds the imported database
    against the bundle in five checks, each run whatever another found:
    rows (every copied row's canonical bytes, matched by key, or by
    position for `requirements`; no extra row, no unaccounted table),
    encryption classes (every item of the ten classes opened with the Root
    KEK and digested, held against the bundle's digests), audit (the
    source's log a prefix of the target's by position, then only the
    migration's revocations and one `installation.migrated` carrying the
    header; every cursor where the source left it), authorization
    (every decision evaluated again with `authz.Decide`) and
    authentication (identities, passkeys, credentials, OIDC bindings,
    setup grants and device sign-ins by key; no session kept; every live
    browser credential of an ended session revoked). Exit 0 when all
    pass, 1 when one fails; the report names checks, tables, classes,
    positions, ids and counts, never a value, a plaintext, a digest or a
    key.
  - The read side is its own: `server/migration/check` queries SQLite
    directly through the manifest and imports nothing of
    `server/migration/migrate` (`TestTheChecksDoNotImportTheImport` walks
    its import graph).
  - Seeded run (`TestASeededImportPasses`, on `migrationtest`'s twelve
    parity fixtures under one Root KEK, every class real): every check
    passes; each damage of the design's list fails at its own check, its
    table or class named (`TestAChangedCiphertextByteFailsItsClass`,
    `TestEachDamageFailsAtItsCheck`); the reports are scanned for every
    seeded plaintext, the Root KEK, the run key and every digest.
- G5's damage gate (step 7, slice 7.3c; `server/migration/g5`, build tag
  `g5`, its own step in go.yml's go-g5 job, beside go, with the Headscale
  tests): the migration's Go path through the
  varlatchd binary, on the seeded installation. The seeded bundle imports
  and passes every check. Each damage of the bundle stream (a changed
  byte, cut short, no end line, the end line's digest or counts, digests
  out of order, a section line not canonical, a session token, a
  sequence) is refused by the import, named, with nothing kept. Each
  damage of the check sections (a digest not the source's, a digest
  missing, a decision answered otherwise) imports and fails at its check.
  Each damage of the imported database, `migrationtest`'s catalog shared
  with the checks' unit tests, fails at its own check with its table or
  class named. Another run key or Root KEK fails the class check, and the
  import refuses the wrong Root KEK. An import killed while it writes
  leaves no `varlatch.db`, and the next import clears what it left
  (`-journal` included) and passes the checks. Every output of the binary
  is scanned for each seeded secret. G5's interrupted phases are 7.4c's,
  its reverse half 7.6a's.
- `varlatch migrate`, the phases (step 7, slice 7.4a; ADR-0059 Decision 9;
  internal docs/design/go-step7.md decisions 2, 9, 14, 19 and 20;
  `cmd/varlatch/internal/migrate`): a Go-only host command (outside the
  parity table), from the last TypeScript release's Compose installation
  (`--from`, the current directory by default) to a host install of
  varlatchd (`--config`). The CLI drives both sides as processes and
  opens no database: the source through `docker compose exec` into its
  varlatchd container (`admin migration status|barrier|export|release|
  mark-migrated-out`) and the TypeScript host CLI (`--ts-cli`, default
  `varlatch-ts`) for the preflight's backup; the target through
  `varlatchd admin migrate`.
  - The phases: preflight (the source is 0.23.0 by its image's version,
    and its image is the published one by its registry digest of
    `ghcr.io/varlatch/varlatchd`, `LastTypeScriptDigest`, v0.23.0's
    varlatchd image index as its release published it; it is
    behind no gate; what an interrupted run left, its scratch directories
    and bundles by their exact names, is removed; a fresh backup made, uploaded,
    downloaded and verified; the target's key files given the source's
    Root KEK and BEK, `admin migrate keys`, absent or the same); the dry
    run (a full copy from a snapshot of the running source, imported into
    a scratch directory, `--scratch`, and checked, timed; the projected
    downtime, drain bound plus copy and checks, held against
    `--max-downtime`, 10 minutes by default, O7; `--dry-run` stops there);
    the barrier; the final copy, imported and checked; the switch (the
    source marked migrated out); open.
  - The journal, `migration.json` (0600, never a key, the run key, a value
    or a bundle), is written before each phase in the source's directory
    and, through `admin migrate state --write`, in the target's data
    directory. varlatchd does not start on a data directory whose journal
    is not open. `--status` prints it; `--resume` redoes a migration
    interrupted before the barrier from its preflight (on its own target
    only), undoes one between
    the barrier and the switch (the barrier lifted, the old installation
    reopened unchanged, the target's database discarded, `admin migrate
    discard`, before the switch only), and opens a switched one (unless
    its barrier was lifted by hand meanwhile: then a person decides). Any
    failure after the barrier undoes the same way.
  - The run key is made per copy and handed to the export and the checks
    on their stdin; the keys go to `admin migrate keys` on its stdin, as
    base64 JSON. None is in an argument, the environment, the journal or
    the output.
  - Not yet: the image target shape (`--to-data`, decision 20's second
    shape), the interruptions' CI cases (7.4c) and the run against a
    Compose installation of 0.23.0.
- The address transfer (step 7, slice 7.4b; decision 12, O3):
  `varlatch migrate --ingress public|proxy|coolify`. The preflight
  refuses a target whose `public_url` origin (scheme, host, port; so the
  passkeys' RP ID) is not the source's `VARLATCH_PUBLIC_URL`, public
  ingress without the source's Caddy overlay or the target's
  `listen_https`, and an own proxy whose target `listen` is not the
  dashboard's `BIND_ADDRESS:VARLATCH_WEB_PORT`.
  - The phases after the checks are transfer, switched, open: the address
    moves before the switch, so an undo still reopens the source. Entering
    transfer, `admin migrate state --write` writes the migration's gate
    (`maintenance.json`, kind `migration`, phase `transfer`, no expiry);
    varlatchd starts on a journal in transfer only under it, isolated,
    answering `GET /v1/meta` and nothing else (`httpserver.MetaAdmission`).
  - Public ingress: the source's Caddy stops (`docker compose stop
    caddy`), the target starts (`systemctl start`, `--unit`) and takes its
    certificate over ACME. Own proxy: the source's dashboard stops,
    freeing its port, and the target starts on it. Coolify: the target
    starts, and `migrate` stops (exit 75) with the exact domain move to
    make; `--resume` checks it.
  - Every check of the address (the transfer's, the reverse's and an
    undo's) asks for `/v1/meta` with `Cache-Control: no-cache` and
    `Pragma: no-cache`, and Go answers `/v1/meta` with `Cache-Control:
    no-store` (a deliberate difference: the TypeScript route sets none),
    so a proxy's cached answer never stands for the installation serving.
  - The check: `<origin>/v1/meta` must answer with the migrated
    installation's id and the target's release, within
    `--transfer-timeout` (3 minutes). Then the source is marked migrated
    out, and the target restarted out of its gate (the journal open removes
    it). If the public URL does not answer, the address goes back (the
    target stopped, the source's Caddy or dashboard started; Coolify: the
    instruction to move the domain back) and the migration is undone.
    `--abort` undoes any migration before its switch. The gate is
    removed before the target's journal says open or released, so a gate
    that cannot be removed leaves the journal where it was (the message
    names the file to remove by hand); `--resume` finishes an open (the
    target's journal open, its service started) or an undo (its journal
    released) that the source's journal records but the target does not.
    `admin migrate state` (reading, not `--write`) answers beside a
    running varlatchd and says whether one runs and whether the gate
    stands.
  - The dry run's projection includes the transfer, estimated by shape
    (a minute for an ACME issuance or a domain move, seconds for a port,
    and the target's restart): nothing is transferred before the barrier,
    so it is not measured.
  - **Accepted difference:** Go's maintenance gate has a kind of its own,
    `migration` with phase `transfer`; a gate the TypeScript server wrote
    with another phase is unreadable to Go, which fails closed.
  - Not yet: an end-to-end transfer with Pebble (7.4c, 7.8).
- The image target (step 7, slice 7.4d; decision 20's second shape, O2):
  `varlatch migrate ... --to-data <dir> --to-keys <dir> --to-config <file>
  --to-image <repository:tag@sha256:...> --to-service <name>`, instead of
  `--config` and `--unit`. The Go image's service (6.10a) is created
  beforehand in setup mode with nothing listening; its data directory,
  keys directory and configuration are bind paths on this host.
  - `migrate` runs no Docker command against it. It fills the bind paths
    with this host's varlatchd, the image's release (the tag must be
    `varlatchd`'s release), run as the image's user (uid and gid 65532)
    so every file is the image's, against a configuration derived from
    the service's (`/var/lib/varlatch`, `/keys` and `/etc/varlatch`
    mapped to the bind paths; a file setting elsewhere, or a path whose
    `..` leads out of its bind path, refused). Each bundle, the dry run's
    scratch database and the derived configuration are staged in a
    directory the image's user owns, in this source's own directory under
    the system's temporary directory (`varlatch-migrate-<hash>`, mode
    0711); a killed run's leftovers there are removed under the lock.
  - The preflight refuses a reference not pinned by its digest (checked
    by its shape only: without Docker, `migrate` does not resolve it, so
    that the service runs that digest is the operator's, and 7.8's
    Coolify rehearsal checks it), a tag
    that is not this varlatchd's release, bind paths not owned by
    65532:65532 or writable by others (the `chown` and `chmod` to run are
    said), and a service already serving on the bind path.
  - Starting and stopping the service are the operator's: `migrate` says
    each exactly (Coolify's Deploy or Stop, or `docker compose up -d` or
    `stop`) and checks it after (varlatchd's control socket in the bind
    path answers while the service serves). The transfer stops once
    (exit 75) for every step the operator takes, the service's start and,
    with Coolify, the domain move; `--resume` checks both through the
    public URL. An undo waits for the service to be stopped, and resumes
    as an undo.
- G5's interrupted half (step 7, slice 7.4c; decision 14;
  `server/migration/g5/interrupt_test.go`, in the G5 gate's step): the
  real `varlatch migrate`, built with the `crashpoint` tag
  (`cmd/varlatch/internal/migrate/crashpoint.go`: it pauses at a named
  point for the gate to SIGKILL it there), killed at every phase boundary
  (each phase entered, the barrier held, the transfer started, the
  source's journal open before the live open), against a real target
  varlatchd, host install and image, and a stand-in for the last
  TypeScript release (`docker`, `varlatch-ts` and `systemctl` answered by
  the test binary, the export from `migrationtest`'s seed; 0.23.0 is not
  published). After each kill: the source's data hashed unchanged, both
  journals in the stated state, which side the public URL answers from
  (the source, its barrier's 503, the target under the transfer's gate,
  the target open), then `--resume` (and `--abort` before the switch) to
  the stated end, a second `--resume` changing nothing; the Coolify shape
  and the image's operator steps too. Every output, journal and log is
  scanned for the keys and the run keys.
- The host target `varlatch migrate` makes (step 7, slice 7.4e; decision
  20): with `--config /etc/varlatch/varlatchd.conf` not there, migrate (as
  root, on a systemd host) makes the Go installation with setup's steps
  (`internal/setup` `PrepareTarget`):
  - **The answers:** the source's public URL and ingress, and for an own
    proxy the dashboard's address; `--acme-email` and `--listen` for what
    the source cannot say.
  - **Checked first:** nothing changes until the unit file is installed
    and not running, an existing user passes, and an `/etc/varlatch` or
    data directory there already is as a target needs (then used as it
    is, never chmodded or chowned; refused otherwise).
  - **What it makes:**
    - the varlatch user (an existing one judged as setup judges it,
      supplementary groups included, unless `--accept-existing-user`);
    - `/etc/varlatch` and the data directory;
    - the unit enabled but not started;
    - the configuration, checked by varlatchd, last: a configuration
      there is a target ready, so a run killed before it makes the rest
      again.
  - **Never keys:** they are the source's, which `admin migrate keys`
    writes where the unit loads them (`CREDENTIALS_DIRECTORY`: the
    configuration names no key file).
  - **Journalled first:** each item goes in the source's journal before
    it is made (`created`), the keys' files too, but only a key file not
    there before (one there is never migrate's, so never removed).
  - **Undone:** an undo before the switch removes exactly those, after
    both journals say released (`UndoTarget`), as does `--abort` of a
    run killed while making it. Until the removal is done the migration
    is not released for good: `--abort` (or `--resume`) goes on removing
    it, and no new migration starts over it. Should it keep failing,
    `--status` names each item's place: removed by hand, then
    `--abort --forget-target` clears the record (it removes nothing, and
    refuses while any item recorded is still there, each checked as the
    undo removes it, the user's own group too). The unit's undo is done
    again harmlessly (nothing to disable once its file is gone, or in a
    state systemctl names as not enabled; any other state is disabled).
    The journal's record is checked as it is read (plain item names, and
    setup's configuration as where it was made).
  - **Root:** whenever the target may change (its configuration missing
    or unreadable, or one migrate made and has not removed, before the
    switch), migrate refuses to run without root.
  - **Never on a tailnet:** setup's answers for a made target are public
    or own proxy (`tailnet = off`), so a source serving a tailnet address,
    or the tailnet's authority given, is refused before anything is made
    or backed up: prepare the configuration with `tailnet = on` first.
    Tailnet on a made target is backlog.
  - **A prepared target** (another `--config`, or one already there) is
    used as it is.
  - **Tests:** G5's `maketarget_test.go` runs it under a test root
    (the crashpoint build's seam); go.yml's runner-only step makes and
    undoes it on a real systemd.
- `varlatch migrate --rollback` (step 7, slice 7.6a; decisions 16 and
  17): the reverse migration, within 30 days of the switch, back to the
  last TypeScript release. Its phases are journalled in both places, as
  the forward migration's:
  - `rollback`: Go's migration barrier, through its control socket (Go
    keeps running, isolated, its frozen copy made);
  - `rollback-exported`: the reverse bundle from the frozen copy, the
    transformed copy kept;
  - `rollback-imported`: the TypeScript release on a fresh database. A
    Compose file of migrate's (`docker-compose.varlatch-rollback.yml`,
    named in `.env`'s `COMPOSE_FILE`) renames the Postgres and Convex
    volumes to fresh ones, the retained ones left as they are, and defines
    the import's one-off service (the release's pinned image, the migrate
    role and the Root KEK as the installation's own secrets and variables,
    never an argument). Its `admin migration import` lifts the migrated-out
    marker; Convex is reset;
  - `rollback-checked`: the reverse checks;
  - `rollback-transfer`: the address back (Go stops serving it, the
    TypeScript release and its ingress start; in Coolify the operator moves
    the domain back, then Go stops);
  - `rolled-back`: Go's journal says so, and varlatchd never starts on that
    data directory again.

  An interruption, a failed check or `--abort` before the transfer undoes
  it: the TypeScript side as the forward migration left it (its marker
  made again), Go's journal open again, then its barrier lifted. For
  rollbacks begun by 0.50.2 or later, the undo removes the fresh volumes. For
  rollbacks begun by 0.50.0, it leaves any surviving fresh volumes for
  reconciliation. Go runs throughout (stopped in the transfer on the
  public and own-proxy shapes, started again by an undo). In the transfer,
  until it records a start of the rebuilt release, `--resume` goes on, a
  failed check of the fresh volumes leaves it pending (repair, then
  `--resume`), and `--abort` still undoes it. The journal records `servedAt` just before
  the transfer first starts the rebuilt release; from then on it may have
  accepted writes, so the reverse goes forward only, a failed start
  included: the fresh volumes and the phase are kept for `--resume`, and
  `--abort` refuses. A 0.50.0 journal (without `recordsServing`) in the
  transfer counts as started.

  Its report lists the Go archives made since the switch, which the
  TypeScript release cannot read (never deleted).
- `varlatch migrate --finish [--delete-old-data]` (slice 7.6a; decision
  17): the operator ends the rollback window.
  - **After a forward migration:**
    - `finished` in both journals (Go's beside it: it serves as before);
      `--rollback` then refuses, and `migrate.RollbackWindowOpen(dataDir,
      now)` (false once finished) is what `varlatch upgrade` asks before a
      release with `endsRollbackWindow`;
    - the TypeScript installation's containers are removed (`docker
      compose down`, its volumes kept), and its old node's state and
      certificates (its Tailscale and Caddy volumes);
    - with `--delete-old-data` only, which nothing implies: a final
      archive of it (format 2, its own backup, uploaded, then downloaded
      and verified) is journalled first, then its Postgres and Convex
      volumes are removed.
  - **After a reverse:**
    - the source's journal says `finished`, and Go's stays `rolled-back`;
    - with `--delete-old-data`: a final archive of Go's copy (format 3,
      verified), then the copy is discarded and the pre-migration volumes
      the rebuild left unused are removed. Never the ones in use.
  - In Coolify's shape, the removals are said as the operator's.
  - Interrupted after `finished`, `--resume` finishes it (each removal is
    done again harmlessly); before, `--finish` runs again. G5's
    `server/migration/g5/finish_test.go` kills it at each step.
- G5's interrupted reverse (`server/migration/g5/rollback_test.go`) kills
  it at every phase boundary and holds the stated state there, with Go
  running until the address moves.
- The live open: `varlatchd admin migrate open --id <migration>` ends the
  transfer's gate in the running varlatchd, through its control socket
  (offline, on the data directory), then writes its journal open (the gate
  first); `migrate` opens a running target this way, with no restart, a
  stopped one by writing its journal and starting it. A switch is the
  journal's word alone, written beside the varlatchd serving under the
  transfer's gate.
- `varlatch migrate --from-archive`, the backup converter (step 7, slice
  7.7b; go-step7 decision 18; `cmd/varlatch/internal/migrate` archive.go):
  a TypeScript archive (format 1 or 2) to a format 3 archive of the same
  installation (`--out`), by the migration's own path, on a host with
  Docker. It opens the archive with the BEK (`--bek-file`, a key or a
  passphrase; a passphrase needs `--out-bek-file`, the key file the output
  is sealed with) and checks the Root KEK (`--kek-file`) against its
  canaries, refusing a wrong key, a varlatchd archive, an output that
  exists or an image not pinned by digest before any container starts.
  Then an isolated restore: a throwaway PostgreSQL 17.6 (by digest) with
  `--network none` takes the Secret Plane's dump as the TypeScript
  restore does, and the last TypeScript release's image (by default the
  one `LastTypeScriptDigest` pins, v0.23.0's; `--ts-image` gives another
  by registry digest, and a local image ID only with
  `VARLATCH_ALLOW_LOCAL_TS_IMAGE=1`, for the tests, with a warning) runs
  in its namespace, read-only, as this
  user, with no capability: `migrate` (an older schema brought forward),
  `admin migration backfill` (the exposure index an archive from before
  0.20.0 lacks) and `admin migration export --dry-run --digests`, the run
  key on its stdin. Never a daemon. Then varlatchd, as a process, on a
  scratch data directory: `admin migrate import`, `admin migrate check`
  (every check passes) and `admin backup run`, whose archive is placed at
  `--out` once its installation and key versions are the source's. Both
  containers and the scratch directory are removed, on an interrupt too
  (SIGINT, SIGTERM, SIGHUP end it through its context), and when a
  removal fails it says the cleanup is incomplete. One conversion runs at
  a time per host, whoever runs it (an flock on
  /run/lock/varlatch-convert.lock, or /tmp's, whatever TMPDIR says), and
  each starts by sweeping what a killed one left: the converter's
  labelled containers, by ID, its working directories in the scratch
  root and the copy it was placing beside `--out` (directories or regular
  files of its own names, never a symbolic link; one it may not remove is
  warned about). Linux and macOS only. PostgreSQL's own
  messages (psql, pg_restore) are not shown: they can quote the
  archive's data. Its tests: the
  refusals before any program runs and the conversion's sequence, with
  fakes; the isolation per pull request in go.yml
  (`TestArchiveIsolationHasNoNetwork`, Docker); the conversions of
  release/0.22's generated archives (format 1 and 2 of the seeded
  installation, format 1 of a 0.7.0 installation), each restored after,
  in the nightly converter job (`TestConvertArchives`).
- `db.go`: `Init` creates the schema on an empty file in one write job and
  records `SchemaVersion` in the `schema_version` table (a row rather than
  `PRAGMA user_version`; `db.go` says why), and on later starts checks the
  recorded version, accepting a newer one only when its `compatible_from`
  allows (rollback-safe releases, G6).
- `version.go` and `upgrade.go` (step 6, slice 6.6a): `SchemaVersion`,
  `CompatibleFrom` (the oldest schema whose varlatchd may open a database
  of this one) and the upgrade steps, one per released schema version.
  `Upgrade` runs every step from the database's version on in one write
  job and records the last step's `compatibleFrom`; a step never lowers
  it. `varlatchd admin schema status|upgrade [--json]` fronts it: status
  reads the database read-only, beside a running varlatchd too; upgrade
  runs offline under the data directory's lock and is refused while
  varlatchd runs or a restore is unfinished (`varlatch upgrade` runs it on
  a copy first). Until the first Go release `schema.sql` still changes in
  place under version 1; from it on, every change raises `SchemaVersion`
  with its step.
- The release's rollback-safety declaration (ADR-0059 Decision 8, G6):
  `go/release/release.json` says the schema version, `compatibleFrom`,
  whether the release is rollback-safe and the previous release it was
  checked against; `build-assets.sh` attaches it as `release.json` with
  the version (`go/lib/release` `Manifest`, format 2).
  `server/db/schemadiff` classifies every change from the previous
  release's schema as additive, review (an enumeration that only gains
  values) or breaking, and `server/db/releasecheck` fails CI when the
  declaration does not hold: a breaking change in a release declared
  rollback-safe, or a changed schema that keeps its version. G6's run
  (`go/release/g6.sh`, go-binary shard 1) serves the previous release on
  a database the new one upgraded, with the conformance suites, then the
  new release on what the previous one wrote. What the schema does not
  show (a value the previous release misreads, an envelope format, a
  restriction kept in code) is G6's run and the release checklist.
- The migration's rollback window (step 7, slice 7.6b; internal
  docs/design/go-step7.md decision 17): the declaration also says what the
  release does to a migration's rollback window:
  - `reversibleTo` names the last TypeScript release (`0.23.0`): a reverse
    migration of this release's data returns to it;
  - or `endsRollbackWindow` is true: after it, `varlatch migrate
    --rollback` can no longer go back. `Manifest.EndsRollbackWindow` and
    `release.RollbackWindowNotice` are what `varlatch upgrade` (6.6b)
    checks and shows before upgrading to such a release.

  Exactly one of the two. A declaration with neither fails `releasecheck`,
  and the release job's `check-assets.sh` refuses such a `release.json`.
  Format 1 (rc.1 and rc.2) predates migrations: it is still read, as
  ending no window.
  - **`varlatch upgrade` (slice 7.6b, part 2).** While the installation's
    window is open (`migrate.RollbackWindowOpen`: Go's journal open,
    switched within 30 days and not ended by an upgrade, or a reverse
    under way), a release with `endsRollbackWindow` is shown with
    `release.RollbackWindowNotice` and upgraded to only once confirmed:
    asked on a terminal; with `--yes`, or off a terminal, refused unless
    `--end-rollback-window` is given.
    - Before anything is upgraded, the end is recorded in Go's journal
      (`windowEnded`: the release and when), written through `varlatchd
      admin migrate state --write` beside the running varlatchd. Open
      over open is the journal's word alone once no transfer gate stands
      (`server/daemon/migrate.go`). From then `--rollback` refuses, and so
      does varlatchd's own reverse barrier, even if the upgrade itself is
      undone: the window is ended, not suspended.
    - A release that keeps the window (`reversibleTo`), or no window open
      (never migrated, finished, or past 30 days), asks nothing more than
      before.
    - Tested on a host (`TestUpgradeCommandOnAHost`, as root: the real
      varlatchd builds) and beside a running varlatchd
      (`TestTheWindowEndsBesideTheRunningVarlatchd`); G5's "ended by an
      upgrade" case refuses the reverse.
  - **The release job's G5** (`release.yml`'s `go-g5`, which `go-release`
    waits for): a release with `reversibleTo` passes G5 whole, forward and
    reverse; one with `endsRollbackWindow` its forward half; any other
    declaration fails. It runs `server/migration/g5`'s stand-ins for the
    TypeScript side; the run against the last TypeScript release's
    published image is the step 7.8 rehearsal's.
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
| `apps/cli/src/securityReport.ts` `KIND_WORDS` and `OUTBOUND_REFUSAL_LABELS`, `auditExport.ts` `LOCK_WORDS`, a refused destination's `kind` or `reason`, or an audit export's `objectLock`, named like a property of `Object.prototype` (`constructor`, `__proto__`, ...) (step 5 defect 32, not a security defect) | the lookup reads the prototype, so `security report` and `security status` print a function's source or `[object Object]` as the word: `function Object() { [native code] } (whk_1)` | a word the table does not hold reads as `undefined`, as TypeScript reads a word it lacks | `internal/cli` `TestSecurityWordsReadOwnNames` | none |
| `packages/matcher` `matcher.ts` `StreamMatcher.push`, a chunk of output holding many matches (step 5 defect 29, not a security defect) | each match is merged by walking every pending segment, and a chunk's matches all stay pending until it is merged, so masking a chunk takes time quadratic in its matches: a 64 KB chunk of a repeated Secret in 170 ms, 1 MB in 45 s; `run --redact` slows down, and still masks correctly | the merge looks only at the segments that end after the match's start, with the same result; linear | `internal/matcher` `TestMatcherIsLinear` and the vectors | none |
| `apps/cli/src/broker.ts` `forward`, a 101 Switching Protocols answered to a request passed through (step 5 defect 43, not a security defect) | Node.js's client has no `upgrade` listener, so the upstream socket is dropped and the request neither answers nor fails: the Agent gets no reply and waits until its own timeout | a 502 refusal, at once | `internal/broker` `TestBrokerScenarios` (`pass.upgrade`) | none |
| `apps/cli/src/request.ts` `sendThroughBroker`, a reply the Broker generated itself (step 5 defect 44, not a security defect) | its text goes to stderr from a handler of both the response's `end` and its `close`, so each line is printed twice | once | `testdata/transcripts/5.5b-request.json`, the `refused.*` cases (`broker-reply-once`) | none |
| `packages/sync` `coolifyCompose.ts` `classifyComposeUsage`, a Compose file with an alias inside its own anchor (step 4 defect 6, not a security defect) | the `yaml` package builds a cyclic object and `scalarsOf` overflows the stack, so the Coolify adapter's `inspectUsage` throws a `RangeError` though it never should: varlatchd's engine catches it (its `usage-unchecked` note says "the destination could not be read"), the CLI's `sync check` fails | `lib/sync` reads the file as unreadable: usage unchecked, every verdict unknown, the note's reason "the service's compose file is too large or could not be read" | `lib/sync` `TestTypeScriptExchanges`, the case "divergence: an alias inside its own anchor" | none |
| `packages/backup` `releaseCheck.ts` `compareVersions`, two prereleases of one release (step 6 defect 45, not a security defect) | prerelease tags compared as strings, so `0.50.0-rc.10` sorts before `0.50.0-rc.9`: the release notice's `newer` flag (and the TypeScript CLI's self-update and upgrade checks) would read a newer prerelease as older | Semantic Versioning precedence (`lib/release` `CompareVersions`): `rc.10` after `rc.9` | `lib/release` `TestCompareVersions`; `server/httpserver` `TestInstallationReleaseReadsTheReleaseCheck` | none |

The TypeScript admin CLI refuses an ordinary command during maintenance
with `Installation is in maintenance; ordinary admin operations are
blocked`, but that error reaches its generic handler, which prints
`Operator command failed; check configuration and maintenance status.`
(exit 1 either way). varlatchd prints the refusal itself.

## Before the first Go release

- G6 has no previous Go release to check against yet
  (`go/release/release.json` names none): until `0.50.0-rc.2` is checked
  against `rc.1`, CI proves the machinery with the `g6fixture` build (this
  commit's schema plus one rollback-safe step, `server/db/version_g6fixture.go`)
  as the new release and this commit's build as the previous one. The
  same step declared not rollback-safe (`g6fixture,g6unsafe`:
  `compatibleFrom` 2) checks the other path without the conformance runs:
  it passes declared so, since the previous release refuses its database,
  and fails declared rollback-safe. The first release's declaration is not
  rollback-safe: there is nothing to go back to.

- G3 at the database level: `go test ./server/values -run TestG3Gate
  -args -g3-gate` passes, so every encryption class in
  `server/values/testdata/g3-matrix.json` but the JWT signing keys (only
  Convex uses them) is proven through both servers' code that reads its
  rows, in both directions. Until step 4 builds the features that store
  them, webhook secrets, Platform credentials, GitHub App keys and audit
  export credentials and drain copies are proven at the envelope level
  only, and the check fails.
- The Go release workflow (built in step 6.1a: `release.yml`'s Go line,
  `release/`): binaries named `varlatch-<version>-<os>-<arch>` (`.exe` on
  Windows) and `varlatchd-<version>-linux-<arch>`, plus
  `varlatchd.service`, all in `SHA256SUMS`; `install.sh` and `install.ps1`
  attached with `@VARLATCH_VERSION@` replaced by the version. Still open:
  varlatch.com serving the latest one with a `Content-Length`.
- Done: THIRD-PARTY-NOTICES.md lists every Go module linked into
  `varlatch` and `varlatchd` for the release platforms (125, go-webauthn,
  modernc.org/sqlite and tailscale.com with their dependencies included),
  with their license texts and the Go standard library's
  (`scripts/go-module-notices.mjs`). Each module's license is recorded by
  hand in `scripts/go-module-licenses.json` after reading its texts, with
  their hash; `pnpm notices:check` (ci.yml) fails on a module that is not
  recorded, changed texts, a license outside the permissive list, or a
  stale file.
