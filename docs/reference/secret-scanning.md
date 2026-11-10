# Secret scanning: `varlatch scan`

`varlatch scan` checks files for the Secrets of an environment before they
leave your machine: what you are about to commit, or the build output you
are about to publish. It reports where each Secret was found, never the
value.

```
varlatch scan --staged [-e <env>] [--json]
varlatch scan <path>... [-e <env>] [--json]
varlatch scan --install-hook [-e <env>]
varlatch scan --find-files [<dir>] [--json]
```

`--find-files` is a separate mode that finds plaintext copies of secrets
on disk by their names, without reading their contents. See
[Finding copies of secrets](#finding-copies-of-secrets).

```
$ varlatch scan --staged
config/settings.py:12:15: STRIPE_KEY (version ver_01j9...), as written

varlatch scan: 3 staged file(s) checked against 5 Secret value(s) of development: 1 finding(s) in 1 file(s).
Values and line contents are never shown. Rotate a Secret that was committed or published.
```

It is a guardrail against accidents, not data-loss prevention. See
[Limits](#limits).

## Where the values come from

- **One audited disclosure.** The scan asks the server once for every
  Secret of the selected environment that your identity may retrieve, both
  the current value and, during a rotation, the retiring one. This is the
  ordinary disclosure, so it needs `secret.reveal` on the environment and is
  recorded as a `secret.disclosed` audit event. The request declares
  `purpose: "scan"`, which the event records. A server that does not
  record a purpose is named on stderr, and the disclosure is audited as an
  ordinary one.
- **Nothing is disclosed when there is nothing to read.** With nothing
  staged, no file among the paths, or no file within the size bounds, the
  scan asks the server for nothing.
- **Values stay in memory.** They are held for the duration of the scan
  and never written anywhere: not to the output, a log, a cache, or the
  baseline file. No hash or fingerprint of a value is kept either.
- **Without `secret.reveal`, nothing is scanned.** The command says so and
  exits with status 1. Agents hold no `secret.reveal` by default, so an
  agent cannot run a scan.
- The environment is chosen as for every command: `-e`/`--environment`,
  then `VARLATCH_ENV`, then `varlatch env use`, then `default_environment`
  in `varlatch.toml`.

## What is read

### `--staged`

- The content the Git index holds for every path that the next commit adds
  or changes, read from Git's object store. The working tree is not read:
  a Secret that you staged and then edited or deleted in your working copy
  is still found, and a change you have not staged is not checked.
- Before the first commit, everything staged is checked.
- Every staged path of the repository is checked, including paths outside
  the directory that holds `varlatch.toml`.
- Inside a Git hook, Git's own index is used, including the temporary one
  that `git commit -a` or `git commit <path>` prepares.
- A staged symbolic link is checked as the text of its target, as Git
  stores it.
- Submodules and unmerged paths are reported as not scanned.

### Paths

- Each file is read; each directory is walked, in a stable order.
- Symbolic links are not followed, and are reported as not scanned. A path
  you give on the command line is resolved first, so
  `varlatch scan dist` works when `dist` itself is a link.
- Special files (sockets, pipes, devices) are reported as not scanned.

## What is found

- **Bytes, not text.** Every file is scanned as bytes, binary files
  included. Nothing is decoded.
- **The whole file at once.** Matching runs across line breaks, so a
  multi-line value such as a PEM private key is found. Content is streamed,
  never read whole.
- **Common encodings:** the value as written, JSON-escaped (with or without
  `\/`, so a PEM key in a JSON file is found), percent-encoded (upper- or
  lower-case hex), and base64 or base64url, also inside a longer encoded
  string at any alignment, so `user:secret` inside a Basic credential is
  found.
- **Every occurrence is reported,** including a Secret that appears inside
  another Secret's value, and two Secrets on one line.
- **Complete occurrences only.** A file that ends with the first part of a
  Secret, and holds no complete occurrence of it there, is not a finding.
  The scan only counts such files on stderr, without naming them:

  ```
  varlatch scan: 1 file(s) end with the first 8 or more bytes of a Secret but hold no complete occurrence there; that is not a finding
  ```

- **Values shorter than 8 bytes are not checked,** because they would match
  unrelated content. The scan names those items on stderr, never their
  values:

  ```
  varlatch scan: values shorter than 8 bytes are not checked: PIN
  ```

## Findings

Each finding is one line:

```
<path>:<line>:<column>: <ITEM> (version <version ID>[, retiring]), <form>
```

- `path` is relative to the directory that holds `varlatch.toml`, with `/`
  separators. A staged file outside that directory starts with `../`.
- `line` counts line feeds (`\n`) from 1. `column` counts bytes from the
  start of the line, from 1: a character outside ASCII counts as more than
  one column.
- `version` is the Secret version that matched, and `retiring` marks the
  previous value of a rotation in progress.
- `form` is how the value was written: `as written`, `JSON-escaped`,
  `percent-encoded`, `base64`, or `base64url`.
- A finding never includes the value, any part of it, or anything else from
  the matched line, so a second Secret on the same line cannot be read from
  the report.
- At most 1000 findings are listed per file. Further occurrences are
  counted per item and version, and still count as findings.

A finding means the value is in that file. If it was already committed,
pushed, or published, rotate the Secret: removing it from the file does not
remove it from Git history or from wherever the file went.

### JSON

`--json` prints one JSON document on stdout instead:

```json
{
  "version": 1,
  "environment": "development",
  "mode": "staged",
  "exitCode": 1,
  "findings": [
    { "path": "config/settings.py", "line": 12, "column": 15, "offset": 311,
      "item": "STRIPE_KEY", "versionId": "ver_01j9...", "retiring": false, "form": "raw" }
  ],
  "unlisted": [],
  "allowed": [],
  "notScanned": [],
  "skippedItems": [],
  "valuesChecked": 5,
  "filesScanned": 3,
  "bytesScanned": 18214,
  "incompletePrefixes": 0
}
```

`offset` is the byte offset from the start of the file. `form` is one of
`raw`, `json`, `percent`, `base64`, and `base64url`. `allowed` lists the
occurrences a marker or the baseline allowed, with `allowedBy`.

### Exit status

| Status | Meaning |
| --- | --- |
| 0 | Every file was scanned, and nothing was found. |
| 1 | At least one finding, or the scan could not run (usage, authentication, permission, or server error). |
| 2 | No finding, but some files were not scanned. |

## Files that are not scanned

A file the scan skips or cannot read is listed as not scanned, with the
reason, and is never reported as clean:

```
Not scanned (1), so not known to be clean:
  assets/video.mp4: larger than the per-file bound (80 MiB > 64 MiB)
```

Reasons include: larger than the per-file bound, over the total size bound,
grew past the bound while being read, unreadable, does not exist, a
symbolic link, not a regular file, a submodule, and an unmerged path. A file
that fails partway keeps the findings made before the failure.

The bounds:

| Option | Default | Meaning |
| --- | --- | --- |
| `--max-file-size <size>` | `64M` | Largest file read. |
| `--max-total-size <size>` | `1G` | Most bytes read in one scan. A file that no longer fits is not scanned; smaller files after it still are. |

Sizes are a number of bytes, or a number with `K`, `M`, or `G` (powers of
1024).

## False positives

A test fixture may hold a real value on purpose, or a value may collide
with unrelated content. Two ways to accept an occurrence, neither of which
stores anything derived from the value:

- **An inline marker.** `varlatch:allow NAME` on a line the occurrence
  touches allows that item there, and only that item:

  ```python
  FIXTURE_KEY = "..."  # varlatch:allow STRIPE_KEY
  ```

  For a value that spans lines, the marker can be on any line from its
  first to its last. The marker needs at least one space before the name,
  and the name must be complete: `varlatch:allow STRIPE` does not allow
  `STRIPE_KEY`.
- **A baseline file.** `varlatch-scan-baseline.json`, next to
  `varlatch.toml`, lists accepted findings by path, item name, and version
  ID:

  ```json
  {
    "version": 1,
    "entries": [
      { "path": "tests/fixtures/key.pem", "item": "TLS_KEY", "versionId": "ver_01j9..." }
    ]
  }
  ```

  An entry allows every occurrence of that version of that item in that
  file, wherever it moves within the file. When the Secret is rotated, its
  new version is found again. Any other field in the file is refused, so a
  hash or fingerprint cannot be added to it. `--baseline <file>` reads
  another file, and `--write-baseline` adds the current findings to the
  baseline file and exits as if they had been allowed. Review the file
  before you commit it.

## Pre-commit hook

```
varlatch scan --install-hook [-e <env>]
```

writes a Git pre-commit hook that runs `varlatch scan --staged` before each
commit and stops the commit when the scan exits with a non-zero status. It
is installed only by this command, never automatically.

- The hook changes to the directory that holds `varlatch.toml` and calls
  `varlatch` from your `PATH`. With `-e`, it passes that environment.
- It is written where Git looks for hooks, including a `core.hooksPath`
  directory.
- An existing pre-commit hook that `varlatch` did not write is left
  unchanged; the command prints the line to add to it instead. Running
  `--install-hook` again updates a hook that `varlatch` wrote.
- `git commit --no-verify` skips it once. Delete the hook file to remove
  it.
- Each commit makes one audited disclosure. The commit is stopped when the
  scan cannot run, for example when you are not logged in or may not
  retrieve Secrets in the environment.

In CI, run the scan on the build output before publishing it:

```
varlatch scan -e production dist/
```

## Finding copies of secrets

```
varlatch scan --find-files [<dir>] [--json]
```

Programs that steal credentials from a developer's machine look first for
plaintext files such as `.env`. `--find-files` lists the files under a
directory that look like such copies by their name, so you can move them
into Varlatch and delete them.

Discovery uses filenames and metadata, without reading candidate contents.
Git ignore checks read configuration and ignore rules; unsupported setups
report unknown. Concurrent changes to those inputs can cause Git to read a
candidate file; preventing such races is outside this command's guarantee.
File contents and raw Git diagnostics are never displayed.

```
$ varlatch scan --find-files
Files that look like copies of secrets, by name, under /home/me/src/web:
  .env: ignored by Git
  certs/dev.key: not ignored by Git, so it can be committed
  services/api/.env.local: Git status unknown: /home/me/src/web/.git/config includes other files, which Git would read

varlatch scan: 3 file(s) look like copies of secrets (1 not ignored by Git); 1830 entries checked by name, without reading their contents.
Move a dotenv file into Varlatch and delete it: varlatch import <file> --delete-source
Store a key or certificate as one Secret, then delete the file: varlatch values set <ITEM> --from-file <file>
A file Git does not ignore may already be committed (git log --all -- <file>): rotate the secrets of one that was.
See docs/reference/secret-scanning.md and docs/reference/import.md.
```

- **By name.** The search reads directory entries and file metadata, not
  the contents of the files it lists. It needs no project, no sign-in, and
  no server: nothing is disclosed or sent, and it works outside a Git
  repository and outside a Varlatch project. Assisted mode changes nothing
  about it.
- **The names:** `.env`; `.env.*` except the templates `.env.example` and
  `.env.schema` (the same two names the coding agent guardrails leave
  readable); `*.pem`; and `*.key`. Names are matched case-sensitively, as
  Git does on Linux. Only files and symbolic links are listed: a directory
  with a matching name (a Python virtual environment called `.env`, say)
  is searched, not listed. A name is a hint, not a verdict: a public
  certificate bundle ends in `.pem` too.
- **Where it looks.** The directory given, or the current directory, and
  every directory below it, in a stable order. `.git`, `.hg`, `.svn`, and
  `node_modules` are skipped. A symbolic link is never followed: a linked
  directory is not entered, and a linked file is listed by its own name as
  `a symbolic link, not followed`, without looking at its target. A
  directory given on the command line is resolved first, so it may itself
  be a link.
- **Bounds.** The search reads at most 200,000 directory entries, counted
  as they are read, so a huge directory is never held in memory whole, and
  does not enter directories more than 20 levels down. Both are reported,
  as is a directory it cannot read, so an incomplete search is never shown
  as clean.
- **Names as they are.** A name that is not UTF-8 keeps its exact bytes
  through the search and Git. On the terminal, a name that holds a control
  character (including DEL and C1 controls such as U+009B) or bytes that
  are not UTF-8 is shown quoted, with each control escaped (`\n`,
  `\u009b`) and each such byte as `\xfe`. Messages that quote a path are
  escaped the same way.
- **Git state.** For each file, the search asks Git whether it ignores
  it, in the repository that holds it (a nested repository or a linked
  worktree counts as its own): `ignored by Git`, `not ignored by Git` (a
  `git add .` would commit it, and it may already be committed: check with
  `git log --all -- <file>`), or `not in a Git repository`. Whether a file
  is tracked is not reported: answering it would make Git read the index
  and more. Git runs once per repository, as `git check-ignore
  --no-index`, which reads no index and no object, with none of your `GIT_`
  environment variables, without the system or global configuration (the
  global `core.excludesFile` is passed to it after the check below), with
  `core.fsmonitor` off, and for at most 30 seconds.
- **When the Git status is unknown.** Git's configuration and ignore
  files can make Git open other files, and one of them could be a secret
  copy. So Git is not run at all for a repository where anything is
  unusual, and its files say `Git status unknown` with the reason:
  - its configuration (`.git/config`, or `config.worktree`) includes
    other files (`include.path` or `includeIf`), sets `core.worktree`, or
    sets a `core.excludesFile` that is not UTF-8;
  - the global configuration includes other files: they are not read,
    and one of them could set the excludes file (this applies to every
    repository);
  - the excludes file (`core.excludesFile`, or `~/.config/git/ignore`) is
    not an absolute path, has the name of a secret copy (directly or
    through a symbolic link), or is not a regular file;
  - a file Git opens there (`.git/HEAD`, `.git/config`,
    `config.worktree`, `info/exclude`, the `.git` file of a linked
    worktree, or its `commondir`) is a symbolic link, has another name (a
    hard link), or is not a regular file, or a pointer in it does not lead
    to a directory;
  - a `.gitignore` that applies to a listed file (in its directory or any
    directory above it, up to the top of the working tree) is a symbolic
    link, has another name (a hard link), or is not a regular file;
  - it uses another object store (`objects/info/alternates`), or is a bare
    repository;
  - Git refuses it (for example a repository owned by someone else), fails,
    does not answer in time, or is not installed; or a directory name on
    the way is not UTF-8. Git's own messages are never shown: only that it
    refused or failed, and its exit status.

  The global configuration (`GIT_CONFIG_GLOBAL`, or else
  `~/.config/git/config` and then `~/.gitconfig`, which wins, as Git
  reads them) is read only for its `core.excludesFile`. When one of its
  files is a link to a file named like a copy, every state is unknown.
- **Next steps.** Move a dotenv file in with
  [`varlatch import <file> --delete-source`](import.md), and store a key or
  certificate file as one Secret with `varlatch values set <ITEM>
  --from-file <file>`, then delete the file. Both run in a Varlatch project.
  Rotate the secrets of a file that was committed or that you cannot
  account for.

`--find-files` takes `--json` and no other option: `--staged`, paths to
scan, `-e`, and the other options of the value scan are refused.

### JSON

```json
{
  "version": 1,
  "mode": "find-files",
  "exitCode": 1,
  "root": "/home/me/src/web",
  "files": [
    { "path": ".env", "kind": "dotenv", "symlink": false, "git": "ignored" },
    { "path": "certs/dev.key", "kind": "key", "symlink": false, "git": "not-ignored" }
  ],
  "notSearched": [],
  "entriesChecked": 1830,
  "stopped": false
}
```

`path` is relative to `root`, with `/` separators. A path (or `root`)
that is not UTF-8 is given lossily in `path`, with its exact bytes in
`pathBase64` (`rootBase64`); use those when present. DEL and C1 controls
are escaped as `\u007f` to `\u009f`, which is still the same JSON.
`kind` is `dotenv` or `key`. `git` is one of `not-ignored`, `ignored`,
`no-repository`, and `unknown` (with `gitError`). `notSearched` lists the
directories not searched, with the reason, and `stopped` is `true` when the
entry bound was reached.

### Exit status

| Status | Meaning |
| --- | --- |
| 0 | The whole tree was searched, and no file looks like a copy. |
| 1 | At least one file looks like a copy, or the search could not run (a usage error, or a directory that does not exist). |
| 2 | No file looks like a copy, but part of the tree was not searched. |

These follow the value scan: 1 for findings, 2 for incomplete. A CI job can
run `varlatch scan --find-files` to fail when such a file is in the
checkout; in a fresh checkout, the files it finds are normally committed ones.

## Checking shell history for values

A secret typed or pasted on a command line ends up in your shell's history
file, another place that programs stealing credentials read. The value scan
checks it like any other file:

```
cd ~/src/web
varlatch scan ~/.bash_history
varlatch scan ~/.zsh_history -e production
```

This is the ordinary value scan, not `--find-files`: it needs what every
value scan needs. Run it from a directory of a Varlatch project (one with
`varlatch.toml` at or above it), signed in as an identity with
`secret.reveal` on the environment, and it makes one audited disclosure. A
file outside the project is scanned as given, and its findings show its
path relative to the project directory (`../../.bash_history:812:16: ...`).
Only the selected environment's Secrets are checked: repeat with `-e` for
others. A finding means the value was in your history: delete those lines
and rotate the Secret.

## Limits

- Only the selected environment's Secrets are checked, at their current
  and retiring versions. Older versions, other environments, and
  non-sensitive values are not.
- Not found: values shorter than 8 bytes; a value in hex, arbitrary
  `\uXXXX` escapes, another character set, compressed content (including
  archives and Git's packed objects), a value with changed line endings, a
  value split by other text, a partial value, and anything derived from a
  value.
- `--staged` checks what the next commit records, not Git history, and
  `varlatch scan <path>` checks only the files given.
- The value scan does not check file names, and prints them as they are.
  `--find-files` checks names and metadata, not contents.
- The scan protects against accidents. It does not stop anyone who means to
  copy a Secret into a file.
