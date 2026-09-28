# Secret scanning: `varlatch scan`

`varlatch scan` checks files for the Secrets of an environment before they
leave your machine: what you are about to commit, or the build output you
are about to publish. It reports where each Secret was found, never the
value.

```
varlatch scan --staged [-e <env>] [--json]
varlatch scan <path>... [-e <env>] [--json]
varlatch scan --install-hook [-e <env>]
```

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
- File names are not checked, and are printed as they are.
- The scan protects against accidents. It does not stop anyone who means to
  copy a Secret into a file.
