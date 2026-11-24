# Release Gate Evidence

This directory stores human-verified release gate evidence checked by the
conformance harness in gate mode (`scripts/conformance/run.mjs --gate`).

## What Gate G1 Requires

### Programmatic checks (`scripts/conformance/run.mjs` and `scripts/conformance/lib/gate.mjs`)

Running the conformance harness in gate mode requires a walkthrough evidence
file named with `--walkthrough docs/evidence/<file>`:

```sh
node scripts/conformance/run.mjs \
  --target go-binary:<path> \
  --cli go:<path> \
  --gate \
  --candidate <candidate-commit> \
  --walkthrough docs/evidence/<walkthrough-file> \
  --walkthrough-commit <evidence-commit> \
  [--recent-cli-report <report.json>]
```

#### The evidence commit

The walkthrough names the candidate's commit, so it cannot be part of it: no
file holds the hash of the commit it is in. The owner's signed file is
committed on top of the candidate, in an **evidence commit**, and the gate
keeps the two apart. It checks out, builds and runs the **candidate**, and
reads one file, the walkthrough, from the evidence commit. Three checks read
it, at different times:

- **The workflow's preflight** (`scripts/conformance/gate-evidence.mjs`, right
  after the checkout, before anything is built) fetches `walkthrough_ref`,
  checks the two commits and the file, and judges the file's content. A bad
  file ends the CI run here.
- **`run.mjs` at startup**, before the target starts, checks the commits and
  the file again (with `--walkthrough-commit`), but not its content rules.
- **`run.mjs` after the suites** judges the content (`judgeGate`).

A direct, local `run.mjs` has no preflight: it fetches nothing, so the evidence
commit must already be in the repository, and a content problem shows only
after the suites. Run `gate-evidence.mjs` first to see it at once.

The preflight and `run.mjs` at startup both require all of this, except where
it says preflight, and refuse the run otherwise:

- the checkout is at the candidate (preflight: and still is after the fetch);
- preflight: `walkthrough_ref` is a plain branch, tag or full commit hash that
  origin has, and the file and the ref are both named;
- the evidence commit's tree is the candidate's, except for **regular files
  added or changed under `docs/evidence/`**. A change anywhere else, a
  deleted or renamed file, a symlink, an executable file or a submodule is
  refused;
- the walkthrough is a regular file of the evidence commit under
  `docs/evidence/`, at most 1 MiB, and plain text: valid UTF-8, with lines
  ending in LF or CRLF, and no byte order mark, NUL or other control
  character. It is judged byte for byte, so the recorded SHA-256 is of exactly
  what was judged.

The file is read as a blob from git's objects. Nothing of the evidence commit
is checked out, so nothing of it can run or change what is built. Without
`--walkthrough-commit`, `run.mjs` reads the file of the checkout (a local
trial run): at startup it must exist and not be a symlink, and the rest,
plain text included, is judged after the suites. The CI gate always names the
evidence commit.

#### The content rules

The rules are `scripts/conformance/lib/gate.mjs`'s. The preflight applies them
before the build, and `judgeGate` again after the suites; a direct `run.mjs`
only after the suites:

1. The `--walkthrough` path must resolve inside `docs/evidence/` of the
   checkout (no `..` path traversal).
2. The file must exist as a regular, non-empty, non-symlink file (`lstat`).
3. The file must not contain the template sentinel
   (`<!-- g1-walkthrough: TEMPLATE -->`), any HTML comment (`<!--`), raw HTML
   block (`<details>`, `<pre>`, `<style>`, `<script>`, `<textarea>`,
   `<template>`, `<noscript>`, `<xmp>`, `<iframe>`, `<table>` or `<div>`), or
   fenced code block (three backticks or tildes, at the margin or opened
   inside a list item or a blockquote): the gate reads
   the evidence as plain lines, not rendered Markdown, so it refuses what it
   would read differently from a reader. Nor may it contain an unchecked
   checklist row (a row whose Done cell is not `[x]`, with or without its
   outer pipes; in a table without a Done column, a cell starting with
   `[ ]`), or unreplaced placeholders (`PENDING`, `<commit-sha>`, `<sha256>`,
   `<version / sha256>`, `<e.g. ...>`, `<GitHub Actions run URL / ID>`,
   `<summary of sign-off>`, `YYYY-MM-DD HH:MM UTC`, `<name / handle>`).
4. The Owner Sign-Off section must record exactly one `**Verdict:**` line,
   which says `PASS`, and a 40-hex
   `Candidate commit` matching the candidate: the commit the run's checkout
   is at (`run.mjs` reads it as the run starts and passes it to `judgeGate`;
   a missing comparison commit fails the gate), never the evidence commit:

   ```markdown
   - **Candidate commit:** `<40-hex-commit-sha>`
   - **Verdict:** `PASS`
   ```

   (Backticks around the commit SHA and `PASS` are optional.)
5. `run.mjs` records `{ path, exists, size, sha256, candidate,
   evidenceCommit }` under `report.gate.walkthrough`.
6. When any check reports `predates-cli` (G2, `--recent-cli-report`), the
   companion recent-CLI gate report must record the exact same
   `gate.walkthrough.sha256` (compared by `sha256`, not by path).

### Substantive requirement (ADR-0059 G1)

Passing `--walkthrough` with a placeholder or template is rejected by
`judgeGate` and does **not** satisfy Gate G1. As documented in
`scripts/conformance/README.md` (Gate mode), G1 requires a full browser
walkthrough of the dashboard against the release candidate's `varlatchd`:

- Performed by hand by the owner, **or**
- Captured via a scripted browser walkthrough against the exact release
  candidate `varlatchd`, with the owner reviewing the captured screenshots,
  contact sheets, and recordings and completing the interactive hands-on
  checks that a read-only capture does not submit.

An automated agent cannot certify G1's browser walkthrough on the owner's
behalf.

## How to Produce a Candidate Evidence File

1. Copy [`g1-walkthrough-template.md`](./g1-walkthrough-template.md) to a
   dated or release-scoped record file in this directory, for example:
   `docs/evidence/g1-walkthrough-v0.50.0.md`.
2. Run the walkthrough against the release candidate's `varlatchd` binary or
   container image (not an earlier commit).
3. Remove the template banner and sentinel comment below the title, fill in all
   candidate metadata (full 40-hex commit SHA, `varlatchd` SHA-256, CLI SHA-256,
   browser/OS, date in UTC), check off every row (`[x]`), record any
   findings, and complete the Owner Sign-Off block.
4. Commit the signed record file, and nothing else, on a branch that starts
   at the candidate, and push that branch. The candidate itself (its commit,
   and its tag) does not move:

   ```sh
   git switch -c evidence/g1-v0.50.0 <candidate-commit>
   git add docs/evidence/g1-walkthrough-v0.50.0.md
   git commit -m "evidence: the G1 walkthrough of v0.50.0"
   git diff --stat <candidate-commit> HEAD   # only docs/evidence/
   git push origin evidence/g1-v0.50.0
   ```

5. Dispatch the CI gate workflow. `gate_ref` is the candidate, which is
   built and run; `walkthrough_ref` is where the record is read from:

   ```sh
   gh workflow run conformance.yml \
     --ref main \
     -f gate=true \
     -f gate_target=go-binary \
     -f gate_cli=go \
     -f gate_ref=<candidate-commit> \
     -f walkthrough=docs/evidence/g1-walkthrough-v0.50.0.md \
     -f walkthrough_ref=evidence/g1-v0.50.0
   ```

   The candidate must hold the gate's scripts, which are what judges: they
   run from the candidate's checkout, not from `--ref`.

   Download the resulting `conformance-report.json` artifacts from that
   single CI run for the release record.

## Files in This Directory

| File | Purpose |
| --- | --- |
| [`g1-walkthrough-template.md`](./g1-walkthrough-template.md) | Owner checklist and evidence template for Gate G1. **Template only: rejected by `judgeGate`; do not pass to `--walkthrough`.** |
