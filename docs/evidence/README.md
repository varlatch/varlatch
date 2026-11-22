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
  --walkthrough docs/evidence/<walkthrough-file> \
  [--recent-cli-report <report.json>]
```

Before starting the target, `scripts/conformance/run.mjs` checks that the
`--walkthrough` file exists and is not a symlink (failing fast instead of
running suites for an hour). After the run, `judgeGate`
(`scripts/conformance/lib/gate.mjs`) enforces all of the following rules:

1. The `--walkthrough` path must resolve inside `docs/evidence/` of the
   checkout (no `..` path traversal).
2. The file must exist as a regular, non-empty, non-symlink file (`lstat`).
3. The file must not contain the template sentinel
   (`<!-- g1-walkthrough: TEMPLATE -->`), any unchecked checklist row
   (`| [ ] |`), or unreplaced placeholders (`PENDING`, `<commit-sha>`).
4. The Owner Sign-Off section must name a valid 40-hex `Candidate commit`,
   which must equal `report.implementation.commit` when the implementation
   fingerprint records a commit.
5. `run.mjs` records `{ path, exists, size, sha256 }` under
   `report.gate.walkthrough`.
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
3. Remove the template banner and top sentinel comment, fill in all candidate
   metadata (full 40-hex commit SHA, `varlatchd` SHA-256, CLI SHA-256,
   browser/OS, date in UTC), check off every row (`[x]`), record any
   findings, and complete the Owner Sign-Off block.
4. Commit the signed record file on the release candidate branch and dispatch
   the CI gate workflow (requires PR #399 for the `gate=true` and
   `walkthrough` workflow_dispatch inputs):

   ```sh
   gh workflow run conformance.yml \
     --ref <candidate-branch-or-tag> \
     -f gate=true \
     -f gate_target=go-binary \
     -f gate_cli=go \
     -f walkthrough=docs/evidence/g1-walkthrough-v0.50.0.md
   ```

   Download the resulting `conformance-report.json` artifacts from that
   single CI run for the release record.

## Files in This Directory

| File | Purpose |
| --- | --- |
| [`g1-walkthrough-template.md`](./g1-walkthrough-template.md) | Owner checklist and evidence template for Gate G1. **Template only: rejected by `judgeGate`; do not pass to `--walkthrough`.** |
