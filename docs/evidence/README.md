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

The runner enforces all of the following before and after the suites run:

1. The `--walkthrough` path must resolve inside `docs/evidence/` of the
   checkout (no `..` path traversal).
2. The file must exist as a regular file and be non-empty (`size > 0`).
3. The report records `{ path, exists, size, sha256 }` under
   `report.gate.walkthrough`.
4. Companion old-CLI gate runs (G2, `--recent-cli-report`) must reference a
   recent-CLI gate report whose `gate.walkthrough.sha256` matches the exact
   same evidence file.

### Substantive requirement (ADR-0059 G1)

Passing `--walkthrough` with a placeholder or template does **not** satisfy
Gate G1. As documented in `scripts/conformance/README.md` (Gate mode), G1
requires a full browser walkthrough of the dashboard against the release
candidate's `varlatchd`:

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
3. Fill in all candidate metadata (commit SHA, `varlatchd` SHA-256, CLI
   SHA-256, browser/OS, date in UTC), check off every section, record any
   findings, and complete the owner sign-off block.
4. Commit the signed record file on the release candidate branch and run the
   CI gate workflow (`conformance.yml`) pointing `--walkthrough` at that exact
   file. Download the resulting `conformance-report.json` artifacts from the
   single CI run for the release record.

## Files in This Directory

| File | Purpose |
| --- | --- |
| [`g1-walkthrough-template.md`](./g1-walkthrough-template.md) | Owner checklist and evidence template for Gate G1. **Template only: do not pass to `--walkthrough` for a gate run.** |
