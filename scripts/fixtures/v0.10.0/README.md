# Published 0.10.0 release fixture

`varlatch-release.json` and `docker-compose.release.yml` are the published
assets of release `v0.10.0` (schema migration 20), the last release with the
environment-name mapping. `scripts/test-backup-v0100-restore.mjs` uses them to
run the exact published daemon, back it up with the CLI its image ships, and
restore that archive into the candidate, which migrates it forward.

`VARLATCH_TEST_V0100_IMAGE=<image>` points the test at another daemon image,
for example a local rebuild of the `v0.10.0` tag.

Do not refresh these fixtures to a newer release; add a new fixture directory.
