# Published 0.7.0 deployment fixture

`varlatch-release.json` and `docker-compose.release.yml` are the published
assets of release `v0.7.0` (schema migration 16), made before Varlatch moved
to this repository. The images they pin were copied to `ghcr.io/varlatch`
with their digests unchanged, so the upgrade test runs the exact published
bytes. Do not refresh these fixtures to a newer release.

`VARLATCH_TEST_LEGACY_IMAGE=<image>` points the test at another daemon image,
for example a local copy of the same digest.
