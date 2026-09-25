# Published 0.9.0 in the Coolify/Tailscale shape: a production-shaped fixture

The shape a reference production installation runs (ADR-0035 design note,
"Implement everything, validate once" plan): used by
`scripts/test-prod-shape.mjs` as the pre-upgrade installation.

- `varlatch-release.json`: the published `v0.9.0` release asset. CI runs
  these exact image digests, copied to `ghcr.io/varlatch` unchanged when
  Varlatch moved to this repository.
- `docker-compose.coolify-tailscale.yml`, `convex-supervisor.cjs`,
  `postgres-init/`: those files as released in `v0.9.0`, i.e. what a Coolify
  deployment of that release uses.

`VARLATCH_TEST_OLD_IMAGES=local` runs the test against images tagged
`varlatch-v090-varlatchd:local`, `varlatch-v090-web:local`, and
`varlatch-v090-convex-deploy:local` instead, for example local copies of the
same digests.

Do not refresh these fixtures to a newer release; add a new fixture directory.
