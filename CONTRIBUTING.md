# Contributing to Varlatch

Thank you for your interest in Varlatch.

## Outside contributions are not accepted yet

Varlatch does not yet accept pull requests from outside Robotsson. Before
it can, it must choose the terms contributions are made under: a Developer
Certificate of Origin or a Contributor License Agreement. That choice has
not been made. Until it is, pull requests from outside Robotsson are closed
without being merged. That way no code arrives without agreed terms. This
file will say when that changes.

## What is welcome now

- **Bug reports and feature requests,** as GitHub issues. Say which version
  you run (`varlatch --version`), what you did, what you expected, and what
  happened instead. Never paste secret values, even ones you think are
  harmless.
- **Security reports,** privately, as described in [`SECURITY.md`](SECURITY.md).
  Never report a vulnerability as a public issue.
- **Questions** about running Varlatch, as GitHub issues.

## Building and testing

```sh
pnpm install && pnpm build
pnpm test
pnpm dev:up       # the whole stack from this checkout, with synthetic data
```

`pnpm dev:up` needs Docker. It prints a one-time link that adds a passkey for
the seeded admin, and the settings the CLI needs. The
[Development section of the README](README.md#development) has the details.
