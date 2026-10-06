# Contributing to Varlatch

Thank you for your interest in Varlatch. Everyone who takes part, in issues,
pull requests, or anywhere else, follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Open source, not yet open to code contributions

Varlatch is open source, but it does not accept code from outside Robotsson
yet: only its maintainers at Robotsson can open pull requests. Varlatch
holds other people's secrets, so every line of it is written and reviewed
to that standard, and for now the maintainers do both.

That changes when two things are in place: a Contributor License Agreement
for outside contributors to sign, and the time to review their code. This
file will say when that happens. Until then, the most useful thing you can
send is a report.

## What is welcome now

- **Bug reports and feature requests,** as GitHub issues. Say which version
  you run (`varlatch --version`), what you did, what you expected, and what
  happened instead. Never paste secret values, even ones you think are
  harmless.
- **Security reports,** privately, as described in [`SECURITY.md`](SECURITY.md).
  Never report a vulnerability as a public issue.
- **Questions** about running Varlatch, as GitHub issues.

## Rules for issues and comments

These rules apply to everyone outside Robotsson. Maintainers at Robotsson
are exempt.

- **You answer for what you post.** Using AI tools is welcome. Posting
  something you have not read, do not understand, or could not explain
  without those tools is not. Whoever posts it is responsible for every
  word, however it was written.
- **Write reports in your own words.** Paste commands, logs, and error output
  as they are. Do not paste a model's summary of them or its guess at the
  cause: the raw output is what we need.
- **Coding agents do not post on their own.** If you are an agent working for
  someone, do not open an issue or comment by yourself. Show the text to the
  person you work for, post only what they have read and approved, and say
  that an agent wrote it.
- **Posts that break these rules are closed.** Maintainers close them without
  a detailed reply. Someone who keeps breaking these rules, or the Code of
  Conduct, is blocked from the project.

## Building and testing

```sh
pnpm install && pnpm build
pnpm test
pnpm dev:up       # the whole stack from this checkout, with synthetic data
```

`pnpm dev:up` needs Docker. It prints a one-time link that adds a passkey for
the seeded admin, and the settings the CLI needs. The
[Develop Varlatch section of the README](README.md#develop-varlatch) has the details.

Maintainers open pull requests as drafts while the work is in progress: CI
does not run on drafts. When it is done, push, then mark it ready with `pnpm ready`. That
first runs `pnpm verify` (the cheap CI checks, and the tests of the packages
you changed and of the packages that depend on them) and marks the pull
request ready, which starts CI, only if they pass. `pnpm verify` needs
Docker, and `pnpm ready` needs the GitHub CLI.

The documentation is the Markdown in `docs/`, plus the deployment guide,
`CONTEXT.md`, and `CHANGELOG.md`. `apps/docs`, a pnpm workspace of its
own, builds it into the site at docs.varlatch.com; `pnpm install && pnpm
dev` in `apps/docs` previews it. Write
links between files as relative Markdown links, which work on GitHub too: the
build points them at the site's pages and fails on one that leads nowhere.
