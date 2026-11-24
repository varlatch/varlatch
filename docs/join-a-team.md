# Join a team

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release, 0.23.0, has a CLI that needs Node.js:
> [its version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/join-a-team.md).

Someone on your team runs a Varlatch installation and sent you an
invitation link. Three steps take you from that link to running your
application with its configuration.

You need a browser that supports passkeys.

## 1. Create your passkey

Open the link you were sent and create your passkey. Varlatch has no
passwords: the passkey stays on your device, in your password manager, or
on a security key. The link works once. The page then shows the next two
steps, with your installation's address filled in.

Add a second passkey later, under your account, then Security, so losing
one device never locks you out:
[Passkeys and sessions](reference/passkeys-and-sessions.md).

## 2. Install the CLI

If your installation serves the CLI, install it from there, on Linux and
macOS:

```sh
curl -fsSLo install.sh https://vault.example.com/install.sh && sh install.sh
```

Otherwise, install the release your installation runs. The dashboard
shows it under Settings, then Server:

```sh
V=0.50.0  # the release your installation runs
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sh install.sh
```

Both check the release's signature before they put anything in place. On
Windows, or to check the signature with cosign yourself, follow
[Install the CLI](reference/install-the-cli.md).

## 3. Sign in and run

In your copy of the repository, which already has `varlatch.toml`:

```sh
varlatch login --server https://vault.example.com
varlatch run -- npm run dev
```

Use your installation's address, the one in your invitation link. `varlatch
login` opens your browser, or prints the address to open, and you approve
with your passkey. On a machine without a browser, sign in with a code
instead: [Signing in from the CLI](reference/passkeys-and-sessions.md#signing-in-from-the-cli).

You sign in with the address once: later, `varlatch login` alone signs you
in again when the credential expires (12 hours by default).

`varlatch run` gives the values to your command as environment
variables. No file of secrets is written to disk. To run against another
environment, add `-e`, for example `varlatch run -e staging -- npm test`.

## What you can reach

A member can read and change development environments, read staging
environments, and see only the names of production items. An admin can
grant more: [Members and access](reference/members.md).

## Where to go next

- [Set up a project](set-up-a-project.md), for a repository that has no
  `varlatch.toml` yet.
- [Set up with a coding agent](set-up-with-an-agent.md): let an agent use
  the configuration without reading Secrets.
- [CI and other machines](reference/ci-and-machines.md).
