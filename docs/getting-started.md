# Getting started

Varlatch is self-hosted. One person on your team runs an installation, and
everyone else signs in to it with the CLI and a passkey. There are no
passwords. Start from where you are:

- **You were sent an invitation link.**
  [Join a team](join-a-team.md): create your passkey, install the CLI,
  sign in, and run your application.
- **You are connecting a repository** to an installation you can sign in
  to. [Set up a project](set-up-a-project.md): create the project, move
  your `.env` file in, and invite your team.
- **Nobody on your team runs an installation yet.**
  [Run an installation](run-an-installation.md), or try one on your own
  machine first.
- **You use a coding agent.** It can do most of this for you, from
  installing the CLI to moving your `.env` files in:
  [Set up with a coding agent](set-up-with-an-agent.md).

## Reference

- [Install the CLI](reference/install-the-cli.md): checking the release
  signature, Windows, and the Node.js versions the CLI needs.
- [Members and access](reference/members.md): inviting people, what they
  can reach, and removing them.
- [Passkeys and sessions](reference/passkeys-and-sessions.md): trusted
  passkeys, signing in without a browser, and signing out.
- [CI and other machines](reference/ci-and-machines.md): OIDC for CI, and
  credentials for servers.
- [Removing Varlatch](reference/uninstall.md): deleting a project or an
  organization, and everything Varlatch puts on your machine.
- [`CONTEXT.md`](../CONTEXT.md): the vocabulary, from planes and identities
  to grants and contracts.
- [Threat model](THREAT-MODEL.md): what Varlatch guarantees, and what it
  does not.
- [`CHANGELOG.md`](../CHANGELOG.md): what each release changed, and how to
  upgrade.
