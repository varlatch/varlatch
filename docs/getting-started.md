# Choose your path

Varlatch is self-hosted. One person runs a server once, and everyone else signs
in with a passkey and the CLI (no passwords). Start with whichever describes
you:

## 1. Self-host Varlatch (setting up a server)

Run `varlatchd` on any Linux host in three commands—one binary with its own
SQLite database, dashboard, HTTPS certificates, and encrypted backups:

```sh
V=0.50.2  # latest release
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sudo sh install.sh --server
```

- **Linux host or local trial (`localhost`):** [Install Varlatch](self-hosting.md)
- **Docker or Coolify:** [Docker and Coolify](self-hosting/docker-and-coolify.md)

## 2. Join a team (you received an invitation link)

Open your invite link to create a passkey, install the CLI, and run your app:

```sh
varlatch login --server https://vault.example.com
varlatch run -- npm run dev
```

- **Full 3-step guide:** [Join a team](join-a-team.md)

## 3. Connect a repository (server already running)

Wire up a repo and move existing `.env` files into Varlatch interactively—or
hand the setup to your coding agent:

```sh
varlatch init
```

- **Do it yourself:** [Connect a project](set-up-a-project.md)
- **Let your coding agent do it:** [Set up with a coding agent](set-up-with-an-agent.md)

---

## Reference

- [How Varlatch works](overview.md): a two-minute overview of organizations, projects, contracts, and agent modes.
- [Install the CLI](reference/install-the-cli.md): Linux, macOS, Windows, and signature verification.
- [Members and access](reference/members.md): inviting people, default roles, and offboarding.
- [Passkeys and sessions](reference/passkeys-and-sessions.md): trusted passkeys, headless login, and signing out.
- [Entry links](reference/entry-links.md): a person enters a secret's value on Varlatch's own page, for an application that never sees it.
- [OAuth connections](reference/oauth-connections.md): access tokens for automations, refreshed in one place, without handing out a refresh token.
- [One-time codes](reference/one-time-codes.md): two-factor sign-in codes for automations, without handing out the seed.
- [CI and other machines](reference/ci-and-machines.md): OIDC for CI and scoped machine credentials.
- [Integrations](reference/integrations.md): pushing environments to GitHub Actions, Coolify, and Convex.
- [Removing Varlatch](reference/uninstall.md): deleting a project, organization, CLI, or server.
- [Glossary](../CONTEXT.md): full Varlatch terminology.
- [Threat model](THREAT-MODEL.md): what Varlatch guarantees and what it does not.
- [Changelog](../CHANGELOG.md): release notes and upgrade steps.

<details>
<summary>Moved sections (links from older pages)</summary>

- <a id="what-you-need"></a>What you need: [Install Varlatch](self-hosting.md#what-you-need)
- <a id="get-the-cli"></a>Get the CLI: [Install the CLI](reference/install-the-cli.md)
- <a id="nodejs-version"></a>Node.js version: [Install the CLI](reference/install-the-cli.md#nodejs-version)
- <a id="on-windows"></a>On Windows: [Install the CLI](reference/install-the-cli.md#on-windows)
- <a id="run-an-installation"></a>Run an installation: [Install Varlatch](self-hosting.md)
- <a id="try-it-on-your-own-machine"></a>Try it on your own machine: [Install Varlatch](self-hosting.md#try-it-on-your-own-machine)
- <a id="set-up-a-project"></a>Set up a project: [Connect a project](set-up-a-project.md)
- <a id="move-an-existing-env-file-in"></a>Move an existing `.env` file in: [Connect a project](set-up-a-project.md#move-an-existing-env-file-in)
- <a id="or-start-from-a-contract"></a>Or start from a contract: [Connect a project](set-up-a-project.md#or-start-from-a-contract)
- <a id="run-your-application"></a>Run your application: [Connect a project](set-up-a-project.md#run-your-application)
- <a id="invite-your-team"></a>Invite your team: [Members and access](reference/members.md#invite-your-team)
- <a id="join-a-project"></a>Join a project: [Join a team](join-a-team.md)
- <a id="your-passkeys"></a>Your passkeys: [Passkeys and sessions](reference/passkeys-and-sessions.md#your-passkeys)
- <a id="connect-ci-and-other-machines"></a>Connect CI and other machines: [CI and other machines](reference/ci-and-machines.md)
- <a id="with-coding-agents"></a>With coding agents: [Connect a project](set-up-a-project.md#with-coding-agents)
- <a id="delete-a-project-or-an-organization"></a>Delete a project or an organization: [Removing Varlatch](reference/uninstall.md#delete-a-project-or-an-organization)
- <a id="what-varlatch-puts-on-your-machine"></a>What Varlatch puts on your machine: [Removing Varlatch](reference/uninstall.md#what-varlatch-puts-on-your-machine)
- <a id="where-to-go-next"></a>Where to go next: [Reference](#reference)

</details>
