# Removing Varlatch

Deleting a project or an organization erases its values on the
installation. Removing the CLI, the files in a repository, or a whole
installation is covered after that.

## Delete a project or an organization

Deleting a project erases every value of its environments at once, with no
undo. Deleting an organization is a request: it freezes the organization
at once, and runs after a waiting period (7 days unless you choose 1 to 30)
and, when the organization has more than one admin, another admin's
approval. Any admin can cancel it until then. Both are in the dashboard (a
project's menu; Settings, then Delete organization), or:

```sh
varlatch project delete api --confirm api
varlatch org delete acme --confirm acme --after 14
varlatch org deletion acme                     # the open request, with its ID
varlatch org delete acme --approve <request-id>   # another admin
varlatch org delete acme --cancel <request-id>
```

Deletion erases data from the live database only. Backups taken before it
keep the data until their retention removes them, values pushed to
platforms stay there, and copies people revealed or downloaded stay where
they are: rotate those at their provider. A GitHub App stays installed on
GitHub until you uninstall or delete it there. After an organization is
deleted, the people who could read its audit log export it with
`varlatch audit export --deleted-org <organization-id>`.

## What Varlatch puts on your machine

Varlatch installs no system packages, services, or scheduled jobs, and
needs no root. You install Node.js for the CLI and Docker for an
installation yourself. Here is everything else, and how to remove it.

**The CLI,** on every machine that uses it:

- The CLI itself: `~/.local/bin/varlatch`, or wherever you put it
  ([Install the CLI](install-the-cli.md)). On Windows,
  `%LOCALAPPDATA%\Programs\Varlatch`, which is also on your user `PATH`.
- Your sign-in: `credentials.json`, `settings.json` (your default
  server), and `pending-sign-ins.json` while a sign-in with a code waits,
  in `~/.config/varlatch` (or
  `$XDG_CONFIG_HOME/varlatch`, or `VARLATCH_CONFIG_DIR`). On Windows, the
  same files are in `.config\varlatch` in your user profile.

To remove it, first sign out of every server. `varlatch logout --all`
asks each server to revoke your credential, then deletes it locally,
and prints for each server whether the revocation worked. When it reports
that a revocation failed, the credential may stay usable until it
expires: revoke it in the dashboard, under your account, then Sessions,
or let it expire. Then delete the CLI and the directory:

```sh
varlatch logout --all
rm ~/.local/bin/varlatch
rm -r ~/.config/varlatch
```

**In a repository,** only what you ask for:

- `varlatch init` writes `varlatch.toml`, which you delete by hand, and
  the files coding agents read: `AGENTS.md`, the skill in
  `.agents/skills/varlatch/` and `.claude/skills/varlatch/`, and the
  settings a few agents need besides
  ([Coding agents](coding-agents.md)). `--no-agent-files` skips
  those.
- `varlatch agents install --guardrails` adds hooks and settings for your
  agents in the repository.
- `varlatch agents install --remove` takes back the skill, the
  instructions and the guardrails, and leaves what you wrote in the same
  files. It lists anything it left in place, such as a setting an agent
  shares with other tools: remove those by hand if you no longer want
  them.
- `varlatch agents install --scope user` installs the skill in your home
  directory instead, in `~/.agents/skills/varlatch/` and
  `~/.claude/skills/varlatch/`. `varlatch agents install --remove --scope
  user` removes it.
- `varlatch env use <name>` keeps your choice of environment in `.varlatch/`,
  which ignores itself in Git. Delete the directory to remove it.
- `varlatch scan --install-hook` writes a pre-commit hook in `.git/hooks`,
  which `git status` does not show. Delete it with
  `rm "$(git rev-parse --git-path hooks/pre-commit)"`, after checking that
  it is the hook Varlatch wrote: Varlatch never replaces a hook it did not
  write.
- Files you name in a command, such as generated types or a scan
  baseline, are yours to keep or delete.

**An installation,** on its host:

- The directory you unpacked the bundle in. Setup writes only there: the
  keys and passwords in `secrets/`, the recovery key copy in `recovery/` if
  you chose a passphrase-protected file, `backups/`, `.env`, and
  `varlatch-install.json`.
- A Docker Compose project named `varlatch`: its containers, a network,
  the volumes that hold the data (`postgres-data`, `convex-data`,
  `varlatch-state`, Caddy's state with the public address, and
  Tailscale's state when the installation uses Tailscale), and the images
  it pulled.
- Ports on `127.0.0.1` only: the address you chose, 8787 by default, and
  two ports Docker picks at random for varlatchd and the Convex backend. With the public address, Caddy also listens on TCP ports 80 and
  443 and UDP port 443, on every interface.

To remove an installation, run this in its directory, then delete the
directory. It erases every value the installation stores and every key on
this host: only a [backup](../operations/backup.md), with the recovery keys
you kept off this host, brings any of it back.

```sh
docker compose down --volumes --rmi all
cd .. && rm -r varlatch-$V
```

`.env` tells Docker Compose which files the installation uses, so this
removes the containers and volumes of every address type. `--rmi all`
also removes the images, including shared ones such as `postgres`: leave
it out to keep them. Outside this machine, remove what you set up for it
by hand: the DNS record of a public address, and, when the installation
used Tailscale, its machine in the Tailscale admin console.

**Your passkey** stays where you created it, on your device, in your
password manager, or on your security key. Delete it there.
