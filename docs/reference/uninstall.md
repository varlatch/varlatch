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
`varlatch audit export --deleted-org <organization-id>`. An organization
with an [audit export](audit-export.md) keeps delivering its final audit
events after the deletion: the export's key stays readable by the
installation for up to 30 days for that, and nothing else does.

## What Varlatch puts on your machine

The CLI needs no root, and installs no packages, services or scheduled
jobs. An installation is one service on its host. Here is everything, and
how to remove it.

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

- `/usr/local/bin/varlatch` and `/usr/local/bin/varlatchd`, and the unit
  `/etc/systemd/system/varlatchd.service`.
- The system user and group `varlatch`.
- `/etc/varlatch`: the configuration, the two keys, and what setup and
  upgrades recorded.
- `/var/lib/varlatch`: the database, local backups, and the certificate and
  tailnet state, when used.
- `/usr/local/lib/varlatch`, once you upgraded: the releases' binaries and
  the snapshots from before upgrades.
- Files you named in a setup command, such as copies of the keys.
- A port: `127.0.0.1:8686`, and with public HTTPS, TCP ports 80 and 443 on
  every interface.

To remove an installation, run this on its host. It erases every value the
installation stores and every key on this host: only a
[backup](../operations/backup.md), with the recovery keys you kept off this
host, brings any of it back.

```sh
sudo systemctl disable --now varlatchd
sudo rm /etc/systemd/system/varlatchd.service
sudo systemctl daemon-reload
sudo rm -r /etc/varlatch /var/lib/varlatch
sudo rm -rf /usr/local/lib/varlatch
sudo rm /usr/local/bin/varlatch /usr/local/bin/varlatchd
sudo userdel varlatch
```

Also remove any drop-in you made in
`/etc/systemd/system/varlatchd.service.d`. Outside this machine, remove what
you set up for it by hand: the DNS record, the node in your tailnet, and the
backup bucket.

With the container image, remove the container, then the data, keys and
configuration paths you mounted (`/srv/varlatch` on Coolify).

An installation of 0.23.x or earlier runs on Docker Compose:
[how to remove it](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/reference/uninstall.md#what-varlatch-puts-on-your-machine).

**Your passkey** stays where you created it, on your device, in your
password manager, or on your security key. Delete it there.
