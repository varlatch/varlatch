# Install and operate

This page is for the person who runs an installation. To install one,
start with [Run an installation](run-an-installation.md).

It describes Varlatch 0.50 and later, where an installation is one program,
`varlatchd`. 0.23.0 and earlier run on Docker Compose: see
[Docker Compose (0.23.0 and earlier)](../infra/compose/README.md), and
[Migrating to 0.50](operations/migrate-to-0.50.md).

## What is where

| Path | Holds | Owner and mode |
|---|---|---|
| `/usr/local/bin/varlatch` | the CLI, which also runs the host commands | root, 0755 |
| `/usr/local/bin/varlatchd` | the server | root, 0755 |
| `/etc/systemd/system/varlatchd.service` | the unit | root, 0644 |
| `/etc/varlatch/varlatchd.conf` | the [configuration](self-hosting/configuration.md); no secrets | `root:varlatch`, 0640 |
| `/etc/varlatch/root-kek`, `/etc/varlatch/backup-key` | the two keys | root, 0600 |
| `/etc/varlatch/setup.json`, `upgrade.json` | what setup was told, and the last upgrade | root |
| `/var/lib/varlatch` | the data: the database `varlatch.db`, `backups/`, `upgrades/`, and, when used, `acme/`, `tailnet/` and `cli/` | `varlatch`, 0700 |
| `/usr/local/lib/varlatch/releases` | the binaries of the releases you upgraded from and to | root |

The service runs as the `varlatch` user. systemd hands it the two keys when
it starts (`LoadCredential` in the unit), so `varlatchd` never needs to read
`/etc/varlatch/root-kek` itself, and no key is in its environment.

## Host commands

Host commands need root on the host, and nothing else: no sign-in and no
passkey.

```sh
sudo systemctl status varlatchd
sudo journalctl -u varlatchd        # its log, requests included
sudo varlatch doctor                # a read-only health check
sudo varlatch admin backup run      # a backup now
sudo varlatch upgrade --check       # is there a newer release?
```

| Command | What it does |
|---|---|
| `varlatch setup` | installs, or continues an install that stopped |
| `varlatch doctor` | [checks the installation's health](#health-check) |
| `varlatch upgrade` | [upgrades, and goes back when the new release fails its checks](operations/upgrade.md) |
| `varlatch move` | [moves the installation to another address](operations/move-installation.md) |
| `varlatch admin ...` | backups, maintenance, re-enrollment, the outbound check, and the ways back below |
| `varlatchd admin ...` | the same commands, and the rarer ones: keys, recovery, the tailnet |

After you change `varlatchd.conf`, check it, then restart the service:

```sh
sudo varlatchd admin config check
sudo systemctl restart varlatchd
```

A configuration error stops `varlatchd` with status 78. systemd does not
restart it until you fix the file and start it again; the journal says
which line is wrong.

## Health check

```sh
sudo varlatch doctor
```

It checks readiness, the configuration, file modes, free space, the disk's
write latency, the clock, the database, the certificate, the tailnet,
backups and the keys' attestations. Each is `PASS`, `FAIL` or `UNKNOWN`,
with what to do about it. It changes nothing. It exits 1 when a mandatory
check fails; a check marked `advisory` never changes the exit code.
`--json` prints the report as JSON.

## Behind your own proxy

With the proxy ingress, `varlatchd` listens on `127.0.0.1:8686` in plain
HTTP, and your proxy serves HTTPS. The proxy must:

- forward everything to that address, at the root of the host name. A path
  prefix does not work;
- keep the `Host` header, and allow long-lived responses: the dashboard's
  live updates are a stream;
- replace `X-Forwarded-For` with the client's address, or append it, and be
  listed in [`trusted_proxies`](self-hosting/configuration.md#trusted_proxies).
  Setup lists this machine (`127.0.0.1,::1`).

## The Root KEK is your responsibility

Every stored value depends on the Root KEK, and every backup archive on the
backup key as well. Whoever loses both the host and a key loses the data.

- Keep at least two copies of each, in two places, neither of them this
  host or the bucket that holds the backups. A password manager and a copy
  on paper are good choices.
- Keep the Root KEK and the backup key apart from each other.
- Say so: `varlatchd admin custody attest` records, with a date, that the
  copies exist. `varlatch doctor` shows the attestations. Nobody can check
  copies held elsewhere but you.

```sh
sudo varlatchd admin kek verify                          # the installed key
sudo varlatchd admin kek verify --file /path/to/a/copy   # a copy, without showing it
sudo varlatchd admin custody attest --key root-kek --method copy
sudo varlatchd admin custody attest --key backup-key --method copy
sudo varlatchd admin custody status
```

`--method` is `copy`, `passphrase-escrow` or `shamir-split`.

### A passphrase-protected copy

`kek export` wraps the Root KEK with a passphrase. The file it writes is
safe to store anywhere, backups included; only the passphrase must be kept
apart. `kek restore` checks the key against the installation's database
before it writes it. On a fresh host, with no database yet, it writes the key
with a warning: run `kek verify` once the installation is restored.

```sh
sudo varlatchd admin kek export --passphrase-file /root/passphrase > kek-escrow.json
sudo varlatchd admin kek restore --in kek-escrow.json --out /root/root-kek \
  --passphrase-file /root/passphrase
```

In a terminal, leave `--passphrase-file` out and type the passphrase.

### Shares for several people

`kek split` makes shares, of which any few you choose give the key back and
fewer reveal nothing. Give each to another person, and never store two
together.

```sh
sudo varlatchd admin kek split --shares 3 --threshold 2
sudo varlatchd admin kek combine --out /root/root-kek
```

`combine` reads the shares from standard input: paste one per line, then
press Ctrl-D. Never give shares as arguments: they would be in the shell's
history, and visible to other users while the command runs. Clear the
terminal afterwards.

## Break-glass recovery

When nobody can sign in any more, the host can let a person back in:

```sh
sudo varlatchd admin bootstrap-status                         # the administrators
sudo varlatchd admin recover --identity <identity id>         # a one-time link for one
sudo varlatchd admin recover --identity <identity id> --enable  # one that was disabled
sudo varlatchd admin recover --new-admin                      # only when none is enabled
sudo varlatch admin reenroll --identity <identity id>         # any person: a link for a new passkey
```

Each prints a one-time link. Send it only to its person. Whoever has root
on the host already has this authority; these commands make it explicit and
record it in the audit log.

When nobody can give the approval that an organization's
[security controls](reference/security-controls.md#the-way-back-the-host-operators-reset)
ask for, set them back to off. When an organization is
[frozen](reference/incident-freeze.md) and nobody can lift the freeze, lift
it from the host:

```sh
sudo varlatch admin security reset --org <slug> --all
sudo varlatch admin security reset --org <slug> --control <name>
sudo varlatch admin unfreeze --org <slug> --confirm <slug>
```

Before anyone relies on the freeze, keep a deploy and rollback credential
for this installation outside Varlatch: a freeze stops every deploy whose
credentials Varlatch serves.

## Remove an installation

[What Varlatch puts on your machine](reference/uninstall.md#what-varlatch-puts-on-your-machine)
has the commands.

## Moved sections

This page described the Docker Compose deployment. Those sections are
[here](../infra/compose/README.md) now; these links still lead to the right
place.

- <a id="first-install"></a>First install: [Run an installation](run-an-installation.md)
- <a id="with-varlatch-setup-recommended"></a>With `varlatch setup`: [Run an installation](run-an-installation.md#install)
- <a id="existing-installations-varlatch-adopt"></a>`varlatch adopt`: [Docker Compose](../infra/compose/README.md#existing-installations-varlatch-adopt)
- <a id="by-hand"></a>By hand: [Docker Compose](../infra/compose/README.md#by-hand)
- <a id="where-to-keep-the-backup"></a>Where to keep the backup: [The Root KEK is your responsibility](#the-root-kek-is-your-responsibility)
- <a id="passphrase-wrapped-escrow-recommended"></a>Passphrase-wrapped escrow: [A passphrase-protected copy](#a-passphrase-protected-copy)
- <a id="shamir-secret-sharing-multi-custodian"></a>Shamir secret sharing: [Shares for several people](#shares-for-several-people)
- <a id="backup"></a>Backup: [Backup and recovery](operations/backup.md)
- <a id="upgrade-backup-gated-forward-only"></a>Upgrade: [Upgrading](operations/upgrade.md)
- <a id="outbound-destinations-after-upgrading-to-0220"></a>Outbound destinations after upgrading to 0.22.0: [Docker Compose](../infra/compose/README.md#outbound-destinations-after-upgrading-to-0220)
- <a id="newer-releases-in-the-dashboard"></a>Newer releases in the dashboard: [Upgrading](operations/upgrade.md#newer-releases-in-the-dashboard)
- <a id="health-check-read-only"></a>Health check: [Health check](#health-check)
- <a id="optional-tailscale-integration"></a>Tailscale: [Configuration](self-hosting/configuration.md#tailscale)
- <a id="september-2026-upgrade-compatibility"></a>September 2026 upgrade compatibility: [Docker Compose](../infra/compose/README.md#september-2026-upgrade-compatibility)
- <a id="client-addresses-behind-proxies"></a>Client addresses behind proxies: [`trusted_proxies`](self-hosting/configuration.md#trusted_proxies)
