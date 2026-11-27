# Operate and recover

Day-to-day commands, file layout, Root KEK custody, and break-glass recovery for
a self-hosted Varlatch installation. Looking to install a new server? Start at
[Install Varlatch](../self-hosting.md).

## Common host commands

Host commands run as `root` on the server: no Varlatch sign-in or passkey is
needed.

```sh
sudo systemctl status varlatchd
sudo journalctl -u varlatchd        # server logs, requests included
sudo varlatch doctor                # read-only health check
sudo varlatch admin backup run      # trigger a backup now
sudo varlatch upgrade --check       # check for a newer release
```

| Command | What it does |
| --- | --- |
| `varlatch setup` | Installs, or resumes an interrupted install |
| `varlatch doctor` | [Checks installation health](#health-check) |
| `varlatch upgrade` | [Upgrades with an automatic rollback if checks fail](../operations/upgrade.md) |
| `varlatch move` | [Moves the installation to a new public URL](../operations/move-installation.md) |
| `varlatch admin ...` | Backups, restore resume, maintenance, user re-enrollment, outbound checks, security resets |
| `varlatchd admin ...` | Same commands, plus rarer host tools: keys, break-glass recovery, tailnet |

After editing `/etc/varlatch/varlatchd.conf`, validate it before restarting:

```sh
sudo varlatchd admin config check
sudo systemctl restart varlatchd
```

If the config has an error, `varlatchd` exits with status `78` and names the
bad line in the journal. systemd will not restart it until you fix the file and
run `sudo systemctl start varlatchd`.

## Where files live

| Path | Holds | Owner & mode |
| --- | --- | --- |
| `/usr/local/bin/varlatch` | CLI and host commands | `root`, `0755` |
| `/usr/local/bin/varlatchd` | Server binary (API + dashboard) | `root`, `0755` |
| `/etc/systemd/system/varlatchd.service` | systemd unit | `root`, `0644` |
| `/etc/varlatch/varlatchd.conf` | [Configuration](configuration.md) (no secrets) | `root:varlatch`, `0640` |
| `/etc/varlatch/root-kek`, `/etc/varlatch/backup-key` | The two encryption keys | `root`, `0600` |
| `/etc/varlatch/setup.json`, `upgrade.json` | Setup answers and upgrade state | `root` |
| `/var/lib/varlatch` | Database (`varlatch.db`), `backups/`, `upgrades/`, plus `acme/`, `tailnet/`, `cli/` when enabled | `varlatch`, `0700` |
| `/usr/local/lib/varlatch/releases` | Binaries kept from upgrades | `root` |
| `/usr/local/lib/varlatch/snapshots` | Encrypted pre-upgrade snapshots ([retention](../operations/upgrade.md#what-is-kept)) | `root` |

The service runs as the unprivileged `varlatch` user. systemd passes both keys
at startup via `LoadCredential`, so `varlatchd` never opens `/etc/varlatch/root-kek`
directly and no key ever enters its environment.

## Health check

```sh
sudo varlatch doctor
```

`varlatch doctor` is read-only (changes nothing) and checks readiness, config,
file permissions, free disk space, disk write latency, clock skew, database
integrity, TLS certificate, tailnet state, backups, and key custody
attestations.

Each check reports `PASS`, `FAIL`, or `UNKNOWN` with remediation advice. It
exits `1` if any mandatory check fails; `advisory` checks never change the exit
code. Pass `--json` for scripts.

## Behind your own reverse proxy

When using the **proxy** ingress, `varlatchd` listens on `127.0.0.1:8686` over
plain HTTP and your proxy terminates HTTPS. Your proxy must:

- Forward the **entire root** of the hostname to `127.0.0.1:8686` (a path prefix
  like `/vault` does not work).
- Preserve the `Host` header and allow long-lived streaming responses (the
  dashboard's live updates use a stream).
- Set or append `X-Forwarded-For` with the client IP, and be listed in
  [`trusted_proxies`](configuration.md#trusted_proxies) (setup sets `127.0.0.1,::1`).

## The Root KEK is your responsibility

Every stored value depends on the **Root KEK**, and every backup archive depends
on the **backup key** as well. Losing both the host and either key means the
data cannot be recovered.

- Keep at least **two copies** of each key in separate locations, neither on the
  Varlatch host nor inside your backup bucket (for example, a password manager
  and a paper copy in a safe).
- Keep the Root KEK and backup key **apart from each other**.
- Record your custody attestation so `varlatch doctor` tracks it:

```sh
sudo varlatchd admin kek verify                          # verify the installed key
sudo varlatchd admin kek verify --file /path/to/a/copy   # verify a backup copy without printing it
sudo varlatchd admin custody attest --key root-kek --method copy
sudo varlatchd admin custody attest --key backup-key --method copy
sudo varlatchd admin custody status
```

`--method` is `copy`, `passphrase-escrow`, or `shamir-split`.

### A passphrase-protected copy

`kek export` wraps the Root KEK with a passphrase so the resulting file is safe
to store anywhere (even alongside backups) as long as the passphrase is kept
separately.

```sh
sudo varlatchd admin kek export --passphrase-file /root/passphrase > kek-escrow.json
sudo varlatchd admin kek restore --in kek-escrow.json --out /root/root-kek \
  --passphrase-file /root/passphrase
```

Omit `--passphrase-file` in an interactive terminal to be prompted. On a fresh
host where no database exists yet, `kek restore` writes the key with a warning: run
`kek verify` once the database is restored.

### Shares for several people

`kek split` splits the Root KEK using Shamir secret sharing so any threshold of
shares reconstructs it and fewer reveal nothing:

```sh
sudo varlatchd admin kek split --shares 3 --threshold 2
sudo varlatchd admin kek combine --out /root/root-kek
```

`combine` reads shares from stdin (paste one per line, then press `Ctrl-D`).
Never pass shares as CLI arguments, and clear your terminal afterward.

## Break-glass recovery

If everyone loses access to their passkeys, `root` on the host can issue a
one-time recovery link (every invocation is recorded in the audit log):

```sh
sudo varlatchd admin bootstrap-status                          # list installation admins
sudo varlatchd admin recover --identity <identity-id>          # one-time link for an admin
sudo varlatchd admin recover --identity <identity-id> --enable # re-enable a disabled admin
sudo varlatchd admin recover --new-admin                       # only when zero admins are enabled
sudo varlatch admin reenroll --identity <identity-id>          # one-time passkey link for any user
```

Send each link only to that person.

If nobody can approve changing a [security control](../reference/security-controls.md#the-way-back-the-host-operators-reset)
or lifting an [incident freeze](../reference/incident-freeze.md), reset or
unfreeze from the host:

```sh
sudo varlatch admin security reset --org <slug> --all
sudo varlatch admin security reset --org <slug> --control <name>
sudo varlatch admin unfreeze --org <slug> --confirm <slug>
```

> Before relying on incident freeze, keep a deploy/rollback credential for this
> installation outside Varlatch: a freeze blocks every deploy whose credentials
> Varlatch serves.

## Remove an installation

See [Removing Varlatch](../reference/uninstall.md#what-varlatch-puts-on-your-machine)
for the exact cleanup commands.
