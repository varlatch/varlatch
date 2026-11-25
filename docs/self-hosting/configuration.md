# Configuration reference

Every setting of an installation is in one file, `varlatchd.conf`. On a host
it is `/etc/varlatch/varlatchd.conf`, and `varlatch setup` writes it. In the
container image you mount it at the same path.

It holds no secrets. The two keys are files of their own:
[Keys](#keys).

## The file

One setting per line:

```ini
# A comment.
listen = 127.0.0.1:8686
public_url = https://vault.example.com
```

- Blank lines and lines that start with `#` are ignored.
- The value is the rest of the line, taken as written: no quotes, no
  escapes, no comment after it.
- An empty value means the default.
- An unknown name, a name given twice, a line without `=`, or a value
  `varlatchd` cannot use is a configuration error. `varlatchd` then exits
  with status 78 and says which line is wrong.

After a change, check the file, then restart the service:

```sh
sudo varlatchd admin config check
sudo systemctl restart varlatchd
```

systemd does not restart the service after a configuration error: fix the
file, then `sudo systemctl start varlatchd`.

## All settings

| Setting | Default | What it is |
|---|---|---|
| [`listen`](#listen) | `127.0.0.1:8686` | the plain HTTP listener |
| [`public_url`](#public_url) | none | the address people open |
| [`trusted_proxies`](#trusted_proxies) | none | proxies whose `X-Forwarded-For` counts |
| [`listen_https`](#listen_https) | off | `varlatchd`'s own public HTTPS |
| [`listen_http_redirect`](#listen_http_redirect) | port 80 | the plain listener beside it |
| [`acme_email`](#acme_email) | none | the certificate account's contact |
| [`acme_ca`](#acme_ca) | Let's Encrypt | the certificate authority |
| [`acme_ca_root`](#acme_ca_root) | the system's | roots trusted for a private one |
| [`data_dir`](#data_dir) | `/var/lib/varlatch` | the data directory |
| [`root_kek_file`](#root_kek_file) | the service's credential | the Root KEK's file |
| [`backup_key_file`](#backup_key_file) | the service's credential | the backup key's file |
| [`backup_interval`](#backup_interval) | `24h` | how often a backup is made |
| [`backup_keep`](#backup_keep) | `7` | archives kept on this host |
| [`backup_destinations_file`](#backup_destinations_file) | none | the buckets archives can go to |
| [`backup_destination`](#backup_destination) | `offsite` | the bucket in use |
| [`outbound_allow`](#outbound_allow) | none | private destinations Organizations may reach |
| [`sync`](#sync) | `on` | Sync Targets |
| [`sync_adapters`](#sync_adapters) | all | the platforms Sync Targets may use |
| [`audit_export`](#audit_export) | `on` | audit export to a bucket |
| [`serve_cli`](#serve_cli) | `off` | serving the CLI |
| [`access_log`](#access_log) | `stdout` | the access log |
| [`tailnet`](#tailnet) | `off` | the tailnet node and its listener |
| [`tailnet_hostname`](#tailnet_hostname) | none | the node's name |
| [`tailnet_tags`](#tailnet_tags) | none | the node's tags |
| [`tailnet_port`](#tailnet_port) | none | the tailnet listener's port |
| [`tailnet_control_url`](#tailnet_control_url) | Tailscale's | a self-hosted control server |
| [`tailnet_auth_key_file`](#tailnet_auth_key_file) | the service's credential | the key the node joins with |
| [`tailnet_https_port`](#tailnet_https_port) | off | the tailnet browser endpoint |
| [`tailnet_browser_origins`](#tailnet_browser_origins) | `public_url` | dashboards that may use it |

## Addresses and listeners

### `listen`

The plain HTTP listener, as `address:port`. The address is an IP address,
or empty for every address. In the container image, use `0.0.0.0:8686`.

It serves the dashboard and the API without TLS, so put a proxy in front of
it. With [`listen_https`](#listen_https) it must stay on a loopback address.

### `public_url`

The origin people open, such as `https://vault.example.com`. Passkeys are
registered for its host name, and enrollment links start with it.

It must be https. Plain http is accepted only for `localhost`, `127.0.0.1`
and `[::1]`.

Choose it once. Changing it here would leave every passkey unusable: use
[`varlatch move`](../operations/move-installation.md). When you restore a
backup on another host, keep the installation's address.

### `trusted_proxies`

The proxies whose `X-Forwarded-For` header `varlatchd` believes:
comma-separated IP addresses, CIDR ranges and host names. With the proxy
ingress, setup writes `127.0.0.1,::1`.

`varlatchd` limits some requests per client, and shows the address that
asked for a sign-in. It reads the header from the right, and takes the first
address that is not a trusted proxy, so an address a caller writes into the
header is never used. Without this setting, everyone behind your proxy
counts as one client.

Your proxy must replace the header with the client's address, or append it.
Host names are resolved again as the server runs; one that does not resolve
is not trusted. Never list a range that holds a Docker network's gateway:
callers on the host reach containers from that address.

### `listen_https`

`varlatchd`'s own public HTTPS, such as `:443`. Off when unset or `off`.
Setup writes it for the public ingress.

`varlatchd` obtains a certificate for `public_url`'s host name over ACME
and renews it. It serves nothing over HTTPS before it has one. `public_url`
must be https and name a DNS name. The certificate and its account key are in
`acme/` in the data directory, and never in a backup.

Clients connect to it directly, so no `X-Forwarded-For` is believed on it.
No `Strict-Transport-Security` header is sent.

### `listen_http_redirect`

With `listen_https`: the plain listener that answers the certificate
authority's HTTP challenges, and redirects everything else to `public_url`.
Default: port 80 on `listen_https`'s address. `off` leaves the challenge on
port 443 as the only one.

### `acme_email`

With `listen_https`: the address the certificate authority sends expiry
notices to.

### `acme_ca`

With `listen_https`: the ACME directory. The default is Let's Encrypt,
`https://acme-v02.api.letsencrypt.org/directory`. For a trial run, use its
staging directory, `https://acme-staging-v02.api.letsencrypt.org/directory`,
whose certificates no browser trusts.

### `acme_ca_root`

With `listen_https`: an absolute path to a PEM file of roots trusted for a
private authority's own API.

## Data

### `data_dir`

The data directory, an absolute path. It holds the database
(`varlatch.db`), local archives, and the certificate and tailnet state.
Default: the service's state directory, `/var/lib/varlatch`. Put it on a
local disk: every write waits for that disk
([Disk](requirements.md#disk)).

## Keys

Keys are never in this file or in an environment variable: `varlatchd`
refuses to start with one in its environment.

| Key | On a host | In the container image |
|---|---|---|
| Root KEK | `/etc/varlatch/root-kek` | `/keys/root-kek` |
| Backup key | `/etc/varlatch/backup-key` | `/keys/backup-key` |

Each file holds 32 bytes, as hex or base64. On a host they are readable by
root only, and systemd hands them to the service. Keep copies off the host:
[The Root KEK is your responsibility](../self-hosting.md#the-root-kek-is-your-responsibility).

### `root_kek_file`

The file the Root KEK is read from, an absolute path. Default: the
`root-kek` credential the service gets from systemd. Leave it unset on a
host; set it in the container image.

At startup `varlatchd` checks the key against the installation, and refuses
to start with another one.

### `backup_key_file`

The backup key's file, an absolute path. Default: the `backup-key`
credential, when the service has one. Without a backup key, no scheduled
backup is made.

## Backups

[Backup and recovery](../operations/backup.md) explains these.

### `backup_interval`

How often a backup is made, from `1h` to `744h`, or `off`.

### `backup_keep`

How many archives stay in `backups/` in the data directory, from 1 to 1000.
Older ones are removed there, never at a destination.

### `backup_destinations_file`

An absolute path to the file that lists your buckets
([S3-compatible destinations](../operations/backup.md#s3-compatible-destinations)).
Unset, archives stay on this host.

### `backup_destination`

The name, in that file, of the bucket each archive is uploaded to.

## Outbound destinations

### `outbound_allow`

The private destinations Organizations may reach: webhook receivers,
Coolify and Convex instances, and OIDC issuers on your LAN, a Docker network
or a tailnet. Comma-separated host names (`coolify.example.com`), subdomain
wildcards (`*.private.example.com`), addresses and CIDR ranges
(`10.0.0.0/8`), each with an optional port (`convex.example.com:3210`,
`10.0.0.5:*`). Without a port, an entry allows 443 for https and 80 for
http.

Unset, Organizations reach public https destinations only.
`sudo varlatch admin outbound check` lists every configured destination
with its verdict, and suggests the value.
[Outbound policy](../reference/outbound-policy.md) has every rule.

## Sync Targets

### `sync`

With `on`, authorized users may add Sync Targets, which push an
environment's values to GitHub Actions, Coolify, or Convex. With `off`,
`varlatchd` delivers nothing, and the dashboard points users at `varlatch
sync push` instead.

### `sync_adapters`

The platforms Sync Targets may use, comma-separated, out of
`github-actions`, `coolify` and `convex`. Unset allows all of them.

## Audit export

### `audit_export`

With `on`, an organization's admins may copy its audit log to a bucket they
control ([Audit export](../reference/audit-export.md)). Nothing is sent
anywhere until one does. With `off`, an export cannot be created or changed;
removing one still works.

## Serving the CLI

### `serve_cli`

`on` makes the installation serve the CLI of the release it runs, for Linux,
macOS and Windows, and the scripts that install it:
[From your installation](../reference/install-the-cli.md#from-your-installation)
shows how people use them. It needs `public_url`, without a path.

`varlatchd` downloads the release's files from github.com in the
background, and checks that Varlatch's release workflow signed them. It
keeps them in `cli/` in the data directory, and checks them again at every
start. Until that is done, or when GitHub cannot be reached, `/install.sh`,
`/install.ps1` and the files answer 404; the journal says when it serves
them.

**What it trusts.** Installing this way trusts the installation, and
whoever controls its host or its address, to run code on each installer's
machine. A compromised installation already exposes the values it holds;
with this on, it can also reach the machines of people who install from it
afterwards. That is why it is off unless you turn it on.

## Logs

### `access_log`

Where the access log goes, one JSON line per request: `stdout` (the
journal), an absolute path, or `off`. A line has the request's times,
client address, method, path, status and `X-Forwarded-For`. It never has
the query.

There are no other log settings. `varlatchd` writes to the journal:
`sudo journalctl -u varlatchd`.

## Tailscale

`varlatchd` can join your tailnet as a node of its own, in the same process:
no sidecar, no TUN device. Its tailnet listener serves the API on the node's
tailnet address, where each request carries the identity of the device it
came from. A Tailnet Requirement ("production values only from these
machines") is met only there; without the listener, such a requirement
refuses every request.

The tailnet listener does not serve the dashboard. People open the dashboard
at `public_url`, which is public HTTPS, your own proxy or this machine. For a
dashboard that only your tailnet reaches, use the proxy ingress with a proxy
that answers on a tailnet address.

To add the node to an installation:

1. Create a tagged auth key in the Tailscale admin console, and put it in a
   file the service can read:

   ```sh
   sudo install -m 640 -o root -g varlatch tailnet-auth-key /etc/varlatch/tailnet-auth-key
   ```

2. Add to `varlatchd.conf`, and restart:

   ```ini
   tailnet = on
   tailnet_hostname = varlatch
   tailnet_tags = tag:varlatch
   tailnet_port = 8687
   tailnet_auth_key_file = /etc/varlatch/tailnet-auth-key
   ```

3. Once the node has joined, delete the key file and its line: the node
   keeps its identity in `tailnet/` in the data directory.

`varlatch setup --ingress tailnet` does this on a new host: it asks for the
address people open and for the auth key's file, and copies the key to
`/etc/varlatch/tailnet-auth-key` for the service. Your own file is not
needed afterwards.

At its first join `varlatchd` pins the tailnet. If it finds itself in
another one later, the listener closes until you decide with `sudo
varlatch tailnet repin`. `sudo varlatch doctor` shows the state, and
**Installation settings**, then **Tailnet**, in the dashboard.

`varlatchd` takes the node's settings from this file only. It refuses to
start the node when `TS_AUTHKEY` or another of Tailscale's variables that
would change them is in its environment.

With a self-hosted control server:
[Self-hosted tailnet control server (Headscale)](self-hosted-tailnet-control.md).

### `tailnet`

`on` starts the node and its listener. It needs `tailnet_hostname`,
`tailnet_tags` and `tailnet_port`. With `off`, none of the other `tailnet_`
settings may be set.

### `tailnet_hostname`

The node's host name, fixed when it joins: lower-case letters, digits and
hyphens, at most 63 characters.

### `tailnet_tags`

The tags the auth key grants, comma-separated, such as `tag:varlatch`. The
node is always tagged.

### `tailnet_port`

The tailnet listener's port, on the node's addresses only. Setup writes
8687. Your tailnet policy must let the devices that use it connect to that
port.

### `tailnet_control_url`

A self-hosted control server, as `https://<IP address>[:port]`. Unset is
Tailscale's.

### `tailnet_auth_key_file`

The auth key's file, an absolute path, read only to join the first time.
Default: the `tailnet-auth-key` credential, when the service has one.

## Tailnet browser endpoint

The dashboard reaches `varlatchd` at `public_url`, where no device is known,
so it cannot read values that a Tailnet Requirement covers. It shows them as
"Values: tailnet only". With the browser endpoint, people on approved
devices can read them in the dashboard, with **Connect to tailnet**. The
device is checked on every request, as for the CLI.

The endpoint serves HTTPS on the node's tailnet name with the node's own
Tailscale certificate, so MagicDNS and HTTPS certificates must be on in the
tailnet. The name, `<tailnet_hostname>.<tailnet>.ts.net`, is published in
Certificate Transparency logs.

### `tailnet_https_port`

The endpoint's port, different from `tailnet_port`. Unset, the endpoint is
off. Your tailnet policy must let people's devices connect to it. It cannot
be used with a self-hosted control server.
`varlatch setup --tailnet-https-port 8688` sets it on a new host; on a host
set up without it, set it here and restart `varlatchd`.

### `tailnet_browser_origins`

More dashboards that may use the endpoint: exact origins, comma-separated.
`public_url`'s origin always may, when it is https or on this machine.
Wildcards are refused.

## Environment

The service needs no environment variables. systemd gives it
`CREDENTIALS_DIRECTORY` (the keys) and `STATE_DIRECTORY` (the data
directory). `SSL_CERT_FILE` changes which certificate authorities it trusts:
[A private certificate authority](../reference/outbound-policy.md#a-private-certificate-authority).

`VARLATCH_KEK_PASSPHRASE` gives `varlatchd admin kek export` and `kek
restore` their passphrase on a host, instead of `--passphrase-file`.

## From the variables of 0.23.0

`varlatch migrate` writes `varlatchd.conf` for you. For reading old notes:

| Variable | Now |
|---|---|
| <a id="varlatch_public_url"></a>`VARLATCH_PUBLIC_URL` | [`public_url`](#public_url) |
| <a id="varlatch_trusted_proxies"></a>`VARLATCH_TRUSTED_PROXIES` | [`trusted_proxies`](#trusted_proxies) |
| <a id="varlatch_outbound_allow"></a>`VARLATCH_OUTBOUND_ALLOW` | [`outbound_allow`](#outbound_allow) |
| <a id="varlatch_sync"></a>`VARLATCH_SYNC` | [`sync`](#sync) |
| <a id="varlatch_sync_adapters"></a>`VARLATCH_SYNC_ADAPTERS` | [`sync_adapters`](#sync_adapters) |
| <a id="varlatch_audit_export"></a>`VARLATCH_AUDIT_EXPORT` | [`audit_export`](#audit_export) |
| <a id="varlatch_serve_cli"></a>`VARLATCH_SERVE_CLI` | [`serve_cli`](#serve_cli) |
| <a id="varlatch_public_host"></a><a id="varlatch_http_port-and-varlatch_https_port"></a>`VARLATCH_PUBLIC_HOST`, `VARLATCH_HTTP_PORT`, `VARLATCH_HTTPS_PORT` | [`listen_https`](#listen_https), [`listen_http_redirect`](#listen_http_redirect) |
| <a id="varlatch_acme_ca"></a>`VARLATCH_ACME_CA` | [`acme_ca`](#acme_ca) |
| <a id="bind_address"></a><a id="varlatch_web_port"></a><a id="varlatchd_port-and-convex_port"></a>`BIND_ADDRESS`, `VARLATCH_WEB_PORT`, `VARLATCHD_PORT` | [`listen`](#listen) |
| <a id="ts_authkey_host_path-and-ts_authkey"></a>`TS_AUTHKEY`, `TS_AUTHKEY_HOST_PATH` | [`tailnet_auth_key_file`](#tailnet_auth_key_file) |
| <a id="varlatch_tailnet_machine"></a>`VARLATCH_TAILNET_MACHINE` | [`tailnet_hostname`](#tailnet_hostname) |
| <a id="varlatch_tailnet_name"></a>`VARLATCH_TAILNET_NAME` | none: pinned when the node joins |
| `VARLATCH_TAILNET_HTTPS_PORT`, `VARLATCH_TAILNET_BROWSER_ORIGINS` | [`tailnet_https_port`](#tailnet_https_port), [`tailnet_browser_origins`](#tailnet_browser_origins) |
| `VARLATCH_KEK_HOST_PATH` | [`root_kek_file`](#root_kek_file) |

Everything else belonged to Docker Compose, PostgreSQL or Convex, which 0.50
does not use. 0.23.0's settings are in
[its version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/self-hosting/configuration.md).

<a id="how-the-configuration-is-applied"></a>
<a id="the-managed-env"></a>
<a id="files-you-do-not-edit"></a>
<a id="varlatch-installjson"></a>
<a id="all-variables"></a>
<a id="public-address"></a>
<a id="convex_cloud_origin"></a>
<a id="convex_site_origin"></a>
<a id="ingress"></a>
<a id="compose_file"></a>
<a id="host-ports"></a>
<a id="internal-addresses"></a>
<a id="varlatch_jwks_url"></a>
<a id="varlatch_convex_url"></a>
<a id="keys-and-passwords"></a>
<a id="secret-files"></a>
<a id="secret-variables"></a>
<a id="what-each-one-is-for"></a>
<a id="convex_admin_key"></a>
<a id="client-addresses"></a>
<a id="fixed-settings"></a>
<a id="operator-cli-environment"></a>
