# Outbound policy

Some of what an Organization configures makes varlatchd send requests: audit
webhooks, Coolify and Convex Connections and their Sync Targets, GitHub
Actions Sync Targets and the GitHub App, and OIDC issuers for machine
sign-in. The outbound policy decides where those requests may go.

By default, an Organization reaches what the internet reaches, over https:

- **Public addresses** are always allowed over https, on any port.
- **Private addresses** (your LAN, Docker networks, a tailnet) are refused
  unless the host operator allows them.
- **Loopback, link-local and cloud metadata addresses** are refused unless
  the host operator allows them with an address range written for them.
- **Unspecified, multicast and reserved addresses** are always refused.
- **Plain http** is refused unless the host operator allows the destination.

Only the host operator can allow a destination, with the
`VARLATCH_OUTBOUND_ALLOW` setting. It is not stored in the database, and no
one can change it through the API or the dashboard: an Organization admin
never decides what the host's network lets through. An allowed destination
is open to every Organization on the installation.

The policy applies to varlatchd only. `varlatch sync push` and the Broker
run on a person's own machine, with that person's network access.

## What is checked

For every governed request, varlatchd:

1. reads the URL's host name after normal URL parsing (an international
   name in its `xn--` form, an IPv4 shorthand such as `127.1` as the full
   address);
2. resolves the name with the system resolver, so `/etc/hosts` and the
   container's DNS apply as for anything else on the host;
3. classifies **every** address the name resolves to. When one of them is
   refused, the request is refused, even if another one is public;
4. connects only to the addresses it checked. The check runs where the
   connection is opened, so a name whose DNS answer changes between saving
   and sending cannot move the request to an address that was not checked.

TLS is unchanged: the server must present a certificate for the name in the
URL, and the `Host` header is the URL's host. A private certificate
authority still works through `NODE_EXTRA_CA_CERTS`.

Requests never follow redirects, and never use a proxy from the environment
(`HTTP_PROXY`, `HTTPS_PROXY`, `NODE_USE_ENV_PROXY`).

## Address classes

| Class | Ranges | Opened by |
|---|---|---|
| Never | `0.0.0.0/8`, `::/128`, multicast `224.0.0.0/4` and `ff00::/8`, reserved `240.0.0.0/4` (with `255.255.255.255`), discard `100::/64` | nothing |
| Host-only | loopback `127.0.0.0/8` and `::1`; link-local `169.254.0.0/16` and `fe80::/10`; the metadata addresses `100.100.100.200`, `fd00:ec2::254` and `168.63.129.16`; site-local `fec0::/10`; protocol assignments `192.0.0.0/24` and `2001::/23`; 6to4 `2002::/16` and `192.88.99.0/24`; NAT64 local-use `64:ff9b:1::/48`; documentation `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`; benchmarking `198.18.0.0/15`; SRv6 `5f00::/16` | a CIDR entry that lies inside the range |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, carrier-grade NAT `100.64.0.0/10` (Tailscale), unique-local `fc00::/7` (Tailscale's `fd7a:115c:a1e0::/48`) | a hostname entry for the name, or a CIDR entry |
| Public | everything else | always allowed over https |

The most specific range decides: `100.100.100.200` is host-only although it
lies inside `100.64.0.0/10`.

IPv6 addresses that carry an IPv4 address are classified by that IPv4
address: IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`) and NAT64
(`64:ff9b::/96`). So `::ffff:127.0.0.1` is loopback, and `64:ff9b::a00:1`
is `10.0.0.1`, private.

## `VARLATCH_OUTBOUND_ALLOW`

A comma-separated list of entries. Spaces are ignored. Empty or unset means
no exceptions. varlatchd reads it at startup: change it in `.env`, then
recreate varlatchd (`docker compose up -d varlatchd`). An invalid entry stops
varlatchd from starting, with an error that names the entry.

| Entry | Matches |
|---|---|
| `coolify.example.com` | that name exactly |
| `*.private.example.com` | every subdomain of `private.example.com`, never `private.example.com` itself |
| `10.0.0.0/8`, `fd7a:115c:a1e0::/48` | addresses inside the range |
| `100.101.102.103` | that address only (`/32`, or `/128` for IPv6) |

### Ports

An entry may end with a port:

- `coolify.lan:8443`, `10.0.0.0/8:8000`, `[fd00::/8]:3210`;
- `:*` means any port, as in `127.0.0.1/32:*`;
- **without a port, an entry allows the scheme's default port only:** 443
  for https and 80 for http. A self-hosted Convex at port 3210 needs
  `convex.example.com:3210`.

Public https destinations are allowed on any port without an entry.

### What an entry opens

- **A hostname entry** lets that name resolve to private addresses, and
  allows plain http to it. It never opens loopback, link-local or metadata
  addresses, and it never matches a URL written with a literal address.
- **A CIDR entry** opens the private addresses inside it, and plain http to
  them.
- **Loopback, link-local and metadata addresses** open only through a CIDR
  entry that lies entirely inside one of their ranges, such as
  `127.0.0.1/32:*`. `0.0.0.0/0` does not open them, `100.64.0.0/10` does not
  open `100.100.100.200`, and `fc00::/7` does not open `fd00:ec2::254`.
- **Never-class addresses** cannot be opened.

There is no setting that turns the policy off.

A hostname entry trusts DNS: whoever controls that name's records decides
which private address it reaches. Use hostname entries for names you
control, and narrow CIDR entries otherwise.

## Check your destinations

```sh
varlatch admin outbound check            # on the host, in the Compose directory
varlatchd admin outbound check           # inside the varlatchd container
```

It lists every configured webhook, Coolify and Convex Connection and OIDC
issuer: the Organization, the kind, its id and name, host and port, the
addresses the name resolves to, and the verdict (public, allowed by an
entry, or refused with the reason). It ends with a suggested
`VARLATCH_OUTBOUND_ALLOW` value. Literal addresses and names that resolve to
loopback, link-local or metadata addresses are listed apart and never
suggested: decide those yourself.

- `--allow <value>` tests a value without a restart.
- `--org <organization>` limits the list to one Organization.
- `--json` prints the report as JSON.

It makes DNS lookups only, never an HTTP request. Exit codes: 0 when
everything is allowed, 1 when something is refused, 2 when nothing is
refused but a name did not resolve.

`varlatch doctor` shows the same count as the advisory check "Outbound
destinations", with warnings for entries that open host-only ranges or add
nothing.

In the dashboard, **Installation, Outbound** shows the same for Installation
Admins: the allow list as varlatchd read it at startup, the same warnings,
every refused destination by Organization (kind, name, host and reason), and
the suggested line. It is read-only: change the allow list on the host. It
never shows the resolved addresses. API: `GET /v1/installation/outbound`.

Each Organization's **Security page** lists the Organization's own refused
destinations for its admins (`organization.manage`): kind, name, host,
reason, and when the first refusal was recorded in the audit log in the last
30 days. `varlatch security report` shows the same list. Neither shows the
allow list or a resolved address. API:
`GET /v1/organizations/{org}/security/refused-destinations`.

## When a destination is refused

A refusal never loses anything:

- **Saving** a webhook, a Coolify or Convex Connection, or an OIDC binding
  to a refused destination fails with a message that names the address
  class, never the address, for example "This address is on a private
  network, which this installation does not let Organizations reach. The
  host operator can allow it with VARLATCH_OUTBOUND_ALLOW." A name that does
  not resolve is saved; the policy decides when it is used.
- **Connection checks and destination listings** report the destination as
  unreachable, with the same message.
- **Webhooks** keep their position. The webhook shows that this
  installation refuses its destination (`outbound_refused` in the API),
  and its events are delivered once the host operator allows the
  destination and restarts varlatchd.
- **Sync Targets** show that their destination is refused, with the reason
  (`outbound_refused: <reason>` in the API), and so does their Connection.
  A refusal does not
  count toward the failures that disable a Target, and the Target keeps
  waiting. After a restart with the destination allowed, it is retried at
  once.
- **OIDC sign-in** fails like any other rejected token.
- **GitHub** is refused only if `api.github.com` resolves to a non-public
  address on the host.

Each refusal is recorded as the audit event `outbound.refused` (decision
`deny`) with the purpose, the host, port and scheme, and the reason, never
the resolved address, a path or a query. Refusals while saving are always
recorded. Refusals while sending are recorded at most once an hour for each
Organization, purpose, object and reason, and at most 100 an hour in all;
the next recorded event says how many were left out. The server log records
the resolved addresses for the host operator, within the same bounds.

## Migration guide

Run `varlatch admin outbound check` with the new release before or right
after upgrading; `varlatch upgrade` runs it for you and shows the suggested
line. Then:

- **Coolify or Convex on a tailnet:** a hostname entry for its name, or its
  address as `/32`. Do not allow `100.64.0.0/10`: that opens the whole
  tailnet to every Organization.
- **On your LAN:** a hostname entry, or the address as `/32`.
- **A port other than 443 or 80:** name it, as in
  `convex.example.com:3210` for a self-hosted Convex on its default port.
- **On the same host as Varlatch:** its public name if it has one.
  Otherwise a hostname entry for a name that resolves to the Docker gateway.
  Never `localhost`: loopback needs a CIDR entry such as `127.0.0.1/32:*`.
- **A webhook receiver on your LAN over plain http:** a hostname entry; port
  80 is the default.
- **A public webhook receiver over plain http:** move it to https, or add a
  hostname entry for it.
- **Local development:** `127.0.0.1/32:*,::1/128:*`.
- **A private certificate authority:** unchanged, through
  `NODE_EXTRA_CA_CERTS`.

For example, an installation whose Coolify is on a tailnet and whose Convex
answers on port 3210 on the LAN:

```sh
VARLATCH_OUTBOUND_ALLOW=coolify.internal.example.com,convex.lan.example.com:3210
```

### OIDC issuers that redirect

OIDC discovery and JWKS requests no longer follow redirects, and the
`jwks_uri` an issuer publishes must use https. An issuer whose discovery
document or JWKS answers with a redirect stops working. When the URL it
redirects to is itself a valid issuer (its discovery document names that URL
as `issuer`, and its tokens carry it as `iss`), bind that URL instead.
Otherwise the issuer cannot be used.

A failing issuer is retried after a pause, not on every sign-in: 30 seconds
after the first failure, doubling up to 10 minutes. After you fix an issuer,
sign-in works again within that time.
