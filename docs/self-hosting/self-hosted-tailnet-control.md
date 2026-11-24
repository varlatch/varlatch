# Self-hosted tailnet control server (Headscale)

`varlatchd` can join a self-hosted tailnet control server such as Headscale instead of Tailscale's hosted control plane, using its built-in tailnet node configured in `/etc/varlatch/varlatchd.conf`.

Tested with **Headscale 0.29.7**.

These settings apply to `varlatchd`'s in-process tailnet node (`tailnet = on` in `varlatchd.conf`), from 0.50.

## Configuration in `varlatchd.conf`

Enable the tailnet listener and set `tailnet_control_url` to your control server's HTTPS IP address:

```ini
tailnet = on
tailnet_hostname = varlatch
tailnet_tags = tag:varlatch
tailnet_port = 8687
tailnet_control_url = https://192.0.2.10:8443
tailnet_auth_key_file = /etc/varlatch/tailnet-auth-key
```

- `tailnet_control_url`: leave unset (or set to `https://controlplane.tailscale.com`) to use Tailscale's control server; set to `https://<IP address>[:port]` for a self-hosted server.
- `tailnet_auth_key_file`: optional if `varlatchd` runs under systemd with a `tailnet-auth-key` credential. The shipped `varlatchd.service` loads only `root-kek` and `backup-key`, so add a drop-in with `LoadCredential=tailnet-auth-key:/etc/varlatch/tailnet-auth-key` to use it. `varlatchd` reads the key only on initial enrolment while `<data_dir>/tailnet` has no state; after enrolment, the node keeps its identity across restarts (never ephemeral, never logged out) and the key is no longer needed.
- **No `TS_*` overrides from the environment:** `varlatchd` takes its control server and enrolment strictly from `varlatchd.conf` and refuses to start the node if any of `TS_CONTROL_URL`, `TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN`, `TS_AUDIENCE`, or `TSNET_FORCE_LOGIN` is set in its environment.

## Control URL rules (`https://<IP address>[:port]` only)

For a self-hosted control server, `tailnet_control_url` accepts **only** `https://` with an IPv4 or bracketed IPv6 literal and an optional port:

- Accepted examples: `https://192.0.2.10`, `https://192.0.2.10:8443`, `https://[2001:db8::10]`, `https://[2001:db8::10]:8443`
- Canonicalization: `:443` and a trailing `/` are normalized away, IPv6 addresses are normalized in brackets, and IPv4-mapped IPv6 addresses (such as `https://[::ffff:192.0.2.10]:8443`) are unmapped to IPv4 before validation and pinning.

### Why host names are refused

Tailscale's embedded client (`tsnet`) includes a bootstrap DNS fallback that resolves a control server's host name through Tailscale's own DERP servers whenever ordinary DNS resolution fails (for example, while your control server or local resolver is unavailable). `tsnet` offers no setting to turn that fallback off.

Because an IP address is never resolved through DNS, using an IP literal ensures the node never sends your control server's address or name to Tailscale, even during outages.

### Refused URL forms

`varlatchd` rejects any of the following at startup (configuration error, exit status `78`):

- Any host name other than `https://controlplane.tailscale.com` (for example `https://headscale.example.com` or `https://headscale:8443`), as well as non-canonical IP forms such as leading-zero octets (`https://010.0.2.10`).
- Plain `http://` (for example `http://192.0.2.10`).
- Credentials in the URL (`https://user@192.0.2.10`).
- A non-root path (`https://192.0.2.10/headscale`), query string (`https://192.0.2.10?x=1`), or fragment (`https://192.0.2.10#x`).
- Unspecified addresses (`0.0.0.0`, `::`, and `::ffff:0.0.0.0`).
- Multicast addresses (`224.0.0.0/4`, IPv6 multicast, and IPv4-mapped multicast).
- Link-local unicast addresses (`169.254.0.0/16`, `fe80::/10`, and IPv4-mapped link-local).
- The broadcast address (`255.255.255.255` and `::ffff:255.255.255.255`).
- Zoned IPv6 addresses (`https://[fe80::1%25eth0]`).
- Ports outside `1` to `65535` (for example `:0` or `:99999`).

### TLS certificate requirements

Because `tailnet_control_url` connects over HTTPS to an IP address, the control server's TLS certificate must:

1. Include that IP address as an IP Subject Alternative Name (IP SAN).
2. Chain to a CA trusted by the host running `varlatchd` (the system trust store, or the PEM bundle pointed to by `SSL_CERT_FILE`).

## Node tags and tagged pre-auth keys

`varlatchd` requires at least one tag in `tailnet_tags` (for example `tag:varlatch`).

With a self-hosted control server, Headscale refuses a node that registers with a pre-auth key while also advertising tags in the registration request. When `tailnet_control_url` is set to a self-hosted server, `varlatchd` does not advertise tags itself; instead, the node receives its tags from the pre-auth key.

1. Define `tagOwners` for the tags in your Headscale policy.
2. Create a **tagged** pre-auth key carrying the tags listed in `tailnet_tags`:

   ```sh
   headscale preauthkeys create --tags tag:varlatch
   ```

3. Place that key in `tailnet_auth_key_file` (or the `tailnet-auth-key` systemd credential) before starting `varlatchd` for initial enrolment.

### Untagged pre-auth keys

If the node enrols using an untagged pre-auth key (a user key without `--tags`), Headscale registers the node with no tags:

- Tailnet access stays open; `varlatchd` does not close the tailnet listener for missing tags.
- `varlatchd` logs a warning when it observes the untagged node on the self-hosted control server.
- The listeners report (`GET /v1/installation/listeners`, under `observed.warnings`, and shown in the dashboard under **Installation settings > Tailnet**) displays a warning instructing you to re-enrol the node with a tagged pre-auth key (`headscale preauthkeys create --tags <tailnet_tags>`).

To clear the warning and ensure the node carries its tags, re-enrol the node using a tagged pre-auth key.

## No tailnet browser endpoint (`tailnet_https_port`)

The tailnet browser endpoint serves HTTPS using a Tailscale-managed node certificate, which a self-hosted control server does not issue.

`varlatchd` refuses to start if `tailnet_https_port` is set alongside a self-hosted `tailnet_control_url`. Leave `tailnet_https_port` and `tailnet_browser_origins` unset.

To read values protected by Tailnet Requirements on a self-hosted tailnet, use the `varlatch` CLI from an approved tailnet device pointed at `varlatchd`'s tailnet listener (`tailnet_port`).

## Log uploads and DERP relays

### Log uploads are always off

`varlatchd` always disables Tailscale log uploads (`TS_NO_LOGS_NO_SUPPORT=true` and `logtail` disabled in process), so the node never sends logs or telemetry to Tailscale's log service.

In Headscale's own configuration, set `logtail.enabled: false` as well.

### DERP map

Headscale's default configuration sets `derp.urls` to Tailscale's public DERP map (`https://controlplane.tailscale.com/derpmap/default`). Leaving that default causes Headscale and connected nodes to fetch Tailscale's DERP map and relay traffic through Tailscale's public DERP servers.

To keep relay traffic inside your own infrastructure, configure Headscale's DERP map to include **only** your self-hosted DERP server and clear `derp.urls`:

```yaml
server_url: https://192.0.2.10:8443
listen_addr: 0.0.0.0:8443

tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key

derp:
  server:
    enabled: true
    region_id: 999
    region_code: "self"
    region_name: "Self-hosted DERP"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 192.0.2.10
  urls: []
  paths: []
  auto_update_enabled: false

disable_check_updates: true

dns:
  magic_dns: true
  base_domain: tailnet.example

logtail:
  enabled: false
```

If you run separate self-hosted DERP servers instead of Headscale's embedded DERP server, list only your own DERP map file in `derp.paths` and keep `derp.urls: []` and `derp.auto_update_enabled: false`.

## Tailnet pinning and inspection

- **Enrolment pin:** When the node first reaches `Running`, `varlatchd` pins the canonical `controlUrl` and the MagicDNS suffix (Headscale's `dns.base_domain`) in `<data_dir>/tailnet-pin.json`. Because Headscale has no tailnet `StableID`, `tailnetId` is empty in the pin.
- **Pin changes:** Changing `tailnet_control_url` to another server closes tailnet access (`control-url-changed`) and latches it closed; a different control server cannot be re-pinned in place and requires enrolling the node again. Changing only `dns.base_domain` under the same control server (`suffix-changed`) closes access until you re-pin on the host with `varlatchd admin tailnet repin`.
- **Dashboard and API:** `GET /v1/installation/listeners` (and **Installation settings > Tailnet** in the dashboard) shows the configured `controlUrl` alongside the tailnet suffix, listener port, checks, and any untagged-node warning.

## Related pages

- [Configuration reference](configuration.md#tailscale)
- [Host requirements](requirements.md#network)
