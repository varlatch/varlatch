# Docker and Coolify

Varlatch ships as a single distroless container image
(`ghcr.io/varlatch/varlatchd`) with its embedded SQLite database and built-in
Tailscale support: no PostgreSQL, Convex, nginx, or sidecar containers.

> **Prefer a plain Linux server?** [Install Varlatch](../self-hosting.md) sets up
> `varlatchd` directly via systemd in three commands with a guided wizard. The
> container image does not have guided setup yet, so you create the key files and
> config once by hand below.

## 1. Prepare directories, keys, and config

Run these commands as `root` on the Docker / Coolify host. The container runs as
uid `65532` (`nonroot`) with a read-only root filesystem and refuses to start if
any key is placed in an environment variable.

```sh
install -d -m 700 -o 65532 -g 65532 /srv/varlatch/data /srv/varlatch/keys

for key in root-kek backup-key; do
  openssl rand -hex 32 | install -m 400 -o 65532 -g 65532 /dev/stdin /srv/varlatch/keys/$key
done

tee /srv/varlatch/varlatchd.conf >/dev/null <<'EOF'
listen = 0.0.0.0:8686
public_url = https://vault.example.com
trusted_proxies = coolify-proxy
data_dir = /var/lib/varlatch
root_kek_file = /keys/root-kek
backup_key_file = /keys/backup-key
EOF

chown root:65532 /srv/varlatch/varlatchd.conf
chmod 640 /srv/varlatch/varlatchd.conf
```

Replace `https://vault.example.com` with your real HTTPS URL. Outside Coolify,
replace `coolify-proxy` with your reverse proxy container's name or IP.

**Important:**
- **Back up both keys off this host now**, apart from each other. Without
  `root-kek`, every stored secret is unrecoverable; without `backup-key`, no
  backup can be restored.
- **Create `/srv/varlatch/varlatchd.conf` before starting the container**, or
  Docker will create an empty directory at that path and `varlatchd` will fail
  with `EISDIR`.
- **Leave `listen_https` unset** when your proxy terminates TLS. Setting
  `listen_https` together with `listen = 0.0.0.0:8686` exits with status `78`.

## 2. Start the container

### Option A: Coolify

1. In Coolify, create a **Docker Compose** resource pointing at the Varlatch
   repository:
   - **Base Directory:** `/`
   - **Docker Compose Location:** `/infra/coolify/varlatchd.compose.yml`
   - **Disable automatic deployments** (stateful installation).
2. Add the environment variable pinning the verified release digest (from the
   release's `varlatchd-image.txt`, see [Verifying a release](../operations/verify-release.md)):
   ```sh
   VARLATCH_VARLATCHD_DIGEST=sha256:<64-lowercase-hex-digest>
   ```
3. Assign your public domain (matching `public_url`) to the `varlatchd` service
   on port **`8686`**, then click **Deploy**.

> Coolify always mounts the default host paths (`/srv/varlatch/data`,
> `/srv/varlatch/keys`, `/srv/varlatch/varlatchd.conf`); custom path env vars in
> the compose file only work with plain Docker Compose.

### Option B: Plain Docker

Start `varlatchd` on your reverse proxy's Docker network and forward your HTTPS
domain to `varlatchd:8686`:

```sh
docker run -d --name varlatchd --network <proxy-network> \
  --restart unless-stopped --read-only --cap-drop ALL \
  --security-opt no-new-privileges --stop-timeout 30 \
  -v /srv/varlatch/data:/var/lib/varlatch \
  -v /srv/varlatch/keys:/keys:ro \
  -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro \
  ghcr.io/varlatch/varlatchd@sha256:<verified-release-digest>
```

## 3. Bootstrap the first administrator

Verify `/readyz` answers `200`, then generate your one-time enrollment link:

```sh
curl -fsS https://vault.example.com/readyz
docker exec <container> varlatchd admin bootstrap
```

Open the printed link within 15 minutes to register your passkey. (If it
expires, run `varlatchd admin bootstrap --revoke-unused` for a new one; if
enrollment was interrupted, check `admin bootstrap-status` and run
`admin recover --identity <id>`.)

## 4. Verify keys and run your first backup

```sh
docker exec <container> varlatchd admin kek verify
docker exec <container> varlatchd admin custody attest --key root-kek --method copy
docker exec <container> varlatchd admin custody attest --key backup-key --method copy
docker exec <container> varlatchd admin backup run
docker exec <container> varlatchd admin doctor
```

Next, configure off-host backups ([S3-compatible destinations](../operations/backup.md#s3-compatible-destinations))
by mounting your destinations and key files readable by uid `65532`.

## Upgrading by digest

In a container deployment, the pinned image digest **is** the version (`varlatch upgrade`
is for systemd hosts only):

1. Look up and verify the new release's digest ([Verifying a release](../operations/verify-release.md)).
2. Take a fresh backup (`docker exec <container> varlatchd admin backup run`).
3. Update `VARLATCH_VARLATCHD_DIGEST` in Coolify (or your `docker run` digest)
   and redeploy.
4. Confirm `GET https://vault.example.com/readyz` returns `200`.

To roll back a compatible release, restore the previous digest and redeploy.

## Restoring a backup in a container

Read [Backup and recovery](../operations/backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore)
first: a restored installation revives credentials revoked since the backup and
starts **held** until you resume it. Keep clients away until you finish cleanup.

<details>
<summary>Step-by-step container restore procedure</summary>

In Coolify, stop the resource and do not deploy it until step 4.

1. Place the `.vltbak` archive in `/srv/varlatch/data/backups/`, comment out
   any `tailnet` lines in `/srv/varlatch/varlatchd.conf`, and restore:

   ```sh
   docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
     -v /srv/varlatch/data:/var/lib/varlatch -v /srv/varlatch/keys:/keys:ro \
     -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro <image> \
     admin backup restore --in /var/lib/varlatch/backups/ARCHIVE-ID.vltbak
   ```

2. Run the restored server on an isolated Docker network bound to loopback only:

   ```sh
   docker network create varlatch-restore
   docker run -d --name varlatch-restore --network varlatch-restore -p 127.0.0.1:8686:8686 \
     --read-only --cap-drop ALL --security-opt no-new-privileges --stop-timeout 30 \
     -v /srv/varlatch/data:/var/lib/varlatch -v /srv/varlatch/keys:/keys:ro \
     -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro <image>
   ```

3. Reach it locally to revoke compromised credentials, cancel unwanted
   deletions, and rotate secrets. For browser/passkey access (which requires
   your real hostname over HTTPS), front it temporarily with Caddy on the same
   isolated network and tunnel via SSH:

   ```sh
   docker run -d --name varlatch-restore-tls --network varlatch-restore -p 127.0.0.1:8443:443 \
     caddy:2 caddy reverse-proxy --from vault.example.com --to varlatch-restore:8686 --internal-certs
   docker cp varlatch-restore-tls:/data/caddy/pki/authorities/local/root.crt ./restore-ca.crt
   ```

   On your workstation, temporarily trust `restore-ca.crt`, map
   `127.0.0.1 vault.example.com` in `/etc/hosts`, forward
   `sudo ssh -L 443:127.0.0.1:8443 you@the-host`, and open
   `https://vault.example.com`.

   For CLI access without a proxy:

   ```sh
   docker exec varlatch-restore varlatchd admin recover --identity <id> --cli-credential |
     grep -o 'vlt_[A-Za-z0-9_-]*' |
     varlatch login --server http://127.0.0.1:8686 --token-stdin
   ```

   Revoke that temporary CLI credential in the dashboard when finished.

4. Resume background jobs, tear down the temporary containers, uncomment any
   `tailnet` lines, remove the temporary CA/hosts entry on your workstation,
   and deploy normally:

   ```sh
   docker exec varlatch-restore varlatchd admin restore resume
   docker rm -f varlatch-restore-tls varlatch-restore
   docker network rm varlatch-restore
   ```

</details>

## Sharing a small host with Coolify

Coolify's scheduler runs periodic work at the start of every minute, which can
compete for CPU on a 2-core host. See
[Sharing the host with other workloads](requirements.md#sharing-the-host-with-other-workloads)
for `cpu_shares` tuning (`4096`).

> **Upgrading from a 0.23.x Coolify stack?** Follow
> [Migrating from 0.23.x to 0.50](../operations/migrate-to-0.50.md#on-coolify).
