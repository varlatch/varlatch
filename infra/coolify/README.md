# Deploying Varlatch on Coolify

Coolify is a first-class deployment target, but **not a second architecture**:
up to 0.23.0, a Coolify deployment is the canonical `infra/compose` contract
deployed through Coolify's Docker Compose support. For Varlatch 0.50 and later
(the single-container Go `varlatchd` image), see
[Single-container Go service (0.50+)](#single-container-go-service-050) below.
The topology, credential separation, upgrade semantics, and break-glass
procedures for the multi-container TypeScript Compose stack are identical to
the plain-Compose runbook in `infra/compose/README.md`. Only the UI clicks
differ.

## Topology: one public domain (or a separate Convex domain)

`varlatch-web`'s nginx already proxies `/auth`, `/v1`, `/enroll`, `/healthz`,
`/readyz`, and `/.well-known` to `varlatchd` same-origin. This is load-bearing,
not convenience: `VARLATCH_PUBLIC_URL` is the WebAuthn rpID/origin, the JWT
issuer, and the enroll-link base, so passkey sign-in only works when it equals
the origin users actually visit. Do **not** route a public domain straight at
varlatchd's port 8686.

**One domain (recommended):** `app.<your-domain>` →
`varlatch-web` (port 80), and `CONVEX_CLOUD_ORIGIN=https://app.<your-domain>/convex`.
The dashboard's nginx proxies `/convex/` to Convex, WebSocket included; the
browser needs no second origin and `convex-backend` needs no public route.
The proxy resolves Convex per request, so the dashboard keeps serving (without
live updates) while Convex is down.

**Separate Convex domain (existing installations):** additionally
`convex.<your-domain>` → `convex-backend` (port 3210) and
`CONVEX_CLOUD_ORIGIN=https://convex.<your-domain>`; the browser connects to
Convex directly. Both work; switching an existing installation is one
variable plus a redeploy, and its `convex.` route can go after.

Never public: PostgreSQL, `varlatch-migrate`, the Convex dashboard.

## Setup

1. Create a Coolify resource of type **Docker Compose** pointing at this
   repository (private repo: connect via a GitHub App or deploy key):
   - Base Directory: `/` (the `build:` contexts are the repo root)
   - Docker Compose Location: `/infra/compose/docker-compose.yml`
   - With the Tailscale sidecar, use
     `/infra/compose/docker-compose.coolify-tailscale.yml` instead. That file
     is **generated** from the canonical file, the Tailscale overlay, and
     `infra/coolify/compose.overlay.yml` (Coolify-only deltas); change those
     inputs and run `pnpm compose:generate`. Never edit it by hand: CI
     rejects hand edits.

2. Assign the domain in Coolify: `https://app.<your-domain>` →
   `varlatch-web` port 80 (plus `https://convex.<your-domain>` →
   `convex-backend` port 3210 only with a separate Convex domain). The Compose file publishes container ports on
   loopback only (`BIND_ADDRESS` defaults to `127.0.0.1`), so Coolify's proxy
   is the only public ingress. Leave `BIND_ADDRESS` unset.

3. Generate the root KEK as a persistent **host file outside the checkout**
   (Coolify redeploys from a fresh clone; `secrets/` is gitignored):

   ```sh
   install -d -m 700 /data/varlatch
   openssl rand -hex 32 > /data/varlatch/varlatch-kek
   chmod 644 /data/varlatch/varlatch-kek   # varlatchd's own user (uid 999) must read it;
                                           # the 700 directory keeps others out
   ```

   A mode-0600 file owned by the host user cannot be read inside the
   container, and varlatchd then fails to start.

   Back it up off this host now, separately from database backups.
   Storing the KEK in Coolify's env settings would persist it in Coolify's
   own database, expanding where the root secret exists. The
   env var below carries only the *path*.

4. Set the environment variables in Coolify (see
   `infra/compose/.env.example` for the full annotated list):

   > **Keep secrets out of Coolify's env settings (#28).** Coolify passes
   > *every* variable below to *every* service, regardless of the
   > per-service `environment:` blocks in the Compose file, so a password set
   > here reaches runtime `varlatchd` too. Instead, give each secret as a
   > host file, like the Root KEK: the Compose file mounts each one only
   > into the services that need it, and only its *path* is a variable.
   >
   > ```sh
   > install -d -m 700 /data/varlatch/secrets
   > for f in postgres-superuser-password varlatch-migrate-password \
   >          varlatch-runtime-password convex-db-password; do
   >   openssl rand -hex 24 > /data/varlatch/secrets/$f
   > done
   > openssl rand -hex 32 > /data/varlatch/secrets/convex-instance-secret
   > chmod 644 /data/varlatch/secrets/*   # container users must read them;
   >                                      # the 700 directory keeps others out
   > ```
   >
   > Then set `POSTGRES_SUPERUSER_PASSWORD_HOST_PATH`,
   > `VARLATCH_MIGRATE_PASSWORD_HOST_PATH`, `VARLATCH_RUNTIME_PASSWORD_HOST_PATH`,
   > `CONVEX_DB_PASSWORD_HOST_PATH`, `CONVEX_INSTANCE_SECRET_HOST_PATH` (and
   > `TS_AUTHKEY_HOST_PATH`) to those files and leave the matching password
   > variables unset. A set variable always wins over its file.
   >
   > **Existing installations** that set the passwords as variables keep
   > working unchanged. Moving them is a deliberate step: `varlatch adopt`
   > (see [Adopting an existing installation](#adopting-an-existing-installation)).

   ```sh
   # Secrets as files (see the note above): paths only, no values
   POSTGRES_SUPERUSER_PASSWORD_HOST_PATH=/data/varlatch/secrets/postgres-superuser-password
   VARLATCH_MIGRATE_PASSWORD_HOST_PATH=/data/varlatch/secrets/varlatch-migrate-password
   VARLATCH_RUNTIME_PASSWORD_HOST_PATH=/data/varlatch/secrets/varlatch-runtime-password
   CONVEX_DB_PASSWORD_HOST_PATH=/data/varlatch/secrets/convex-db-password
   CONVEX_INSTANCE_SECRET_HOST_PATH=/data/varlatch/secrets/convex-instance-secret

   VARLATCH_KEK_HOST_PATH=/data/varlatch/varlatch-kek

   VARLATCH_PUBLIC_URL=https://app.<your-domain>
   VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json
   VARLATCH_CONVEX_URL=http://convex-backend:3210

   CONVEX_CLOUD_ORIGIN=https://app.<your-domain>/convex
   CONVEX_SITE_ORIGIN=https://app.<your-domain>/convex
   # No CONVEX_ADMIN_KEY: convex-deploy derives it (step 6)
   ```

   `CONVEX_CLOUD_ORIGIN` is served to the browser by `varlatch-web` as
   runtime config, read when its container is created: apply a change with a
   redeploy (`docker compose up -d` elsewhere). Restarting the container
   keeps the old value.
   The three PostgreSQL role passwords are consumed once, on first database
   init. Changing them later requires a manual `ALTER ROLE`.

5. Deploy, then verify:

   ```sh
   curl -fsS https://app.<your-domain>/readyz   # expect "ready":true
   ```

   `/readyz` is real serviceability: DB reachable, migrations current, KEK
   loaded **and** canary-verified, so a wrong KEK fails here instead of
   silently starting.

   varlatchd's log should also show `trusted proxy coolify-proxy is <address>`.
   varlatchd needs it to tell callers apart behind Coolify's Traefik, for its
   per-client limits and the device sign-in confirmation. If the log says
   `coolify-proxy does not resolve`, set `VARLATCH_TRUSTED_PROXIES` to
   `varlatch-web,<Traefik's address on this stack's network>`. Until then,
   every public caller counts as one client (see "Client addresses behind
   proxies" in `infra/compose/README.md`).

6. Nothing to do for the Application Plane. The `convex-deploy` one-shot
   runs on **every** deploy of this Compose file (it carries no `deploy`
   profile here, unlike the plain Compose file) and reconciles the
   Application Plane with the release: it deploys the
   functions and applies Convex's trust configuration only where they
   differ, deriving the Convex admin key inside its own container from
   `CONVEX_INSTANCE_SECRET`. Check its exit in the deploy log. Nothing
   gates on it, so a failed push does not take the stack down; `varlatch
   doctor` reports whether Convex serves this release's functions.

   Existing installations that set `CONVEX_ADMIN_KEY` keep working: the job
   uses a provided key. Removing it is part of `varlatch adopt`, after the derived key has been verified in operation.

   The Convex admin key is deployment authority only and is meant to live
   only in the one-shot job. On Coolify it currently reaches
   every service, runtime `varlatchd` included (#28, see step 4).

7. Bootstrap the first Installation Admin via Coolify's terminal for
   `varlatchd`:

   ```sh
   node dist/cli.js admin bootstrap --name "Your Name"
   node dist/cli.js admin mirror-sync    # populate the Convex read models
   ```

   Bootstrap prints a one-time `https://app.<your-domain>/enroll#…` link:
   open it where you want your passkey and enroll immediately. It is
   single-use, expires after 15 minutes, and is never retrievable again.
   Cancelling the passkey prompt does not use it up; only a completed
   enrollment does. If a completed enrollment still left no working
   passkey, `admin bootstrap` names the affected admin and the
   `admin recover --identity …` command to run.

## Sharing the host

Coolify's scheduler does its periodic work at the start of every minute.
On a 2-core host it took on average 0.65 to 0.70 of a core over the first
ten seconds of each minute, and a Varlatch stack on the same host waited
for CPU in those seconds.
[Sharing the host with other workloads](../../docs/self-hosting/requirements.md#sharing-the-host-with-other-workloads)
has the measurements and the CPU weight to set.

**An application Coolify builds itself** (from a Dockerfile, an image or
Nixpacks, one container): Coolify sets the container's CPU weight from the
application's CPU shares setting (Resource Limits in the dashboard,
`limits_cpu_shares` in the API), 1024 by default.
- To give such a container priority, set its CPU shares to **4096**.
- A `--cpu-shares` in the application's custom Docker run options does not
  take effect: Coolify's own setting overrides it.
- On runtimes with the older linear conversion (the table on the
  requirements page), Coolify's default of 1024 gives weight **39**, below
  the 100 that a container that sets nothing gets. Every such application
  runs at that weight unless its setting is changed.
- Check the weight you get from the host, as the requirements page shows.

**A Compose resource**, the way this guide deploys Varlatch: Coolify does
not apply its resource limits, CPU shares included, to an application
deployed from a Compose file. It deploys the file it points at (its Docker
Compose Location), and the repository's file sets no CPU weight. On a small
host shared with Coolify, there are three choices:
- point the resource at a Compose file of your own that adds `cpu_shares`
  as the requirements page shows, and keep that file current with each
  release;
- install with `varlatch setup` and set the weight in
  `docker-compose.override.yml`;
- give the host enough cores that Coolify's minute work does not take
  Varlatch's.

The requirements page gives one measurement of the weight's effect on
latency, at weights 39 and 157.

## Adopting an existing installation

An installation deployed before 0.10.0, with passwords and
`CONVEX_INSTANCE_SECRET` in Coolify's env settings and often a
`CONVEX_ADMIN_KEY` and the old `http://tailscale:8686` JWKS URL, keeps
working as it is; `varlatch doctor` lists it as not adopted (advisory). To
move it, first deploy this release and take a verified backup, then run
`varlatch adopt` on the host, as a user with Docker access, against the
directory Coolify deploys the resource from (its `docker-compose.yaml` and
`.env`):

```sh
varlatch adopt --dir /data/coolify/applications/<uuid>           # the plan; changes nothing
varlatch adopt --dir /data/coolify/applications/<uuid> --apply   # the next step
```

`adopt` cannot edit Coolify's settings. Each `--apply` does what it can on
the host: it writes the secret files with their current values (to
`/data/varlatch/secrets`, or `--secrets-dir`), proves the derived admin key
works, walks you through Root KEK escrow, and then prints the change to
make in the resource's environment variables: `add X_HOST_PATH=…`,
`delete X`, `set VARLATCH_JWKS_URL=…`. Make it, redeploy, and rerun. It
verifies the deployed result before the next step, never removes a working
setting before its replacement has worked, and prints names and paths,
never a secret value. It is done when it reports "Adopted": runtime
`varlatchd` then receives no other service's secret (#28), the deploy job
derives its admin key, and Convex trusts `varlatchd` at its fixed name.
Archives made before adoption still restore (the permanent `tailscale`
alias).

## Trust honesty

Anyone with Coolify access sufficient to open a terminal into these
containers, read volumes, or edit environment variables is an
**Infrastructure Operator** for this Varlatch installation.
That is authority they already possess through the host; Varlatch makes its
exercise explicit and audited rather than pretending to prevent it.

## Upgrades

The dashboard's Installation settings → Release shows a newer release once
`varlatch upgrade --check --dir <the resource's directory>` has run on the
host, for example after the scheduled backup. Here it only looks:
`varlatch upgrade` itself does not apply to a Coolify deployment, which
upgrades as follows.

Disable automatic deployments for this stateful installation. Follow the
[installation backup runbook](../../docs/operations/backup.md): create an
encrypted full-installation archive and verify it with the BEK and candidate
Root KEK against the target release before manually deploying. The published
v0.7.0 release needs the documented offline bridge using the 0.8.0 or newer CLI.

Use the actual deployed Compose project/configuration, preserving its volume
names and networking. Both Compose variants now include `varlatch-state` and
the Convex supervisor; keep those mounts through every restart and restore.
The former plaintext pre-deploy dump job is removed. Its existing volume is
retained until an encrypted replacement and restore rehearsal are checked.

Then update the repository ref, deploy, and confirm `/readyz`. Migrations run
before `varlatchd` starts. With the combined Tailscale file, check the automatic
`convex-deploy` job's exit; with canonical Compose, run that profiled job
explicitly. Do not treat successful migration alone as a complete deployment:
on the host, `varlatch doctor --dir <the resource's directory>` must report no
mandatory failure. (`--gate`, which `varlatch upgrade` requires on plain
Compose, also needs a release manifest; a source-built Coolify deployment has
none, so its release consistency stays unknown there.)


## Single-container Go service (0.50+)

From 0.50.0, Varlatch runs as a single distroless container
(`ghcr.io/varlatch/varlatchd`, see `go/image/README.md`) with its own embedded
SQLite database and in-process Tailscale (`tsnet`) support. No PostgreSQL,
Convex, nginx, or Tailscale sidecar containers are needed.

Coolify deploys this service from `infra/coolify/varlatchd.compose.yml`, which
pins the published image by digest using Coolify environment variables.

### Creating the Coolify application

1. Prepare the host bind paths owned by the image user (`65532:65532`,
   distroless `nonroot`) and not writable by others:

   ```sh
   install -d -m 700 -o 65532 -g 65532 /srv/varlatch/data
   install -d -m 700 -o 65532 -g 65532 /srv/varlatch/keys
   ```

   Write `/srv/varlatch/varlatchd.conf` (mode `0644` or `0640` readable by
   `65532:65532`) with at least:

   ```ini
   listen = 0.0.0.0:8686
   public_url = https://app.<your-domain>
   trusted_proxies = coolify-proxy
   data_dir = /var/lib/varlatch
   root_kek_file = /keys/root-kek
   backup_key_file = /keys/backup-key
   ```

   When migrating from 0.23.0 with `varlatch migrate --ingress coolify`, leave
   `/srv/varlatch/data` empty and let `varlatch migrate` populate the bind
   paths as `65532:65532`. For a fresh install, follow
   [A fresh install by hand](#a-fresh-install-by-hand) instead of this step.

   **Keys never go in Coolify environment variables.** `varlatchd` refuses to
   start (exit `78`) if any key value or key variable name is present in its
   environment.

2. Create a Coolify resource of type **Docker Compose** pointing at this
   repository:
   - Base Directory: `/`
   - Docker Compose Location: `/infra/coolify/varlatchd.compose.yml`
   - Disable automatic deployments.

   If you are preparing the target for `varlatch migrate --ingress coolify`,
   **leave the application in setup mode (do not click Deploy yet and do not
   assign the production domain yet)**: nothing should listen on the target
   until `varlatch migrate` stops (exit `75`) and asks you to move the domain
   over (first) and **Deploy** it (then).

   Ensure `/srv/varlatch/varlatchd.conf` already
   exists on the host as a regular file before clicking **Deploy**: if a
   bind-mounted file path is missing, Docker creates an empty directory there
   instead, and `varlatchd` fails with `EISDIR` when reading its configuration.

3. Set the Coolify environment variables:

   ```sh
   VARLATCH_VARLATCHD_DIGEST=sha256:<64-lowercase-hex-digest>
   ```

   - `VARLATCH_VARLATCHD_DIGEST` (required): the release's verified
     `ghcr.io/varlatch/varlatchd` image digest (`sha256:` followed by 64
     lowercase hex characters). A deploy without it stops before anything
     starts, naming `VARLATCH_VARLATCHD_DIGEST`.
   - `VARLATCH_IMAGE_REGISTRY` (optional, default `ghcr.io/varlatch`): override
     only when pulling from another registry (for example, a lab rehearsal
     registry).

   **The host paths are `/srv/varlatch/data`, `/srv/varlatch/keys` and
   `/srv/varlatch/varlatchd.conf`, and cannot be changed in Coolify.** The
   file's variables for them, `VARLATCH_DATA_DIR`, `VARLATCH_KEYS_DIR` and
   `VARLATCH_CONFIG_FILE`, have no effect there: Coolify (4.7.6, tested)
   replaces a mount's `${NAME:-default}` by the default when it reads the
   file, whatever the variable is set to, and the container then starts on
   empty directories at the default paths. They work with plain Docker
   Compose only. Give `varlatch migrate` the same paths (`--to-data`,
   `--to-keys`, `--to-config`).

4. Routing and readiness:
   - Assign the public domain in Coolify to the `varlatchd` service on port
     `8686`. The Compose file publishes no host ports; Coolify's Traefik proxy
     terminates TLS and reaches `varlatchd:8686` over the Docker network.
     Leave `listen_https` (public HTTPS + ACME) unset in `varlatchd.conf`:
     setting `listen_https` together with `listen = 0.0.0.0:8686` makes
     `varlatchd` refuse to start (exit `78`) and crash-loop.
   - `varlatchd.compose.yml` omits a Docker `healthcheck` because the image is
     distroless (`gcr.io/distroless/static-debian12`) and contains no shell,
     `curl`, or HTTP probe subcommand. Verify readiness externally at
     `GET https://app.<your-domain>/readyz` (expect HTTP `200`).
   - Tailnet listeners (`tailnet = on`, `tailnet_port`, `tailnet_https_port` in
     `varlatchd.conf`) run in-process via `tsnet` and store node state under
     `/var/lib/varlatch/tailnet`. No Tailscale sidecar container,
     `/dev/net/tun` device, or elevated Linux capabilities are required.

### A fresh install by hand

There is no guided setup for the container yet: a later release adds one.
Until then, these are the steps of `varlatch setup`, one by one. Run them as
root on the host.

1. Make the directories, the two keys and the configuration. Put your own
   address in `public_url`. Outside Coolify, put your proxy container's name
   in `trusted_proxies`.

   ```sh
   install -d -m 700 -o 65532 -g 65532 /srv/varlatch/data /srv/varlatch/keys
   for key in root-kek backup-key; do
     openssl rand -hex 32 | install -m 400 -o 65532 -g 65532 /dev/stdin /srv/varlatch/keys/$key
   done
   tee /srv/varlatch/varlatchd.conf >/dev/null <<'EOF'
   listen = 0.0.0.0:8686
   public_url = https://app.example.com
   trusted_proxies = coolify-proxy
   data_dir = /var/lib/varlatch
   root_kek_file = /keys/root-kek
   backup_key_file = /keys/backup-key
   EOF
   ```

   Do this once. Never make the keys again for an installation that has
   data: it would not start, and nothing could read its values.

2. **Copy both keys off the host**, apart from each other, before you store
   anything in the installation. Without the Root KEK, every value is lost;
   without the backup key, every backup.

3. Deploy it: in Coolify, steps 2 to 4
   [above](#creating-the-coolify-application), then **Deploy**. With plain
   Docker, on the network of your own proxy's container:

   ```sh
   docker run -d --name varlatchd --network <the proxy's network> \
     --restart unless-stopped --read-only --cap-drop ALL \
     --security-opt no-new-privileges --stop-timeout 30 \
     -v /srv/varlatch/data:/var/lib/varlatch -v /srv/varlatch/keys:/keys:ro \
     -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro \
     ghcr.io/varlatch/varlatchd@sha256:<the release's digest>
   ```

   The proxy serves HTTPS and forwards to `varlatchd:8686`.
   [Verifying a release](../../docs/operations/verify-release.md#the-go-lines-image-0500-and-later)
   gives the digest.

4. Create the first administrator. This prints a one-time link, valid for 15
   minutes. Open it and create the passkey:

   ```sh
   docker exec <container> varlatchd admin bootstrap --name "Your Name"
   ```

   Too late? `varlatchd admin bootstrap --revoke-unused` prints a new one.

5. Check the key, and record that both copies exist off the host:

   ```sh
   docker exec <container> varlatchd admin kek verify
   docker exec <container> varlatchd admin custody attest --key root-kek --method copy
   docker exec <container> varlatchd admin custody attest --key backup-key --method copy
   ```

6. Make the first backup, and check the installation:

   ```sh
   docker exec <container> varlatchd admin backup run
   docker exec <container> varlatchd admin doctor
   ```

Give it a bucket next: [S3-compatible
destinations](../../docs/operations/backup.md#s3-compatible-destinations).
Mount both files, readable by `65532`, at the paths they name.

To restore an archive, stop the container, run the image once with the same
mounts, and start the container again:

```sh
docker run --rm -v /srv/varlatch/data:/var/lib/varlatch -v /srv/varlatch/keys:/keys:ro \
  -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro <the image> \
  admin backup restore --in /var/lib/varlatch/backups/ARCHIVE-ID.vltbak
```

### Pinning and upgrading by digest

Because the Compose file resolves the image through `VARLATCH_VARLATCHD_DIGEST`,
upgrading to a new 0.50.x release changes that variable and redeploys the
Coolify application without editing the Compose file.

- **Manual upgrade:** update `VARLATCH_VARLATCHD_DIGEST` in Coolify to the
  verified target release digest, deploy, and confirm `/readyz` answers `200`.
  To roll back, restore the previous `VARLATCH_VARLATCHD_DIGEST` and redeploy.
- **Guarded digest helper (`guarded.mjs` digest mode):** for automated
  deployments where the Coolify API token is held in one helper process across
  deploy, `/readyz` verification, and rollback, `guarded.mjs`'s digest mode
  drives this application by its Coolify UUID: it records the current
  `VARLATCH_VARLATCHD_DIGEST` via Coolify's `/applications/{uuid}/envs` API,
  patches `VARLATCH_VARLATCHD_DIGEST` to the new verified digest (from `--set`
  or a digest env file), verifies read-back, triggers a Coolify deploy, waits
  for `/readyz` to return `200`, and re-pins the previous digest and redeploys
  in the same process on any failure.
