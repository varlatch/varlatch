# Deploying Varlatch on Coolify

Coolify is a first-class deployment target, but **not a second architecture**:
a Coolify deployment is the canonical `infra/compose` contract
deployed through Coolify's Docker Compose support. The topology, credential
separation, upgrade semantics, and break-glass procedures are identical to
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
   - Base Directory: `/` (the files the Compose file mounts, such as
     `convex-supervisor.cjs`, are found from the repo root)
   - Docker Compose Location: `/infra/compose/docker-compose.coolify.yml`
   - With the Tailscale sidecar, use
     `/infra/compose/docker-compose.coolify-tailscale.yml` instead.

   Both files are **generated**: `docker-compose.coolify.yml` from the
   canonical file, and `docker-compose.coolify-tailscale.yml` from the
   canonical file, the Tailscale overlay and `infra/coolify/compose.overlay.yml`
   (Coolify-only deltas). Both take `infra/coolify/compose.images.yml` last,
   so Coolify runs the release's published, signed images by digest (step
   4) instead of building from the checkout; `varlatch migrate` requires
   that of its source too. Change the inputs and run `pnpm compose:generate`.
   Never edit a generated file by hand: CI rejects hand edits. (The
   canonical `/infra/compose/docker-compose.yml` still works in Coolify, but
   builds from the checkout: see [Upgrades](#upgrades).)

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
   `infra/compose/.env.example` for the full annotated list).

   **The release's images.** Take the release's
   `coolify-image-digests.env` (a release file, listed in its signed
   `SHA256SUMS`: check it as
   [Verifying a release](../../docs/operations/verify-release.md) describes)
   and set each of its lines as a Coolify variable:

   ```sh
   VARLATCH_IMAGE_REGISTRY=ghcr.io/varlatch
   VARLATCH_VARLATCHD_DIGEST=sha256:<varlatchd's digest>
   VARLATCH_WEB_DIGEST=sha256:<varlatch-web's digest>
   VARLATCH_CONVEX_DEPLOY_DIGEST=sha256:<convex-deploy's digest>
   ```

   They are the same digests the release's `varlatch-release.json` pins.
   A deploy without one stops before anything starts, naming the variable.
   Keep `VARLATCH_IMAGE_REGISTRY` at the release's own repository
   (`ghcr.io/varlatch`): with a mirror, the images are not pulled from the
   repository the release was signed for, and a later `varlatch migrate`
   refuses the installation, since it starts only from the published
   `ghcr.io/varlatch/varlatchd` image.
   Set them again for every release, together with the repository ref
   ([Upgrades](#upgrades)).

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

Then set the new release's four variables from its
`coolify-image-digests.env` (Setup, step 4), update the repository ref to
the release's tag, deploy, and confirm `/readyz`. The ref and the digests
move together: the ref brings the release's Compose file, the digests its
images. A rollback sets both back. Migrations run
before `varlatchd` starts. With the combined Tailscale file, check the automatic
`convex-deploy` job's exit; with canonical Compose, run that profiled job
explicitly. Do not treat successful migration alone as a complete deployment:
on the host, `varlatch doctor --dir <the resource's directory>` must report no
mandatory failure. (`--gate`, which `varlatch upgrade` requires on plain
Compose, also needs a release manifest, which a Coolify deployment has
none of, so its release consistency stays unknown there.)

**From the canonical file** (`docker-compose.yml`, which builds from the
checkout): switch the Docker Compose Location to
`docker-compose.coolify.yml` in the same upgrade, with the four variables
set. The services and volumes stay the same; the images come from the
release, and the Coolify-only deltas of `infra/coolify/compose.overlay.yml`
apply as in the Tailscale file: `convex-deploy` runs on every deploy, the
dashboard and Convex join the default network explicitly, and varlatchd
trusts `coolify-proxy`. `varlatch migrate` refuses an installation whose
images were built locally.
