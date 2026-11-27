# The single-container image

`ghcr.io/varlatch/varlatchd` from 0.50.0: the Go `varlatchd` and the
`varlatch` CLI in one image (ADR-0059 Decision 8), for linux/amd64 and
linux/arm64. The Dockerfile here builds it; `build.sh` builds it locally
from a directory of release assets; `check-image.mjs` checks it.

## Running it

| Path | What it holds |
| --- | --- |
| `/var/lib/varlatch` | the data directory: a volume, the image user's |
| `/etc/varlatch/varlatchd.conf` | the configuration, mounted read-only |
| `/keys` | the Root KEK and the Backup Encryption Key, mounted as files |
| `/opt/varlatch/varlatchd`, `/opt/varlatch/varlatch` | the server (the entrypoint) and the CLI |

The image runs as uid and gid 65532 and listens where the configuration
says (8686 by convention). A configuration for it:

```
listen = 0.0.0.0:8686
public_url = https://vault.example.com
data_dir = /var/lib/varlatch
root_kek_file = /keys/root-kek
backup_key_file = /keys/backup-key
```

Mount each key file readable by uid 65532, as a Docker or Coolify secret
or a read-only volume. The default command is `serve --config
/etc/varlatch/varlatchd.conf`; an admin command runs in the container:
`docker exec <container> varlatchd admin status --config
/etc/varlatch/varlatchd.conf`.

## Keys never go in the environment

Keys reach varlatchd only as files. `varlatchd serve` refuses to start,
with exit 78, when its environment:

- holds the Root KEK or the Backup Encryption Key, as hex (either case) or
  base64 (with or without padding, standard or URL-safe), anywhere in a
  variable's value; or
- has a key or passphrase variable name, whatever its value and in any
  case: `VARLATCH_KEK`, `VARLATCH_KEK_PASSPHRASE`, `VARLATCH_ROOT_KEK`,
  `VARLATCH_BEK`, `VARLATCH_BEK_PASSPHRASE`, `VARLATCH_BACKUP_KEY`. (The
  TypeScript line used the first two.)

In the image, `varlatchd admin` and the CLI refuse to run the same way,
against the keys the configuration names that they can read. The refusal
names the variable and never shows its value. If `backup_key_file` cannot
be read when the check runs, only the Root KEK's value and the names are
checked. Coolify passes every environment variable to every service of a
stack, so a key set there as a variable would be in every container: give
it as a file instead.

## Upgrades by digest

An installation of the image is upgraded by deploying a newer release's
digest ([Upgrading by digest](../../docs/self-hosting/docker-and-coolify.md#upgrading-by-digest)).
The image sets `VARLATCH_IMAGE=varlatchd`, and in it `varlatchd serve`
upgrades an older database's schema when it starts, before it serves, when
the upgrade is rollback-safe: the release that wrote the database still
opens it, so the previous digest is the way back. One that is not
rollback-safe is refused and changes nothing; it runs as `varlatchd admin
schema upgrade` in a one-off container, after a backup. Outside the image
(`VARLATCH_IMAGE` unset), serve refuses an older schema, and `varlatch
upgrade` upgrades a systemd installation with its snapshot. In the image,
`VARLATCH_IMAGE` also makes `varlatchd admin` and the CLI refuse a key in
their environment (above); do not unset it.

The container runs with a read-only root filesystem (`docker run
--read-only`) and needs no tmpfs: it writes only to the data volume.
SQLite's temporary files go there too (the image sets `SQLITE_TMPDIR`, and
varlatchd falls back to the data directory by itself), and have no name in
it.

Give it 30 seconds to stop (`docker run --stop-timeout 30`, or
`stop_grace_period: 30s` in a Compose file): at a stop `varlatchd` gives
requests in flight up to 20 seconds, and Docker kills a container after 10
unless told otherwise.

## Building and checking it

```
go/image/build.sh --version <v> --assets <dir> --tag <image> --platforms linux/amd64 --load
node go/image/check-image.mjs <image>
```

`<dir>` holds `varlatchd-<v>-linux-<arch>` and `varlatch-<v>-linux-<arch>`
(`go/release/build-assets.sh` writes them). `--check` instead of `--load`
builds every platform given and keeps nothing. The check uses Docker and its
compose plugin only, and pulls one published image: 0.50.0's, by digest, for
its upgrade by digest across a schema change;
every container and volume it makes is named `vl-image-test-<run>-*` and
removed by that name. `VARLATCH_TEST_SLOWDOWN` multiplies its waits (the
release runs it on an emulated arm64 image when no arm64 runner is
available).

## How a release publishes it

Only the release workflow pushes (`.github/workflows/release.yml`, job
`go-image`), with `build.sh --push`, from the very assets the release
publishes, checked against their `SHA256SUMS` first:

- **Tags:** `ghcr.io/varlatch/varlatchd:<version>` only, prereleases
  included. No `latest` and no floating `0.50`: an upgrade is the tag or
  digest you pin, and the digest is the pin that cannot move.
- **Signed** keyless by the release workflow for its tag, on the
  multi-platform index; the signature is in
  `ghcr.io/varlatch/varlatch-signatures`, as the TypeScript images' are.
- **Attested:** build provenance, and an SBOM per platform (or, built on a
  self-hosted runner, SBOM files attached to the release).
- **Checked** before the release is published: `check-image.mjs` runs on
  the pushed digest for linux/amd64 and linux/arm64.
- **Recorded:** `varlatchd-image.txt`, a release asset listed in the
  signed `SHA256SUMS`, holds `ghcr.io/varlatch/varlatchd:<version>@sha256:<index digest>`,
  and the release notes name it. Pin the image by that digest.

The published-release workflow checks it again from outside: the record
against `SHA256SUMS` and its signature, the tag still on the recorded
digest, the image's signature, and provenance and an SBOM for both
platforms (`check-attestations.sh`, which go-release also runs before it
publishes: an SLSA predicate and an SPDX SBOM per platform, or an SBOM
release file whose bytes match the signed `SHA256SUMS`).

A version's image is pushed once: two builds of the same assets give
different index digests, so a second push would move the tag off the
signed record. The release workflow runs one release per tag at a time,
and go-image refuses a version unless it knows the version is unpublished
(`check-unpublished.sh`): the releases API must answer "Not Found" for the
tag, and the registry, after a successful token exchange, exactly
"manifest unknown" for the image tag. Any other answer (a release or a tag
that exists, 401, 403, 429, 5xx, an incomplete transfer, no answer) stops
the run. The package must exist already: `ghcr.io/varlatch/varlatchd`
does (it holds the TypeScript line's images). A registry that does not
know the package says nothing about the tag, so for a new package (a
fork's, say) push its first image by hand under a tag that is not a
version, and link the package to the repository with Actions access.

### When a release run fails after go-image

A run that pushed its image and failed later resumes with "Re-run failed
jobs", which keeps go-image's outputs (the pushed digest) and pushes
nothing again. GitHub allows re-running a run for 30 days after it
started; the go-assets artifact the later jobs download is kept as long.
The workflow runs only on a tag push, so after those 30 days the run
cannot be resumed or restarted at all.

Publishing can leave a draft behind: `gh release create` uploads the
assets to a draft and publishes it last, and a run killed in between, or
one that could not delete its draft, leaves it. A draft is not a release:
go-image's guard does not see it, and a later `gh release create` makes
another one beside it. Its notes name the image's digest from the start
(its assets may be incomplete). Before deleting an image, look for drafts
of the tag or naming its digest, with an account that can push to the
repository (others are shown no drafts, so an empty answer from them
proves nothing):

```sh
REPO=varlatch/varlatch TAG=v0.50.0 DIGEST=sha256:...   # the digest the tag names in GHCR
gh api "repos/$REPO" --jq '.permissions.push'          # must print true
gh api --paginate "repos/$REPO/releases?per_page=100" --jq ".[] | select(.draft
  and (.tag_name == \"$TAG\" or ((.body // \"\") | contains(\"$DIGEST\")))) | \"\(.id) \(.html_url)\""
```

If that lists a draft, or either command fails, do not delete the image or
rebuild it: the draft's signed record names the old digest. Resume with
"Re-run failed jobs", which publishes a new release of the same digest,
or, when that cannot succeed, cut the next patch version as below. Either
way leave the stranded draft unpublished: it may be incomplete.

Within those 30 days, and with no such draft, a version can also start
over: check it has no GitHub release, check the run still offers "Re-run
all jobs", then delete the package version that carries its tag in GHCR
(the organization's packages, `varlatchd`, "Manage versions"; a package
admin can) and re-run all jobs. go-image's guard then finds no tag and
builds a new image.

After the 30 days, or whenever the run cannot be re-run: do not delete the
image, and do not delete and re-push the tag. Cut the next patch version
instead (0.50.1 after a stranded 0.50.0), the normal path with its guards.
The stranded version keeps its image and has no published GitHub release
(a draft of it stays unpublished), so installers and `published-release.yml`, which go by releases, never offer
it; its tag counts as a Go release for `release.json`'s `previous` (G6),
so name it there as after any tag. This costs a version number, and
nothing else: deleting the image without a run that can rebuild it would
leave the version with neither, and re-pushing a tag depends on tag rules
and on GitHub starting a new run, which nothing here can check first.
