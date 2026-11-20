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
- has one of the variables the TypeScript line kept a key or its
  passphrase in, whatever its value and in any case: `VARLATCH_KEK`,
  `VARLATCH_KEK_PASSPHRASE`, `VARLATCH_ROOT_KEK`, `VARLATCH_BEK`,
  `VARLATCH_BEK_PASSPHRASE`, `VARLATCH_BACKUP_KEY`.

The CLI in the image refuses to run the same way. The refusal names the
variable and never shows its value. Coolify passes every environment
variable to every service of a stack, so a key set there as a variable
would be in every container: give it as a file instead.

## Building and checking it

```
go/image/build.sh --version <v> --assets <dir> --tag <image> --platforms linux/amd64 --load
node go/image/check-image.mjs <image>
```

`<dir>` holds `varlatchd-<v>-linux-<arch>` and `varlatch-<v>-linux-<arch>`
(`go/release/build-assets.sh` writes them). `--check` instead of `--load`
builds every platform given and keeps nothing. Nothing here pushes or
signs: the release workflow does. The check uses Docker only; every
container and volume it makes is named `vl-image-test-<run>-*` and removed
by that name.
