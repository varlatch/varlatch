# Verifying a release

A Varlatch release is signed by the repository's release workflow, unless
its release notes say otherwise (see
[signed and unsigned releases](#signed-and-unsigned-releases)). Signing is
keyless: Sigstore certifies the workflow's GitHub Actions identity for the
release tag, so there is no key to fetch or trust separately. Each image also
carries a build-provenance attestation and an SBOM, and is published for
linux/amd64 and linux/arm64.

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.x or later, `docker buildx`, `jq`, and the GitHub CLI. A release from a
private repository also needs a `gh` login with access to the repository and
a registry login that can read its images (`docker login ghcr.io` with a
token that has the `read:packages` scope).

```sh
V=0.14.0                                      # the release to verify
REPO=varlatch/varlatch                        # the repository releases come from
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${V}"
ISSUER=https://token.actions.githubusercontent.com
```

## Signed and unsigned releases

The release workflow always signs a release published from a public
repository: the GitHub release is not published if signing fails, although
the release's images may already have been pushed. A private repository's
releases are signed only when its `SIGN_PRIVATE_RELEASES` repository
variable is `true`, because keyless signatures are recorded in Sigstore's
public transparency log with the repository, tag, and digests they cover.

A signed release has `SHA256SUMS.sigstore.json` among its assets and a
signature on each of Varlatch's three images. An unsigned release has
neither.

Treat a release as unsigned only when its release notes say it is not
signed. A release from the public repository is always signed, whatever its
notes say. If a release you expect to be signed has no
`SHA256SUMS.sigstore.json`, or a signature check below fails, stop: do not
install it, and do not fall back to the checks for unsigned releases. Its
missing signatures may mean it was tampered with or published incorrectly.

For a release whose notes say it is not signed, go to
[unsigned releases](#unsigned-releases).

## Release assets

```sh
gh release download "v$V" -R "$REPO"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum --check --ignore-missing SHA256SUMS
```

The first check proves that `SHA256SUMS` was produced by the release
workflow for this tag. The second checks every downloaded asset against it,
including the operator CLI and the release manifest.

## Images

The release manifest pins each image by digest. Verify Varlatch's own three
images against the same identity:

```sh
for image in $(jq -r '.images | to_entries[]
    | select(.key == "varlatchd" or .key == "varlatch-web" or .key == "convex-deploy")
    | .value.digest' varlatch-release.json); do
  cosign verify "$image" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null \
    && echo "verified $image"
done
```

The third-party images (PostgreSQL, the Convex backend, Caddy, Tailscale)
are pinned by digest in the same manifest, which `SHA256SUMS` covers.

## Provenance and SBOM

```sh
image=$(jq -r '.images.varlatchd.digest' varlatch-release.json)
docker buildx imagetools inspect "$image" --format '{{ json (index .Provenance "linux/amd64") }}'
docker buildx imagetools inspect "$image" --format '{{ json (index .SBOM "linux/arm64") }}'
```

The provenance records the repository, commit, and workflow that built the
image. The SBOM lists every package in it, operating-system packages
included. `THIRD-PARTY-NOTICES.md` lists the third-party components with
their licenses.

A release whose images were built on a self-hosted runner has no SBOM
attestation, and its release notes say so. It attaches each image's SBOM as
a release file instead, one per image and architecture
(`sbom-IMAGE-VERSION-linux-ARCH.spdx.json`, in SPDX 2.3 JSON). `SHA256SUMS`
lists them, so the release-asset checks above cover them.

## Unsigned releases

These checks are for a release whose notes say it is not signed. They show
that your download is complete and consistent, and that the pinned images
describe the expected build. They do not verify the release workflow's
identity: read [what they cannot show](#what-unsigned-checks-cannot-show)
before you rely on them.

The checks are one script. Save it as `verify-unsigned.sh` and run it with
Bash, giving the version, and the repository if releases come from another
one:

```sh
bash verify-unsigned.sh 0.14.0
```

It downloads the release into a new temporary directory and stops at the
first failed check, with a nonzero status. Do not paste it into an
interactive shell, where a failed check would not stop the commands after
it. It runs the downloaded CLI only at the end, once every other check has
passed; that runs code from the release, as installing it would.

```bash
#!/usr/bin/env bash
# Checks for a Varlatch release whose notes say it is not signed.
# Usage: bash verify-unsigned.sh VERSION [REPOSITORY]
set -euo pipefail
shopt -s dotglob nullglob # "*" below also matches hidden files

V=${1:?usage: bash verify-unsigned.sh VERSION [REPOSITORY]}
REPO=${2:-varlatch/varlatch}
WORKFLOW="$REPO/.github/workflows/release.yml@refs/tags/v$V"
fail() { echo "FAILED: $*" >&2; exit 1; }

COMMIT=$(gh api "repos/$REPO/commits/v$V" --jq .sha) # the commit the tag names
dir=$(mktemp -d)
cd "$dir"
echo "v$V of $REPO, tagged at $COMMIT, downloading to $dir"
gh release download "v$V" -R "$REPO"

# Every file SHA256SUMS lists is present and matches it.
sha256sum --check --strict --quiet SHA256SUMS
# Every downloaded file, hidden or not, is listed in SHA256SUMS.
for f in *; do
  if [ "$f" = SHA256SUMS ]; then continue; fi
  F=$f awk '$2 == ENVIRON["F"] { found = 1 } END { exit !found }' SHA256SUMS \
    || fail "$f is not listed in SHA256SUMS"
done
# Every file matches the digest GitHub recorded when it was uploaded.
gh release view "v$V" -R "$REPO" --json assets \
  --jq '.assets[] | "\(.digest | ltrimstr("sha256:"))  \(.name)"' \
  | sha256sum --check --strict --quiet
# The first-install archive carries the same manifest, and it is for $V.
tar -xzOf "varlatch-compose-$V.tar.gz" "varlatch-$V/varlatch-release.json" \
  | cmp -s - varlatch-release.json || fail "the archive's manifest differs from varlatch-release.json"
test "$(jq -r .version varlatch-release.json)" = "$V" || fail "the manifest is not for $V"
echo "assets: complete, listed in SHA256SUMS, and as GitHub recorded them"

# Varlatch's own images, by the digests the manifest pins: both platforms,
# provenance naming the tag's commit and release workflow in one run, and an
# SBOM for each platform (attested, or a release file checked above).
run=
for key in varlatchd varlatch-web convex-deploy; do
  image=$(jq -er --arg k "$key" '.images[$k].digest' varlatch-release.json)
  name=${image%@*}
  name=${name##*/}
  platforms=$(docker buildx imagetools inspect "$image" --raw \
    | jq -r '[.manifests[].platform | select(.os != "unknown") | .os + "/" + .architecture] | sort | join(" ")')
  test "$platforms" = "linux/amd64 linux/arm64" || fail "$key is published for: $platforms"
  for platform in linux/amd64 linux/arm64; do
    provenance=$(docker buildx imagetools inspect "$image" --format "{{ json (index .Provenance \"$platform\") }}")
    built=$(jq -r '[.. | objects | .["vcs:revision"]? // empty] | unique | join(" ")' <<<"$provenance")
    by=$(jq -r '.SLSA.buildDefinition.internalParameters.github_workflow_ref' <<<"$provenance")
    in_run=$(jq -r '.SLSA.buildDefinition.internalParameters.github_run_id' <<<"$provenance")
    test "$built" = "$COMMIT" || fail "$key $platform was built from '$built', not $COMMIT"
    test "$by" = "$WORKFLOW" || fail "$key $platform was built by '$by', not $WORKFLOW"
    if [ -z "$run" ]; then run=$in_run; fi
    test "$in_run" = "$run" || fail "$key $platform was built in run $in_run, not $run"
    packages=$(docker buildx imagetools inspect "$image" --format "{{ json (index .SBOM \"$platform\") }}" \
      | jq -r '.SPDX.packages // [] | length')
    sbom_file="sbom-$name-$V-linux-${platform#linux/}.spdx.json"
    if [ "$packages" -gt 0 ]; then
      echo "$key $platform: built from $COMMIT in run $run, SBOM attested ($packages packages)"
    elif [ -f "$sbom_file" ]; then
      echo "$key $platform: built from $COMMIT in run $run, SBOM in $sbom_file"
    else
      fail "$key $platform has no SBOM"
    fi
  done
done

# Only now, with every other check passed, run the downloaded CLI.
cli=$(node "varlatch-cli-$V.cjs" --version)
case $cli in "varlatch $V "*) ;; *) fail "the CLI reports '$cli'" ;; esac
echo "$cli"
echo "all checks passed; the release files are in $dir"
```

`--ignore-missing` is left out, so every file `SHA256SUMS` lists must be
present, and a downloaded file it does not list fails the check. GitHub's
digests are the ones it recorded when each file was uploaded. The manifest
pins each image by digest, and Compose pulls them by digest, so the images
you run are the ones checked here even if a tag is moved later. Images
built on a self-hosted runner have no SBOM attestation: their SBOMs are
release files, covered by the asset checks.

### What unsigned checks cannot show

Checksums and unsigned metadata do not verify the release workflow's
cryptographic identity:

- `SHA256SUMS` comes from the same release as the files it lists. Anyone
  able to replace an asset can replace `SHA256SUMS` along with it. Matching
  checksums show that your download is complete and intact, not who
  published it.
- GitHub records an asset's digest when the file is uploaded. A match shows
  that the file has not changed since then, not that the release workflow
  uploaded it.
- An unsigned image's provenance and SBOM attestations are unsigned
  metadata stored with it in the registry. Anyone able to push to that
  image repository can push an image with whatever provenance they choose.
  Inspecting them shows what an image claims about its build, not that the
  claim is true.
- The release notes are not signed either, including their statement that
  a release is unsigned. That is why a release from the public repository
  needs its signatures whatever its notes say.

An unsigned release is therefore only as trustworthy as access to the
repository and its packages: who can push tags, publish releases, and push
images. If that is not enough for your installation, do not install an
unsigned release.

`varlatch upgrade` does not verify signatures yet. Verify a release before
you upgrade to it.
