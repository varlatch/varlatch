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
repository: if signing fails, it publishes nothing. A private repository's
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
before you rely on them. Run them in an empty directory.

```sh
V=0.14.0                                      # the release to verify
REPO=varlatch/varlatch                        # the repository releases come from
COMMIT=$(gh api "repos/$REPO/commits/v$V" --jq .sha)   # the commit the tag names
```

### Assets and checksums

```sh
gh release download "v$V" -R "$REPO"
sha256sum --check --strict SHA256SUMS
for f in *; do
  [ "$f" = SHA256SUMS ] || awk '{ print $2 }' SHA256SUMS | grep -qxF "$f" || echo "not in SHA256SUMS: $f"
done
gh release view "v$V" -R "$REPO" --json assets \
  --jq '.assets[] | "\(.digest | ltrimstr("sha256:"))  \(.name)"' | sha256sum --check --strict
tar -xzOf "varlatch-compose-$V.tar.gz" "varlatch-$V/varlatch-release.json" | cmp - varlatch-release.json
node "varlatch-cli-$V.cjs" --version
jq -r '"\(.version) at migration \(.migrationVersion)"' varlatch-release.json
```

`--ignore-missing` is left out on purpose: every file `SHA256SUMS` lists
must be present, and the loop names any downloaded file it does not list.
The release view compares each file with the digest GitHub recorded when it
was uploaded. The manifest inside the first-install archive must be the same
file as the one beside it, and the CLI and the manifest must both name the
release you meant to download.

### Images, provenance, and SBOMs

The manifest pins each image by digest, and Compose pulls them by digest:
the images you run are exactly the ones the manifest names, even if a tag is
moved later. For Varlatch's own three images, check the platforms each
pinned digest is published for, what its provenance says about its build,
and its SBOMs:

```sh
for key in varlatchd varlatch-web convex-deploy; do
  image=$(jq -r ".images[\"$key\"].digest" varlatch-release.json)
  echo "$key: $image"
  docker buildx imagetools inspect "$image" --raw \
    | jq -r '.manifests[] | select(.platform.os != "unknown") | "  " + .platform.os + "/" + .platform.architecture'
  for platform in linux/amd64 linux/arm64; do
    docker buildx imagetools inspect "$image" --format "{{ json (index .Provenance \"$platform\") }}" \
      | jq -r --arg p "$platform" '.SLSA.buildDefinition.internalParameters as $gh
          | "  \($p) built from " + ([.. | objects | .["vcs:revision"]? // empty] | unique | join(" "))
            + " by \($gh.github_workflow_ref), run \($gh.github_run_id)"'
    docker buildx imagetools inspect "$image" --format "{{ json (index .SBOM \"$platform\") }}" \
      | jq -r --arg p "$platform" '"  \($p) SBOM: " + (if .SPDX then "\(.SPDX.packages | length) packages" else "none attached" end)'
  done
done
echo "expected: built from $COMMIT by $REPO/.github/workflows/release.yml@refs/tags/v$V"
```

Each image must list linux/amd64 and linux/arm64, and every provenance line
must name the expected commit and workflow, all with the same run. Images
built on a self-hosted runner have no SBOM attestation: their SBOMs are
release files, which the asset checks cover.

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
