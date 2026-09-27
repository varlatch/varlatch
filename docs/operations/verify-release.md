# Verifying a release

A Varlatch release from the public repository is signed by that
repository's release workflow. Signing is keyless: Sigstore
certifies the workflow's GitHub Actions identity for the release tag, so
there is no key to fetch or trust separately. Each image also carries a build-provenance
attestation and an SBOM, and is published for linux/amd64 and linux/arm64.

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.x or later, `docker buildx`, `jq`, and the GitHub CLI.

```sh
V=0.10.0                                      # the release to verify
REPO=varlatch/varlatch                        # the repository releases come from
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${V}"
ISSUER=https://token.actions.githubusercontent.com
```

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

`varlatch upgrade` does not verify signatures yet. Verify a release before
you upgrade to it.
