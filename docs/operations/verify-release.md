# Verifying a release

Every Varlatch release after 0.15.0 is signed keylessly by its GitHub Actions
release workflow via Sigstore: no separate signing key to fetch or trust.

> `install.sh`, `install.ps1`, `varlatch upgrade`, and `varlatch self-update`
> already verify these signatures automatically before installing anything. Use
> this page when you want to verify artifacts first with tools you already
> trust (`cosign`, `sha256sum`, `gh`, `docker buildx`, `jq`).

Set the release you want to check:

```sh
V=0.50.2                                      # the release to verify
REPO=varlatch/varlatch                        # the repository releases come from
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${V}"
ISSUER=https://token.actions.githubusercontent.com
```

## Release assets

Download the release files (or just the binary you need), verify the Sigstore
signature on `SHA256SUMS`, and check the file hashes:

```sh
gh release download "v$V" -R "$REPO"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum --check --ignore-missing SHA256SUMS
```

Without the GitHub CLI, fetch with `curl` instead:

```sh
BASE="https://github.com/$REPO/releases/download/v$V"
curl -fLO "$BASE/SHA256SUMS"
curl -fLO "$BASE/SHA256SUMS.sigstore.json"
curl -fLO "$BASE/varlatch-$V-linux-amd64"
```

## Container image (0.50.0 and later)

<a id="the-go-lines-image-0500-and-later"></a>

Each 0.50+ release records its container image digest in `varlatchd-image.txt`
(covered by the signed `SHA256SUMS`). Save and run this script with Bash
(`bash verify-go.sh`; requires `gh`, `cosign`, `docker buildx`, and `jq`) to
verify the record, signature, build provenance, and SBOMs before pulling:

```sh
set -euo pipefail
V=0.50.2                                      # the release to verify
REPO=varlatch/varlatch
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${V}"
ISSUER=https://token.actions.githubusercontent.com
mkdir "varlatch-$V" && cd "varlatch-$V"
gh release download "v$V" --repo "$REPO" -p SHA256SUMS -p SHA256SUMS.sigstore.json -p varlatchd-image.txt
assets=$(gh release view "v$V" --repo "$REPO" --json assets -q '.assets[].name')
if grep -q '^sbom-varlatchd-' <<< "$assets"; then
  gh release download "v$V" --repo "$REPO" -p 'sbom-varlatchd-*.spdx.json'
fi

# Verify SHA256SUMS and varlatchd-image.txt
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
grep -E '^[0-9a-f]{64}  varlatchd-image\.txt$' SHA256SUMS | sha256sum --check --strict -

# Verify the image signature by digest
ref=$(cat varlatchd-image.txt)                # ghcr.io/varlatch/varlatchd:V@sha256:...
image="${ref%%:*}@${ref##*@}"
COSIGN_REPOSITORY=ghcr.io/varlatch/varlatch-signatures \
  cosign verify "$image" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null

# Verify provenance and per-platform SBOMs
gh api -H 'Accept: application/vnd.github.raw' \
  "repos/$REPO/contents/go/image/check-attestations.sh?ref=v$V" > check-attestations.sh
bash check-attestations.sh "$image" "$V" --sbom-dir . --sums SHA256SUMS

echo "verified $image"
```

Then pull and run the image by that exact verified digest.

## Signed and unsigned releases

- Releases **after 0.15.0** are published from the public repository and are
  **always signed** (`SHA256SUMS.sigstore.json` plus image signatures). If a
  release after 0.15.0 is missing its signature or fails verification, **stop
  and do not install it**; never fall back to unsigned checks.
- Releases **0.15.0 and earlier** were published while the repository was
  private and are unsigned.
- Every night, the repository's
  [image scan](https://github.com/varlatch/varlatch/actions/workflows/image-scan.yml)
  scans the latest published images with OSV-Scanner and reports known
  vulnerabilities in the run summary. It only reports: it never changes a
  published release or holds back the next one.

<details>
<summary>Legacy: verifying 0.23.x and earlier (three Compose images, provenance, SBOM)</summary>

<a id="images"></a>

Releases up to 0.23.1 ship three images pinned in `varlatch-release.json`, with
signatures stored in `ghcr.io/varlatch/varlatch-signatures`:

```sh
export COSIGN_REPOSITORY=ghcr.io/varlatch/varlatch-signatures
for image in $(jq -r '.images | to_entries[]
    | select(.key == "varlatchd" or .key == "varlatch-web" or .key == "convex-deploy")
    | .value.digest' varlatch-release.json); do
  cosign verify "$image" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null \
    && echo "verified $image"
done
```

Without `COSIGN_REPOSITORY`, cosign looks beside each image and reports
that no signatures were found. 0.15.1's signatures are in both places.

<a id="provenance-and-sbom"></a>

Inspect provenance and SBOM attestations:

```sh
image=$(jq -r '.images.varlatchd.digest' varlatch-release.json)
docker buildx imagetools inspect "$image" --format '{{ json (index .Provenance "linux/amd64") }}'
docker buildx imagetools inspect "$image" --format '{{ json (index .SBOM "linux/arm64") }}'
```

Releases built on self-hosted runners attach SPDX 2.3 SBOMs as release files
(`sbom-IMAGE-VERSION-linux-ARCH.spdx.json`), covered by `SHA256SUMS`. Up to
0.23.1, `varlatch upgrade` did not verify signatures automatically: verify
before upgrading.

</details>

<details>
<summary>Legacy: unsigned releases (0.15.0 and earlier)</summary>

<a id="unsigned-releases"></a>

Releases 0.15.0 and earlier are not cryptographically signed. Checksums and
unsigned attestations confirm download integrity and claimed provenance, **not**
who published them (anyone with repo/registry write access could replace both).
Save as `verify-unsigned.sh` and run `bash verify-unsigned.sh 0.15.0`. Do not
paste it into an interactive shell, where a failed check would not stop the
commands after it. It runs the downloaded CLI only at the end, once every
other check has passed; that runs code from the release, as installing it
would.

```bash
#!/usr/bin/env bash
# Checks for an unsigned Varlatch release (0.15.0 and earlier).
# Usage: bash verify-unsigned.sh VERSION [REPOSITORY]
set -euo pipefail
shopt -s dotglob nullglob

V=${1:?usage: bash verify-unsigned.sh VERSION [REPOSITORY]}
REPO=${2:-varlatch/varlatch}
WORKFLOW="$REPO/.github/workflows/release.yml@refs/tags/v$V"
fail() { echo "FAILED: $*" >&2; exit 1; }

COMMIT=$(gh api "repos/$REPO/commits/v$V" --jq .sha)
case $COMMIT in *[!0-9a-f]*) fail "the tag v$V names no commit ('$COMMIT')" ;; esac
[ "${#COMMIT}" -eq 40 ] || fail "the tag v$V names no commit ('$COMMIT')"
dir=$(mktemp -d)
cd "$dir"
echo "v$V of $REPO, tagged at $COMMIT, downloading to $dir"
gh release download "v$V" -R "$REPO"

sha256sum --check --strict --quiet SHA256SUMS
for f in *; do
  if [ "$f" = SHA256SUMS ]; then continue; fi
  F=$f awk '$2 == ENVIRON["F"] { found = 1 } END { exit !found }' SHA256SUMS \
    || fail "$f is not listed in SHA256SUMS"
done
gh release view "v$V" -R "$REPO" --json assets \
  --jq '.assets[] | "\(.digest | ltrimstr("sha256:"))  \(.name)"' \
  | sha256sum --check --strict --quiet
tar -xzOf "varlatch-compose-$V.tar.gz" "varlatch-$V/varlatch-release.json" \
  | cmp -s - varlatch-release.json || fail "the archive's manifest differs from varlatch-release.json"
test "$(jq -r .version varlatch-release.json)" = "$V" || fail "the manifest is not for $V"
echo "assets: complete, listed in SHA256SUMS, and as GitHub recorded them"

sbom_packages='.packages | if type == "array" and length > 0
  and all(.[]; type == "object" and (.name | type) == "string") then length else empty end'
spdx_document='select(.spdxVersion == "SPDX-2.3" and .SPDXID == "SPDXRef-DOCUMENT"
  and all(.packages[]?; (.SPDXID | type) == "string"))'
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
    in_run=$(jq -r '.SLSA.buildDefinition.internalParameters.github_run_id // empty | tostring' <<<"$provenance")
    test "$built" = "$COMMIT" || fail "$key $platform was built from '$built', not $COMMIT"
    test "$by" = "$WORKFLOW" || fail "$key $platform was built by '$by', not $WORKFLOW"
    case $in_run in '' | 0* | *[!0-9]*) fail "$key $platform names no build run ('$in_run')" ;; esac
    if [ -z "$run" ]; then run=$in_run; fi
    test "$in_run" = "$run" || fail "$key $platform was built in run $in_run, not $run"
    attested=$(docker buildx imagetools inspect "$image" --format "{{ json (index .SBOM \"$platform\") }}")
    sbom_file="sbom-$name-$V-linux-${platform#linux/}.spdx.json"
    if packages=$(jq -e ".SPDX | $sbom_packages" <<<"$attested"); then
      echo "$key $platform: built from $COMMIT in run $run, SBOM attested ($packages packages)"
    elif [ -f "$sbom_file" ] && packages=$(jq -e "$spdx_document | $sbom_packages" "$sbom_file"); then
      echo "$key $platform: built from $COMMIT in run $run, SBOM in $sbom_file ($packages packages)"
    else
      fail "$key $platform has no SBOM: none attested, and $sbom_file is missing or not an SPDX 2.3 SBOM with packages"
    fi
  done
done

cli=$(node "varlatch-cli-$V.cjs" --version)
case $cli in "varlatch $V "*) ;; *) fail "the CLI reports '$cli'" ;; esac
echo "$cli"
echo "all checks passed; the release files are in $dir"
```

<a id="what-unsigned-checks-cannot-show"></a>

</details>
