// SPDX-License-Identifier: Apache-2.0

// Package release verifies Varlatch releases (ADR-0059 Decision 8): a
// release's SHA256SUMS must carry a Sigstore signature made by the
// repository's release workflow for that release's tag, and every asset
// must match its line in SHA256SUMS. It is the embedded verifier the
// installers, varlatch upgrade and the CLI's self-update rely on, and does
// what docs/operations/verify-release.md does with cosign:
//
//	cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
//	  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
//	sha256sum --check SHA256SUMS
//
// It fails closed: there is no unsigned fallback, and releases from before
// signing began are refused.
package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// Repository is where releases come from.
	Repository = "varlatch/varlatch"
	// Issuer is the OIDC issuer of the release workflow's identity.
	Issuer = "https://token.actions.githubusercontent.com"
)

// firstSigned is the first signed release: 0.15.0 and earlier were
// published unsigned from a private repository.
var firstSigned = [3]int{0, 15, 1}

// versionPattern is a release version: digits, optionally a pre-release
// suffix. Nothing in it can change what the identity below points to.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

var (
	// ErrVersion means the version is not a release version.
	ErrVersion = errors.New("release: not a release version")
	// ErrUnsigned means the version predates signed releases; it is never
	// installed by these tools.
	ErrUnsigned = errors.New("release: releases up to 0.15.0 are unsigned and cannot be verified")
)

// Identity is the certificate identity a release is signed with: the
// release workflow, run for the release's tag.
func Identity(version string) string {
	return "https://github.com/" + Repository + "/.github/workflows/release.yml@refs/tags/v" + version
}

// Verifier checks release signatures against Sigstore's trusted material.
type Verifier struct {
	sv *verify.Verifier
}

// NewVerifier verifies against trusted (Sigstore's trusted root). As cosign
// does for a keyless signature, it requires the signing certificate to chain
// to Fulcio, an SCT from a certificate transparency log, and an entry in
// Rekor whose time shows the certificate was valid when it signed.
func NewVerifier(trusted root.TrustedMaterial) (*Verifier, error) {
	sv, err := verify.NewVerifier(trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	return &Verifier{sv: sv}, nil
}

// LiveTrustedRoot fetches Sigstore's trusted root through its TUF
// repository, starting from the root embedded in sigstore-go, and caches it
// in cacheDir (as cosign does in ~/.sigstore). Key rotations at Sigstore
// therefore need no Varlatch release.
func LiveTrustedRoot(ctx context.Context, cacheDir string) (*root.TrustedRoot, error) {
	opts := tuf.DefaultOptions().WithContext(ctx)
	if cacheDir != "" {
		opts = opts.WithCachePath(cacheDir)
	} else {
		opts = opts.WithDisableLocalCache()
	}
	tr, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("release: fetching Sigstore's trusted root: %w", err)
	}
	return tr, nil
}

// VerifySums checks that sums (a release's SHA256SUMS) is signed, through
// bundleJSON (its SHA256SUMS.sigstore.json, in either bundle format), by the
// release workflow for version, and returns the checksums it lists.
func (v *Verifier) VerifySums(version string, sums, bundleJSON []byte) (Sums, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	if err := v.verifyBlob(sums, bundleJSON, Identity(version), Issuer); err != nil {
		return nil, fmt.Errorf("release: SHA256SUMS of %s is not signed by %s's release workflow: %w", version, Repository, err)
	}
	return ParseSums(sums)
}

// verifyBlob checks that bundleJSON signs blob with a certificate for
// exactly san, issued through issuer. Only tests call it with anything but
// a release's identity.
func (v *Verifier) verifyBlob(blob, bundleJSON []byte, san, issuer string) error {
	b, err := readBundle(bundleJSON)
	if err != nil {
		return fmt.Errorf("reading the signature bundle: %w", err)
	}
	id, err := verify.NewShortCertificateIdentity(issuer, "", san, "")
	if err != nil {
		return err
	}
	_, err = v.sv.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(blob)), verify.WithCertificateIdentity(id)))
	return err
}

func checkVersion(version string) error {
	m := versionPattern.FindStringSubmatch(version)
	if m == nil {
		return ErrVersion
	}
	var v [3]int
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return ErrVersion
		}
		v[i] = n
	}
	for i := range v {
		if v[i] != firstSigned[i] {
			if v[i] < firstSigned[i] {
				return ErrUnsigned
			}
			break
		}
	}
	return nil
}
