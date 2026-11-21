// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"context"
	"fmt"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/lib/release"
)

// Assets are the files a server upgrade takes from a release, for the
// host's architecture: the CLI, the server and the manifest.
func Assets(version, goarch string) (varlatch, varlatchd, manifest string) {
	return selfupdate.Asset(version, "linux", goarch), "varlatchd-" + version + "-linux-" + goarch, release.ManifestAsset
}

// Fetch downloads release version's assets for the host and verifies them
// (selfupdate.FetchAssets: the signature on SHA256SUMS as the release
// workflow's for the tag, fail closed, then each file against it), then
// reads the manifest, which must be for that release. Nothing on the host
// changes.
func Fetch(ctx context.Context, src selfupdate.Source, version, goarch string) (Release, error) {
	cli, server, manifest := Assets(version, goarch)
	files, err := selfupdate.FetchAssets(ctx, src, version, []string{cli, server, manifest}, "nothing was changed")
	if err != nil {
		return Release{}, err
	}
	m, err := release.ParseManifest(files[manifest])
	if err != nil {
		return Release{}, fmt.Errorf("%v; nothing was changed", err)
	}
	if m.Version != version {
		return Release{}, fmt.Errorf("the manifest of %s is for %s; nothing was changed", version, m.Version)
	}
	return Release{Version: version, Varlatch: files[cli], Varlatchd: files[server], Manifest: m}, nil
}
