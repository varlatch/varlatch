// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	rel "github.com/varlatch/varlatch/go/lib/release"
)

// TestUpgradeFixtureVersions checks that build-upgrade.sh and test-upgrade.sh
// match go/release/release.json's previous release. When previous is a stable
// release, varlatch upgrade refuses prereleases without --prerelease, so the
// synthetic upgrade targets must be non-prereleases newer than previous and in
// ascending order.
func TestUpgradeFixtureVersions(t *testing.T) {
	declRaw, err := os.ReadFile(filepath.Join("..", "release", "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	decl, err := rel.ParseDeclaration(declRaw)
	if err != nil {
		t.Fatal(err)
	}
	if decl.Previous == nil {
		t.Fatal("release.json has no previous release")
	}
	from := decl.Previous.Version

	buildRaw, err := os.ReadFile("build-upgrade.sh")
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	re := regexp.MustCompile(`\b(CANDIDATE|NEXT|UNSAFE|BROKEN)=([^\s]+)`)
	for _, m := range re.FindAllStringSubmatch(string(buildRaw), -1) {
		vars[m[1]] = m[2]
	}

	names := []string{"CANDIDATE", "NEXT", "UNSAFE", "BROKEN"}
	prevName, prevVer := "previous", from
	for _, name := range names {
		ver := vars[name]
		if !rel.ValidVersion(ver) {
			t.Fatalf("build-upgrade.sh: %s=%q is not a release version", name, ver)
		}
		if order, ok := rel.CompareVersions(ver, prevVer); !ok || order <= 0 {
			t.Errorf("build-upgrade.sh: %s (%s) must be newer than %s (%s)", name, ver, prevName, prevVer)
		}
		if !rel.Prerelease(from) && rel.Prerelease(ver) {
			t.Errorf("build-upgrade.sh: %s (%s) is a prerelease, which stable %s refuses without --prerelease", name, ver, from)
		}
		prevName, prevVer = name, ver
	}

	testRaw, err := os.ReadFile("test-upgrade.sh")
	if err != nil {
		t.Fatal(err)
	}
	wantCase := "  " + from + ") FROM_INSTALL="
	if !strings.Contains(string(testRaw), wantCase) {
		t.Errorf("test-upgrade.sh has no pinned install.sh hash entry %q", wantCase)
	}
}
