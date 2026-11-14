// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/web/inputs"
)

// RequireEnv makes a missing build a failure instead of a skip: go.yml sets
// it, since it runs go generate ./server/web before the tests.
const RequireEnv = "VARLATCH_REQUIRE_DASHBOARD"

// CommitEnv, when set, is the commit the embedded build must record (CI
// passes the checkout's).
const CommitEnv = "VARLATCH_DASHBOARD_COMMIT"

var repoRoot = filepath.Join("..", "..", "..")

// The dashboard varlatchd embeds was built from the sources checked out
// here: its recorded inputs hash is the checkout's (and, where CI says,
// the commit is the checkout's, with no change to the sources).
func TestEmbeddedFromCheckout(t *testing.T) {
	b, ok := Embedded()
	if !ok {
		if os.Getenv(RequireEnv) != "" {
			t.Fatalf("%s is set, but this build embeds the placeholder: run go generate ./server/web", RequireEnv)
		}
		t.Skip("no dashboard build in dist/ (go generate ./server/web); the placeholder is embedded")
	}
	hash, err := inputs.Hash(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if b.Inputs != hash {
		t.Fatalf("the embedded dashboard was built from other sources (recorded %s, checkout %s): run go generate ./server/web", b.Inputs, hash)
	}
	if want := os.Getenv(CommitEnv); want != "" && (b.Commit != want || !b.Clean) {
		t.Fatalf("the embedded dashboard records commit %s (clean %v), the checkout is %s", b.Commit, b.Clean, want)
	}
	if !strings.HasPrefix(b.Node, "v26.") || b.Pnpm == "" {
		t.Errorf("built with Node %s, pnpm %s", b.Node, b.Pnpm)
	}
	index, err := fs.ReadFile(FS(), "index.html")
	if err != nil || !strings.Contains(string(index), `<div id="root">`) {
		t.Errorf("index.html is not the dashboard's: %v", err)
	}
}

func TestFSHidesDotFiles(t *testing.T) {
	f := FS()
	if _, err := fs.Stat(f, "index.html"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{BuildFile, ".gitkeep", "assets/.hidden"} {
		if _, err := f.Open(name); err == nil {
			t.Errorf("%s is served", name)
		}
	}
}

func TestPlaceholderWithoutBuild(t *testing.T) {
	if _, ok := Embedded(); ok {
		t.Skip("a build is embedded")
	}
	index, err := fs.ReadFile(FS(), "index.html")
	if err != nil || !strings.Contains(string(index), "built without the dashboard") {
		t.Errorf("placeholder: %v %q", err, index)
	}
}

func TestInputPackages(t *testing.T) {
	dirs, err := inputs.Packages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dirs, []string{"apps/web", "packages/protocol", "packages/sdk"}) {
		t.Errorf("the dashboard's workspace packages: %q", dirs)
	}
}
