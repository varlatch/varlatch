// SPDX-License-Identifier: Apache-2.0

// Package licensing holds the Go side of the repository's license map
// (ADR-0021; ADR-0059 Decision 1 and gate G12): varlatchd's packages are
// AGPL-3.0-or-later, everything else under go/ is Apache-2.0, and no
// Apache-2.0 package (the CLI and the shared libraries) may depend on an
// AGPL-3.0-or-later one. scripts/check-licenses.mjs checks the SPDX headers
// and LICENSE files of the same directories.
package licensing

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/varlatch/varlatch/go"

// agplRoots are the AGPL-3.0-or-later package trees; keep them in step with
// AGPL_DIRS in scripts/check-licenses.mjs.
var agplRoots = []string{module + "/server", module + "/cmd/varlatchd"}

func isAGPL(importPath string) bool {
	for _, root := range agplRoots {
		if importPath == root || strings.HasPrefix(importPath, root+"/") {
			return true
		}
	}
	return false
}

type pkg struct {
	ImportPath string
	Dir        string
	Deps       []string
}

// variant strips go list's test-variant suffix from a dependency: "p [q.test]"
// is p.
func variant(importPath string) string {
	if i := strings.Index(importPath, " ["); i >= 0 {
		return importPath[:i]
	}
	return importPath
}

// owner is the package whose license a listed entry falls under, found from
// its directory, as scripts/check-licenses.mjs does: a package, its test
// variants, its external test package and its generated test binary all
// share the package's directory, while a real package whose name happens to
// end in "_test" or ".test" has a directory of its own.
func owner(p pkg, root string) (string, bool) {
	rel, err := filepath.Rel(root, p.Dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if rel == "." {
		return module, true
	}
	return module + "/" + filepath.ToSlash(rel), true
}

// violations lists every Apache-2.0 package of the module (its tests
// included) that depends, directly or not, on an AGPL-3.0-or-later package.
// root is the module's directory.
func violations(pkgs []pkg, root string) []string {
	seen := map[string]bool{}
	var found []string
	for _, p := range pkgs {
		o, ok := owner(p, root)
		if !ok || isAGPL(o) {
			continue
		}
		for _, dep := range p.Deps {
			if d := variant(dep); isAGPL(d) && !seen[o+" -> "+d] {
				seen[o+" -> "+d] = true
				found = append(found, o+" -> "+d)
			}
		}
	}
	return found
}

// targets are every platform a binary ships for (ADR-0059 Decision 1).
// Apache-2.0 code must stay clean on all of them; a file built only for one
// platform could otherwise import server code unnoticed.
var targets = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"}

// listModule lists the module's packages, their tests and test binaries, as
// built for one target.
func listModule(t *testing.T, target string) []pkg {
	t.Helper()
	goos, goarch, _ := strings.Cut(target, "/")
	cmd := exec.Command("go", "list", "-test", "-json=ImportPath,Dir,Deps", "./...")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list for %s: %v\n%s", target, err, stderr.String())
	}
	var pkgs []pkg
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("go list output for %s: %v", target, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func TestNoApachePackageDependsOnAGPL(t *testing.T) {
	for _, target := range targets {
		pkgs := listModule(t, target)
		seen := map[string]bool{}
		for _, p := range pkgs {
			seen[p.ImportPath] = true
		}
		// The check means nothing if it does not see both binaries and their tests.
		for _, want := range []string{module + "/cmd/varlatch", module + "/cmd/varlatchd", module + "/cmd/varlatch.test"} {
			if !seen[want] {
				t.Fatalf("%s: go list did not report %s", target, want)
			}
		}
		root, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if v := violations(pkgs, root); len(v) > 0 {
			t.Fatalf("%s: Apache-2.0 packages depend on AGPL-3.0-or-later packages:\n%s", target, strings.Join(v, "\n"))
		}
	}
}

func TestViolationsDetectsTransitiveAndTestImports(t *testing.T) {
	const root = "/m"
	m := module
	pkgs := []pkg{
		// go list reports transitive dependencies in Deps.
		{ImportPath: m + "/cmd/varlatch", Dir: root + "/cmd/varlatch", Deps: []string{"fmt", m + "/lib/x", m + "/server/storage"}},
		{ImportPath: m + "/lib/x", Dir: root + "/lib/x", Deps: []string{m + "/server/storage"}},
		// A test of an Apache package importing server code, its external
		// test package and its generated test binary.
		{ImportPath: m + "/lib/y [" + m + "/lib/y.test]", Dir: root + "/lib/y", Deps: []string{m + "/server [" + m + "/lib/y.test]"}},
		{ImportPath: m + "/lib/y_test [" + m + "/lib/y.test]", Dir: root + "/lib/y", Deps: []string{m + "/server/w"}},
		{ImportPath: m + "/lib/y.test", Dir: root + "/lib/y", Deps: []string{m + "/server [" + m + "/lib/y.test]"}},
		// The server's own tests and test binary may import anything.
		{ImportPath: m + "/server/z [" + m + "/server/z.test]", Dir: root + "/server/z", Deps: []string{m + "/server"}},
		{ImportPath: m + "/server/z_test [" + m + "/server/z.test]", Dir: root + "/server/z", Deps: []string{m + "/server"}},
		{ImportPath: m + "/server/z.test", Dir: root + "/server/z", Deps: []string{m + "/server/z [" + m + "/server/z.test]"}},
		{ImportPath: m + "/cmd/varlatchd", Dir: root + "/cmd/varlatchd", Deps: []string{m + "/server", m + "/lib/x"}},
		// Real Apache packages whose names end like test entries, or start
		// like the server's.
		{ImportPath: m + "/server_test", Dir: root + "/server_test", Deps: []string{m + "/server"}},
		{ImportPath: m + "/server.test", Dir: root + "/server.test", Deps: []string{m + "/server"}},
		{ImportPath: m + "/serverless", Dir: root + "/serverless", Deps: nil},
		// The module root package (this file's).
		{ImportPath: m, Dir: root, Deps: []string{"testing"}},
	}
	got := violations(pkgs, root)
	want := []string{
		m + "/cmd/varlatch -> " + m + "/server/storage",
		m + "/lib/x -> " + m + "/server/storage",
		m + "/lib/y -> " + m + "/server",
		m + "/lib/y -> " + m + "/server/w",
		m + "/server_test -> " + m + "/server",
		m + "/server.test -> " + m + "/server",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if isAGPL(m + "/serverless") {
		t.Fatal("a sibling whose name starts with server is not under go/server")
	}
}
