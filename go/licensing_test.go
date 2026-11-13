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
	ForTest    string // set on a test variant: the package under test
	Deps       []string
}

// variant strips go list's test-variant suffix: "p [p.test]" is p.
func variant(importPath string) string {
	if i := strings.Index(importPath, " ["); i >= 0 {
		return importPath[:i]
	}
	return importPath
}

// owner is the package whose license a listed package (or test variant, or
// generated test binary) falls under.
func owner(p pkg) string {
	if p.ForTest != "" {
		return p.ForTest
	}
	path := variant(p.ImportPath)
	// The generated test main "p.test" and an external test package "p_test"
	// belong to p.
	path = strings.TrimSuffix(path, ".test")
	return strings.TrimSuffix(path, "_test")
}

func inModule(importPath string) bool {
	return importPath == module || strings.HasPrefix(importPath, module+"/")
}

// violations lists every Apache-2.0 package of the module (its tests
// included) that depends, directly or not, on an AGPL-3.0-or-later package.
func violations(pkgs []pkg) []string {
	seen := map[string]bool{}
	var found []string
	for _, p := range pkgs {
		o := owner(p)
		if isAGPL(o) || !inModule(o) {
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
	cmd := exec.Command("go", "list", "-test", "-json=ImportPath,ForTest,Deps", "./...")
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
		if v := violations(pkgs); len(v) > 0 {
			t.Fatalf("%s: Apache-2.0 packages depend on AGPL-3.0-or-later packages:\n%s", target, strings.Join(v, "\n"))
		}
	}
}

func TestViolationsDetectsTransitiveAndTestImports(t *testing.T) {
	pkgs := []pkg{
		// go list reports transitive dependencies in Deps.
		{ImportPath: module + "/cmd/varlatch", Deps: []string{"fmt", module + "/lib/x", module + "/server/storage"}},
		{ImportPath: module + "/lib/x", Deps: []string{module + "/server/storage"}},
		// A test of an Apache package importing server code.
		{ImportPath: module + "/lib/y [" + module + "/lib/y.test]", ForTest: module + "/lib/y", Deps: []string{module + "/server [" + module + "/lib/y.test]"}},
		{ImportPath: module + "/lib/y.test", Deps: []string{module + "/lib/y [" + module + "/lib/y.test]", module + "/server [" + module + "/lib/y.test]"}},
		// The server's own tests and test binary may import anything.
		{ImportPath: module + "/server/z [" + module + "/server/z.test]", ForTest: module + "/server/z", Deps: []string{module + "/server"}},
		{ImportPath: module + "/server/z_test [" + module + "/server/z.test]", ForTest: module + "/server/z", Deps: []string{module + "/server"}},
		{ImportPath: module + "/server/z.test", Deps: []string{module + "/server/z [" + module + "/server/z.test]"}},
		{ImportPath: module + "/cmd/varlatchd", Deps: []string{module + "/server", module + "/lib/x"}},
		{ImportPath: module + "/serverless", Deps: nil},
	}
	got := violations(pkgs)
	want := []string{
		module + "/cmd/varlatch -> " + module + "/server/storage",
		module + "/lib/x -> " + module + "/server/storage",
		module + "/lib/y -> " + module + "/server",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
	if isAGPL(module + "/serverless") {
		t.Fatal("a sibling whose name starts with server is not under go/server")
	}
}
