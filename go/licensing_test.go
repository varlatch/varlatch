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
	Deps       []string
}

// violations lists every Apache-2.0 package of the module that depends,
// directly or not, on an AGPL-3.0-or-later package.
func violations(pkgs []pkg) []string {
	var found []string
	for _, p := range pkgs {
		if isAGPL(p.ImportPath) || !(p.ImportPath == module || strings.HasPrefix(p.ImportPath, module+"/")) {
			continue
		}
		for _, dep := range p.Deps {
			if isAGPL(dep) {
				found = append(found, p.ImportPath+" -> "+dep)
			}
		}
	}
	return found
}

func listModule(t *testing.T) []pkg {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var pkgs []pkg
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func TestNoApachePackageDependsOnAGPL(t *testing.T) {
	pkgs := listModule(t)
	seen := map[string]bool{}
	for _, p := range pkgs {
		seen[p.ImportPath] = true
	}
	// The check means nothing if it does not see both binaries.
	for _, want := range []string{module + "/cmd/varlatch", module + "/cmd/varlatchd"} {
		if !seen[want] {
			t.Fatalf("go list did not report %s", want)
		}
	}
	if v := violations(pkgs); len(v) > 0 {
		t.Fatalf("Apache-2.0 packages depend on AGPL-3.0-or-later packages:\n%s", strings.Join(v, "\n"))
	}
}

func TestViolationsDetectsTransitiveImport(t *testing.T) {
	pkgs := []pkg{
		// go list reports transitive dependencies in Deps.
		{ImportPath: module + "/cmd/varlatch", Deps: []string{"fmt", module + "/lib/x", module + "/server/storage"}},
		{ImportPath: module + "/lib/x", Deps: []string{module + "/server/storage"}},
		{ImportPath: module + "/cmd/varlatchd", Deps: []string{module + "/server", module + "/lib/x"}},
		{ImportPath: module + "/serverless", Deps: nil},
	}
	got := violations(pkgs)
	want := []string{
		module + "/cmd/varlatch -> " + module + "/server/storage",
		module + "/lib/x -> " + module + "/server/storage",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
	if isAGPL(module + "/serverless") {
		t.Fatal("a sibling whose name starts with server is not under go/server")
	}
}
