// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The checks' read side is their own: no package this one imports,
// directly or through others of the module, is the import's
// (server/migration/migrate) or the test seed's (migrationtest). The
// import graph is read from the sources (every non-test file, whatever its
// build tags), so the guard holds without the go command.
func TestTheChecksDoNotImportTheImport(t *testing.T) {
	const module = "github.com/varlatch/varlatch/go/"
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{module + "server/migration/migrate", module + "server/migration/migrationtest"}
	seen := map[string]bool{}
	var walk func(pkg string, path []string)
	walk = func(pkg string, path []string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		if slices.Contains(forbidden, pkg) {
			t.Errorf("the checks import %s: %s", pkg, strings.Join(append(path, pkg), " -> "))
			return
		}
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, module)))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", pkg, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, module) {
					walk(p, append(path, pkg))
				}
			}
		}
	}
	walk(module+"server/migration/check", nil)
	if len(seen) < 5 {
		t.Fatalf("the walk read %d packages; the guard reads nothing", len(seen))
	}
}
