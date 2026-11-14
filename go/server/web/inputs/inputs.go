// SPDX-License-Identifier: AGPL-3.0-or-later

// Package inputs identifies the sources the dashboard is built from: the
// apps/web workspace package, the workspace packages it depends on (found
// from the package.json files, "workspace:" dependencies, transitively), and
// the repository files every pnpm build reads (the lockfile, the workspace,
// the root package.json, tsconfig.base.json, .npmrc, .pnpmfile.cjs).
//
// Hash is recorded with the build (go generate ./server/web) and checked
// again by the tests against the checkout, so the dashboard varlatchd
// embeds is shown to come from the sources it is tested with. It reads the
// file tree, not git, so it works where git does not (the pinned Go
// container); the generator records the commit too, where git is there.
package inputs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// RootFiles are the repository files every build reads.
var RootFiles = []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "tsconfig.base.json", ".npmrc", ".pnpmfile.cjs"}

// skipped are directories and files that are build output or local state,
// as the repository's .gitignore leaves them out.
func skipped(name string, dir bool) bool {
	if dir {
		return name == "node_modules" || name == "dist" || name == "coverage" || name == ".turbo"
	}
	return strings.HasSuffix(name, ".tsbuildinfo") || name == ".DS_Store" || name == ".env" ||
		(strings.HasPrefix(name, ".env.") && name != ".env.schema" && name != ".env.example")
}

// Packages returns the workspace directories the dashboard is built from,
// relative to root, sorted: apps/web and its workspace dependencies.
func Packages(root string) ([]string, error) {
	byName := map[string]string{}
	for _, glob := range []string{"apps/*/package.json", "packages/*/package.json", "services/*/package.json"} {
		matches, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			var p struct{ Name string }
			if err := readJSON(m, &p); err != nil {
				return nil, err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(m))
			byName[p.Name] = filepath.ToSlash(rel)
		}
	}
	seen := map[string]bool{}
	var visit func(dir string) error
	visit = func(dir string) error {
		if seen[dir] {
			return nil
		}
		seen[dir] = true
		var p struct {
			Dependencies    map[string]string
			DevDependencies map[string]string
		}
		if err := readJSON(filepath.Join(root, dir, "package.json"), &p); err != nil {
			return err
		}
		for _, deps := range []map[string]string{p.Dependencies, p.DevDependencies} {
			for name, spec := range deps {
				if !strings.HasPrefix(spec, "workspace:") {
					continue
				}
				d, ok := byName[name]
				if !ok {
					return fmt.Errorf("inputs: %s depends on %s, which is not a workspace package", dir, name)
				}
				if err := visit(d); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit("apps/web"); err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	slices.Sort(dirs)
	return dirs, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("inputs: %s: %w", path, err)
	}
	return nil
}

// Hash returns the sha256 of the dashboard's sources under root: each file
// as its path relative to root, a NUL, the sha256 of its content and a
// newline, in path order.
func Hash(root string) (string, error) {
	dirs, err := Packages(root)
	if err != nil {
		return "", err
	}
	var files []string
	for _, f := range RootFiles {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			files = append(files, f)
		}
	}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if skipped(d.Name(), d.IsDir()) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				rel, _ := filepath.Rel(root, p)
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	slices.Sort(files)
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(h, "%s\x00%x\n", f, sum)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
