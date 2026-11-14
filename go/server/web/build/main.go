// SPDX-License-Identifier: AGPL-3.0-or-later

// Command build stages the dashboard for varlatchd to embed: `go generate
// ./server/web` in go/ runs it (varlatchd-core decision 8).
//
// It builds apps/web as the dashboard's image does (apps/web/Dockerfile):
// pnpm installs the dashboard's workspace packages from the lockfile, then
// generates and builds @varlatch/protocol, builds @varlatch/sdk and builds
// @varlatch/web. The Node and pnpm it runs must be the pinned ones: Node's
// major version as the Dockerfile's and CI's (26), and pnpm exactly as the
// root package.json's packageManager names it. The output replaces
// go/server/web/dist/ (which is not committed), with dist/.build.json
// recording the sources' hash (package inputs), the commit and the versions.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/varlatch/varlatch/go/server/web"
	"github.com/varlatch/varlatch/go/server/web/inputs"
)

// NodeMajor is the pinned Node major version (apps/web/Dockerfile's
// node:26-slim, CI's setup-node 26).
const NodeMajor = "26"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "go generate ./server/web:", err)
		os.Exit(1)
	}
}

func run() error {
	// go generate runs this in the package directory, go/server/web.
	here, err := os.Getwd()
	if err != nil {
		return err
	}
	root := filepath.Clean(filepath.Join(here, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "apps", "web", "package.json")); err != nil {
		return fmt.Errorf("run from go/server/web in the repository (no apps/web/package.json under %s)", root)
	}
	nodeVersion, err := output(root, "node", "--version")
	if err != nil {
		return fmt.Errorf("node: %w (the dashboard needs Node %s)", err, NodeMajor)
	}
	if !strings.HasPrefix(nodeVersion, "v"+NodeMajor+".") {
		return fmt.Errorf("node is %s, not the pinned Node %s", nodeVersion, NodeMajor)
	}
	var pkg struct{ PackageManager string }
	if b, err := os.ReadFile(filepath.Join(root, "package.json")); err != nil {
		return err
	} else if err := json.Unmarshal(b, &pkg); err != nil {
		return err
	}
	wantPnpm, ok := strings.CutPrefix(pkg.PackageManager, "pnpm@")
	if !ok {
		return fmt.Errorf("package.json names no pnpm in packageManager (%q)", pkg.PackageManager)
	}
	pnpmVersion, err := output(root, "pnpm", "--version")
	if err != nil {
		return fmt.Errorf("pnpm: %w (the dashboard needs pnpm %s)", err, wantPnpm)
	}
	if pnpmVersion != wantPnpm {
		return fmt.Errorf("pnpm is %s, not the pinned %s (package.json packageManager)", pnpmVersion, wantPnpm)
	}

	steps := [][]string{
		{"pnpm", "install", "--frozen-lockfile", "--filter", "@varlatch/web..."},
		{"pnpm", "--filter", "@varlatch/protocol", "generate"},
		{"pnpm", "--filter", "@varlatch/protocol", "build"},
		{"pnpm", "--filter", "@varlatch/sdk", "build"},
		{"pnpm", "--filter", "@varlatch/web", "build"},
	}
	for _, s := range steps {
		fmt.Fprintln(os.Stderr, "+", strings.Join(s, " "))
		cmd := exec.Command(s[0], s[1:]...)
		cmd.Dir = root
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(s, " "), err)
		}
	}

	// The sources as built (the protocol's generate step writes some).
	hash, err := inputs.Hash(root)
	if err != nil {
		return err
	}
	build := web.Build{Inputs: hash, Node: nodeVersion, Pnpm: pnpmVersion}
	if commit, err := output(root, "git", "rev-parse", "HEAD"); err == nil {
		build.Commit = commit
		dirs, _ := inputs.Packages(root)
		status, err := output(root, "git", append([]string{"status", "--porcelain", "--untracked-files=all", "--"}, append(dirs, inputs.RootFiles...)...)...)
		build.Clean = err == nil && status == ""
	}

	src := filepath.Join(root, "apps", "web", "dist")
	dst := filepath.Join(here, "dist")
	if err := clear(dst); err != nil {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		return err
	}
	b, err := json.MarshalIndent(build, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, web.BuildFile), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "staged the dashboard in %s (sources %s, commit %s, clean %v)\n", dst, hash[:12], orNone(build.Commit), build.Clean)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(no git)"
	}
	return s
}

func output(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(errOut.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// clear empties dir but for .gitkeep, creating it when missing.
func clear(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == ".gitkeep" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	if _, err := os.Stat(filepath.Join(src, "index.html")); err != nil {
		return fmt.Errorf("the build left no %s", filepath.Join(src, "index.html"))
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, 0o644)
		default:
			return errors.New("the build output has " + rel + ", which is not a regular file")
		}
	})
}
