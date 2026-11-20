// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUsageTextIsNeverMasked: every usage error that prints a usage text
// prints the constant byte for byte, after the fail-safe, whatever the
// message before it echoes (a credentialed URL included), so usage text
// stays as TypeScript prints it. Usage itself holds "@<file>" after
// colons: through the fail-safe it would be masked.
func TestUsageTextIsNeverMasked(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\nserver = \"https://h.example\"\ndefault_environment = \"development\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	login, ok := CommandHelp("login")
	if !ok {
		t.Fatal("no help for login")
	}
	const cred = "https://u:PW@h.example"
	for _, c := range []struct {
		args    []string
		message string // what comes before the usage text, after the fail-safe: the whole stderr is message, usage, newline
		usage   string
	}{
		// The usage text alone.
		{[]string{"agents"}, "", agentsUsage},
		{[]string{"agents", "nosuch"}, "", agentsUsage},
		{[]string{"init", "--project", "web"}, "", initUsage}, // outside the repository, as every init case
		{[]string{"server", "use"}, "", serverUsage},
		{[]string{"env"}, "", envUsage},
		{[]string{"env", "nosuch"}, "", envUsage},
		{[]string{"env", "use"}, "", envUseUsage},
		// A message, then the usage text.
		{[]string{cred}, "varlatch:[redacted]@h.example: unknown command\n\n", Usage},
		{[]string{"nosuch"}, "varlatch: unknown command nosuch\n\n", Usage},
		{[]string{"help", cred}, "varlatch:[redacted]@h.example: not a command\n\n", Usage},
		{[]string{"server", "--nosuch=" + cred}, "varlatch server: unknown option --nosuch=[redacted]\n", serverUsage},
		{[]string{"server", "use", cred, "extra"}, "varlatch server use: unexpected argument extra\n", serverUsage},
		{[]string{"whoami", "--nosuch"}, "varlatch whoami: unknown option --nosuch\n", whoamiUsage},
		{[]string{"login", "--nosuch", cred}, "varlatch login: unknown option --nosuch\n", login},
		{[]string{"agents", "guide", "--nosuch"}, "varlatch agents guide: unknown option --nosuch\n", agentsUsage},
		{[]string{"init", "--org", "acme", "--project", "web", "--nosuch", cred}, "varlatch init: unknown option --nosuch\n", initUsage},
	} {
		if c.args[0] == "init" {
			t.Chdir(dir)
		} else {
			t.Chdir(repo)
		}
		var stdout, stderr strings.Builder
		code := Main(c.args, MapEnv{"HOME": filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		got := stderr.String()
		usageOK := got == c.message+c.usage+"\n"
		if code != ExitUsage || stdout.String() != "" || !usageOK || strings.Contains(got, "PW") {
			t.Errorf("%q: exit %d, stdout %q, stderr\n%q\nwant\n%q", c.args, code, stdout.String(), got, c.message+c.usage+"\n")
		}
	}
}

// TestHelpIsTheUsageText: every command's --help and `varlatch help
// <command>` print its entry of Usage byte for byte on stdout (`admin`'s
// is the Go installation's, the accepted difference admin-usage), and no
// arguments or --help print Usage itself.
func TestHelpIsTheUsageText(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, stderr strings.Builder
		code := Main(args, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		return code, stdout.String(), stderr.String()
	}
	for _, args := range [][]string{{}, {"--help"}, {"-h"}, {"help"}} {
		if code, out, errs := run(args...); code != ExitOK || out != Usage+"\n" || errs != "" {
			t.Errorf("%q: exit %d, stdout is not Usage byte for byte (stderr %q)", args, code, errs)
		}
	}
	for _, c := range commands {
		help, ok := CommandHelp(c.name)
		if !ok {
			continue
		}
		switch c.name {
		case "admin":
			help = adminUsage
		case "doctor":
			help = doctorUsage
		case "setup":
			help = setupUsage
		}
		for _, args := range [][]string{{c.name, "--help"}, {"help", c.name}} {
			if code, out, errs := run(args...); code != ExitOK || out != help+"\n" || errs != "" {
				t.Errorf("%q: exit %d, stdout\n%q\nwant\n%q (stderr %q)", args, code, out, help+"\n", errs)
			}
		}
	}
}

// TestNoUsageTextThroughTheFailSafe: a go/ast check over the package: no
// usage text (an identifier ending in "Usage" or "usage", or a string
// literal starting with "Usage:") is part of the message of UsageError or
// Fail, which goes through the fail-safe; usage text goes in
// UsageErrorWithUsage's usage argument or UsageOnly.
func TestNoUsageTextThroughTheFailSafe(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			var message ast.Expr
			switch {
			case ok && (fn.Name == "UsageError" || fn.Name == "Fail"):
				message = call.Args[0]
			case ok && fn.Name == "UsageErrorWithUsage":
				message = call.Args[0]
			default:
				return true
			}
			ast.Inspect(message, func(m ast.Node) bool {
				switch v := m.(type) {
				case *ast.Ident:
					if strings.HasSuffix(v.Name, "Usage") || v.Name == "usage" {
						t.Errorf("%s: %s's message holds usage text %s; pass it as the usage (UsageErrorWithUsage, UsageOnly)", fset.Position(v.Pos()), fn.Name, v.Name)
					}
				case *ast.BasicLit:
					if v.Kind == token.STRING && strings.HasPrefix(strings.Trim(v.Value, "\"`"), "Usage:") {
						t.Errorf("%s: %s's message is a usage text literal; make it a constant and use UsageOnly", fset.Position(v.Pos()), fn.Name)
					}
				}
				return true
			})
			return true
		})
	}
}
