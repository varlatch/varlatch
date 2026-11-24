// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEveryWriteGoesThroughTheFailSafe parses every Go file of the CLI
// (go/cmd/varlatch; tests, `//go:build ignore` generators, the test-only
// transcript replayer and fakegithub excepted) and fails on any way to stdout or
// stderr outside the fail-safe:
//   - any reference to os.Stdout or os.Stderr, to a Stdout or Stderr field,
//     or to a stdout or stderr variable, outside the allow-listed sites
//     (so `w := r.Stderr` or `var out io.Writer = os.Stderr` fails too);
//   - in an allow-listed writing function, a write whose arguments do not
//     go through cli.RedactDiagnostic or cli.RedactOutput;
//   - any fmt.Print, Printf or Println (stdout, unredacted);
//   - any import of the log package, and any json.NewEncoder outside
//     encoderSites;
//   - outJSON, which writes a document printJSON redacted, called by
//     anything but printJSON, and a redactedJSON made anywhere but
//     redactJSON;
//   - outShowing, the one writer that lets a token through, reached
//     (called or taken as a method value) anywhere but inviteCommand,
//     showReenrollLinks and showEnrollLink, and
//     redactOutputShowing reached anywhere but outShowing;
//   - os.NewFile (a stream by its descriptor) outside newFileSites,
//     syscall.Write and unix.Write;
//   - a stream's Write, WriteString, WriteByte or WriteRune, called or
//     taken as a method value (`w := r.Stdout.Write`).
//
// Multi-line calls are one node, so they are judged whole.
//
// It is a tripwire, not a security boundary. It does not catch an alias
// made inside an allow-listed writer (`w := r.Stdout` in Run.out, then a
// write to w), a stream reached through reflection or unsafe, or a write
// by a dependency outside go/cmd/varlatch; the writers are few and short,
// so review covers them.
func TestEveryWriteGoesThroughTheFailSafe(t *testing.T) {
	// writers: "file:function" -> whether every write there must carry a
	// Redact call (main and run only hand the process's streams over;
	// outJSON writes what printJSON already redacted).
	writers := map[string]bool{
		"main.go:main":                    false,
		"main.go:run":                     false,
		"verify_release.go:verifyRelease": true,
		"internal/cli/cli.go:finish":      true,
		"internal/cli/cli.go:warn":        true,
		"internal/cli/cli.go:ask":         true, // the hidden prompt's question (5.3a)
		"internal/cli/cli.go:out":         true,
		"internal/cli/cli.go:outJSON":     false,
		// invite's enrollment link: the one token it prints on purpose
		// (RedactOutputShowing keeps exactly that one, redacts the rest).
		"internal/cli/cli.go:outShowing": true,
		// The command `run` starts writes to the process's streams (directly,
		// or through internal/matcher's redaction): its own bytes, never the
		// CLI's text, so the fail-safe does not rewrite them (5.4b).
		"internal/cli/runchild.go:runChild": false,
		// `varlatch request` relays the destination's response as the
		// Broker relayed it, already scrubbed: the destination's bytes,
		// never the CLI's text (5.5b).
		"internal/cli/request.go:relayResponse": false,
		// The upgrade's child in the data directory (__upgrade-data): its
		// Stdout and Stderr are set to two buffers, never to a stream. What
		// it said becomes a result or an error of the engine's, which reach
		// the terminal through println (RedactOutput) and finish
		// (RedactDiagnostic) only.
		"internal/upgrade/datadir.go:data": false,
	}
	// encoderSites may call json.NewEncoder.
	encoderSites := map[string]bool{
		// That child's answer, into the buffer above: a path, a checksum
		// and a size, in a document of its own type.
		"internal/upgrade/datadir.go:Child": true,
	}
	// newFileSites may call os.NewFile: each wraps a handle it opened
	// itself for reading, never a stream.
	newFileSites := map[string]bool{
		// The --delete-source file, opened read-only with FILE_SHARE_DELETE.
		"internal/cli/nofollow_windows.go:openNoFollow": true,
	}
	fset := token.NewFileSet()
	refs := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Every exemption and site is a slash path: on Windows, WalkDir
		// gives backslashes.
		rel := slashed(path, filepath.Separator)
		if d.IsDir() {
			if failSafeSkipsDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		if hasBuildIgnore(f) {
			return nil // a generator, never part of the CLI
		}
		path = rel
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "log" {
				t.Errorf("%s imports log", path)
			}
		}
		// Each top-level declaration, with the function it is (if any).
		for _, decl := range f.Decls {
			fn := ""
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			site := path + ":" + fn
			mustRedact, allowed := writers[site]
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if pkg, ok := sel.X.(*ast.Ident); ok {
							if pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print") {
								t.Errorf("%s: fmt.%s writes stdout unredacted", fset.Position(x.Pos()), sel.Sel.Name)
							}
							if pkg.Name == "json" && sel.Sel.Name == "NewEncoder" && !encoderSites[site] {
								t.Errorf("%s: json.NewEncoder", fset.Position(x.Pos()))
							}
						}
						if pkg, ok := sel.X.(*ast.Ident); ok {
							if pkg.Name == "os" && sel.Sel.Name == "NewFile" && !newFileSites[site] {
								t.Errorf("%s: os.NewFile opens a stream by its descriptor", fset.Position(x.Pos()))
							}
							if (pkg.Name == "syscall" || pkg.Name == "unix") && sel.Sel.Name == "Write" {
								t.Errorf("%s: %s.Write writes a descriptor directly", fset.Position(x.Pos()), pkg.Name)
							}
						}
						if sel.Sel.Name == "outJSON" && site != "internal/cli/contextcmds.go:printJSON" {
							t.Errorf("%s: outJSON called outside printJSON", fset.Position(x.Pos()))
						}
						if sel.Sel.Name == "isTerminal" {
							return false // isTerminal(r.Stdout) reads, never writes
						}
					}
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "isTerminal" {
						return false
					}
					if allowed && mustRedact && writesStream(x) && !redacts(x) {
						t.Errorf("%s: a write without cli.RedactDiagnostic or cli.RedactOutput", fset.Position(x.Pos()))
					}
				case *ast.CompositeLit:
					if id, ok := x.Type.(*ast.Ident); ok && id.Name == "redactedJSON" && site != "internal/cli/cli.go:redactJSON" {
						t.Errorf("%s: a redactedJSON made outside redactJSON", fset.Position(x.Pos()))
					}
				case *ast.SelectorExpr:
					switch x.Sel.Name {
					case "Write", "WriteString", "WriteByte", "WriteRune":
						if inner, ok := x.X.(*ast.SelectorExpr); ok && isStream(inner.Sel.Name) {
							t.Errorf("%s: a stream's %s, called or taken as a method value", fset.Position(x.Pos()), x.Sel.Name)
						}
					}
					if isStream(x.Sel.Name) {
						refs++
						if !allowed {
							t.Errorf("%s: %s reached outside the fail-safe's writers", fset.Position(x.Pos()), x.Sel.Name)
						}
					}
				case *ast.Ident:
					if msg := showingMisuse(site, x.Name); msg != "" && !(fn == x.Name && site == "internal/cli/cli.go:"+fn) {
						t.Errorf("%s: %s", fset.Position(x.Pos()), msg)
					}
					if (x.Name == "stdout" || x.Name == "stderr") && !allowed {
						t.Errorf("%s: %s used outside the fail-safe's writers", fset.Position(x.Pos()), x.Name)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if refs == 0 {
		t.Fatal("found no stream at all: the scan is broken")
	}
}

func isStream(name string) bool { return name == "Stdout" || name == "Stderr" }

// showingSites: where the token-showing writer and its redactor may be
// reached. outShowing prints invite's enrollment token, a move's
// re-enrollment links (one token each, slice 6.9) and the first
// administrator's enrollment link (setup on a terminal); nothing else may
// print a token through it.
var showingSites = map[string][]string{
	"outShowing":          {"internal/cli/admin.go:inviteCommand", "internal/cli/move.go:showReenrollLinks", "internal/cli/setup.go:showEnrollLink"},
	"redactOutputShowing": {"internal/cli/cli.go:outShowing"},
}

// showingMisuse is the guard's complaint about the identifier name reached
// at site, or "". A selector's name is an identifier too, so a call, a
// method value (`f := r.outShowing`) and a function value count alike; the
// declarations themselves are exempt.
func showingMisuse(site, name string) string {
	allowed, ok := showingSites[name]
	if !ok || slices.Contains(allowed, site) {
		return ""
	}
	var names []string
	for _, a := range allowed {
		names = append(names, a[strings.LastIndex(a, ":")+1:])
	}
	return name + " reached outside " + strings.Join(names, " and ")
}

// writesStream is whether a call takes a stream as an argument.
func writesStream(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		switch x := a.(type) {
		case *ast.SelectorExpr:
			if isStream(x.Sel.Name) {
				return true
			}
		case *ast.Ident:
			if x.Name == "stdout" || x.Name == "stderr" {
				return true
			}
		}
	}
	return false
}

// redacts is whether a call's arguments go through a Redact function.
func redacts(call *ast.CallExpr) bool {
	found := false
	for _, a := range call.Args {
		ast.Inspect(a, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				name := ""
				switch f := c.Fun.(type) {
				case *ast.Ident:
					name = f.Name
				case *ast.SelectorExpr:
					name = f.Sel.Name
				}
				if name == "RedactDiagnostic" || name == "RedactOutput" || name == "redactOutputShowing" {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// slashed is path with sep, the platform's separator, written as "/", so
// the fail-safe guard's exemptions and allow-listed sites match the same
// files on every platform. A parameter rather than filepath.Separator, so a
// test on Linux can give it Windows paths.
func slashed(path string, sep byte) string {
	if sep == '/' {
		return path
	}
	return strings.ReplaceAll(path, string(sep), "/")
}

// failSafeSkipsDir reports whether the guard skips a directory (a slash
// path): the test-only transcript replayer, the program go/install's upgrade
// test stands in for GitHub with (a main package, so never part of the CLI),
// and the test data.
func failSafeSkipsDir(rel string) bool {
	return rel == "internal/transcript" || rel == "internal/selfupdate/fakerelease/fakegithub" || rel == "testdata"
}

// TestFailSafeGuardPathsOnWindows: with Windows separators, the guard skips
// the same directories and names the same sites as with slashes (the
// replayer was flagged on windows-latest because its exemption compared a
// backslash path with a slash one).
func TestFailSafeGuardPathsOnWindows(t *testing.T) {
	for _, c := range []struct {
		path string
		want string
		skip bool
	}{
		{`internal\transcript`, "internal/transcript", true},
		{`testdata`, "testdata", true},
		{`internal\selfupdate\fakerelease\fakegithub`, "internal/selfupdate/fakerelease/fakegithub", true},
		{`internal\selfupdate\fakerelease`, "internal/selfupdate/fakerelease", false},
		{`internal\cli`, "internal/cli", false},
		{`internal\transcript\transcript.go`, "internal/transcript/transcript.go", false},
		{`internal\cli\cli.go`, "internal/cli/cli.go", false},
		// Only those directories themselves: a deeper one with the same
		// name, or a longer name, is walked like any other.
		{`x\internal\transcript`, "x/internal/transcript", false},
		{`internal\transcriptfoo`, "internal/transcriptfoo", false},
	} {
		got := slashed(c.path, '\\')
		if got != c.want {
			t.Errorf("slashed(%q) = %q, want %q", c.path, got, c.want)
		}
		if failSafeSkipsDir(got) != c.skip {
			t.Errorf("failSafeSkipsDir(%q) = %v, want %v", got, !c.skip, c.skip)
		}
	}
	// The same paths with slashes are left as they are.
	if got := slashed("internal/transcript", '/'); got != "internal/transcript" || !failSafeSkipsDir(got) {
		t.Errorf("slashed on a slash platform changed %q to %q", "internal/transcript", got)
	}
	// An allow-listed site is named the same from a Windows path.
	if site := slashed(`internal\cli\cli.go`, '\\') + ":finish"; site != "internal/cli/cli.go:finish" {
		t.Errorf("site %q", site)
	}
}

// hasBuildIgnore says whether f carries the real `//go:build ignore`
// constraint: a line comment of exactly that text before the package
// clause. A comment that merely mentions it does not count.
func hasBuildIgnore(f *ast.File) bool {
	for _, group := range f.Comments {
		if group.Pos() >= f.Package {
			break
		}
		for _, c := range group.List {
			if strings.TrimSpace(c.Text) == "//go:build ignore" {
				return true
			}
		}
	}
	return false
}

// TestHasBuildIgnoreNeedsTheConstraint: only the constraint line before
// the package clause exempts a file from the write guard.
func TestHasBuildIgnoreNeedsTheConstraint(t *testing.T) {
	for src, want := range map[string]bool{
		"//go:build ignore\n\npackage main\n":                                           true,
		"// SPDX-License-Identifier: Apache-2.0\n\n//go:build ignore\n\npackage main\n": true,
		"// Not built: see go:build ignore files.\npackage main\n":                      false,
		"/* //go:build ignore */\npackage main\n":                                       false,
		"package main\n\n//go:build ignore\n":                                           false,
		"//go:build ignore_other\n\npackage main\n":                                     false,
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if got := hasBuildIgnore(f); got != want {
			t.Errorf("%q: %v, want %v", src, got, want)
		}
	}
}
