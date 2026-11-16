// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The structural test (feature-parity decision 6; ADR-0057 Decision 9,
// test/outbound-structure.test.ts): no code in go/server makes a network
// request except through this package. It fails on, outside it:
//   - net.Dial, DialTimeout, DialTCP, DialUDP, DialIP and DialUnix, and a
//     net.Dialer;
//   - http.DefaultClient and http.DefaultTransport, http.Get, Head, Post
//     and PostForm, a new http.Transport, and an http.Client literal (one
//     without a Transport uses the default one);
//   - an S3 client (s3.New, s3.NewFromConfig, lib/backup's NewClient);
// in every non-test file, by import path (so a renamed import is caught
// too), with the reviewed exceptions below.

// exception is a reviewed use: a file (relative to go/server), the use,
// and why it is not an Organization's destination.
type exception struct{ file, use, why string }

var exceptions = []exception{
	{"daemon/control.go", "net.DialTimeout", "the daemon's own Unix control socket in the data directory (decision 11)"},
	{"daemon/backup.go", "net.DialTimeout", "restore checks that no varlatchd answers on the data directory's control socket"},
	{"backups/backups.go", "backup.NewClient", "the host's backup destination, for uploads and the bucket test (ADR-0057 Decision 1: 4.14's uploads are an exception by name)"},
}

type forbidden struct {
	path string // import path
	name string
	// literal: a composite literal of the type, rather than a selector.
	literal bool
}

var rules = []forbidden{
	{"net", "Dial", false}, {"net", "DialTimeout", false}, {"net", "DialTCP", false}, {"net", "DialUDP", false},
	{"net", "DialIP", false}, {"net", "DialUnix", false}, {"net", "Dialer", false},
	{"net/http", "DefaultClient", false}, {"net/http", "DefaultTransport", false},
	{"net/http", "Get", false}, {"net/http", "Head", false}, {"net/http", "Post", false}, {"net/http", "PostForm", false},
	{"net/http", "Transport", true}, {"net/http", "Client", true},
	{"github.com/aws/aws-sdk-go-v2/service/s3", "New", false}, {"github.com/aws/aws-sdk-go-v2/service/s3", "NewFromConfig", false},
	{"github.com/varlatch/varlatch/go/lib/backup", "NewClient", false},
}

// use is one forbidden use found: file, the use as package.Name, line.
type use struct {
	file, use string
	line      int
}

// scanTree finds the forbidden uses in the non-test Go files under root,
// leaving out skip (relative directories).
func scanTree(t *testing.T, root string, skip ...string) []use {
	t.Helper()
	var found []use
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if slices.Contains(skip, rel) || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		names := map[string]string{} // local name -> import path
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			name := p[strings.LastIndexByte(p, '/')+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			names[name] = p
		}
		match := func(x ast.Expr, literal bool) (string, bool) {
			sel, ok := x.(*ast.SelectorExpr)
			if !ok {
				return "", false
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			p, ok := names[id.Name]
			if !ok {
				return "", false
			}
			for _, r := range rules {
				if r.path == p && r.name == sel.Sel.Name && r.literal == literal {
					return p[strings.LastIndexByte(p, '/')+1:] + "." + r.name, true
				}
			}
			return "", false
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if u, ok := match(n.Type, true); ok {
					found = append(found, use{filepath.ToSlash(rel), u, fset.Position(n.Pos()).Line})
				}
			case *ast.SelectorExpr:
				if u, ok := match(n, false); ok {
					found = append(found, use{filepath.ToSlash(rel), u, fset.Position(n.Pos()).Line})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestNoRequestOutsideThePolicy(t *testing.T) {
	found := scanTree(t, "..", "outbound")
	used := map[exception]bool{}
	for _, u := range found {
		i := slices.IndexFunc(exceptions, func(e exception) bool { return e.file == u.file && e.use == u.use })
		if i < 0 {
			t.Errorf("go/server/%s:%d uses %s: requests go through go/server/outbound (ADR-0057 Decision 9); a destination the host chose needs a reviewed entry in exceptions", u.file, u.line, u.use)
			continue
		}
		used[exceptions[i]] = true
	}
	for _, e := range exceptions {
		if !used[e] {
			t.Errorf("the exception %s %s is not used any more: remove it", e.file, e.use)
		}
	}
}

// The scan itself catches what it must: every rule, a renamed import, and
// nothing in a test file.
func TestStructureScanCatches(t *testing.T) {
	dir := t.TempDir()
	src := `package x

import (
	"net"
	h "net/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func f() {
	net.Dial("tcp", "x")
	_ = net.Dialer{}
	_ = h.DefaultClient
	h.Get("http://x")
	_ = &h.Transport{}
	_ = h.Client{}
	s3.New(s3.Options{})
}
`
	writeFile(t, filepath.Join(dir, "x.go"), src)
	writeFile(t, filepath.Join(dir, "x_test.go"), src)
	got := scanTree(t, dir)
	var uses []string
	for _, u := range got {
		uses = append(uses, u.file+" "+u.use)
	}
	want := []string{"x.go net.Dial", "x.go net.Dialer", "x.go http.DefaultClient", "x.go http.Get", "x.go http.Transport", "x.go http.Client", "x.go s3.New"}
	if !slices.Equal(uses, want) {
		t.Errorf("found %q, want %q", uses, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
