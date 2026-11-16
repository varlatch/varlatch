// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The structural test (feature-parity decision 6; ADR-0057 Decision 9,
// test/outbound-structure.test.ts): no code makes a network request except
// through this package, apart from reviewed exceptions. It parses every
// non-test file under go/server and go/cmd/varlatchd (and go/lib, which
// has its own exceptions) and fails on, outside this package:
//   - any use of net.Dial, DialTimeout, DialTCP, DialUDP, DialIP, DialUnix,
//     the net.Dialer type, ListenPacket, ListenUDP, ListenIP and
//     ListenMulticastUDP; crypto/tls's Dial, DialWithDialer and Dialer;
//     anything of net/smtp;
//   - http.DefaultClient, http.DefaultTransport, http.Get, Head, Post,
//     PostForm and ProxyFromEnvironment;
//   - an http.Client or http.Transport value made outside: a composite
//     literal, new(...), or a variable or struct field of the type (a
//     zero Client sends through the default transport); a pointer to one,
//     handed in, is not caught;
//   - a dot-import of net, net/http, crypto/tls or net/smtp (its names
//     would not be qualified);
//   - an S3 client (s3.New, s3.NewFromConfig, lib/backup's NewClient).
// Imports are matched by path, so a renamed import is caught too.
//
// It is a check of syntax, not of types: it does not see a request made
// through a value of these types obtained some other way (returned by a
// function, reached through reflection), nor what a third-party package
// does inside. Review covers those.

// exception is a reviewed use: a file (relative to its root), the use, how
// many times, and why it is not an Organization's destination.
type exception struct {
	file, use string
	count     int
	why       string
}

// serverExceptions are go/server's and go/cmd/varlatchd's (paths relative
// to go/).
var serverExceptions = []exception{
	{"server/daemon/control.go", "net.DialTimeout", 1, "the daemon's own Unix control socket in the data directory (decision 11)"},
	{"server/daemon/backup.go", "net.DialTimeout", 1, "restore checks that no varlatchd answers on the data directory's control socket"},
	{"server/backups/backups.go", "backup.NewClient", 1, "the host's backup destination, for uploads and the bucket test (ADR-0057 Decision 1: 4.14's uploads are an exception by name)"},
}

// libExceptions are go/lib's: code the CLI shares, whose destinations the
// host or the user chose.
var libExceptions = []exception{
	{"lib/backup/s3.go", "http.Client", 1, "the backup destination's client when none is passed in (the CLI's admin backup; varlatchd passes none today: its destination is the host's)"},
	{"lib/backup/s3.go", "s3.New", 1, "the backup destination's S3 client, on the http.Client passed in or the one above"},
	{"lib/release/verify.go", "http.DefaultClient", 1, "Sigstore's TUF repository (fixed, not chosen by an Organization), for the release verifier of the installer and upgrade"},
}

type rule struct {
	path, name string
	// value: only a value of the type (a literal, new, a variable or
	// field), not every mention.
	value bool
}

var rules = []rule{
	{path: "net", name: "Dial"}, {path: "net", name: "DialTimeout"}, {path: "net", name: "DialTCP"}, {path: "net", name: "DialUDP"},
	{path: "net", name: "DialIP"}, {path: "net", name: "DialUnix"}, {path: "net", name: "Dialer"},
	{path: "net", name: "ListenPacket"}, {path: "net", name: "ListenUDP"}, {path: "net", name: "ListenIP"}, {path: "net", name: "ListenMulticastUDP"},
	{path: "crypto/tls", name: "Dial"}, {path: "crypto/tls", name: "DialWithDialer"}, {path: "crypto/tls", name: "Dialer"},
	{path: "net/smtp", name: "*"},
	{path: "net/http", name: "DefaultClient"}, {path: "net/http", name: "DefaultTransport"},
	{path: "net/http", name: "Get"}, {path: "net/http", name: "Head"}, {path: "net/http", name: "Post"}, {path: "net/http", name: "PostForm"},
	{path: "net/http", name: "ProxyFromEnvironment"},
	{path: "net/http", name: "Client", value: true}, {path: "net/http", name: "Transport", value: true},
	{path: "github.com/aws/aws-sdk-go-v2/service/s3", name: "New"}, {path: "github.com/aws/aws-sdk-go-v2/service/s3", name: "NewFromConfig"},
	{path: "github.com/varlatch/varlatch/go/lib/backup", name: "NewClient"},
}

// guarded are the packages a dot-import of is refused.
var guarded = []string{"net", "net/http", "crypto/tls", "net/smtp"}

// use is one forbidden use found: file, the use as package.Name, line.
type use struct {
	file, use string
	line      int
}

// scanTree finds the forbidden uses in the non-test Go files under each
// root (relative to base), leaving out skip (directories relative to
// base).
func scanTree(t *testing.T, base string, roots []string, skip ...string) []use {
	t.Helper()
	var found []use
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(base, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(base, path)
			rel = filepath.ToSlash(rel)
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
			found = append(found, scanFile(fset, f, rel)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}

func scanFile(fset *token.FileSet, f *ast.File, rel string) []use {
	var found []use
	add := func(n ast.Node, u string) { found = append(found, use{rel, u, fset.Position(n.Pos()).Line}) }
	names := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := p[strings.LastIndexByte(p, '/')+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." && slices.Contains(guarded, p) {
			add(imp, "dot-import of "+p)
		}
		names[name] = p
	}
	// match is the rule a selector names, if any.
	match := func(x ast.Expr, value bool) (string, bool) {
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
			if r.path == p && (r.name == sel.Sel.Name || r.name == "*") && r.value == value {
				return p[strings.LastIndexByte(p, '/')+1:] + "." + sel.Sel.Name, true
			}
		}
		return "", false
	}
	// valueOf reports a value use of a guarded type: the type itself, not
	// a pointer to it.
	valueOf := func(typ ast.Expr) {
		if typ == nil {
			return
		}
		if u, ok := match(typ, true); ok {
			add(typ, u)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			valueOf(n.Type)
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
				valueOf(n.Args[0])
			}
		case *ast.ValueSpec:
			valueOf(n.Type)
		case *ast.Field:
			valueOf(n.Type)
		case *ast.SelectorExpr:
			if u, ok := match(n, false); ok {
				add(n, u)
			}
		}
		return true
	})
	return found
}

// judge compares the uses found with the reviewed exceptions: every use
// must be one, each as many times as reviewed, and every exception used.
func judge(errorf func(string, ...any), found []use, exceptions []exception) {
	counts := map[[2]string][]int{}
	for _, u := range found {
		k := [2]string{u.file, u.use}
		counts[k] = append(counts[k], u.line)
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		lines := counts[k]
		i := slices.IndexFunc(exceptions, func(e exception) bool { return e.file == k[0] && e.use == k[1] })
		switch {
		case i < 0:
			errorf("go/%s:%v uses %s: requests go through go/server/outbound (ADR-0057 Decision 9); a destination the host chose needs a reviewed exception", k[0], lines, k[1])
		case exceptions[i].count != len(lines):
			errorf("go/%s uses %s %d times (lines %v); its exception was reviewed for %d", k[0], k[1], len(lines), lines, exceptions[i].count)
		}
	}
	for _, e := range exceptions {
		if _, ok := counts[[2]string{e.file, e.use}]; !ok {
			errorf("the exception %s %s is not used any more: remove it", e.file, e.use)
		}
	}
}

func TestNoRequestOutsideThePolicy(t *testing.T) {
	judge(t.Errorf, scanTree(t, "../..", []string{"server", "cmd/varlatchd"}, "server/outbound"), serverExceptions)
}

func TestNoRequestInLibOutsideItsExceptions(t *testing.T) {
	judge(t.Errorf, scanTree(t, "../..", []string{"lib"}), libExceptions)
}

// Exceptions count per file: a second use of an excepted call fails, and so
// does an exception nothing uses.
func TestExceptionsCount(t *testing.T) {
	var got []string
	errorf := func(format string, args ...any) { got = append(got, fmt.Sprintf(format, args...)) }
	judge(errorf, []use{{"a.go", "net.Dial", 3}, {"a.go", "net.Dial", 9}}, []exception{{"a.go", "net.Dial", 1, ""}, {"b.go", "net.Dial", 1, ""}})
	if len(got) != 2 || !strings.Contains(got[0], "uses net.Dial 2 times (lines [3 9]); its exception was reviewed for 1") || !strings.Contains(got[1], "b.go net.Dial is not used any more") {
		t.Errorf("%q", got)
	}
}

// The scan itself catches what it must: every form, a renamed import, a
// dot-import, and nothing in a test file; a pointer type is not a value.
func TestStructureScanCatches(t *testing.T) {
	dir := t.TempDir()
	src := `package x

import (
	"crypto/tls"
	"net"
	h "net/http"
	"net/smtp"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type holder struct {
	c   h.Client
	ok  *h.Client
	h.Transport
}

var zero h.Client

func f(passed *h.Client) {
	net.Dial("tcp", "x")
	_ = net.Dialer{}
	net.ListenPacket("udp", ":0")
	_ = h.DefaultClient
	h.Get("http://x")
	_ = &h.Transport{}
	_ = h.Client{}
	_ = new(h.Client)
	_ = new(h.Transport)
	var c h.Client
	c.Get("http://x")
	_ = h.ProxyFromEnvironment
	tls.Dial("tcp", "x", nil)
	smtp.SendMail("x", nil, "", nil, nil)
	s3.New(s3.Options{})
}
`
	writeFile(t, filepath.Join(dir, "x.go"), src)
	writeFile(t, filepath.Join(dir, "x_test.go"), src)
	writeFile(t, filepath.Join(dir, "dot.go"), "package x\n\nimport . \"net/http\"\n\nfunc g() { Get(\"http://x\") }\n")
	var uses []string
	for _, u := range scanTree(t, dir, []string{"."}) {
		uses = append(uses, fmt.Sprintf("%s:%d %s", u.file, u.line, u.use))
	}
	want := []string{
		"dot.go:3 dot-import of net/http",
		"x.go:12 http.Client", "x.go:14 http.Transport", "x.go:17 http.Client",
		"x.go:20 net.Dial", "x.go:21 net.Dialer", "x.go:22 net.ListenPacket", "x.go:23 http.DefaultClient", "x.go:24 http.Get",
		"x.go:25 http.Transport", "x.go:26 http.Client", "x.go:27 http.Client", "x.go:28 http.Transport", "x.go:29 http.Client",
		"x.go:31 http.ProxyFromEnvironment", "x.go:32 tls.Dial", "x.go:33 smtp.SendMail", "x.go:34 s3.New",
	}
	sort.Strings(uses)
	sort.Strings(want)
	if !slices.Equal(uses, want) {
		t.Errorf("found\n%q\nwant\n%q", uses, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
