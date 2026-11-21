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
//     anything of net/smtp; net/rpc's and net/rpc/jsonrpc's Dial,
//     DialHTTP and DialHTTPPath, net/textproto.Dial;
//   - DNS lookups, a channel out of their own (a name under a domain
//     someone else serves carries data to its servers): every net.Lookup*,
//     net.ResolveTCPAddr, ResolveUDPAddr and ResolveIPAddr,
//     net.DefaultResolver and the net.Resolver type;
//   - httputil's ReverseProxy and NewSingleHostReverseProxy (a nil
//     Transport sends through the default transport);
//   - http.DefaultClient, http.DefaultTransport, http.Get, Head, Post,
//     PostForm and ProxyFromEnvironment;
//   - an http.Client or http.Transport value made outside: a composite
//     literal, new(...) or make(...), a variable, struct field or declared
//     type of the type (an alias or a defined type: a zero Client sends
//     through the default transport), or of an array, slice, map or
//     channel of it, and in a composite literal a pointer element too (an
//     elided {} makes one); a pointer to one, handed in, is not caught;
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
	{"server/daemon/control.go", "net.DialTimeout", 2, "the daemon's own Unix control socket in the data directory (decision 11): route's client, and controlAnswers, the probe of commands that must not run beside a running varlatchd (the migration's)"},
	{"server/daemon/backup.go", "net.DialTimeout", 1, "restore checks that no varlatchd answers on the data directory's control socket"},
	{"server/daemon/schema.go", "net.DialTimeout", 1, "a schema upgrade checks that no varlatchd answers on the data directory's control socket, as restore does"},
	{"server/clientaddr/clientaddr.go", "net.DefaultResolver", 1, "the names in the host's trusted_proxies, looked up every 30 seconds (the host's configuration, never an Organization's)"},
	{"server/auditexport/probe.go", "backup.NewClient", 1, "the audit export's destination, on the outbound policy's audit_export client (ADR-0057 Decision 9: the S3 client takes the policy's transport)"},
	{"server/backups/backups.go", "backup.NewClient", 1, "the host's backup destination, for uploads and the bucket test (ADR-0057 Decision 1: 4.14's uploads are an exception by name)"},
}

// libExceptions are go/lib's: code the CLI shares, whose destinations the
// host or the user chose.
var libExceptions = []exception{
	{"lib/backup/s3.go", "http.Client", 1, "the backup destination's client when none is passed in (the CLI's admin backup; varlatchd passes none today: its destination is the host's)"},
	{"lib/backup/s3.go", "s3.New", 1, "the backup destination's S3 client, on the http.Client passed in or the one above"},
	{"lib/release/verify.go", "http.DefaultClient", 1, "Sigstore's TUF repository (fixed, not chosen by an Organization), for the release verifier of the installer and upgrade"},
	{"lib/release/download.go", "http.Client", 1, "release files from github.com and its storage hosts only (fixed, not chosen by an Organization), every redirect checked, on the Transport passed in: varlatchd's serve_cli passes the outbound policy's"},
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
	{path: "net/rpc", name: "Dial"}, {path: "net/rpc", name: "DialHTTP"}, {path: "net/rpc", name: "DialHTTPPath"},
	{path: "net/rpc/jsonrpc", name: "Dial"}, {path: "net/textproto", name: "Dial"},
	{path: "net", name: "Lookup*"}, {path: "net", name: "DefaultResolver"}, {path: "net", name: "Resolver"},
	{path: "net", name: "ResolveTCPAddr"}, {path: "net", name: "ResolveUDPAddr"}, {path: "net", name: "ResolveIPAddr"},
	{path: "net/http/httputil", name: "ReverseProxy"}, {path: "net/http/httputil", name: "NewSingleHostReverseProxy"},
	{path: "net/http", name: "DefaultClient"}, {path: "net/http", name: "DefaultTransport"},
	{path: "net/http", name: "Get"}, {path: "net/http", name: "Head"}, {path: "net/http", name: "Post"}, {path: "net/http", name: "PostForm"},
	{path: "net/http", name: "ProxyFromEnvironment"},
	{path: "net/http", name: "Client", value: true}, {path: "net/http", name: "Transport", value: true},
	{path: "github.com/aws/aws-sdk-go-v2/service/s3", name: "New"}, {path: "github.com/aws/aws-sdk-go-v2/service/s3", name: "NewFromConfig"},
	{path: "github.com/varlatch/varlatch/go/lib/backup", name: "NewClient"},
}

// guarded are the packages a dot-import of is refused.
var guarded = []string{"net", "net/http", "crypto/tls", "net/smtp", "net/rpc", "net/rpc/jsonrpc", "net/textproto", "net/http/httputil"}

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
			named := r.name == sel.Sel.Name || r.name == "*" || strings.HasSuffix(r.name, "*") && strings.HasPrefix(sel.Sel.Name, strings.TrimSuffix(r.name, "*"))
			if r.path == p && named && r.value == value {
				return p[strings.LastIndexByte(p, '/')+1:] + "." + sel.Sel.Name, true
			}
		}
		return "", false
	}
	// valueOf reports a value use of a guarded type: the type itself, or
	// the element type of an array, slice, map or channel of it; a pointer
	// only where literal says so (a composite literal's elements, where
	// an elided {} makes one).
	var valueOf func(typ ast.Expr, literal bool)
	valueOf = func(typ ast.Expr, literal bool) {
		switch t := typ.(type) {
		case nil:
		case *ast.ParenExpr:
			valueOf(t.X, literal)
		case *ast.ArrayType:
			valueOf(t.Elt, literal)
		case *ast.MapType:
			valueOf(t.Key, literal)
			valueOf(t.Value, literal)
		case *ast.ChanType:
			valueOf(t.Value, literal)
		case *ast.StarExpr:
			if literal {
				valueOf(t.X, literal)
			}
		default:
			if u, ok := match(typ, true); ok {
				add(typ, u)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			// The literal's type and its element types, pointers included
			// ([]*http.Client{{}} makes Clients). An elided inner
			// literal has no type: the outer one was judged.
			valueOf(n.Type, true)
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && (id.Name == "new" || id.Name == "make") && len(n.Args) >= 1 {
				valueOf(n.Args[0], false)
			}
		case *ast.ValueSpec:
			valueOf(n.Type, false)
		case *ast.Field:
			valueOf(n.Type, false)
		case *ast.TypeSpec:
			valueOf(n.Type, false)
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
// dot-import, declared types, element types, DNS lookups, and nothing in a
// test file; a pointer type is not a value outside a composite literal.
func TestStructureScanCatches(t *testing.T) {
	dir := t.TempDir()
	src := `package x

import (
	"crypto/tls"
	"net"
	h "net/http"
	"net/http/httputil"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/smtp"
	"net/textproto"
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

type alias = h.Client
type defined h.Transport
type pointer *h.Client

var (
	list   []h.Client
	table  map[string]h.Transport
	queue  chan h.Client
	refs   []*h.Client
	array  [2]h.Client
)

func g() {
	_ = []h.Client{{}}
	_ = []*h.Client{{}}
	_ = map[string]*h.Transport{"a": {}}
	_ = make([]h.Client, 3)
	_ = make(chan *h.Client)
	net.LookupHost("x")
	net.LookupTXT("x")
	net.ResolveTCPAddr("tcp", "x:1")
	_ = &httputil.ReverseProxy{}
	_ = net.DefaultResolver
	_ = &net.Resolver{}
	rpc.Dial("tcp", "x")
	jsonrpc.Dial("tcp", "x")
	textproto.Dial("tcp", "x")
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
		"x.go:16 http.Client", "x.go:18 http.Transport", "x.go:21 http.Client",
		"x.go:24 net.Dial", "x.go:25 net.Dialer", "x.go:26 net.ListenPacket", "x.go:27 http.DefaultClient", "x.go:28 http.Get",
		"x.go:29 http.Transport", "x.go:30 http.Client", "x.go:31 http.Client", "x.go:32 http.Transport", "x.go:33 http.Client",
		"x.go:35 http.ProxyFromEnvironment", "x.go:36 tls.Dial", "x.go:37 smtp.SendMail", "x.go:38 s3.New",
		"x.go:41 http.Client", "x.go:42 http.Transport",
		"x.go:46 http.Client", "x.go:47 http.Transport", "x.go:48 http.Client", "x.go:50 http.Client",
		"x.go:54 http.Client", "x.go:55 http.Client", "x.go:56 http.Transport", "x.go:57 http.Client",
		"x.go:59 net.LookupHost", "x.go:60 net.LookupTXT", "x.go:61 net.ResolveTCPAddr", "x.go:62 httputil.ReverseProxy",
		"x.go:63 net.DefaultResolver", "x.go:64 net.Resolver",
		"x.go:65 rpc.Dial", "x.go:66 jsonrpc.Dial", "x.go:67 textproto.Dial",
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
