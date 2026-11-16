// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The adapters take the caller's *http.Client and never build one
// (ADR-0059 step 4, decision 6): varlatchd passes its outbound policy's
// client, the CLI a plain one. No file of this package (tests aside) may
// make a client, a transport or a dialer, or use the default ones; the
// one copy of the caller's client (transport.go's send, to refuse
// redirects) keeps its transport.
func TestAdaptersNeverBuildAClient(t *testing.T) {
	forbidden := map[string]map[string]bool{
		"http": {"Client": true, "Transport": true, "DefaultClient": true, "DefaultTransport": true,
			"Get": true, "Post": true, "Head": true, "PostForm": true, "NewFileTransport": true},
		"net": {"Dial": true, "DialTimeout": true, "Dialer": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true},
		"tls": {"Dial": true, "DialWithDialer": true, "Dialer": true, "Client": true},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if names, ok := forbidden[pkg.Name]; ok && names[sel.Sel.Name] {
				// The one use allowed: *http.Client as a type (Request.Client).
				if pkg.Name == "http" && sel.Sel.Name == "Client" && typeOnly(f, sel) {
					return true
				}
				t.Errorf("%s: %s.%s", fset.Position(sel.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if checked < 8 {
		t.Fatalf("checked only %d files", checked)
	}
}

// typeOnly reports whether sel appears only as the element of a pointer
// type (*http.Client, Request.Client's type). A value of type http.Client
// (a composite literal, new(http.Client), or a var of the type) is a
// client made from scratch.
func typeOnly(f *ast.File, sel *ast.SelectorExpr) bool {
	pointer := false
	ast.Inspect(f, func(n ast.Node) bool {
		if star, ok := n.(*ast.StarExpr); ok && star.X == sel {
			pointer = true
		}
		return true
	})
	return pointer
}

// roundTrips counts the requests a transport saw.
type roundTrips struct {
	n      int
	answer func(*http.Request) *http.Response
}

func (r *roundTrips) RoundTrip(req *http.Request) (*http.Response, error) {
	r.n++
	return r.answer(req), nil
}

// A request goes through the caller's transport, with the caller's
// client otherwise intact, and a redirect is refused even by a client that
// would follow one.
func TestSendUsesTheCallersTransportAndRefusesRedirects(t *testing.T) {
	transport := &roundTrips{answer: func(r *http.Request) *http.Response {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://elsewhere.example/x"}},
			Body: io.NopCloser(strings.NewReader("")), Request: r}
	}}
	followed := false
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		followed = true
		return nil
	}}
	req := &Request{BaseIdentity: "https://coolify.example.com", Credential: "tok", Client: client}
	_, err := send(context.Background(), req, "GET", "https://coolify.example.com/api/v1/version", nil, nil)
	var ae *AdapterError
	if !errors.As(err, &ae) || ae.Message != "TypeError" || transportProblem(err) != problemRedirect {
		t.Fatalf("got %v, want a refused redirect", err)
	}
	if transport.n != 1 || followed {
		t.Fatalf("transport saw %d requests, followed %v", transport.n, followed)
	}
	if client.CheckRedirect == nil {
		t.Fatal("the caller's client was changed")
	}
	if check := CoolifyAdapter.CheckAccess(context.Background(), req); check.Status != StatusUnreachable ||
		!strings.Contains(check.Message, "answered with a redirect") {
		t.Fatalf("check: %+v", check)
	}
	if _, err := send(context.Background(), &Request{}, "GET", "https://x.example/", nil, nil); err == nil {
		t.Fatal("a request without a client must fail")
	}
}

func TestRequestTimeoutIsTimeoutError(t *testing.T) {
	slow := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	req := &Request{Client: slow, Timeout: 20 * time.Millisecond}
	_, err := send(context.Background(), req, "GET", "https://x.example/", nil, nil)
	var ae *AdapterError
	if !errors.As(err, &ae) || ae.Message != "TimeoutError" || transportProblem(err) != problemTimeout {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := send(ctx, req, "GET", "https://x.example/", nil, nil); !errors.As(err, &ae) || ae.Message != "AbortError" {
		t.Fatalf("cancelled: got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The outbound policy's refusal is found through any wrapping, in the
// host's words.
func TestPolicyRefusal(t *testing.T) {
	r := &refusal{"This address is on a private network."}
	for _, err := range []error{r, &AdapterError{Message: "TypeError", Cause: errors.Join(errors.New("dial"), r)}} {
		if msg, ok := PolicyRefusal(err); !ok || msg != r.message {
			t.Fatalf("%v: %q %v", err, msg, ok)
		}
	}
	if _, ok := PolicyRefusal(errors.New("ECONNREFUSED")); ok {
		t.Fatal("not a refusal")
	}
	if _, err := os.Stat("testdata/ts-exchanges.json"); err != nil {
		t.Fatal(err)
	}
}
