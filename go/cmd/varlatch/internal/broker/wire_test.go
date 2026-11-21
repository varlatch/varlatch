// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The Agent's side of the wire against testdata/vectors/broker-wire.json,
// recorded from broker.ts and Node.js's parser by
// apps/cli/test/go-vectors-broker-wire.test.ts: every byte the Broker
// answers a raw request with, but for the differences go/README.md lists.

// wireDifferences are the documented ones: where Node.js reads a request
// line leniently, the Go Broker refuses it (go/README.md, "The Broker's
// HTTP/1.1 reader").
var wireDifferences = map[string]string{
	"parse.two-spaces": rawRefusal(errBadRequest),
	"parse.no-version": rawRefusal(errBadRequest),
	"parse.http2-line": rawRefusal(errBadRequest),
}

var (
	wireDate    = regexp.MustCompile(`\r\nDate: [^\r]*\r\n`)
	wireNetwork = regexp.MustCompile(`[0-9a-f]+\r\nvarlatch-broker: (?:dial tcp|read tcp|write tcp|EOF)[^\n]*\n`)
)

func wireSend(t *testing.T, port int, raw []byte) string {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	go func() { _, _ = conn.Write(raw) }()
	out, _ := io.ReadAll(conn)
	return string(out)
}

func itoa(n int) string { return jsjson.Number(float64(n)) }

func TestWireVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/broker-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := str(doc, "placeholder")
	closed := str(doc, "closed")
	for _, c := range list(doc, "cases") {
		name := str(c, "name")
		t.Run(name, func(t *testing.T) {
			b, err := Start(Options{
				Placeholders: map[string]string{placeholder: "API_KEY"},
				Destinations: []string{"api.example.com:443", closed},
				Targets:      map[string][]string{"API_KEY": {"header:authorization"}},
				Strict:       field(c, "strict") == true,
				Exercise: func(context.Context, string, int, []Placement) (Exercised, error) {
					return Exercised{}, errors.New("not exercised in these vectors")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			basic := base64.StdEncoding.EncodeToString([]byte("vlt:" + b.Token))
			fill := strings.NewReplacer(
				"{{auth}}", "Proxy-Authorization: Basic "+basic,
				"{{basic}}", basic,
				"{{other-user}}", base64.StdEncoding.EncodeToString([]byte("varlatch:"+b.Token)),
				"{{placeholder}}", placeholder,
			)
			request := str(c, "raw")
			if name == "connect.then-tunnels" {
				wireSend(t, b.Port, latin1Raw(t, fill.Replace(request)))
				request = "GET " + TunnelsPath + " HTTP/1.1\r\nHost: x\r\n{{auth}}\r\n\r\n"
			}
			got := wireSend(t, b.Port, latin1Raw(t, fill.Replace(request)))
			got = wireDate.ReplaceAllString(got, "\r\nDate: {{date}}\r\n")
			got = strings.ReplaceAll(got, b.Token, "{{token}}")
			got = wireNetwork.ReplaceAllString(got, "{{size}}\r\nvarlatch-broker: {{network}}\n")
			want, _ := latin1Bytes(str(c, "reply"))
			if d, ok := wireDifferences[name]; ok {
				want = []byte(d)
			}
			if got != string(want) {
				t.Fatalf("reply\n%q\nwant\n%q", got, want)
			}
		})
	}
}

func latin1Raw(t *testing.T, s string) []byte {
	b, ok := latin1Bytes(s)
	if !ok {
		t.Fatalf("not latin1: %q", s)
	}
	return b
}

// FuzzReadHead: the reader never panics, never reads past its bounds, and
// whatever it accepts is unambiguous: header names are tokens, values hold
// no CR, LF, NUL or other control but a tab, and the body's framing is one
// of none, a length of digits, or chunked alone.
func FuzzReadHead(f *testing.F) {
	for _, seed := range []string{
		"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
		"POST http://a/ HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n",
		"GET / HTTP/1.1\nHost: a\n\n",
		"CONNECT a:443 HTTP/1.1\r\n\r\n",
		"\r\n\r\nGET / HTTP/1.0\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		h, err := readHead(r)
		if err != nil {
			return
		}
		if len(h.headers) > maxHeaderFields {
			t.Fatalf("%d header fields", len(h.headers))
		}
		for _, p := range h.headers {
			if !isToken(p.Name) {
				t.Fatalf("name %q", p.Name)
			}
			for _, c := range p.Value {
				if (c < 0x20 && c != '\t') || c == 0x7f {
					t.Fatalf("value %q", p.Value)
				}
			}
		}
		lengths, codings := 0, 0
		for _, p := range h.headers {
			switch strings.ToLower(p.Name) {
			case "content-length":
				lengths++
			case "transfer-encoding":
				codings++
			}
		}
		switch h.framing {
		case "none":
			if lengths+codings != 0 {
				t.Fatal("framing none with framing headers")
			}
		case "length":
			if lengths != 1 || codings != 0 || h.length < 0 {
				t.Fatal("framing length")
			}
		case "chunked":
			if codings != 1 || lengths != 0 {
				t.Fatal("framing chunked")
			}
		default:
			t.Fatalf("framing %q", h.framing)
		}
		body, over, err := readBody(r, h, 1024)
		if err == nil && !over && int64(len(body)) > 1024 {
			t.Fatalf("a body of %d bytes over the limit", len(body))
		}
	})
}
