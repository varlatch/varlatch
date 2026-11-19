// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The Broker against testdata/vectors/broker.json, recorded from broker.ts
// and scrub.ts by apps/cli/test/go-vectors-broker.test.ts: the same
// scenario (a Broker, the Agent's request, a scripted TLS destination), the
// same request at the destination and response at the Agent, the same
// events. What is compared, and the differences go/README.md lists:
//
//   - at the destination, the method, path, body and headers as a set but
//     for Connection (each client's own) and User-Agent;
//   - at the Agent, the status, reason phrase, headers as a set but those
//     that frame the connection, body (an aborted one up to where either
//     stopped), and whether it ended as framed;
//   - the events, an abort reported once where TypeScript reports it twice
//     (step 5 defect 42); for a destination that resets its connection after
//     the headers, the Go Broker's abort as go/README.md describes it.

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// destination is the scripted TLS server: it records the first request,
// then plays the steps.
type destination struct {
	port     int
	mu       sync.Mutex
	received []byte
	l        net.Listener
}

func startDestination(t *testing.T, cert tls.Certificate, steps []any) *destination {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &destination{port: l.Addr().(*net.TCPAddr).Port, l: l}
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			go d.serve(raw, tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}}), steps)
		}
	}()
	return d
}

func (d *destination) serve(raw net.Conn, conn *tls.Conn, steps []any) {
	defer conn.Close()
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if end := bytes.Index(buf, []byte("\r\n\r\n")); end >= 0 {
			head := strings.ToLower(string(buf[:end]))
			length := 0
			if i := strings.Index(head, "\r\ncontent-length:"); i >= 0 {
				rest := strings.TrimSpace(strings.SplitN(head[i+len("\r\ncontent-length:"):], "\r\n", 2)[0])
				length, _ = strconv.Atoi(rest)
			}
			if len(buf) >= end+4+length {
				d.mu.Lock()
				if d.received == nil {
					d.received = slices.Clone(buf[:end+4+length])
				}
				d.mu.Unlock()
				break
			}
		}
		if err != nil {
			return
		}
	}
	for _, step := range steps {
		switch {
		case field(step, "write") != nil:
			b, _ := latin1Bytes(str(step, "write"))
			if _, err := conn.Write(b); err != nil {
				return
			}
		case field(step, "writeB64") != nil:
			b, _ := base64.StdEncoding.DecodeString(str(step, "writeB64"))
			if _, err := conn.Write(b); err != nil {
				return
			}
		case field(step, "fill") != nil:
			if _, err := conn.Write(bytes.Repeat([]byte(str(step, "fill")), int(field(step, "bytes").(float64)))); err != nil {
				return
			}
		case field(step, "pause") != nil:
			time.Sleep(time.Duration(field(step, "pause").(float64)) * time.Millisecond)
		case field(step, "end") != nil:
			_ = conn.CloseWrite()
			time.Sleep(50 * time.Millisecond)
			return
		case field(step, "reset") != nil:
			_ = raw.(*net.TCPConn).SetLinger(0)
			_ = raw.Close()
			return
		case field(step, "bomb") != nil:
			head, _ := latin1Bytes(str(step, "head"))
			if _, err := conn.Write(head); err != nil {
				return
			}
			var body bytes.Buffer
			var w io.WriteCloser
			switch str(step, "bomb") {
			case "gzip":
				w = gzip.NewWriter(&body)
			case "deflate":
				w = zlib.NewWriter(&body)
			default:
				w = brotli.NewWriter(&body)
			}
			_, _ = w.Write(make([]byte, int(field(step, "bytes").(float64))))
			_ = w.Close()
			if _, err := conn.Write(body.Bytes()); err != nil {
				return
			}
		}
	}
}

// headerSet is header lines as sorted [name, value] pairs, names
// lower-cased, without the names left out.
func headerSet(lines []string, skip ...string) [][2]string {
	var out [][2]string
	for _, l := range lines {
		name, value, _ := strings.Cut(l, ":")
		name = strings.ToLower(name)
		if slices.Contains(skip, name) {
			continue
		}
		out = append(out, [2]string{name, strings.TrimSpace(value)})
	}
	slices.SortFunc(out, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	return out
}

func recordedSet(v any) [][2]string {
	var out [][2]string
	for _, p := range v.([]any) {
		pair := p.([]any)
		out = append(out, [2]string{pair[0].(string), pair[1].(string)})
	}
	return out
}

type agentReply struct {
	status   int
	reason   string
	headers  [][2]string
	body     []byte
	complete bool
}

// parseAgent is the recorder's parseAgent.
func parseAgent(raw []byte, method string) (agentReply, bool) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		return agentReply{}, false
	}
	lines := strings.Split(string(raw[:end]), "\r\n")
	statusLine := strings.TrimPrefix(lines[0], "HTTP/1.1 ")
	codeText, reason, _ := strings.Cut(statusLine, " ")
	status, _ := strconv.Atoi(codeText)
	all := headerSet(lines[1:])
	r := agentReply{status: status, reason: latin1([]byte(reason)), headers: headerSet(lines[1:], "date", "connection", "keep-alive", "transfer-encoding")}
	rest := raw[end+4:]
	chunked, length := false, -1
	for _, h := range all {
		if h[0] == "transfer-encoding" && strings.EqualFold(h[1], "chunked") {
			chunked = true
		}
		if h[0] == "content-length" {
			length, _ = strconv.Atoi(h[1])
		}
	}
	switch {
	case method == "HEAD" || status == 204 || status == 304 || status == 100:
		r.complete = len(rest) == 0
	case chunked:
		for {
			lineEnd := bytes.Index(rest, []byte("\r\n"))
			if lineEnd < 0 {
				break
			}
			size, err := strconv.ParseInt(string(rest[:lineEnd]), 16, 64)
			if err != nil {
				break
			}
			if size == 0 {
				r.complete = bytes.HasPrefix(rest[lineEnd:], []byte("\r\n\r\n"))
				break
			}
			if int64(len(rest)) < int64(lineEnd)+2+size+2 {
				r.body = append(r.body, rest[lineEnd+2:]...)
				break
			}
			r.body = append(r.body, rest[lineEnd+2:int64(lineEnd)+2+size]...)
			rest = rest[int64(lineEnd)+2+size+2:]
		}
	case length >= 0:
		r.body = rest[:min(length, len(rest))]
		r.complete = len(rest) == length
	default:
		r.body = rest
		r.complete = true
	}
	return r, true
}

// eventsOf is the events as the recorder writes them.
func eventsOf(events []Event) []string {
	var out []string
	for _, e := range events {
		o := jsjson.Object{{Key: "kind", Value: e.Kind}}
		switch e.Kind {
		case "blocked":
			o = append(o, jsjson.Member{Key: "status", Value: float64(e.Status)}, jsjson.Member{Key: "rule", Value: e.Rule}, jsjson.Member{Key: "message", Value: e.Message})
		case "failed":
			o = append(o, jsjson.Member{Key: "rule", Value: e.Rule}, jsjson.Member{Key: "message", Value: e.Message})
		case "stray":
			o = append(o, jsjson.Member{Key: "item", Value: e.Item}, jsjson.Member{Key: "surface", Value: e.Surface})
		case "tunnel":
			o = append(o, jsjson.Member{Key: "destination", Value: e.Destination})
		case "scrubbed":
			o = append(o, jsjson.Member{Key: "item", Value: e.Item}, jsjson.Member{Key: "count", Value: float64(e.Count)})
		case "unscrubbable":
			o = append(o, jsjson.Member{Key: "item", Value: e.Item})
		case "incomplete-prefix":
			o = append(o, jsjson.Member{Key: "item", Value: e.Item}, jsjson.Member{Key: "length", Value: float64(e.Length)})
		case "aborted":
			o = append(o, jsjson.Member{Key: "reason", Value: e.Reason})
		}
		out = append(out, string(jsjson.Stringify(o)))
	}
	return out
}

// recordedEvents are the recorded events as the Go Broker gives them: an
// abort reported twice is reported once (defect 42), and a destination's
// reset after the headers is the abort go/README.md describes.
func recordedEvents(name string, v []any) []string {
	var out []string
	for _, e := range v {
		s := string(jsjson.Stringify(e))
		if len(out) > 0 && out[len(out)-1] == s && str(e, "kind") == "aborted" {
			continue
		}
		out = append(out, s)
	}
	if name == "abort.reset-mid-stream" {
		return []string{`{"kind":"aborted","reason":"the destination's response failed mid-stream"}`}
	}
	return out
}

type exerciseError struct{ message string }

func (e exerciseError) Error() string { return e.message }

func TestBrokerScenarios(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/broker.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, pool := testCert(t)
	placeholders := map[string]string{}
	phOf := map[string]string{}
	for _, m := range field(doc, "placeholders").(jsjson.Object) {
		placeholders[m.Value.(string)] = m.Key
		phOf[m.Key] = m.Value.(string)
	}
	secret := str(doc, "secret")
	for _, sc := range list(doc, "scenarios") {
		name := str(sc, "name")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dest := startDestination(t, cert, list(sc, "upstream"))
			defer dest.l.Close()
			targets := map[string][]string{"API_KEY": {"header:authorization"}, "DB_PASSWORD": {"header:x-db"}}
			if v := field(sc, "targets"); v != nil {
				targets = toTargets(v)
			}
			values := map[string]string{"API_KEY": secret, "DB_PASSWORD": `hunter2/db"pass word`}
			if v := field(sc, "values"); v != nil {
				values = toStrings(v)
			}
			ex := field(sc, "exercise")
			var mu sync.Mutex
			var events []Event
			exercises := 0
			limits := DefaultLimits
			if l := field(sc, "limits"); l != nil {
				if v, ok := field(l, "maxDecodedBytes").(float64); ok {
					limits.MaxDecodedBytes = int64(v)
				}
				if v, ok := field(l, "idleMs").(float64); ok {
					limits.IdleMillis = int64(v)
				}
				if v, ok := field(l, "bufferedBytes").(float64); ok {
					limits.BufferedBytes = int64(v)
				}
			}
			b, err := Start(Options{
				Placeholders: placeholders,
				Destinations: []string{"127.0.0.1:" + strconv.Itoa(dest.port)},
				Targets:      targets,
				Strict:       field(sc, "strict") == true,
				Limits:       limits,
				RootCAs:      pool,
				Report: func(e Event) {
					mu.Lock()
					events = append(events, e)
					mu.Unlock()
				},
				Exercise: func(_ context.Context, _ string, _ int, placements []Placement) (Exercised, error) {
					mu.Lock()
					exercises++
					mu.Unlock()
					if e := field(ex, "error"); e != nil {
						if str(e, "code") != "" {
							return Exercised{}, &apiclient.APIError{Code: str(e, "code"), Message: str(e, "message")}
						}
						return Exercised{}, exerciseError{str(e, "message")}
					}
					out := Exercised{Values: map[string]string{}, Targets: targets}
					if v := field(ex, "values"); v != nil {
						out.Values = toStrings(v)
					} else {
						for _, p := range placements {
							out.Values[p.Item] = values[p.Item]
						}
					}
					if v := field(ex, "targets"); v != nil {
						out.Targets = toTargets(v)
					}
					for _, w := range list(ex, "withheld") {
						out.Withheld = append(out.Withheld, w.(string))
					}
					if v := field(ex, "retiring"); v != nil {
						out.Retiring = toStrings(v)
					}
					return out, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			basic := base64.StdEncoding.EncodeToString([]byte("vlt:" + b.Token))
			request := strings.ReplaceAll(strings.ReplaceAll(str(sc, "request"), "{{port}}", strconv.Itoa(dest.port)), "{{auth}}", "Proxy-Authorization: Basic "+basic)
			for item, ph := range phOf {
				request = strings.ReplaceAll(request, "{{ph:"+item+"}}", ph)
			}
			if head, body, ok := strings.Cut(request, "\r\n\r\n"); ok && strings.Contains(head, "Content-Length: ") {
				i := strings.LastIndex(head, "Content-Length: ")
				head = head[:i] + "Content-Length: " + strconv.Itoa(len(body))
				request = head + "\r\n\r\n" + body
			}
			wait := 2000 * time.Millisecond
			if w, ok := field(sc, "wait").(float64); ok {
				wait = time.Duration(w) * time.Millisecond
			}
			wait *= raceSlowdown
			conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.Port))
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(wait))
			reqBytes, _ := latin1Bytes(request)
			_, _ = conn.Write(reqBytes)
			if leave, ok := field(sc, "agentLeavesAfter").(float64); ok {
				time.AfterFunc(time.Duration(leave)*time.Millisecond, func() { _ = conn.Close() })
			}
			got, _ := io.ReadAll(conn)
			_ = conn.Close()
			time.Sleep(100 * time.Millisecond)
			// The destination's port is each run's own: written {{port}} once
			// parsed (a chunk's size counts its digits).
			port := strconv.Itoa(dest.port)
			unport := func(v string) string { return strings.ReplaceAll(v, port, "{{port}}") }
			want := field(sc, "expect")

			// At the destination.
			dest.mu.Lock()
			received := bytes.ReplaceAll(dest.received, []byte(port), []byte("{{port}}"))
			if dest.received == nil {
				received = nil
			}
			dest.mu.Unlock()
			if wd := field(want, "destination"); wd == nil {
				if received != nil {
					t.Fatalf("the destination got a request: %q", received)
				}
			} else {
				if received == nil {
					t.Fatal("the destination got no request")
				}
				end := bytes.Index(received, []byte("\r\n\r\n"))
				lines := strings.Split(string(received[:end]), "\r\n")
				parts := strings.SplitN(lines[0], " ", 3)
				if parts[0] != str(wd, "method") || parts[1] != str(wd, "path") {
					t.Fatalf("destination request %s %s, want %s %s", parts[0], parts[1], str(wd, "method"), str(wd, "path"))
				}
				gotHeaders := headerSet(lines[1:], "connection", "user-agent")
				var wantHeaders [][2]string
				for _, h := range recordedSet(field(wd, "headers")) {
					if h[0] != "connection" && h[0] != "user-agent" {
						wantHeaders = append(wantHeaders, h)
					}
				}
				for i := range gotHeaders {
					gotHeaders[i][1] = latin1([]byte(gotHeaders[i][1]))
				}
				if !slices.Equal(gotHeaders, wantHeaders) {
					t.Fatalf("destination headers\n%q\nwant\n%q", gotHeaders, wantHeaders)
				}
				wantBody, _ := base64.StdEncoding.DecodeString(str(wd, "bodyB64"))
				if !bytes.Equal(received[end+4:], wantBody) {
					t.Fatalf("destination body %q, want %q", received[end+4:], wantBody)
				}
			}

			// At the Agent.
			wa := field(want, "agent")
			if name == "pass.upgrade" {
				// TypeScript answers nothing (step 5 defect 43); Go refuses
				// the switch (go/README.md).
				wa = jsjson.Object{{Key: "status", Value: float64(502)}, {Key: "reason", Value: "Bad Gateway"},
					{Key: "headers", Value: []any{[]any{"content-type", "text/plain"}, []any{"varlatch-broker", "refused"}}},
					{Key: "bodyB64", Value: base64.StdEncoding.EncodeToString([]byte("varlatch-broker: the destination switched protocols; the Broker relays HTTP only\n"))},
					{Key: "complete", Value: true}}
			}
			if wa != nil {
				method, _, _ := strings.Cut(request, " ")
				r, ok := parseAgent(got, method)
				if !ok {
					t.Fatalf("no response: %q", got)
				}
				r.reason = unport(r.reason)
				r.body = []byte(unport(string(r.body)))
				for i := range r.headers {
					r.headers[i][1] = unport(r.headers[i][1])
				}
				if float64(r.status) != field(wa, "status") || r.reason != str(wa, "reason") || r.complete != (field(wa, "complete") == true) {
					t.Fatalf("agent %d %q complete %v, want %v %q %v (%q)", r.status, r.reason, r.complete, field(wa, "status"), str(wa, "reason"), field(wa, "complete"), got)
				}
				for i := range r.headers {
					r.headers[i][1] = latin1([]byte(r.headers[i][1]))
				}
				if !slices.Equal(r.headers, recordedSet(field(wa, "headers"))) {
					t.Fatalf("agent headers\n%q\nwant\n%q", r.headers, recordedSet(field(wa, "headers")))
				}
				if b64, ok := field(wa, "bodyB64").(string); ok {
					wantBody, _ := base64.StdEncoding.DecodeString(b64)
					// An aborted body stops where the destination's bytes
					// happened to arrive: one is a prefix of the other.
					aborted := !r.complete && (bytes.HasPrefix(r.body, wantBody) || bytes.HasPrefix(wantBody, r.body))
					if !aborted && !bytes.Equal(r.body, wantBody) {
						t.Fatalf("agent body %q, want %q", r.body, wantBody)
					}
				} else {
					sum := sha256.Sum256(r.body)
					if float64(len(r.body)) != field(wa, "bodyLength") || hex.EncodeToString(sum[:]) != str(wa, "bodySha256") {
						t.Fatalf("agent body of %d bytes, want %v", len(r.body), field(wa, "bodyLength"))
					}
				}
			}

			// Events, exercises and what is held.
			b.Close()
			mu.Lock()
			gotEvents := eventsOf(events)
			gotExercises := exercises
			mu.Unlock()
			if wantEvents := recordedEvents(name, list(want, "events")); !slices.Equal(gotEvents, wantEvents) {
				t.Fatalf("events\n%q\nwant\n%q", gotEvents, wantEvents)
			}
			if float64(gotExercises) != field(want, "exercises") {
				t.Fatalf("%d exercises, want %v", gotExercises, field(want, "exercises"))
			}
			if b.HeldValues() != 0 {
				t.Fatalf("%d value sets held after the request", b.HeldValues())
			}
			if secret != "" && bytes.Contains(got, []byte(secret)) && !strings.HasPrefix(name, "pass.") {
				t.Fatal("the Agent received the Secret")
			}
		})
	}
}

func toStrings(v any) map[string]string {
	out := map[string]string{}
	for _, m := range v.(jsjson.Object) {
		out[m.Key] = m.Value.(string)
	}
	return out
}

func toTargets(v any) map[string][]string {
	out := map[string][]string{}
	for _, m := range v.(jsjson.Object) {
		out[m.Key] = []string{}
		for _, t := range m.Value.([]any) {
			out[m.Key] = append(out[m.Key], t.(string))
		}
	}
	return out
}

var _ = errors.New
