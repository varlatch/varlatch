// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSlowClientIsCutOff: a client that never finishes its request's head
// is answered 408, as Node.js answers it, when the head timeout passes,
// and the Broker keeps serving others.
func TestSlowClientIsCutOff(t *testing.T) {
	saved := headTimeout
	headTimeout = 300 * time.Millisecond
	defer func() { headTimeout = saved }()
	b, err := Start(Options{Destinations: []string{"api.example.com:443"}, Exercise: noExercise})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET " + TunnelsPath + " HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(conn)
	if string(got) != rawRefusal(errTimeout) {
		t.Fatalf("%q", got)
	}
	// Another client is still served.
	basic := base64.StdEncoding.EncodeToString([]byte("vlt:" + b.Token))
	reply := wireSend(t, b.Port, []byte("GET "+TunnelsPath+" HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic "+basic+"\r\n\r\n"))
	if !strings.HasPrefix(reply, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("%q", reply)
	}
}

// TestWrongCredentialReachesNothing: without the run's credential, a
// request (its body included, and a Placeholder in it) never reaches its
// destination: no connection is opened there and nothing is exercised.
func TestWrongCredentialReachesNothing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	reached := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			reached <- struct{}{}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	exercised := false
	placeholder := GeneratePlaceholder()
	b, err := Start(Options{
		Placeholders: map[string]string{placeholder: "API_KEY"},
		Destinations: []string{"127.0.0.1:" + strconv.Itoa(port)},
		Targets:      map[string][]string{"API_KEY": {"header:authorization"}},
		Exercise: func(context.Context, string, int, []Placement) (Exercised, error) {
			exercised = true
			return Exercised{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, auth := range []string{"", "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("vlt:wrong")) + "\r\n", "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("other:"+b.Token)) + "\r\n"} {
		for _, target := range []string{"http://127.0.0.1:" + strconv.Itoa(port) + "/", "https://127.0.0.1:" + strconv.Itoa(port) + "/"} {
			reply := wireSend(t, b.Port, []byte("POST "+target+" HTTP/1.1\r\nHost: x\r\n"+auth+"Authorization: Bearer "+placeholder+"\r\nContent-Length: 5\r\n\r\nhello"))
			if !strings.HasPrefix(reply, "HTTP/1.1 407 Proxy Authentication Required\r\n") {
				t.Fatalf("%q", reply)
			}
		}
		reply := wireSend(t, b.Port, []byte("CONNECT 127.0.0.1:"+strconv.Itoa(port)+" HTTP/1.1\r\n"+auth+"\r\n"))
		if !strings.HasPrefix(reply, "HTTP/1.1 407 Proxy Authentication Required\r\n") {
			t.Fatalf("%q", reply)
		}
	}
	select {
	case <-reached:
		t.Fatal("the destination was reached without the credential")
	case <-time.After(200 * time.Millisecond):
	}
	if exercised {
		t.Fatal("the Capability was exercised without the credential")
	}
}

func noExercise(context.Context, string, int, []Placement) (Exercised, error) {
	return Exercised{}, nil
}

// TestPortZeroDialsTheSchemesPort: a URL naming port 0 is checked against
// the scheme's port, and the Broker connects to that port, as broker.ts
// does; the Host header keeps the URL's authority.
func TestPortZeroDialsTheSchemesPort(t *testing.T) {
	for _, c := range []struct{ url, dial string }{
		{"http://127.0.0.1:0/x", "127.0.0.1:80"},
		{"https://api.example.com:0/x", "api.example.com:443"},
		{"https://[::1]:0/x", "[::1]:443"},
		{"https://api.example.com/x", "api.example.com:443"},
	} {
		b, err := Start(Options{Destinations: []string{"127.0.0.1:80"}, Exercise: noExercise})
		if err != nil {
			t.Fatal(err)
		}
		basic := base64.StdEncoding.EncodeToString([]byte("vlt:" + b.Token))
		var dialled string
		b.b.transport.DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = addr
			return nil, io.EOF
		}
		b.b.transport.DialTLSContext = b.b.transport.DialContext
		wireSend(t, b.Port, []byte("GET "+c.url+" HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic "+basic+"\r\n\r\n"))
		b.Close()
		if dialled != c.dial {
			t.Errorf("%s: dialled %q, want %q", c.url, dialled, c.dial)
		}
	}
}

// TestLimitsKeepTheirDefaults: a partial override changes only the bounds
// it gives, as {...SCRUB_LIMITS, ...limits} does.
func TestLimitsKeepTheirDefaults(t *testing.T) {
	b, err := Start(Options{Limits: Limits{MaxDecodedBytes: 10}, Exercise: noExercise})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	want := DefaultLimits
	want.MaxDecodedBytes = 10
	if b.b.opts.Limits != want {
		t.Fatalf("%+v, want %+v", b.b.opts.Limits, want)
	}
}
