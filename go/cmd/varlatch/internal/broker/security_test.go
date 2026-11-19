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
