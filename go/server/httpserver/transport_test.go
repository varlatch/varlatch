// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawRequest sends a request with a body of size bytes over a real
// connection, framed chunked or with a Content-Length, and returns the
// answer's status. The body is written while the answer is read, since
// the server may answer before it has read the body.
func rawRequest(t *testing.T, addr, method, target, framing string, size int) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	head := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nConnection: close\r\n", method, target, addr)
	if framing == "chunked" {
		head += "Transfer-Encoding: chunked\r\n\r\n"
	} else {
		head += fmt.Sprintf("Content-Length: %d\r\n\r\n", size)
	}
	go func() {
		w := bufio.NewWriterSize(conn, 64<<10)
		_, _ = w.WriteString(head)
		const piece = 64 << 10
		for sent := 0; sent < size; sent += piece {
			n := min(piece, size-sent)
			if framing == "chunked" {
				_, _ = fmt.Fprintf(w, "%x\r\n", n)
			}
			_, _ = w.WriteString(strings.Repeat("a", n))
			if framing == "chunked" {
				_, _ = w.WriteString("\r\n")
			}
		}
		if framing == "chunked" {
			_, _ = w.WriteString("0\r\n\r\n")
		}
		_ = w.Flush()
	}()
	res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s %s (%s, %d bytes): %v", method, target, framing, size, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

// The body limit over a real listener, against the shared table
// (services/varlatchd/test/go-parity.test.ts runs it against the Node
// adapter): GET, HEAD and TRACE bodies are ignored, every other method's
// body is limited, chunked or not.
func TestParityTransportBodies(t *testing.T) {
	var table struct {
		TransportBodies []struct {
			Method, Target, Framing string
			Size, Status            int
		} `json:"transportBodies"`
	}
	loadParityInto(t, &table)
	if len(table.TransportBodies) == 0 {
		t.Fatal("no transportBodies")
	}
	for _, c := range table.TransportBodies {
		s, _, _, _ := newTestServer(t, nil)
		srv := httptest.NewServer(s)
		if got := rawRequest(t, srv.Listener.Addr().String(), c.Method, c.Target, c.Framing, c.Size); got != c.Status {
			t.Errorf("%s %s (%s, %d bytes): %d, want %d", c.Method, c.Target, c.Framing, c.Size, got, c.Status)
		}
		srv.Close()
	}
}
