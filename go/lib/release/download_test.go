// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloaderStaysOnItsHosts(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte("from elsewhere"))
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/file":
			http.Redirect(w, r, "/storage/file?signed=query", http.StatusFound)
		case "/storage/file":
			_, _ = w.Write([]byte("the file"))
		case "/elsewhere":
			http.Redirect(w, r, other.URL+"/file", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, "http://"+r.Host+"/storage/file", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		case "/cut":
			conn, buf, _ := w.(http.Hijacker).Hijack()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
			_ = buf.Flush()
			_ = conn.Close()
		case "/busy":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs.AddCert(other.Certificate())
	d := Downloader{Hosts: []string{srv.Listener.Addr().String()}, Transport: transport, UserAgent: "test"}
	ctx := context.Background()

	if b, err := d.Get(ctx, srv.URL+"/file", 1<<10); err != nil || string(b) != "the file" {
		t.Fatalf("%q %v", b, err)
	}
	for path, want := range map[string]string{
		"/elsewhere": "not a host releases come from",
		"/plain":     "not HTTPS",
		"/loop":      "too many redirects",
		"/large":     "larger than 10 bytes",
		"/missing":   "not found",
	} {
		limit := int64(1 << 10)
		if path == "/large" {
			limit = 10
		}
		if _, err := d.Get(ctx, srv.URL+path, limit); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	if elsewhere.Load() != 0 {
		t.Fatal("a request reached another host")
	}
	for _, path := range []string{"/cut", "/busy"} {
		var ue *UnreachableError
		if _, err := d.Get(ctx, srv.URL+path, 1<<10); !errors.As(err, &ue) {
			t.Errorf("%s: %v, want an unreachable error", path, err)
		}
	}
	if _, err := d.Get(ctx, other.URL+"/file", 1<<10); err == nil || elsewhere.Load() != 0 {
		t.Fatalf("a first request to another host: %v", err)
	}
	if _, err := d.Get(ctx, "http://"+srv.Listener.Addr().String()+"/file", 1<<10); err == nil || !strings.Contains(err.Error(), "not HTTPS") {
		t.Fatalf("plain http: %v", err)
	}
}

func TestDownloadURL(t *testing.T) {
	if got := DownloadURL("0.50.0-rc.1", "varlatch-0.50.0-rc.1-linux-amd64"); got != "https://github.com/varlatch/varlatch/releases/download/v0.50.0-rc.1/varlatch-0.50.0-rc.1-linux-amd64" {
		t.Fatal(got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type firstByteReader struct {
	io.ReadCloser
	once   sync.Once
	onRead func()
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.once.Do(r.onRead)
	}
	return n, err
}

// A host that stops sending fails the download within the bound, before
// its headers or after them; one that keeps sending, however slowly, does
// not.
func TestDownloaderStall(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/silent":
			<-r.Context().Done()
		case "/stalls":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("a start"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/slow":
			w.Header().Set("Content-Length", "10")
			for range 10 {
				_, _ = w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(60 * time.Millisecond):
				}
			}
		}
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	// Before headers arrive: Stall bounds the wait for the first answer.
	t.Run("silent", func(t *testing.T) {
		d := Downloader{Hosts: []string{host}, Transport: srv.Client().Transport, Stall: 150 * time.Millisecond}
		start := time.Now()
		_, err := d.Get(context.Background(), srv.URL+"/silent", 1<<10)
		var ue *UnreachableError
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), "did not answer within 150ms") {
			t.Errorf("/silent: %v, want %q", err, "did not answer within 150ms")
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("/silent took %s", took)
		}
	})

	// After headers and initial body bytes arrive: answerStall keeps a slow
	// TLS handshake on a busy runner from racing the short body stall bound.
	t.Run("stalls", func(t *testing.T) {
		var sawFirstByte atomic.Bool
		transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			res, err := srv.Client().Transport.RoundTrip(req)
			if err != nil {
				return nil, err
			}
			res.Body = &firstByteReader{ReadCloser: res.Body, onRead: func() { sawFirstByte.Store(true) }}
			return res, nil
		})
		d := Downloader{
			Hosts:       []string{host},
			Transport:   transport,
			Stall:       150 * time.Millisecond,
			answerStall: 10 * time.Second,
		}
		start := time.Now()
		_, err := d.Get(context.Background(), srv.URL+"/stalls", 1<<10)
		var ue *UnreachableError
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), "stopped sending for 150ms") {
			t.Errorf("/stalls: %v, want %q", err, "stopped sending for 150ms")
		}
		if !sawFirstByte.Load() {
			t.Error("/stalls: client stalled before receiving the initial body bytes")
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("/stalls took %s", took)
		}
	})

	// Longer than Stall in all (~540 ms > 400 ms), never 400 ms without a byte.
	t.Run("slow", func(t *testing.T) {
		d := Downloader{
			Hosts:       []string{host},
			Transport:   srv.Client().Transport,
			Stall:       400 * time.Millisecond,
			answerStall: 10 * time.Second,
		}
		if b, err := d.Get(context.Background(), srv.URL+"/slow", 1<<10); err != nil || len(b) != 10 {
			t.Fatalf("slow: %d bytes, %v", len(b), err)
		}
	})
}
