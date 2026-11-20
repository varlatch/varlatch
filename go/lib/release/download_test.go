// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
