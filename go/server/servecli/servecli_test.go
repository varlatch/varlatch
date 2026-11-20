// SPDX-License-Identifier: AGPL-3.0-or-later

package servecli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/release/releasetest"
)

const (
	version    = "0.50.0-rc.2"
	testOrigin = "https://vault.example.com"
)

// fakeSource is a release's files, signed by a test Sigstore when asked,
// recording what was asked for.
type fakeSource struct {
	mu        sync.Mutex
	files     map[string][]byte
	sums      []byte // when set, served instead of the files' own
	bundle    []byte
	requested []string
	fail      error
}

func (f *fakeSource) Get(_ context.Context, name string, limit int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requested = append(f.requested, name)
	if f.fail != nil {
		return nil, f.fail
	}
	var b []byte
	switch name {
	case Sums:
		b = f.sums
	case Bundle:
		b = f.bundle
	default:
		var ok bool
		if b, ok = f.files[name]; !ok {
			return nil, release.ErrNotFound
		}
	}
	if int64(len(b)) > limit {
		return nil, errors.New("too large")
	}
	return b, nil
}

func (f *fakeSource) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requested)
}

func sumsOf(files map[string][]byte) []byte {
	var b bytes.Buffer
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		b.WriteString(hexSum(files[n]) + "  " + n + "\n")
	}
	return b.Bytes()
}

// installer is one of this repository's installers, stamped with version
// as the release stamps it.
func installer(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "install", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Replace(b, []byte("@VARLATCH_VERSION@"), []byte(version), 1)
}

// published is a release as the release workflow publishes it, signed by s
// for the release workflow's identity.
func published(t *testing.T, s *releasetest.Sigstore) *fakeSource {
	files := map[string][]byte{"install.sh": installer(t, "install.sh"), "install.ps1": installer(t, "install.ps1"), "varlatchd-" + version + "-linux-amd64": []byte("a server")}
	for _, n := range Served(version)[:6] {
		files[n] = []byte("a varlatch for " + n)
	}
	sums := sumsOf(files)
	return &fakeSource{files: files, sums: sums, bundle: s.Sign(sums, release.Identity(version), release.Issuer)}
}

func options(t *testing.T, s *releasetest.Sigstore, src Source, cache string) Options {
	return Options{
		Version: version, Origin: testOrigin, Source: src, CacheDir: cache,
		Trusted: func(context.Context) (root.TrustedMaterial, error) { return s.TrustedRoot(), nil },
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestPrepareAndServe(t *testing.T) {
	s := releasetest.New()
	src := published(t, s)
	cache := t.TempDir()
	r, err := Prepare(context.Background(), options(t, s, src, cache))
	if err != nil {
		t.Fatal(err)
	}
	// SHA256SUMS and its signature first, then the served files only (the
	// server's binary is listed but not served).
	asked := src.asked()
	if !slices.Equal(asked[:2], []string{Sums, Bundle}) || slices.Contains(asked, "varlatchd-"+version+"-linux-amd64") || len(asked) != 2+len(Served(version)) {
		t.Fatalf("asked %q", asked)
	}
	want := append(Served(version), Sums, Bundle)
	slices.Sort(want)
	if !slices.Equal(r.Names(), want) {
		t.Fatalf("names %q", r.Names())
	}

	// The installers name the installation, in their one empty line.
	sh := get(t, r, "/install.sh")
	if sh.Code != 200 || !strings.Contains(sh.Body.String(), "\nORIGIN='"+testOrigin+"'\n") || strings.Contains(sh.Body.String(), "\nORIGIN=''\n") {
		t.Fatalf("install.sh: %d", sh.Code)
	}
	ps1 := get(t, r, "/install.ps1")
	if ps1.Code != 200 || !strings.Contains(ps1.Body.String(), "$Origin = '"+testOrigin+"'") {
		t.Fatalf("install.ps1: %d", ps1.Code)
	}
	if ct := sh.Header().Get("Content-Type"); ct != "text/plain; charset=UTF-8" || sh.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("install.sh headers %v", sh.Header())
	}
	// Each file as the release published it.
	for name, body := range src.files {
		w := get(t, r, "/cli/v"+version+"/"+name)
		served := slices.Contains(Served(version), name)
		if served && (w.Code != 200 || !bytes.Equal(w.Body.Bytes(), body)) || !served && w.Code != 404 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := get(t, r, "/cli/v"+version+"/"+Sums); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), src.sums) {
		t.Fatalf("SHA256SUMS: %d", w.Code)
	}
	// Nothing else: another version, a path below or above, another method.
	binary := Served(version)[0]
	for _, p := range []string{
		"/cli/v0.50.0-rc.1/" + binary, "/cli/" + binary, "/cli/v" + version + "/", "/cli/v" + version + "/../v" + version + "/" + binary,
		"/cli/v" + version + "/sub/" + binary, "/cli/v" + version + "/" + binary + "/", "/cli/v" + version + "/..", "/cli/varlatch.cjs", "/install.bat",
	} {
		if w := get(t, r, p); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/cli/v"+version+"/"+binary, nil))
	if w.Code != 404 {
		t.Fatalf("POST: %d", w.Code)
	}
}

// Nothing is downloaded beyond SHA256SUMS and its signature, and nothing
// is cached, unless the signature verifies for this release's identity.
func TestPrepareVerifiesFirst(t *testing.T) {
	s := releasetest.New()
	for name, change := range map[string]func(*fakeSource){
		"SHA256SUMS changed after signing": func(f *fakeSource) { f.sums = append(bytes.Clone(f.sums), "00  extra\n"...) },
		"another release's identity":       func(f *fakeSource) { f.bundle = s.Sign(f.sums, release.Identity("0.50.0-rc.1"), release.Issuer) },
		"another workflow": func(f *fakeSource) {
			f.bundle = s.Sign(f.sums, "https://github.com/"+release.Repository+"/.github/workflows/other.yml@refs/tags/v"+version, release.Issuer)
		},
		"another Sigstore": func(f *fakeSource) {
			f.bundle = releasetest.New().Sign(f.sums, release.Identity(version), release.Issuer)
		},
		"no signature": func(f *fakeSource) { f.bundle = []byte("{}") },
	} {
		t.Run(name, func(t *testing.T) {
			src := published(t, s)
			change(src)
			cache := t.TempDir()
			if _, err := Prepare(context.Background(), options(t, s, src, cache)); err == nil {
				t.Fatal("prepared")
			}
			if asked := src.asked(); !slices.Equal(asked, []string{Sums, Bundle}) {
				t.Fatalf("asked %q", asked)
			}
			if entries, _ := os.ReadDir(cache); len(entries) != 0 {
				t.Fatalf("cached %v", entries)
			}
		})
	}
}

func TestPrepareRefuses(t *testing.T) {
	s := releasetest.New()
	for name, c := range map[string]struct {
		change func(*fakeSource)
		o      func(*Options)
		want   string
	}{
		"a file that does not match": {change: func(f *fakeSource) { f.files[Served(version)[2]] = []byte("something else") }, want: "does not match SHA256SUMS"},
		"no installer": {change: func(f *fakeSource) {
			delete(f.files, "install.ps1")
			f.sums = sumsOf(f.files)
			f.bundle = s.Sign(f.sums, release.Identity(version), release.Issuer)
		}, want: "does not list install.ps1"},
		"no binary": {change: func(f *fakeSource) {
			for _, n := range Served(version)[:6] {
				delete(f.files, n)
			}
			f.sums = sumsOf(f.files)
			f.bundle = s.Sign(f.sums, release.Identity(version), release.Issuer)
		}, want: "lists no varlatch binary"},
		"an installer without the address line": {change: func(f *fakeSource) {
			f.files["install.sh"] = []byte("#!/bin/sh\necho no line\n")
			f.sums = sumsOf(f.files)
			f.bundle = s.Sign(f.sums, release.Identity(version), release.Issuer)
		}, want: "no single line for the installation's address"},
		"a development build":    {o: func(o *Options) { o.Version = "dev" }, want: "not a release version"},
		"an origin with a path":  {o: func(o *Options) { o.Origin = "https://vault.example.com/x" }, want: "not one an installer may name"},
		"an origin with a quote": {o: func(o *Options) { o.Origin = "https://vault.example.com'" }, want: "not one an installer may name"},
		"plain http elsewhere":   {o: func(o *Options) { o.Origin = "http://vault.example.com" }, want: "not one an installer may name"},
		"port zero":              {o: func(o *Options) { o.Origin = "https://vault.example.com:0" }, want: "not one an installer may name"},
		"port too large":         {o: func(o *Options) { o.Origin = "https://vault.example.com:65536" }, want: "not one an installer may name"},
		"port with a leading 0":  {o: func(o *Options) { o.Origin = "http://127.0.0.1:08686" }, want: "not one an installer may name"},
		"an unreachable source":  {change: func(f *fakeSource) { f.fail = &release.UnreachableError{Err: errors.New("no route")} }, want: "no route"},
	} {
		t.Run(name, func(t *testing.T) {
			src := published(t, s)
			if c.change != nil {
				c.change(src)
			}
			cache := t.TempDir()
			o := options(t, s, src, cache)
			if c.o != nil {
				c.o(&o)
			}
			_, err := Prepare(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if entries, _ := os.ReadDir(cache); len(entries) != 0 {
				t.Fatalf("cached %v", entries)
			}
		})
	}
	t.Run("a loopback origin", func(t *testing.T) {
		src := published(t, s)
		o := options(t, s, src, t.TempDir())
		o.Origin = "http://127.0.0.1:8686"
		r, err := Prepare(context.Background(), o)
		if err != nil || !strings.Contains(string(r.scripts["install.sh"]), "ORIGIN='http://127.0.0.1:8686'") {
			t.Fatalf("err %v", err)
		}
	})
}

// A restart serves the cache, verified again, without downloading; a
// cache that no longer matches is downloaded again; other versions go.
func TestPrepareFromTheCache(t *testing.T) {
	s := releasetest.New()
	cache := t.TempDir()
	if _, err := Prepare(context.Background(), options(t, s, published(t, s), cache)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cache, "v0.50.0-rc.1"), 0o700); err != nil {
		t.Fatal(err)
	}
	offline := &fakeSource{fail: &release.UnreachableError{Err: errors.New("offline")}}
	r, err := Prepare(context.Background(), options(t, s, offline, cache))
	if err != nil || len(offline.asked()) != 0 {
		t.Fatalf("err %v, asked %q", err, offline.asked())
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 1 || entries[0].Name() != "v"+version {
		t.Fatalf("cache holds %v", entries)
	}
	if w := get(t, r, "/cli/v"+version+"/"+Served(version)[0]); w.Code != 200 {
		t.Fatalf("from the cache: %d", w.Code)
	}

	// A cached file changed: refused offline, downloaded again online.
	if err := os.WriteFile(filepath.Join(cache, "v"+version, Served(version)[1]), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), options(t, s, offline, cache)); err == nil {
		t.Fatal("prepared from a changed cache")
	}
	src := published(t, s)
	if _, err := Prepare(context.Background(), options(t, s, src, cache)); err != nil || len(src.asked()) == 0 {
		t.Fatalf("err %v, asked %q", err, src.asked())
	}
	// A cache whose signature is another identity's is never served.
	other := releasetest.New()
	if _, err := Prepare(context.Background(), options(t, other, offline, cache)); err == nil {
		t.Fatal("served a cache another Sigstore cannot verify")
	}
}

// The manager serves once a later attempt succeeds.
func TestManagerRetries(t *testing.T) {
	s := releasetest.New()
	src := published(t, s)
	src.fail = &release.UnreachableError{Err: errors.New("not yet")}
	o := options(t, s, src, t.TempDir())
	o.RetryAfter = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := Start(ctx, o, slog.New(slog.NewTextHandler(io.Discard, nil)))
	time.Sleep(30 * time.Millisecond)
	if m.Current() != nil {
		t.Fatal("serving before an attempt succeeded")
	}
	src.mu.Lock()
	src.fail = nil
	src.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for m.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.Current() == nil {
		t.Fatal("never served")
	}
}
