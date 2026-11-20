// SPDX-License-Identifier: Apache-2.0

// Package fakerelease serves releases the way GitHub does for self-update's
// tests: a REST listing, release files behind a redirect to a storage path,
// and SHA256SUMS signed at the moment it is served by a test Sigstore
// (lib/release/releasetest), as the release workflow signs it. Nothing in
// it is a real key: every key is generated when the server starts. Only
// tests import it.
package fakerelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/release/releasetest"
)

// Release is one published release.
type Release struct {
	// Files are its files, SHA256SUMS and its signature aside.
	Files map[string][]byte
	// Identity signs SHA256SUMS; "" is the release workflow's for the
	// version (release.Identity), as a real release.
	Identity string
	// Issuer is the identity's OIDC issuer; "" is release.Issuer.
	Issuer string
	// SumsAfterSigning changes SHA256SUMS after it is signed (the
	// signature then fails).
	SumsAfterSigning func([]byte) []byte
	// NoSignature serves no SHA256SUMS.sigstore.json.
	NoSignature bool
	// Draft lists it as a draft.
	Draft bool
	// Redirect, when set, is where a download of name is sent instead of
	// the storage path.
	Redirect func(name string) string
	// Served replaces a file's content as served, while SHA256SUMS lists
	// Files' (a changed or cut-off download).
	Served map[string][]byte
}

// Server is the fake GitHub.
type Server struct {
	*httptest.Server
	Sigstore *releasetest.Sigstore

	// PageSize, when set, splits the listing into pages of that many
	// releases, linked as GitHub links them (Link rel="next"); Order lists
	// the versions in the listing's order (newest created first), the
	// published ones by version, highest first, otherwise; Endless links a
	// next page from every page, the last one repeated.
	PageSize int
	Order    []string
	Endless  bool
	// LinkBase, when set, is the base of the Link header's URLs instead of
	// this server's (a next page on another host).
	LinkBase string

	mu       sync.Mutex
	releases map[string]*Release
	requests []string
}

// New starts a server with no releases; Close stops it.
func New() *Server {
	s := &Server{Sigstore: releasetest.New(), releases: map[string]*Release{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Publish adds (or replaces) a release.
func (s *Server) Publish(version string, r *Release) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases[version] = r
}

// Requests are the paths requested so far, in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Host is the server's host:port, the one host its Source allows.
func (s *Server) Host() string { return s.Listener.Addr().String() }

// Source is a self-update Source for this server, verifying against its
// Sigstore.
func (s *Server) Source() selfupdate.Source {
	pool := s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	src := selfupdate.Source{
		API: s.URL + "/api", Download: s.URL + "/download", Pages: s.URL + "/pages",
		Hosts: []string{s.Host()}, UserAgent: "fakerelease-test",
		Trusted: func(context.Context) (root.TrustedMaterial, error) { return s.Sigstore.TrustedRoot(), nil },
	}
	return src.WithRoots(pool)
}

// WriteSourceConfig writes what a binary built with -tags selfupdatetest
// reads from VARLATCH_TEST_SELFUPDATE_SOURCE into dir, and returns its
// path: the server's addresses, its TLS certificate and the trusted root.
func (s *Server) WriteSourceConfig(dir string) (string, error) {
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o644); err != nil {
		return "", err
	}
	trusted := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(trusted, s.Sigstore.TrustedRootJSON(), 0o644); err != nil {
		return "", err
	}
	cfg, err := json.Marshal(map[string]any{
		"API": s.URL + "/api", "Download": s.URL + "/download", "Pages": s.URL + "/pages",
		"Hosts": []string{s.Host()}, "CA": ca, "TrustedRoot": trusted,
	})
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "source.json")
	return path, os.WriteFile(path, cfg, 0o644)
}

// Sums is SHA256SUMS for files, as sha256sum writes it.
func Sums(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return []byte(b.String())
}

func (s *Server) serve(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, req.URL.RequestURI())
	s.mu.Unlock()
	switch path := req.URL.Path; {
	case path == "/api/releases":
		s.mu.Lock()
		order := append([]string(nil), s.Order...)
		if len(order) == 0 {
			for v := range s.releases {
				order = append(order, v)
			}
			sort.Slice(order, func(i, j int) bool { c, _ := release.CompareVersions(order[i], order[j]); return c > 0 })
		}
		var listed []map[string]any
		for _, v := range order {
			r := s.releases[v]
			draft := r != nil && r.Draft
			listed = append(listed, map[string]any{"tag_name": "v" + v, "draft": draft, "prerelease": release.Prerelease(v)})
		}
		s.mu.Unlock()
		page := 1
		if p, err := strconv.Atoi(req.URL.Query().Get("page")); err == nil && p > 0 {
			page = p
		}
		if s.PageSize > 0 {
			from := min((page-1)*s.PageSize, len(listed))
			if s.Endless && from >= len(listed) {
				from = max(len(listed)-s.PageSize, 0)
			}
			to := min(from+s.PageSize, len(listed))
			if to < len(listed) || s.Endless {
				base := s.URL
				if s.LinkBase != "" {
					base = s.LinkBase
				}
				w.Header().Set("Link", fmt.Sprintf(`<%s/api/releases?per_page=100&page=%d>; rel="next", <%s/api/releases?per_page=100&page=1>; rel="first"`, base, page+1, base))
			}
			listed = listed[from:to]
		}
		if listed == nil {
			listed = []map[string]any{}
		}
		body, err := json.Marshal(listed)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case strings.HasPrefix(path, "/download/v"):
		version, name, _ := strings.Cut(strings.TrimPrefix(path, "/download/v"), "/")
		r := s.release(version)
		if r == nil {
			http.NotFound(w, req)
			return
		}
		to := "/storage/" + version + "/" + name + "?signed=query"
		if r.Redirect != nil {
			if other := r.Redirect(name); other != "" {
				to = other
			}
		}
		http.Redirect(w, req, to, http.StatusFound)
	case strings.HasPrefix(path, "/storage/"):
		version, name, _ := strings.Cut(strings.TrimPrefix(path, "/storage/"), "/")
		body, ok := s.file(version, name)
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	default:
		http.NotFound(w, req)
	}
}

func (s *Server) release(version string) *Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releases[version]
}

// file is a release file as served: SHA256SUMS computed, its signature made
// now.
func (s *Server) file(version, name string) ([]byte, bool) {
	r := s.release(version)
	if r == nil {
		return nil, false
	}
	sums := Sums(r.Files)
	switch name {
	case "SHA256SUMS":
		if r.SumsAfterSigning != nil {
			sums = r.SumsAfterSigning(sums)
		}
		return sums, true
	case "SHA256SUMS.sigstore.json":
		if r.NoSignature {
			return nil, false
		}
		identity, issuer := r.Identity, r.Issuer
		if identity == "" {
			identity = release.Identity(version)
		}
		if issuer == "" {
			issuer = release.Issuer
		}
		return s.Sigstore.Sign(sums, identity, issuer), true
	}
	if body, ok := r.Served[name]; ok {
		return body, true
	}
	body, ok := r.Files[name]
	return body, ok
}
