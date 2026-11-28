// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// headS3 is a bucket that takes uploads and answers HEAD as a key of the
// kind given would be answered: "write" (refused, 403), "read" (metadata,
// or 404 for a name never written), "read-no-list" (metadata, or 403 for
// a name never written).
type headS3 struct {
	mu    sync.Mutex
	kind  string
	puts  map[string]bool
	heads []string
	gets  int
}

func (s *headS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		_, _ = io.Copy(io.Discard, r.Body)
		s.puts[r.URL.Path] = true
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(200)
	case http.MethodHead:
		s.heads = append(s.heads, r.URL.Path)
		switch {
		case s.kind == "write":
			w.WriteHeader(403)
		case s.puts[r.URL.Path]:
			w.Header().Set("ETag", `"etag"`)
			w.WriteHeader(200)
		case s.kind == "read":
			w.WriteHeader(404)
		default:
			w.WriteHeader(403)
		}
	default:
		s.gets++
		w.WriteHeader(400)
	}
}

func (f *fixture) bucket(t *testing.T, kind string, mode os.FileMode) (*headS3, string) {
	t.Helper()
	fake := &headS3{kind: kind, puts: map[string]bool{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	conf := filepath.Join(f.dir, "conf-"+kind)
	if err := os.Mkdir(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "destinations.json"), []byte(`{"offsite":{"endpoint":"`+srv.URL+`","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(conf, "write.json")
	if err := os.WriteFile(key, []byte(`{"accessKeyId":"AKIDTEST","secretAccessKey":"not-a-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, mode); err != nil {
		t.Fatal(err)
	}
	f.cfg.BackupDestinationsFile = filepath.Join(conf, "destinations.json")
	return fake, key
}

// KeyAccess asks with HEAD only (never a GET of content): the newest
// archive delivered there, or, before one, a name never written.
func TestKeyAccess(t *testing.T) {
	for _, c := range []struct {
		kind                  string
		before, after         *bool
		beforeWord, afterWord string
	}{
		{"write", nil, ptr(false), "refused to say", "may not read"},
		{"read", ptr(true), ptr(true), "never written is not there", "read the metadata"},
		{"read-no-list", nil, ptr(true), "refused to say", "read the metadata"},
	} {
		t.Run(c.kind, func(t *testing.T) {
			f := newFixture(t)
			fake, _ := f.bucket(t, c.kind, 0o600)
			s := f.service(nil)
			got := s.KeyAccess(context.Background())
			if !same(got.Reads, c.before) || !strings.Contains(got.Detail, c.beforeWord) {
				t.Errorf("before an upload: %+v", got)
			}
			res, err := s.Run(context.Background())
			if err != nil || res.Delivery == nil {
				t.Fatalf("%+v %v", res, err)
			}
			got = s.KeyAccess(context.Background())
			if !same(got.Reads, c.after) || !strings.Contains(got.Detail, c.afterWord) {
				t.Errorf("after an upload: %+v", got)
			}
			if fake.heads[len(fake.heads)-1] != "/b/varlatch/"+res.ArchiveID+".vltbak" || fake.gets != 0 {
				t.Errorf("asked %q, %d GETs", fake.heads, fake.gets)
			}
		})
	}
}

// Each upload says when the bucket key file is open to others, writable
// by its group, or another group's; the upload goes on.
func TestUploadWarnsOfALooseBucketKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	for _, c := range []struct {
		mode os.FileMode
		warn string
	}{
		{0o644, "is open to others (mode 0644)"},
		{0o660, "may be written by its group (mode 0660)"},
		{0o640, ""},
		{0o600, ""},
	} {
		f := newFixture(t)
		_, key := f.bucket(t, "write", c.mode)
		var log bytes.Buffer
		s := f.service(func(o *Options) { o.Log = slog.New(slog.NewTextHandler(&log, nil)) })
		res, err := s.Run(context.Background())
		if err != nil || res.Delivery == nil {
			t.Fatalf("mode %04o: %+v %v", c.mode, res, err)
		}
		said := log.String()
		if c.warn == "" && strings.Contains(said, "bucket key file") || c.warn != "" && (!strings.Contains(said, "level=WARN") || !strings.Contains(said, "the bucket key file "+key+" "+c.warn)) {
			t.Errorf("mode %04o: %s", c.mode, said)
		}
	}
}

func ptr(b bool) *bool { return &b }

func same(a, b *bool) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
