// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// lockedFake is a versioned S3 bucket with a retention on every version,
// whose delete answers as deleteMode says: "refused" (AccessDenied),
// "unavailable" (503 on every attempt) or "drop" (the connection closes).
type lockedFake struct {
	mu         sync.Mutex
	objects    map[string][]byte
	deleteMode string
}

func (f *lockedFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objects[r.URL.Path] = b
		w.Header().Set("x-amz-version-id", "v1")
		w.Header().Set("ETag", `"etag"`)
	case r.Method == http.MethodGet && q.Has("retention"):
		io.WriteString(w, `<?xml version="1.0"?><Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>`)
	case r.Method == http.MethodGet:
		w.Write(f.objects[r.URL.Path])
	case r.Method == http.MethodHead:
		w.Header().Set("x-amz-version-id", "v1")
	case r.Method == http.MethodDelete:
		switch f.deleteMode {
		case "refused":
			w.WriteHeader(403)
			io.WriteString(w, `<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>locked</Message></Error>`)
		case "unavailable":
			w.WriteHeader(503)
			io.WriteString(w, `<?xml version="1.0"?><Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>`)
		default:
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}
	}
}

// Only a refused delete counts toward protection: a delete that failed
// otherwise (the service unavailable, the connection lost) leaves the
// retention inconclusive, never protected.
func TestBucketDeleteRefusalOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.vltbak")
	files, paths := components(t, dir, 100, 10)
	_ = files
	key := make([]byte, 32)
	bek, _ := KeyBEK(key)
	if err := Seal(path, goManifest(t, make([]byte, 32), files), paths, bek, SealOptions{}); err != nil {
		t.Fatal(err)
	}
	for mode, protected := range map[string]bool{"refused": true, "unavailable": false, "drop": false} {
		fake := &lockedFake{objects: map[string][]byte{}, deleteMode: mode}
		srv := httptest.NewServer(fake)
		d := Destination{Endpoint: srv.URL, Region: "us-east-1", Bucket: "b", Prefix: "p/", ForcePathStyle: true}
		r := NewClient(d, Credentials{AccessKeyID: "k", SecretAccessKey: "s"}, nil).TestBucket(context.Background(), BucketTestKey(d, "x"), path, dir, func(string) error { return nil })
		srv.Close()
		if r.Retention.Protected != protected || !r.Delivery.OK || !r.Recoverability.OK || r.Retention.Mode != "COMPLIANCE" {
			t.Errorf("%s: %+v", mode, r)
		}
		if !protected && !strings.Contains(r.Retention.Detail, "whether the bucket protects it is not known") {
			t.Errorf("%s: %q", mode, r.Retention.Detail)
		}
	}
}
