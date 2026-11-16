// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// The S3 client against a real S3 server (the Go replacement of
// scripts/test-backup-s3.mjs, and gate G13's bucket test): a local MinIO
// (go.yml runs the pinned cgr.dev/chainguard/minio image) named by
// VARLATCH_TEST_S3_ENDPOINT with its root key in VARLATCH_TEST_S3_ACCESS_KEY
// and VARLATCH_TEST_S3_SECRET_KEY. Without them the tests skip;
// VARLATCH_REQUIRE_S3=1 (CI) makes them fail instead. Each test makes
// buckets of its own.

type liveS3 struct {
	endpoint string
	creds    Credentials
	admin    *s3.Client
}

func newLiveS3(t *testing.T) *liveS3 {
	t.Helper()
	endpoint := os.Getenv("VARLATCH_TEST_S3_ENDPOINT")
	if endpoint == "" {
		if os.Getenv("VARLATCH_REQUIRE_S3") == "1" {
			t.Fatal("VARLATCH_REQUIRE_S3=1, but VARLATCH_TEST_S3_ENDPOINT names no S3 server")
		}
		t.Skip("no S3 server (VARLATCH_TEST_S3_ENDPOINT)")
	}
	l := &liveS3{endpoint: endpoint, creds: Credentials{AccessKeyID: os.Getenv("VARLATCH_TEST_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("VARLATCH_TEST_S3_SECRET_KEY")}}
	l.admin = NewClient(l.destination("unused"), l.creds, nil).S3()
	return l
}

func (l *liveS3) destination(bucket string) Destination {
	return Destination{Endpoint: l.endpoint, Region: "us-east-1", Bucket: bucket, Prefix: "installation/", ForcePathStyle: true, WriteCredentialsFile: "unused"}
}

// bucket makes a bucket: "locked" (versioned, Object Lock with a one-day
// compliance default), "versioned" (versions, no lock) or "plain".
func (l *liveS3) bucket(t *testing.T, kind string) string {
	t.Helper()
	ctx := context.Background()
	b := make([]byte, 5)
	rand.Read(b)
	name := "vlt-" + kind + "-" + hex.EncodeToString(b)
	in := &s3.CreateBucketInput{Bucket: &name}
	if kind == "locked" {
		in.ObjectLockEnabledForBucket = aws.Bool(true)
	}
	if _, err := l.admin.CreateBucket(ctx, in); err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "locked":
		if _, err := l.admin.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{Bucket: &name, ObjectLockConfiguration: &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule:              &types.ObjectLockRule{DefaultRetention: &types.DefaultRetention{Mode: types.ObjectLockRetentionModeCompliance, Days: aws.Int32(1)}},
		}}); err != nil {
			t.Fatal(err)
		}
	case "versioned":
		if _, err := l.admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &name, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
			t.Fatal(err)
		}
	}
	return name
}

func randomFile(t *testing.T, dir string, n int) (string, []byte) {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	p := filepath.Join(dir, hex.EncodeToString(b[:6])+".in")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// One request up to a part, multipart beyond it (17 MiB), into a bucket
// with Object Lock and into one without; the download is byte for byte
// the upload, and a missing object is a retrieval failure that names it.
func TestS3UploadDownload(t *testing.T) {
	l := newLiveS3(t)
	ctx := context.Background()
	dir := t.TempDir()
	for _, kind := range []string{"plain", "locked"} {
		d := l.destination(l.bucket(t, kind))
		c := NewClient(d, l.creds, nil)
		for _, n := range []int{1024, 17 << 20} {
			in, want := randomFile(t, dir, n)
			key, _ := ObjectKey(d, uuid())
			if err := c.Upload(ctx, key, in); err != nil {
				t.Fatalf("%s, %d bytes: %v", kind, n, err)
			}
			out := filepath.Join(dir, "out-"+kind)
			os.Remove(out)
			version, err := c.Download(ctx, key, out)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
				t.Errorf("%s, %d bytes: the download differs", kind, n)
			}
			if (version != "") != (kind == "locked") {
				t.Errorf("%s: version %q", kind, version)
			}
		}
		missing, _ := ObjectKey(d, uuid())
		os.Remove(filepath.Join(dir, "missing"))
		if _, err := c.Download(ctx, missing, filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "Remote archive retrieval failed (S3 error NoSuchKey") {
			t.Errorf("a missing object: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
			t.Errorf("a failed download left a file: %v", err)
		}
	}
}

// faulty fails one multipart part: always (refused, so the upload is
// aborted), or once (a server error, which the client retries).
type faulty struct {
	once    bool
	failed  atomic.Int32
	partPut atomic.Int32
}

func (f *faulty) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && r.URL.Query().Get("partNumber") == "2" {
		f.partPut.Add(1)
		if !f.once || f.failed.Load() == 0 {
			f.failed.Add(1)
			if r.Body != nil {
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
			}
			status, code := http.StatusForbidden, "AccessDenied"
			if f.once {
				status, code = http.StatusServiceUnavailable, "ServiceUnavailable"
			}
			body := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>injected</Message></Error>`
			return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": {"application/xml"}},
				Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}, nil
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// A multipart upload whose part is refused is aborted: no upload stays
// open and no object appears; one whose part fails once with a server
// error is retried and completes byte for byte.
func TestS3MultipartAbortAndRetry(t *testing.T) {
	l := newLiveS3(t)
	ctx := context.Background()
	dir := t.TempDir()
	d := l.destination(l.bucket(t, "plain"))
	in, want := randomFile(t, dir, 33<<20)

	refused := &faulty{}
	key, _ := ObjectKey(d, uuid())
	err := NewClient(d, l.creds, &http.Client{Transport: refused, Timeout: time.Minute}).Upload(ctx, key, in)
	if err == nil || !strings.Contains(err.Error(), "Destination upload failed (S3 error AccessDenied") || !strings.Contains(err.Error(), "local archive remains available") {
		t.Fatalf("a refused part: %v", err)
	}
	open, err := l.admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &d.Bucket})
	if err != nil || len(open.Uploads) != 0 {
		t.Errorf("multipart uploads left open: %v %v", open, err)
	}
	if _, err := l.admin.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &d.Bucket, Key: &key}); err == nil {
		t.Error("an object appeared after the abort")
	}

	retried := &faulty{once: true}
	key, _ = ObjectKey(d, uuid())
	if err := NewClient(d, l.creds, &http.Client{Transport: retried, Timeout: time.Minute}).Upload(ctx, key, in); err != nil {
		t.Fatalf("a part that failed once: %v", err)
	}
	if retried.failed.Load() != 1 || retried.partPut.Load() != 2 {
		t.Errorf("part 2 failed %d times in %d attempts", retried.failed.Load(), retried.partPut.Load())
	}
	out := filepath.Join(dir, "out")
	if _, err := NewClient(d, l.creds, nil).Download(ctx, key, out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
		t.Error("the retried upload differs")
	}
}

// G13's bucket test: a bucket with Object Lock and a default retention
// protects the uploaded version (its retention read back, its deletion
// refused, still there) and gives it back; a versioned bucket without the
// lock and a plain one deliver and give it back but are unprotected; a
// wrong key delivers nothing.
func TestBucketTest(t *testing.T) {
	l := newLiveS3(t)
	ctx := context.Background()
	dir := t.TempDir()
	rootKEK := envelope.GenerateKey()
	files, paths := components(t, dir, 4096, 10)
	manifest := goManifest(t, rootKEK, files)
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	archive := filepath.Join(dir, "test.vltbak")
	if err := Seal(archive, manifest, paths, bek, SealOptions{}); err != nil {
		t.Fatal(err)
	}
	verify := func(path string) error {
		o, err := Open(path, bek, dir)
		if err != nil {
			return err
		}
		defer o.Close()
		if !CheckKeys(o.Manifest, map[int][]byte{1: rootKEK}) {
			return errors.New("keys")
		}
		return nil
	}
	for _, c := range []struct {
		kind      string
		protected bool
		detail    string
	}{
		{"locked", true, "COMPLIANCE retention until "},
		{"versioned", false, "deleting the uploaded version succeeded"},
		{"plain", false, "keeps no object versions"},
	} {
		d := l.destination(l.bucket(t, c.kind))
		r := NewClient(d, l.creds, nil).TestBucket(ctx, BucketTestKey(d, uuid()), archive, dir, verify)
		if !r.Delivery.OK || !r.Recoverability.OK || r.Retention.Protected != c.protected || !strings.Contains(r.Retention.Detail, c.detail) || r.Passed() != c.protected {
			t.Errorf("%s: %+v", c.kind, r)
		}
		if c.protected {
			until, err := time.Parse(time.RFC3339, r.Retention.RetainUntil)
			if err != nil || r.Retention.Mode != "COMPLIANCE" || until.Before(time.Now().Add(23*time.Hour)) {
				t.Errorf("retention %+v", r.Retention)
			}
			if _, err := l.admin.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &d.Bucket, Key: &r.Key, VersionId: &r.Retention.VersionID}); err != nil {
				t.Errorf("the protected version is gone: %v", err)
			}
		}
	}
	d := l.destination(l.bucket(t, "locked"))
	r := NewClient(d, Credentials{AccessKeyID: "wrong", SecretAccessKey: "wrong-secret"}, nil).TestBucket(ctx, BucketTestKey(d, uuid()), archive, dir, verify)
	if r.Delivery.OK || r.Passed() || !strings.Contains(r.Delivery.Detail, "S3 error InvalidAccessKeyId") {
		t.Errorf("a wrong key: %+v", r)
	}
}
