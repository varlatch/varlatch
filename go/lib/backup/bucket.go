// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// The bucket test (ADR-0059 Decision 7, gate G13): one test archive is
// uploaded, then the exact object version's retention is read, that
// version is downloaded and checked, and deleting it is tried, after which
// it must still be there. Delivery, retention and recoverability are
// reported separately: a failed check, or a bucket that keeps no
// retention, is unprotected, never verified.

// BucketReport is a bucket test's outcome.
type BucketReport struct {
	Key            string         `json:"key"`
	Delivery       Check          `json:"delivery"`
	Retention      RetentionCheck `json:"retention"`
	Recoverability Check          `json:"recoverability"`
}

// Check is one part of the report: passed, or why not.
type Check struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// RetentionCheck is the retention the uploaded version holds: its mode
// and deadline as the bucket reports them, and whether deleting that
// version was refused and it is still there (Protected).
type RetentionCheck struct {
	Protected   bool   `json:"protected"`
	Mode        string `json:"mode,omitempty"`
	RetainUntil string `json:"retainUntil,omitempty"`
	VersionID   string `json:"versionId,omitempty"`
	Detail      string `json:"detail"`
}

// Passed is whether the bucket delivered, holds retention and gave the
// archive back.
func (r BucketReport) Passed() bool {
	return r.Delivery.OK && r.Retention.Protected && r.Recoverability.OK
}

// TestBucket runs the bucket test with the archive at path, uploaded as
// key. verify checks the downloaded copy (it opens the archive and checks
// its keys); scratch is a directory for that copy.
func (c *Client) TestBucket(ctx context.Context, key, path, scratch string, verify func(path string) error) BucketReport {
	r := BucketReport{Key: key}
	put, err := c.put(ctx, key, path)
	if err != nil {
		r.Delivery.Detail = "the upload failed" + StorageErrorDetail(err)
		r.Retention.Detail = "not checked: nothing was uploaded"
		r.Recoverability.Detail = "not checked: nothing was uploaded"
		return r
	}
	version := aws.ToString(put.VersionId)
	r.Delivery = Check{OK: true, Detail: "uploaded"}
	r.Retention.VersionID = version
	if version == "" {
		r.Retention.Detail = "the bucket keeps no object versions, so it cannot hold an upload against deletion (enable versioning and Object Lock)"
	} else {
		r.Retention = c.retention(ctx, key, version)
	}

	// The version is downloaded before deleting it is tried: in a bucket
	// that does not protect it, the delete succeeds.
	copyPath := filepath.Join(scratch, "bucket-test.vltbak")
	_ = os.Remove(copyPath)
	if err := c.download(ctx, key, version, copyPath); err != nil {
		r.Recoverability.Detail = err.Error()
	} else if err := verify(copyPath); err != nil {
		r.Recoverability.Detail = "the downloaded archive did not verify: " + err.Error()
	} else {
		r.Recoverability = Check{OK: true, Detail: "the uploaded version was downloaded, opened and its keys checked"}
	}
	_ = os.Remove(copyPath)
	if version != "" {
		r.Retention = c.tryDelete(ctx, key, r.Retention)
	}
	return r
}

// put uploads the test archive in one request, with its Content-MD5.
func (c *Client) put(ctx context.Context, key, path string) (*s3.PutObjectOutput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sum, err := md5Of(io.NewSectionReader(f, 0, st.Size()))
	if err != nil {
		return nil, err
	}
	return c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket, Key: &key, Body: io.NewSectionReader(f, 0, st.Size()), ContentLength: aws.Int64(st.Size()),
		ContentType: aws.String("application/octet-stream"), ContentMD5: aws.String(sum),
	})
}

// retention reads the version's retention.
func (c *Client) retention(ctx context.Context, key, version string) RetentionCheck {
	r := RetentionCheck{VersionID: version}
	got, err := c.s3.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &c.bucket, Key: &key, VersionId: &version})
	switch {
	case err != nil && noLock(err):
		r.Detail = "the uploaded version has no retention (enable Object Lock with a default retention on the bucket)"
	case err != nil:
		r.Detail = "its retention could not be read" + StorageErrorDetail(err)
	case got.Retention == nil || got.Retention.Mode == "" || got.Retention.RetainUntilDate == nil:
		r.Detail = "the uploaded version has no retention (enable Object Lock with a default retention on the bucket)"
	default:
		r.Mode = string(got.Retention.Mode)
		r.RetainUntil = got.Retention.RetainUntilDate.UTC().Format(time.RFC3339)
	}
	return r
}

// tryDelete tries to delete the version and checks it is still there:
// only then, with a retention, is the bucket protecting archives.
func (c *Client) tryDelete(ctx context.Context, key string, r RetentionCheck) RetentionCheck {
	version := r.VersionID
	_, delErr := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &c.bucket, Key: &key, VersionId: &version})
	_, headErr := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &c.bucket, Key: &key, VersionId: &version})
	switch {
	case delErr == nil:
		r.Detail = join(r.Detail, "deleting the uploaded version succeeded: the bucket does not protect archives")
	case !refusedDelete(delErr):
		// A network error, or an answer that is not a refusal, says nothing
		// about the retention: inconclusive, never protected.
		r.Detail = join(r.Detail, "deleting the uploaded version failed without a refusal"+StorageErrorDetail(delErr)+", so whether the bucket protects it is not known; run the test again")
	case headErr != nil:
		r.Detail = join(r.Detail, "deleting the uploaded version was refused, but it could not be read back"+StorageErrorDetail(headErr))
	case r.Mode == "":
		r.Detail = join(r.Detail, "deleting the uploaded version was refused and it is still there")
	default:
		r.Protected = true
		r.Detail = fmt.Sprintf("%s retention until %s; deleting the uploaded version was refused and it is still there", r.Mode, r.RetainUntil)
	}
	return r
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// refusedDelete is a delete the bucket refused: access denied, or the
// version locked.
func refusedDelete(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "AccessDenied", "ObjectLocked":
		return true
	}
	return false
}

// noLock is a retention read refused because the object has none.
func noLock(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFoundError", "InvalidRequest":
		return true
	}
	return false
}

// download writes one version of key to output, a new file.
func (c *Client) download(ctx context.Context, key, version, output string) error {
	in := &s3.GetObjectInput{Bucket: &c.bucket, Key: &key}
	if version != "" {
		in.VersionId = &version
	}
	got, err := c.s3.GetObject(ctx, in)
	if err != nil {
		return &Error{"Remote archive retrieval failed" + StorageErrorDetail(err)}
	}
	defer got.Body.Close()
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, got.Body); err != nil {
		out.Close()
		os.Remove(output)
		return &Error{"Remote archive retrieval failed" + StorageErrorDetail(err)}
	}
	return out.Close()
}

// BucketTestKey is the test archive's object name: the destination's
// prefix, bucket-test/, and the test's ID.
func BucketTestKey(d Destination, id string) string {
	return strings.TrimSuffix(d.Prefix, "/") + "/bucket-test/" + id + ".vltbak"
}
