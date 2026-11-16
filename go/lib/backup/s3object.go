// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Single objects written once and read back (packages/backup s3.ts:
// putObjectIfAbsent, objectSha256, objectRetention), for the audit export
// (ADR-0056 Decision 4).

// Retention is an object's Object Lock retention: mode "compliance" or
// "governance" (lower case), and the date it holds until.
type Retention struct {
	Mode        string
	RetainUntil time.Time
}

// ConditionalPut is one object written only if its name is free, with its
// checksums (hex) and its retention (nil for none).
type ConditionalPut struct {
	Key         string
	Body        []byte
	SHA256, MD5 string
	ContentType string
	Retention   *Retention
}

// PutIfAbsent is putObjectIfAbsent: a PutObject with If-None-Match: *,
// Content-MD5 (B2 needs it with Object Lock), x-amz-checksum-sha256, the
// SHA-256 as the object's sha256 metadata, and the retention headers when
// set. A taken name fails with HTTP 412 (IsPreconditionFailed).
func (c *Client) PutIfAbsent(ctx context.Context, p ConditionalPut) error {
	md5, err := hex.DecodeString(p.MD5)
	if err != nil {
		return err
	}
	sha, err := hex.DecodeString(p.SHA256)
	if err != nil {
		return err
	}
	in := &s3.PutObjectInput{
		Bucket: &c.bucket, Key: aws.String(p.Key), Body: bytes.NewReader(p.Body), ContentLength: aws.Int64(int64(len(p.Body))),
		ContentType: aws.String(p.ContentType), ContentMD5: aws.String(base64.StdEncoding.EncodeToString(md5)),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sha)),
		Metadata:       map[string]string{"sha256": p.SHA256}, IfNoneMatch: aws.String("*"),
	}
	if p.Retention != nil {
		in.ObjectLockMode = types.ObjectLockMode(strings.ToUpper(p.Retention.Mode))
		in.ObjectLockRetainUntilDate = aws.Time(p.Retention.RetainUntil)
	}
	_, err = c.s3.PutObject(ctx, in)
	return err
}

// ObjectSHA256 is objectSha256: an existing object's sha256 metadata (""
// when it has none), read with HEAD. It needs a key that can read.
func (c *Client) ObjectSHA256(ctx context.Context, key string) (string, error) {
	head, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &c.bucket, Key: aws.String(key)})
	if err != nil {
		return "", err
	}
	return head.Metadata["sha256"], nil
}

// ObjectRetention is objectRetention: an object's retention read back
// (GetObjectRetention); nil when it has none, whether the answer says so
// (NoSuchObjectLockConfiguration) or names no mode and date. A refusal
// (AccessDenied) is an error: reading retention is a permission of its own.
func (c *Client) ObjectRetention(ctx context.Context, key string) (*Retention, error) {
	got, err := c.s3.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &c.bucket, Key: aws.String(key)})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && (api.ErrorCode() == "NoSuchObjectLockConfiguration" || api.ErrorCode() == "ObjectLockConfigurationNotFoundError") {
			return nil, nil
		}
		return nil, err
	}
	if got.Retention == nil || got.Retention.Mode == "" || got.Retention.RetainUntilDate == nil {
		return nil, nil
	}
	return &Retention{Mode: strings.ToLower(string(got.Retention.Mode)), RetainUntil: *got.Retention.RetainUntilDate}, nil
}

func statusOf(err error) int {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

func codeOf(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

// IsPreconditionFailed is isPreconditionFailed: an HTTP 412, the
// conditional write found the name taken.
func IsPreconditionFailed(err error) bool {
	return statusOf(err) == http.StatusPreconditionFailed || codeOf(err) == "PreconditionFailed"
}

// IsAccessDenied is isAccessDenied: an HTTP 403 or AccessDenied, the key
// may not do this.
func IsAccessDenied(err error) bool {
	return statusOf(err) == http.StatusForbidden || codeOf(err) == "AccessDenied"
}
