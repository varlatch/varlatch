// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// An S3 or B2 destination (packages/backup s3.ts): the destinations file
// maps names to destinations (destinationsSchema), each naming the file of
// its write credentials (credentialsSchema). Both in the TypeScript
// server's formats.

// Destination is one bucket (destinationSchema).
type Destination struct {
	Endpoint       string `json:"endpoint,omitempty"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	ForcePathStyle bool   `json:"forcePathStyle"`
	// WriteCredentialsFile is the file of the key that uploads.
	WriteCredentialsFile string `json:"writeCredentialsFile"`
}

// Credentials is an access key (credentialsSchema).
type Credentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

// ReadDestination reads one destination from a destinations file, with
// the schema's defaults (prefix "varlatch/", path-style addressing).
func ReadDestination(path, name string) (Destination, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Destination{}, err
	}
	var all map[string]map[string]any
	if err := decodeStrict(raw, &all); err != nil {
		return Destination{}, &Error{"The destinations file is not valid"}
	}
	o, ok := all[name]
	if !ok {
		return Destination{}, &Error{fmt.Sprintf("No destination named %s", name)}
	}
	d := Destination{Prefix: "varlatch/", ForcePathStyle: true}
	for k, v := range o {
		switch k {
		case "endpoint":
			s, ok := v.(string)
			u, err := url.Parse(s)
			if !ok || err != nil || u.Scheme == "" || u.Host == "" {
				return Destination{}, &Error{"The destination's endpoint is not a URL"}
			}
			d.Endpoint = s
		case "region", "bucket", "prefix", "writeCredentialsFile":
			s, ok := v.(string)
			if !ok || (k != "prefix" && s == "") {
				return Destination{}, &Error{fmt.Sprintf("The destination's %s is not valid", k)}
			}
			switch k {
			case "region":
				d.Region = s
			case "bucket":
				d.Bucket = s
			case "prefix":
				d.Prefix = s
			default:
				d.WriteCredentialsFile = s
			}
		case "forcePathStyle":
			b, ok := v.(bool)
			if !ok {
				return Destination{}, &Error{"The destination's forcePathStyle is not a boolean"}
			}
			d.ForcePathStyle = b
		default:
			return Destination{}, &Error{fmt.Sprintf("The destination has an unknown setting %s", k)}
		}
	}
	if d.Region == "" || d.Bucket == "" || d.WriteCredentialsFile == "" {
		return Destination{}, &Error{"A destination needs a region, a bucket and a writeCredentialsFile"}
	}
	return d, nil
}

// ReadCredentials reads a credentials file.
func ReadCredentials(path string) (Credentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if decodeExact(raw, &c) != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return Credentials{}, &Error{"The credentials file is not valid"}
	}
	return c, nil
}

// ObjectKey is an archive's object name: the prefix, with one slash, and
// <archive id>.vltbak.
func ObjectKey(d Destination, archiveID string) (string, error) {
	if !uuidPattern.MatchString(archiveID) {
		return "", &Error{"Invalid archive ID"}
	}
	return strings.TrimSuffix(d.Prefix, "/") + "/" + archiveID + ".vltbak", nil
}

// Client is an S3 client for one destination and key.
type Client struct {
	s3     *s3.Client
	bucket string
}

// NewClient makes the client: the destination's region, endpoint and
// addressing, the key, three attempts per request, and checksums only
// where the protocol requires them (B2 and other S3-compatible stores do
// not take every flexible checksum). client is the HTTP client; nil is a
// default one.
func NewClient(d Destination, c Credentials, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	o := s3.Options{
		Region:                     d.Region,
		UsePathStyle:               d.ForcePathStyle,
		Credentials:                credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken),
		RetryMaxAttempts:           3,
		HTTPClient:                 client,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if d.Endpoint != "" {
		o.BaseEndpoint = aws.String(d.Endpoint)
	}
	return &Client{s3: s3.New(o), bucket: d.Bucket}
}

// partSize is a multipart upload's part (16 MiB, as the TypeScript upload).
const partSize = 16 << 20

// Upload uploads an archive to key: in one request when it fits one part,
// else as a multipart upload, aborted on failure. A failure says what the
// destination answered (StorageErrorDetail) and that the local archive
// remains.
func (c *Client) Upload(ctx context.Context, key, path string) error {
	err := c.upload(ctx, key, path)
	if err != nil {
		return &Error{"Destination upload failed" + StorageErrorDetail(err) + "; local archive remains available"}
	}
	return nil
}

func (c *Client) upload(ctx context.Context, key, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() <= partSize {
		_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &c.bucket, Key: &key, Body: f, ContentLength: aws.Int64(st.Size()), ContentType: aws.String("application/octet-stream"),
		})
		return err
	}
	created, err := c.s3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &c.bucket, Key: &key, ContentType: aws.String("application/octet-stream")})
	if err != nil {
		return err
	}
	abort := func(cause error) error {
		_, _ = c.s3.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{Bucket: &c.bucket, Key: &key, UploadId: created.UploadId})
		return cause
	}
	var parts []types.CompletedPart
	for n, offset := int32(1), int64(0); offset < st.Size(); n, offset = n+1, offset+partSize {
		size := min(partSize, st.Size()-offset)
		got, err := c.s3.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &c.bucket, Key: &key, UploadId: created.UploadId, PartNumber: aws.Int32(n),
			Body: io.NewSectionReader(f, offset, size), ContentLength: aws.Int64(size),
		})
		if err != nil {
			return abort(err)
		}
		parts = append(parts, types.CompletedPart{ETag: got.ETag, PartNumber: aws.Int32(n)})
	}
	if _, err := c.s3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &c.bucket, Key: &key, UploadId: created.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	}); err != nil {
		return abort(err)
	}
	return nil
}

// Download writes the object at key to output, a new file (mode 0600);
// returns the object's version.
func (c *Client) Download(ctx context.Context, key, output string) (string, error) {
	got, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &c.bucket, Key: &key})
	if err != nil {
		return "", &Error{"Remote archive retrieval failed" + StorageErrorDetail(err)}
	}
	defer got.Body.Close()
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, got.Body); err != nil {
		out.Close()
		os.Remove(output)
		return "", &Error{"Remote archive retrieval failed" + StorageErrorDetail(err)}
	}
	if err := out.Close(); err != nil {
		os.Remove(output)
		return "", err
	}
	return aws.ToString(got.VersionId), nil
}

// S3 is the underlying client, for the bucket test.
func (c *Client) S3() *s3.Client { return c.s3 }

// Bucket is the destination's bucket.
func (c *Client) Bucket() string { return c.bucket }

// What an operator needs to tell a wrong key from a missing object or an
// unreachable endpoint (s3.ts storageErrorDetail). Every word comes from
// these tables: a store's error message or body may echo a key ID, a
// signature or an object path, so an unrecognised value is never shown.
const (
	hintKey    = "the destination rejected the key; check its ID and secret, and that it is not deleted or expired"
	hintAccess = "the key may not do this; check that it can access this bucket"
	hintExists = "an object with this name already exists at the destination"
	hintLock   = "the destination refused the request; if it sets retention, check that the bucket has Object Lock enabled and that the key may set retention"
	hintAgain  = "the destination had a temporary problem; try again later"
)

var s3Codes = map[string]string{
	"InvalidAccessKeyId": hintKey, "SignatureDoesNotMatch": hintKey, "ExpiredToken": hintKey, "InvalidToken": hintKey,
	"TokenRefreshRequired": hintKey, "Unauthorized": hintKey,
	"AccessDenied": hintAccess, "AllAccessDisabled": hintAccess, "AccountProblem": "the destination account has a problem; check it with the provider",
	"NoSuchKey": "the archive is not at the destination", "NotFound": "the archive is not at the destination",
	"NoSuchBucket":         "the bucket does not exist at the destination",
	"RequestTimeTooSkewed": "this host's clock differs too much from the destination's; check the time on this host",
	"InvalidObjectState":   "the archive is in a storage class that cannot be read directly; restore it at the provider first",
	"InternalError":        hintAgain, "ServiceUnavailable": hintAgain,
	"SlowDown":           "the destination is limiting requests; try again later",
	"PreconditionFailed": hintExists,
	"InvalidRequest":     hintLock, "ObjectLockConfigurationNotFoundError": hintLock, "NoSuchObjectLockConfiguration": hintLock,
}

// StorageErrorDetail is " (S3 error X, HTTP n, network cause): hint" for
// what is known of err, or "" when nothing is.
func StorageErrorDetail(err error) string {
	var parts []string
	code := ""
	var api smithy.APIError
	if errors.As(err, &api) {
		if _, ok := s3Codes[api.ErrorCode()]; ok {
			code = api.ErrorCode()
			parts = append(parts, "S3 error "+code)
		}
	}
	status := 0
	var re *awshttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() >= 100 && re.HTTPStatusCode() <= 599 {
		status = re.HTTPStatusCode()
		parts = append(parts, fmt.Sprintf("HTTP %d", status))
	}
	if local := localCause(err); local != "" {
		parts = append(parts, local)
	}
	if len(parts) == 0 {
		return ""
	}
	hint := s3Codes[code]
	if hint == "" {
		switch status {
		case 401:
			hint = hintKey
		case 403:
			hint = "the destination refused the request; check that the key can access this bucket"
		case 404:
			hint = "the bucket or archive is not at the destination"
		case 412:
			hint = hintExists
		}
	}
	out := " (" + strings.Join(parts, ", ") + ")"
	if hint != "" {
		out += ": " + hint
	}
	return out
}

// localCause names a network or TLS failure, without its text.
func localCause(err error) string {
	var dns *net.DNSError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var tlsRecord tls.RecordHeaderError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return "endpoint host name not found"
	case errors.As(err, &dns):
		return "endpoint host name lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "endpoint unreachable"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	case errors.Is(err, syscall.EPIPE):
		return "connection closed"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "endpoint TLS certificate expired"
	case errors.As(err, &hostname):
		return "endpoint TLS certificate does not match the host"
	case errors.As(err, &unknown), errors.As(err, &tlsRecord):
		return "endpoint TLS certificate not trusted"
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "request timed out"
	}
	return ""
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
