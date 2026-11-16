// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// verifiedLockProviders are the endpoints whose Object Lock behaviour is
// verified (ADR-0040's spike): AWS S3 and Backblaze B2.
var verifiedLockProviders = []*regexp.Regexp{regexp.MustCompile(`(?i)(^|\.)amazonaws\.com$`), regexp.MustCompile(`(?i)(^|\.)backblazeb2\.com$`)}

// ProbeWords are PROBE_WORDS: the probe's own findings.
var ProbeWords = struct{ Overwrote, NoMetadata, NoRetention, WeakerRetention string }{
	Overwrote:       "This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)",
	NoMetadata:      "This destination did not keep the test object's SHA-256 metadata, which audit export compares when a write finds its name taken",
	NoRetention:     "This destination accepted the retention headers but kept no retention on the test object; check that the bucket has Object Lock enabled",
	WeakerRetention: "This destination kept the test object with a weaker retention than requested (another mode, or an earlier date)",
}

// ProbeResult is what a probe found (Decision 6). Message holds fixed
// wording only (the storage error tables, the outbound policy's words).
type ProbeResult struct {
	OK                  bool
	Message             *string
	ConditionalCreation *bool
	// ObjectLock is "verified", "accepted" or "not-set"; nil when unknown.
	ObjectLock                    *string
	KeyCanRead, RetentionReadable *bool
}

func ptr[T any](v T) *T { return &v }

func orNull[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// JS is the result as the API gives it (AuditExportCheck).
func (p ProbeResult) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "ok", Value: p.OK}, {Key: "message", Value: orNull(p.Message)}, {Key: "conditionalCreation", Value: orNull(p.ConditionalCreation)},
		{Key: "objectLock", Value: orNull(p.ObjectLock)}, {Key: "keyCanRead", Value: orNull(p.KeyCanRead)},
		{Key: "retentionReadable", Value: orNull(p.RetentionReadable)},
	}
}

// refusedProbe is probeRefused: a probe that did not pass, its words and
// what it learned before.
func refusedProbe(message string, partial ProbeResult) ProbeResult {
	partial.OK, partial.Message, partial.ObjectLock = false, &message, nil
	return partial
}

// FailureWords is failureWords: the outbound policy's words for a refusal,
// or the prefix and what the storage error tables know, never the store's
// own text.
func FailureWords(prefix string, err error) string {
	if r := outbound.RefusalOf(err); r != nil {
		return r.Error()
	}
	return prefix + backup.StorageErrorDetail(err)
}

// RetentionHolds is retentionHolds: the mode read back is the one asked
// for, or compliance for governance, and the date is no earlier than the
// one asked for, which a provider may round down to its second.
func RetentionHolds(askedMode string, askedUntil time.Time, got backup.Retention) bool {
	modeHolds := got.Mode == askedMode || (askedMode == "governance" && got.Mode == "compliance")
	askedSecond := askedUntil.Truncate(time.Second)
	return modeHolds && !got.RetainUntil.Before(askedSecond)
}

func (s *Service) verifiedProvider(endpoint string) bool {
	if s.VerifiedProvider != nil && s.VerifiedProvider(endpoint) {
		return true
	}
	u, ok := whatwg.ParseURL(endpoint)
	if !ok {
		return false
	}
	host := u.Host
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	for _, re := range verifiedLockProviders {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// client is the S3 client for a destination and key, built on the
// outbound policy's audit_export client (ADR-0057): every connection
// checked as it opens, one attempt per request.
func (s *Service) client(d Destination, c Credential) *backup.Client {
	return backup.NewClient(
		backup.Destination{Endpoint: d.Endpoint, Region: d.Region, Bucket: d.Bucket, Prefix: d.Prefix, ForcePathStyle: d.PathStyle},
		backup.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey},
		s.Policy.Client(outbound.AuditExport), backup.WithMaxAttempts(1))
}

// request runs one request to the destination within UploadTimeout (and
// the effect's deadline, which ctx carries).
func request[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, UploadTimeout)
	defer cancel()
	return fn(ctx)
}

// probe is probe (Decision 6), under <prefix>varlatch-audit/<org>/probe/:
// a first write (with the retention headers when retention is set), a
// second write of the same name that must be refused with 412, a HEAD of
// the object (can the key read content, and is the SHA-256 metadata the
// 412 check compares kept), and, with retention, the retention read back.
// Reading content and reading retention are separate permissions,
// recorded separately. A retention read back weaker than asked fails the
// probe; one that cannot be read is "verified" only on a verified
// provider (Decision 7). The probe objects stay.
func (s *Service) probe(ctx context.Context, organizationID string, d Destination, c Credential, r *Retention, now time.Time) ProbeResult {
	now = msTime(now)
	cl := s.client(d, c)
	body := append(jsvalue.Stringify(jsvalue.Object{
		{Key: "format", Value: formatName}, {Key: "version", Value: FormatVersion}, {Key: "kind", Value: "probe"}, {Key: "at", Value: isoMs(now)},
	}), '\n')
	name := make([]byte, 16)
	_, _ = rand.Read(name)
	put := backup.ConditionalPut{
		Key: d.Prefix + "varlatch-audit/" + organizationID + "/probe/" + hex.EncodeToString(name) + ".json", Body: body,
		SHA256: sha256Hex(body), MD5: md5Hex(body), ContentType: "application/json",
	}
	var until time.Time
	if r != nil {
		until = now.Add(time.Duration(r.Days) * 24 * time.Hour)
		put.Retention = &backup.Retention{Mode: r.Mode, RetainUntil: until}
	}
	putOnce := func(ctx context.Context) (struct{}, error) { return struct{}{}, cl.PutIfAbsent(ctx, put) }
	if _, err := request(ctx, putOnce); err != nil {
		return refusedProbe(FailureWords("The test write failed", err), ProbeResult{})
	}
	if _, err := request(ctx, putOnce); err == nil {
		return refusedProbe(ProbeWords.Overwrote, ProbeResult{ConditionalCreation: ptr(false)})
	} else if !backup.IsPreconditionFailed(err) {
		return refusedProbe(FailureWords("The conditional test write failed", err), ProbeResult{})
	}
	// Content read (HEAD): what the worker's 412 check needs.
	var keyCanRead *bool
	sum, err := request(ctx, func(ctx context.Context) (string, error) { return cl.ObjectSHA256(ctx, put.Key) })
	switch {
	case err == nil && sum != put.SHA256:
		return refusedProbe(ProbeWords.NoMetadata, ProbeResult{ConditionalCreation: ptr(true)})
	case err == nil:
		keyCanRead = ptr(true)
	case backup.IsAccessDenied(err):
		keyCanRead = ptr(false)
	}
	if r == nil {
		return ProbeResult{OK: true, ConditionalCreation: ptr(true), ObjectLock: ptr("not-set"), KeyCanRead: keyCanRead}
	}
	// Retention read (GetObjectRetention): a permission of its own.
	var readable *bool
	got, err := request(ctx, func(ctx context.Context) (*backup.Retention, error) { return cl.ObjectRetention(ctx, put.Key) })
	readBack := err == nil
	switch {
	case err == nil:
		readable = ptr(true)
	case backup.IsAccessDenied(err):
		readable = ptr(false)
	}
	learned := ProbeResult{ConditionalCreation: ptr(true), KeyCanRead: keyCanRead, RetentionReadable: readable}
	if readBack && got == nil {
		return refusedProbe(ProbeWords.NoRetention, learned)
	}
	if readBack && !RetentionHolds(r.Mode, until, *got) {
		return refusedProbe(ProbeWords.WeakerRetention, learned)
	}
	lock := "accepted"
	if readBack || s.verifiedProvider(d.Endpoint) {
		lock = "verified"
	}
	learned.OK, learned.ObjectLock = true, &lock
	return learned
}
