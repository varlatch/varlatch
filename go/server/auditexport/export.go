// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditexport is an Organization's audit export to object storage
// (ADR-0056; domain/auditexport.ts; ADR-0059 step 4.11): its whole audit
// log, in position order, copied to an S3-compatible bucket it controls,
// with Object Lock retention nobody on the Varlatch side can shorten.
//
// This package holds the configuration side (4.11a): creating, checking,
// changing, re-keying and removing the export, each refused while the
// Organization is frozen or being deleted (removal excepted from the host
// switch). Creating, checking and changing the destination send the key
// out (the probe), so they run as external effects (write.RunEffect). A
// change that loosens (another destination, a shorter or removed
// retention, compliance to governance), a new key and removal always need
// the requester's step-up approval, whatever the Security Controls' modes.
// The worker, the drains and `admin audit-export` come in 4.11b.
package auditexport

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Limits are AUDIT_EXPORT_LIMITS (the configuration's).
const (
	PrefixMax        = 256
	RetentionDaysMax = 3650
	// UploadTimeout bounds one request to the destination.
	UploadTimeout = 30 * time.Second
	// FormatVersion is the object format this release writes.
	FormatVersion = 1
	formatName    = "varlatch-audit-export"
)

// uploadableFormats are the formats this release can upload from a plan.
var uploadableFormats = map[int64]bool{1: true}

// Destination is AuditExportDestination.
type Destination struct {
	Endpoint, Region, Bucket, Prefix string
	PathStyle                        bool
}

// JS is the destination as the API gives it.
func (d Destination) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "endpoint", Value: d.Endpoint}, {Key: "region", Value: d.Region}, {Key: "bucket", Value: d.Bucket},
		{Key: "prefix", Value: d.Prefix}, {Key: "pathStyle", Value: d.PathStyle},
	}
}

// Retention is AuditExportRetention; nil is none.
type Retention struct {
	Mode string // "compliance" or "governance"
	Days int64
}

func (r *Retention) js() any {
	if r == nil {
		return nil
	}
	return jsvalue.Object{{Key: "mode", Value: r.Mode}, {Key: "days", Value: r.Days}}
}

// Credential is AuditExportCredential, sealed as its JSON.
type Credential struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

func (c Credential) js() jsvalue.Object {
	return jsvalue.Object{{Key: "accessKeyId", Value: c.AccessKeyID}, {Key: "secretAccessKey", Value: c.SecretAccessKey}}
}

// The validation of Decision 6, without the network.
var (
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	ipLike   = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	keyIDRE  = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	secretRE = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	badChars = regexp.MustCompile(`[\x00-\x1f\x7f\\]`)
)

func invalid(msg string) error { return domainerr.New("VALIDATION_FAILED", msg) }

func jsLength(s string) int { return len(utf16.Encode([]rune(s))) }

// NormalizeDestination is normalizeDestination: the endpoint's origin,
// and a prefix that is empty or ends with "/".
func NormalizeDestination(in Destination) (Destination, error) {
	u, ok := whatwg.ParseURL(in.Endpoint)
	if !ok {
		return Destination{}, invalid("endpoint: not a URL")
	}
	if u.Protocol != "https:" && u.Protocol != "http:" {
		return Destination{}, invalid("endpoint: must be https")
	}
	if u.Username != "" || u.Password != "" {
		return Destination{}, invalid("endpoint: must not carry user info")
	}
	if u.Search != "" || u.Hash != "" || (u.Pathname != "/" && u.Pathname != "") {
		return Destination{}, invalid("endpoint: must be a scheme, host and optional port, without a path or query")
	}
	b := in.Bucket
	if !bucketRE.MatchString(b) || strings.Contains(b, "..") || ipLike.MatchString(b) || strings.Contains(b, ".-") || strings.Contains(b, "-.") {
		return Destination{}, invalid("bucket: 3 to 63 lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit")
	}
	if !regionRE.MatchString(in.Region) {
		return Destination{}, invalid("region: lowercase letters, digits and hyphens")
	}
	prefix := in.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if jsLength(prefix) > PrefixMax {
		return Destination{}, invalid("prefix: at most " + strconv.Itoa(PrefixMax) + " characters")
	}
	dots := false
	for _, part := range strings.Split(prefix, "/") {
		if part == ".." || part == "." {
			dots = true
		}
	}
	if strings.HasPrefix(prefix, "/") || dots || badChars.MatchString(prefix) {
		return Destination{}, invalid("prefix: no leading slash, no . or .. parts, no control characters")
	}
	return Destination{Endpoint: u.Protocol + "//" + u.Host, Region: in.Region, Bucket: b, Prefix: prefix, PathStyle: in.PathStyle}, nil
}

// ValidateRetention is validateRetention.
func ValidateRetention(r *Retention) (*Retention, error) {
	if r == nil {
		return nil, nil
	}
	if r.Mode != "compliance" && r.Mode != "governance" {
		return nil, invalid("retention.mode: compliance or governance")
	}
	if r.Days < 1 || r.Days > RetentionDaysMax {
		return nil, invalid("retention.days: a whole number from 1 to " + strconv.Itoa(RetentionDaysMax))
	}
	return &Retention{Mode: r.Mode, Days: r.Days}, nil
}

// ValidateCredential is validateCredential.
func ValidateCredential(c Credential) (Credential, error) {
	if !keyIDRE.MatchString(c.AccessKeyID) || !secretRE.MatchString(c.SecretAccessKey) {
		return Credential{}, invalid("credential: an access key ID and a secret, without spaces")
	}
	return c, nil
}

func nullTime(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

func nullBool(n sql.NullBool) any {
	if !n.Valid {
		return nil
	}
	return n.Bool
}

func nullString(n sql.NullString) any {
	if !n.Valid {
		return nil
	}
	return n.String
}

func destinationOf(r query.AuditExport) Destination {
	return Destination{Endpoint: r.Endpoint, Region: r.Region, Bucket: r.Bucket, Prefix: r.Prefix, PathStyle: r.PathStyle}
}

func retentionOf(r query.AuditExport) *Retention {
	if !r.RetentionMode.Valid || !r.RetentionDays.Valid || r.RetentionDays.Int64 == 0 {
		return nil
	}
	return &Retention{Mode: r.RetentionMode.String, Days: r.RetentionDays.Int64}
}

// view is viewOf: the export as the Security page and the API show it,
// never the key.
func view(r query.AuditExport) jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: r.ID}, {Key: "organizationId", Value: r.OrganizationID},
		{Key: "destination", Value: destinationOf(r).JS()}, {Key: "retention", Value: retentionOf(r).js()},
		{Key: "state", Value: r.State}, {Key: "streamId", Value: r.StreamID}, {Key: "cursor", Value: strconv.FormatInt(r.CursorOrder, 10)},
		{Key: "version", Value: r.Version}, {Key: "lastAttemptAt", Value: nullTime(r.LastAttemptAt)},
		{Key: "lastSuccessAt", Value: nullTime(r.LastSuccessAt)}, {Key: "lastHeartbeatAt", Value: nullTime(r.LastHeartbeatHour)},
		{Key: "lastError", Value: nullString(r.LastError)}, {Key: "failingSince", Value: nullTime(r.FailingSince)},
		{Key: "keyCanRead", Value: nullBool(r.KeyCanRead)}, {Key: "retentionReadable", Value: nullBool(r.RetentionReadable)},
		{Key: "stoppedReason", Value: nullString(r.StoppedReason)}, {Key: "conditionalCheckedAt", Value: nullTime(r.ConditionalCheckedAt)},
		{Key: "lockVerified", Value: nullBool(r.LockVerified)}, {Key: "drainDeadline", Value: nullTime(r.DrainDeadline)},
		{Key: "createdBy", Value: r.CreatedBy}, {Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)}, {Key: "removedAt", Value: nullTime(r.RemovedAt)},
	}
}

func live(r query.AuditExport) bool { return r.State == "active" || r.State == "draining" }

func objectLock(r query.AuditExport) string {
	switch {
	case retentionOf(r) == nil:
		return "not-set"
	case r.LockVerified.Valid && r.LockVerified.Bool:
		return "verified"
	}
	return "accepted"
}

// statusView is AuditExportStatusView: the view, the lag of a live export,
// the Object Lock word and a pending plan's format this release cannot
// upload.
func statusView(ctx context.Context, db query.DBTX, r query.AuditExport) (jsvalue.Object, error) {
	out := view(r)
	var lag, unsupported any
	if live(r) {
		q := query.New(db)
		l, err := q.AuditExportLag(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		var oldest any
		if v, ok := l.Oldest.(int64); ok {
			oldest = audit.ISOTime(v)
		}
		lag = jsvalue.Object{{Key: "pending", Value: l.N}, {Key: "oldestPendingAt", Value: oldest}}
		plan, err := q.AuditExportPlanOf(ctx, r.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil && !uploadableFormats[plan.FormatVersion] {
			unsupported = plan.FormatVersion
		}
	}
	return append(out, jsvalue.Member{Key: "lag", Value: lag}, jsvalue.Member{Key: "objectLock", Value: objectLock(r)},
		jsvalue.Member{Key: "unsupportedPlanFormat", Value: unsupported}), nil
}

// removedView is the removal's answer: the view, with no lag and no plan.
func removedView(r query.AuditExport) jsvalue.Object {
	return append(view(r), jsvalue.Member{Key: "lag", Value: nil}, jsvalue.Member{Key: "objectLock", Value: objectLock(r)},
		jsvalue.Member{Key: "unsupportedPlanFormat", Value: nil})
}

// Status is auditExportStatus: whether the host left the export on, and the
// Organization's export (the live one, else the most recent, else null),
// read in one snapshot (db: the caller's read transaction).
func Status(ctx context.Context, db query.DBTX, organizationID string, enabled bool) (jsvalue.Object, error) {
	r, err := query.New(db).LatestAuditExport(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return jsvalue.Object{{Key: "enabled", Value: enabled}, {Key: "export", Value: nil}}, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := statusView(ctx, db, r)
	if err != nil {
		return nil, err
	}
	return jsvalue.Object{{Key: "enabled", Value: enabled}, {Key: "export", Value: v}}, nil
}

// LiveID is liveAuditExportId: the live export's id, or "aex_none", a
// placeholder no row has (the operation answers its not-found after the
// deletion and freeze refusals).
func LiveID(ctx context.Context, db query.DBTX, organizationID string) (string, error) {
	r, err := query.New(db).LiveAuditExport(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "aex_none", nil
	}
	return r.ID, err
}

// The stream's objects (Decision 4).

func streamBase(prefix, organizationID, streamID string) string {
	return prefix + "varlatch-audit/" + organizationID + "/" + streamID + "/"
}

// planned is an object planned before it is uploaded.
type planned struct {
	kind, objectName, contentType string
	body                          []byte
}

// msTime is a time as a JavaScript Date holds it: milliseconds.
func msTime(t time.Time) time.Time { return t.Truncate(time.Millisecond) }

func isoMs(t time.Time) string { return audit.ISOTime(msTime(t).UnixMicro()) }

// manifestPlan is manifestPlan: the stream's stream.json.
func manifestPlan(prefix, organizationID, streamID string, startOrder int64, previousStreamID *string, reason string, plannedAt time.Time) planned {
	var previous any
	if previousStreamID != nil {
		previous = *previousStreamID
	}
	body := jsvalue.Stringify(jsvalue.Object{
		{Key: "format", Value: formatName}, {Key: "version", Value: FormatVersion}, {Key: "kind", Value: "stream"},
		{Key: "organizationId", Value: organizationID}, {Key: "streamId", Value: streamID},
		{Key: "startOrder", Value: strconv.FormatInt(startOrder, 10)}, {Key: "previousStreamId", Value: previous},
		{Key: "reason", Value: reason}, {Key: "possibleOverlap", Value: nil}, {Key: "plannedAt", Value: isoMs(plannedAt)},
	})
	return planned{kind: "manifest", objectName: streamBase(prefix, organizationID, streamID) + "stream.json",
		body: append(body, '\n'), contentType: "application/json"}
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func md5Hex(b []byte) string    { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

// insertPlan is insertPlan, for the export's current binding.
func insertPlan(ctx context.Context, db query.DBTX, exportID string, version int64, streamID string, generation int64, p planned, r *Retention, plannedAt time.Time) error {
	plannedAt = msTime(plannedAt)
	var mode sql.NullString
	var until sql.NullInt64
	if r != nil {
		mode = sql.NullString{String: r.Mode, Valid: true}
		until = sql.NullInt64{Int64: plannedAt.Add(time.Duration(r.Days) * 24 * time.Hour).UnixMicro(), Valid: true}
	}
	return query.New(db).InsertAuditExportPlan(ctx, query.InsertAuditExportPlanParams{
		ID: ids.New(ids.AuditExportPlan), ExportID: exportID, ExportVersion: version, StreamID: streamID, Generation: generation,
		Kind: p.kind, ObjectName: p.objectName, Body: p.body, Sha256: sha256Hex(p.body), Md5: md5Hex(p.body),
		ContentType: p.contentType, FormatVersion: FormatVersion, RetentionMode: mode, RetainUntil: until, PlannedAt: plannedAt.UnixMicro(),
	})
}

// streamStarted is streamStartedEvent.
func streamStarted(organizationID, exportID, streamID string, previous *string, reason string, actor *string, requestID *string) audit.Event {
	var prev any
	if previous != nil {
		prev = *previous
	}
	return audit.Event{
		Type: "audit_export.stream_started", Decision: audit.Info, ActorIdentityID: actor, OrganizationID: &organizationID, RequestID: requestID,
		Resource: jsvalue.Object{{Key: "exportId", Value: exportID}},
		Metadata: jsvalue.Object{{Key: "streamId", Value: streamID}, {Key: "previousStreamId", Value: prev}, {Key: "reason", Value: reason}},
	}
}
