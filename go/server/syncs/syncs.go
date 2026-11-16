// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syncs is Platform Connections (ADR-0031 §1-2, domain/sync.ts;
// ADR-0059 step 4.9b) and, from 4.9c, Sync Targets: a Connection
// authenticates once per platform account or instance with a Platform
// Credential sealed under the Organization KEK; a Target binds one
// Environment to one destination on it.
//
// Creating a Connection, replacing its credential and revoking it are
// protected operations (ADR-0054, security.Prepare): admin-step-up's
// connection.create, .replace_credential and .delete. An access check and
// a destination listing are external effects (write.RunEffect) that send
// the credential only to the Connection's base identity, through the
// outbound policy (ADR-0057), with the adapters of go/lib/sync.
//
// A GitHub App Connection (ADR-0047) is listed, read and revoked here; what
// mints a token from its App (creating one, and its access checks and
// listings) comes with step 4.10 and answers NOT_IMPLEMENTED_YET until then.
package syncs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Service is what the operations work with.
type Service struct {
	Writer    *write.Writer
	Approvals *auth.Service
	RootKEK   []byte
	// Policy is the outbound policy: base identities are checked before
	// anything is held, and every request goes through its clients.
	Policy *outbound.Policy
	// Adapters is the host's sync_adapters; nil allows every platform.
	Adapters []string
	Now      func() time.Time
	Log      *slog.Logger
	// client replaces the policy's clients (tests only).
	client *http.Client
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) store() *storage.DB { return s.Writer.Store }

// Request is who asks, with what Varlatch-Approval header (nil for none)
// and the request's id.
type Request struct {
	Principal *auth.Principal
	Approval  *string
	RequestID string
}

func (r Request) security(approvals *auth.Service) security.Request {
	out := security.Request{Principal: r.Principal, Approvals: approvals}
	if r.Approval != nil {
		if out.ApprovalID = auth.ParseApprovalID(*r.Approval); out.ApprovalID == "" {
			out.ApprovalMalformed = true
		}
	}
	return out
}

func authzPrincipal(p *auth.Principal) authz.Principal {
	out := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
	if p.Identity.OrganizationID != nil {
		out.OrganizationID = *p.Identity.OrganizationID
	}
	return out
}

// ManageIn is actionIn's config.sync.manage, rechecked in a protected
// operation's job once its approval was consumed; a denial's event is
// recorded after the job.
func ManageIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		d, err := authz.Decide(ctx, tx, authzPrincipal(p), "config.sync.manage", authz.Resource{OrganizationID: organizationID},
			authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

// ---------------------------------------------------------------------------
// Refusals, in the TypeScript server's words.

func connectionNotFound() error {
	return domainerr.New("RESOURCE_NOT_FOUND", "Platform Connection not found")
}

func versionConflict() error {
	return domainerr.New("VERSION_CONFLICT", "Connection was modified concurrently; reload and retry")
}

func emptyCredential() error {
	return domainerr.New("VALIDATION_FAILED", "Platform Credential must not be empty")
}

func adapterNotAllowed() error {
	return domainerr.New("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter")
}

func appHasNoCredential() error {
	return domainerr.New("VALIDATION_FAILED",
		"A GitHub App Connection has no credential of its own to replace or supply: its tokens are issued from the App's key. Rotate the App's key instead.")
}

// NotImplementedYet is the code of what this build answers for the GitHub
// App paths that mint a token (step 4.10).
const NotImplementedYet = "NOT_IMPLEMENTED_YET"

func appMintingNotBuilt() error {
	return domainerr.New(NotImplementedYet,
		"A GitHub App Connection's tokens are not built yet in this varlatchd (ADR-0059 step 4.10: the Go server is being written)")
}

// validation is canonicalizeOrValidationError: an adapter's refusal is a
// validation failure in its words.
func validation(err error) error {
	var ae *vsync.AdapterError
	if errors.As(err, &ae) {
		return domainerr.New("VALIDATION_FAILED", ae.Message)
	}
	return err
}

func (s *Service) allowed(platform string) bool {
	return s.Adapters == nil || slices.Contains(s.Adapters, platform)
}

// ---------------------------------------------------------------------------
// The rows, as the API shows them.

// Connection is a platform_connections row as the operations read it.
type Connection struct {
	ID, OrganizationID, Platform, BaseIdentity, Name string
	CreatedAt                                        int64
	Version                                          int64
	UpdatedAt                                        sql.NullInt64
	CredentialExpiresAt, CredentialExpirySeenAt      sql.NullInt64
	CredentialKind                                   string
	GitHubAppID                                      sql.NullString
	InstallationID                                   sql.NullInt64
	// TargetCount is the live Targets' count, in a listing only.
	TargetCount *int64
}

func connectionOf(r query.LiveConnectionRow) Connection {
	return Connection{
		ID: r.ID, OrganizationID: r.OrganizationID, Platform: r.Platform, BaseIdentity: r.BaseIdentity, Name: r.Name,
		CreatedAt: r.CreatedAt, Version: r.Version, UpdatedAt: r.UpdatedAt,
		CredentialExpiresAt: r.CredentialExpiresAt, CredentialExpirySeenAt: r.CredentialExpirySeenAt,
		CredentialKind: r.CredentialKind, GitHubAppID: r.GithubAppID, InstallationID: r.GithubInstallationID,
	}
}

func iso(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

// JS is serializeConnection.
func (c Connection) JS() jsvalue.Object {
	o := jsvalue.Object{
		{Key: "id", Value: c.ID}, {Key: "organizationId", Value: c.OrganizationID}, {Key: "platform", Value: c.Platform},
		{Key: "baseIdentity", Value: c.BaseIdentity}, {Key: "name", Value: c.Name},
	}
	if c.TargetCount != nil {
		o = append(o, jsvalue.Member{Key: "targetCount", Value: *c.TargetCount})
	}
	var app, installation any
	if c.GitHubAppID.Valid {
		app = c.GitHubAppID.String
	}
	if c.InstallationID.Valid {
		installation = c.InstallationID.Int64
	}
	return append(o,
		jsvalue.Member{Key: "createdAt", Value: audit.ISOTime(c.CreatedAt)}, jsvalue.Member{Key: "version", Value: c.Version},
		jsvalue.Member{Key: "updatedAt", Value: iso(c.UpdatedAt)},
		jsvalue.Member{Key: "credentialExpiresAt", Value: iso(c.CredentialExpiresAt)},
		jsvalue.Member{Key: "credentialExpirySeenAt", Value: iso(c.CredentialExpirySeenAt)},
		jsvalue.Member{Key: "credentialKind", Value: c.CredentialKind},
		jsvalue.Member{Key: "githubAppId", Value: app}, jsvalue.Member{Key: "installationId", Value: installation},
	)
}

// List is listConnections: the live Connections with their Targets'
// count, oldest first.
func List(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationConnections(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(rows))
	for i, r := range rows {
		n := r.TargetCount
		out[i] = Connection{
			ID: r.ID, OrganizationID: r.OrganizationID, Platform: r.Platform, BaseIdentity: r.BaseIdentity, Name: r.Name,
			CreatedAt: r.CreatedAt, Version: r.Version, UpdatedAt: r.UpdatedAt,
			CredentialExpiresAt: r.CredentialExpiresAt, CredentialExpirySeenAt: r.CredentialExpirySeenAt,
			CredentialKind: r.CredentialKind, GitHubAppID: r.GithubAppID, InstallationID: r.GithubInstallationID, TargetCount: &n,
		}.JS()
	}
	return out, nil
}

// read is readConnection and getConnection: a live Connection of the
// Organization, or nil.
func read(ctx context.Context, db query.DBTX, organizationID, connectionID string) (*Connection, error) {
	r, err := query.New(db).LiveConnection(ctx, query.LiveConnectionParams{ID: connectionID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := connectionOf(r)
	return &c, nil
}

// Get is getConnection.
func Get(ctx context.Context, db query.DBTX, organizationID, connectionID string) (Connection, error) {
	c, err := read(ctx, db, organizationID, connectionID)
	if err == nil && c == nil {
		err = connectionNotFound()
	}
	if err != nil {
		return Connection{}, err
	}
	return *c, nil
}

// Target is a sync_targets row as the operations read it.
type Target = query.ConnectionTargetsRow

func targetsOf(rows []query.OrganizationConnectionTargetsRow) []Target {
	out := make([]Target, len(rows))
	for i, r := range rows {
		out[i] = Target(r)
	}
	return out
}

// jsonbOf is a JSON column as the TypeScript server reads it from jsonb.
func jsonbOf(text string) (any, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	return jsvalue.Jsonb(v), nil
}

func jsonbOrNull(text sql.NullString) (any, error) {
	if !text.Valid {
		return nil, nil
	}
	return jsonbOf(text.String)
}

// TargetsJS is serializeTargets: each Target with whether it is drained
// (no live run) and its earliest live run's start.
func TargetsJS(ctx context.Context, db query.DBTX, targets []Target, now int64) ([]any, error) {
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.ID
	}
	idList, _ := json.Marshal(ids)
	runs := map[string]int64{}
	if len(targets) > 0 {
		rows, err := query.New(db).LiveRunStarts(ctx, query.LiveRunStartsParams{TargetIds: string(idList), Now: now})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			runs[r.TargetID] = r.StartedAt
		}
	}
	out := make([]any, len(targets))
	for i, t := range targets {
		destination, err := jsonbOf(t.Destination)
		if err != nil {
			return nil, err
		}
		mapping, err := jsonbOf(t.Mapping)
		if err != nil {
			return nil, err
		}
		notes, err := jsonbOrNull(t.LastNotes)
		if err != nil {
			return nil, err
		}
		var drift any
		if t.LastDriftAt.Valid {
			count := int64(0)
			if t.LastDriftCount.Valid {
				count = t.LastDriftCount.Int64
			}
			var names any = []any{}
			if t.LastDriftNames.Valid {
				if names, err = jsonbOf(t.LastDriftNames.String); err != nil {
					return nil, err
				}
			}
			var event any
			if t.LastDriftEventID.Valid {
				event = t.LastDriftEventID.String
			}
			drift = jsvalue.Object{{Key: "at", Value: audit.ISOTime(t.LastDriftAt.Int64)}, {Key: "count", Value: count},
				{Key: "names", Value: names}, {Key: "eventId", Value: event}}
		}
		var reason, result any
		if t.DisabledReason.Valid {
			reason = t.DisabledReason.String
		}
		if t.LastResult.Valid {
			result = t.LastResult.String
		}
		started, running := runs[t.ID]
		var startedAt any
		if running {
			startedAt = audit.ISOTime(started)
		}
		out[i] = jsvalue.Object{
			{Key: "id", Value: t.ID}, {Key: "organizationId", Value: t.OrganizationID}, {Key: "projectId", Value: t.ProjectID},
			{Key: "environmentId", Value: t.EnvironmentID}, {Key: "connectionId", Value: t.ConnectionID},
			{Key: "destination", Value: destination}, {Key: "mapping", Value: mapping},
			{Key: "removeOrphans", Value: t.RemoveOrphans}, {Key: "redeploy", Value: t.Redeploy}, {Key: "state", Value: t.State},
			{Key: "disabledReason", Value: reason}, {Key: "failureCount", Value: t.FailureCount}, {Key: "needsSync", Value: t.NeedsSync},
			{Key: "lastAttemptAt", Value: iso(t.LastAttemptAt)}, {Key: "lastResult", Value: result}, {Key: "lastNotes", Value: notes},
			{Key: "lastDrift", Value: drift}, {Key: "drained", Value: !running}, {Key: "runStartedAt", Value: startedAt},
			{Key: "createdAt", Value: audit.ISOTime(t.CreatedAt)}, {Key: "version", Value: t.Version}, {Key: "updatedAt", Value: iso(t.UpdatedAt)},
		}
	}
	return out, nil
}

// GetWithTargets is GET …/platform-connections/{connection}: the
// Connection with every Target it feeds (the dependency list shown before
// a credential replacement).
func GetWithTargets(ctx context.Context, db query.DBTX, organizationID, connectionID string, now int64) (jsvalue.Object, error) {
	c, err := Get(ctx, db, organizationID, connectionID)
	if err != nil {
		return nil, err
	}
	rows, err := query.New(db).OrganizationConnectionTargets(ctx, query.OrganizationConnectionTargetsParams{OrganizationID: organizationID, ConnectionID: c.ID})
	if err != nil {
		return nil, err
	}
	targets, err := TargetsJS(ctx, db, targetsOf(rows), now)
	if err != nil {
		return nil, err
	}
	return append(c.JS(), jsvalue.Member{Key: "targets", Value: targets}), nil
}

// ---------------------------------------------------------------------------
// The integration index (ADR-0052 Decision 6).

// indexIntegration is recordIntegrationChange: written in the job that
// changes the Connection, before its audit event.
func indexIntegration(ctx context.Context, tx query.DBTX, organizationID, identityID, kind, resourceID string, changes []string, at int64) error {
	if len(changes) == 0 {
		return nil
	}
	sorted := slices.Clone(changes)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	text, _ := json.Marshal(sorted)
	return query.New(tx).UpsertIntegration(ctx, query.UpsertIntegrationParams{
		OrganizationID: organizationID, IdentityID: identityID, Kind: kind, ResourceID: resourceID, Changes: string(text), At: at,
	})
}

// ---------------------------------------------------------------------------
// The credential.

// orgKEK is orgKekOf, read in db: a deleted Organization's KEK is
// destroyed, so it fails closed.
func (s *Service) orgKEK(ctx context.Context, db query.DBTX, organizationID string) ([]byte, error) {
	o, err := query.New(db).RetrievalOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if !o.WrappedOrgKek.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(o.WrappedOrgKek.String), &env); err != nil {
		return nil, err
	}
	return envelope.UnwrapOrgKEK(s.RootKEK, env, organizationID)
}

// seal is encryptPlatformCredential: the credential's UTF-8 (a lone
// surrogate as U+FFFD, as Node encodes it) under the Organization KEK.
func (s *Service) seal(ctx context.Context, organizationID, connectionID, credential string) (string, error) {
	kek, err := s.orgKEK(ctx, s.store().Reader(), organizationID)
	if err != nil {
		return "", err
	}
	sealed, err := envelope.Seal(kek, []byte(strings.ToValidUTF8(wtf8ToUTF8(credential), "�")),
		envelope.PlatformCredentialContext(organizationID, connectionID))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(sealed)
	return string(b), err
}

// open is decryptPlatformCredential.
func (s *Service) open(ctx context.Context, db query.DBTX, organizationID, connectionID, sealed string) (string, error) {
	kek, err := s.orgKEK(ctx, db, organizationID)
	if err != nil {
		return "", err
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return "", err
	}
	plain, err := envelope.Open(kek, env, envelope.PlatformCredentialContext(organizationID, connectionID))
	return string(plain), err
}

// wtf8ToUTF8 turns lone surrogates (WTF-8, as jsvalue.Parse keeps them)
// into U+FFFD.
func wtf8ToUTF8(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
			b.WriteRune('�')
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// credentialRejection is isCredentialRejection: a run's result that says
// the platform refused the credential.
var credentialRejection = regexp.MustCompile(`(?i)\b(?:401|403)\b|unauthori[sz]ed|bad credentials|forbidden|invalid (?:api )?(?:token|key|credential)|authentication failed`)

// approvalMetadata is approvalMetadata.
func approvalMetadata(used *auth.UsedApproval) jsvalue.Object { return security.ApprovalMetadata(used) }
