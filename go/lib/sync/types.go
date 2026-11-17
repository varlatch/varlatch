// SPDX-License-Identifier: Apache-2.0

// Package sync is the Platform Adapters of Sync Targets (ADR-0031 §8), as
// packages/sync (@varlatch/sync) has them: the closed allowlist of platforms
// varlatchd and the CLI can push Values to. Each adapter owns its
// platform's API shape, auth and encoding. There is deliberately no generic
// "POST values to a URL template" adapter: that would be a first-class
// exfiltration primitive.
//
// The adapters take the caller's *http.Client and never build one
// (ADR-0059 step 4, decision 6): varlatchd passes its outbound policy's
// client (ADR-0057), the CLI a plain one. A test in this package checks it.
//
// Vectors recorded from the TypeScript adapters (testdata/ts-exchanges.json,
// written by packages/sync/test/go-vectors.test.ts) hold every request,
// answer and result to theirs.
package sync

import (
	"context"
	"net/http"
	"slices"
	"time"
)

// Platform is one of the allowlisted platforms.
type Platform string

const (
	GitHubActions Platform = "github-actions"
	Coolify       Platform = "coolify"
	Convex        Platform = "convex"
)

// Platforms is PLATFORMS: the closed allowlist, in its order.
var Platforms = []Platform{GitHubActions, Coolify, Convex}

// AdapterError is an adapter's own refusal or failure. Message holds a
// status or an error class only, never a value, credential material or
// platform text.
type AdapterError struct {
	Message string
	// Retryable is true when retrying without operator intervention may
	// succeed.
	Retryable bool
	// Cause is the transport error, for an access check to read; never in
	// the message.
	Cause error
}

func (e *AdapterError) Error() string { return e.Message }
func (e *AdapterError) Unwrap() error { return e.Cause }

// ScriptError is an error the TypeScript adapter does not wrap, which
// JavaScript raises by name (a SyntaxError from an answer that is not
// JSON, a TypeError from one of the wrong shape, a URIError). Name is
// JavaScript's; Message is Go's wording, never V8's.
type ScriptError struct {
	Name    string
	Message string
}

func (e *ScriptError) Error() string { return e.Name + ": " + e.Message }

// SyncItem is one destination name with its fully rendered value.
type SyncItem struct {
	Name  string
	Value string
}

// NameOutcome is one name's outcome; a single name's failure is never an
// error of the call.
type NameOutcome struct {
	Name string
	OK   bool
	// Error is a status or short cause only, never the value or credential
	// material; "" when OK.
	Error string
}

// CredentialKind is what a credential is (GitHub only).
type CredentialKind string

const (
	// Token is a stored personal access token (the default).
	Token CredentialKind = "token"
	// GitHubApp is a one-hour installation token Varlatch minted for this
	// use from a GitHub App (ADR-0047).
	GitHubApp CredentialKind = "github-app"
)

// Fields is a canonical destination record: string fields in the order
// canonicalizeDestination gives them.
type Fields []Field

// Field is one field of a destination record.
type Field struct {
	Key   string
	Value string
}

// Get is the field's value, "" when absent (where the TypeScript code reads
// undefined, which every use treats as "").
func (f Fields) Get(key string) string {
	for _, x := range f {
		if x.Key == key {
			return x.Value
		}
	}
	return ""
}

// Has reports whether the record has the field.
func (f Fields) Has(key string) bool {
	return slices.ContainsFunc(f, func(x Field) bool { return x.Key == key })
}

// Request is AdapterRequest.
type Request struct {
	// BaseIdentity is the canonical base identity (GitHub owner, Coolify
	// instance origin, Convex deployment origin).
	BaseIdentity string
	// Destination is the canonical destination record.
	Destination Fields
	// Credential is the Platform Credential, plaintext, in memory only.
	// Never log it.
	Credential string
	// CredentialKind is "" or Token for a stored token.
	CredentialKind CredentialKind
	// Client is the client every request goes through: varlatchd's
	// outbound policy client, or the CLI's. Required.
	Client *http.Client
	// Timeout bounds each request; 0 is DefaultTimeout.
	Timeout time.Duration
	// ShouldAbort is checked before each write or delete request in a batch
	// and before a redeploy trigger (preparatory reads are not gated): true
	// means the caller lost its authority to send, and the adapter stops,
	// returning the outcomes it has. An error stops the call with it.
	ShouldAbort func(context.Context) (bool, error)
	// OnCredentialExpiry is called when the platform says when the
	// credential expires (GitHub, for personal access tokens), as an ISO
	// 8601 instant.
	OnCredentialExpiry func(expiresAt string)
	// Usage is what InspectUsage reported for this run, when the caller ran
	// it: lets a write refuse a value the destination would change.
	Usage *UsageReport
}

func (r *Request) abort(ctx context.Context) (bool, error) {
	if r.ShouldAbort == nil {
		return false, nil
	}
	return r.ShouldAbort(ctx)
}

// Destination is a canonical destination and its key, the stable per-base
// discriminator in the canonical destination identity.
type Destination struct {
	Fields Fields
	Key    string
}

// ScopeUnit is where a credential honestly scopes.
type ScopeUnit string

const (
	ScopeDestination ScopeUnit = "destination"
	ScopeInstance    ScopeUnit = "instance"
)

// Adapter is PlatformAdapter's required part; the optional methods are the
// interfaces below.
type Adapter interface {
	Platform() Platform
	CredentialScopeUnit() ScopeUnit
	// SupportsReadBack reports whether the platform can read values back.
	SupportsReadBack() bool
	SupportsRedeploy() bool
	// CanonicalizeBaseIdentity validates and canonicalizes a user-supplied
	// base identity; the error is an *AdapterError.
	CanonicalizeBaseIdentity(raw string) (string, error)
	// CanonicalizeDestination validates and canonicalizes a destination
	// record, its properties in JavaScript's order.
	CanonicalizeDestination(raw Object) (Destination, error)
	// ValidateName is why the platform cannot store name, "" when it can.
	// With a canonical destination (non-nil), also the names that
	// destination's platform sets itself.
	ValidateName(name string, destination Fields) string
	// CanonicalizeName is the form the platform stores.
	CanonicalizeName(name string) string
	WriteValues(ctx context.Context, req *Request, items []SyncItem) ([]NameOutcome, error)
	DeleteNames(ctx context.Context, req *Request, names []string) ([]NameOutcome, error)
	// CheckAccess is the read-only access check; it never fails.
	CheckAccess(ctx context.Context, req *Request) AccessCheck
}

// ValueReader reads values back. A name the platform holds but whose
// value it does not return as a string maps to nil: present, never equal
// to a value.
type ValueReader interface {
	ReadValues(ctx context.Context, req *Request) (map[string]*string, error)
}

// RemoteReader is ReadValues plus the names stored in another form than
// WriteValues stores a value.
type RemoteReader interface {
	ReadRemote(ctx context.Context, req *Request) (RemoteState, error)
}

// ValueChecker refuses values the destination would change.
type ValueChecker interface {
	// ValueProblem is why value would not reach the destination as given,
	// "" when it would.
	ValueProblem(destination Fields, name, value string, usage *UsageReport) string
	// HeldFix is the Target option that would make the destination accept
	// a refused value, "" when none would.
	HeldFix(destination Fields, name, value string) string
}

// UsageInspector reads how the destination uses names (a Coolify
// service's compose files). It returns nil when the destination has no
// such notion, and never fails.
type UsageInspector interface {
	InspectUsage(ctx context.Context, req *Request, names []string) *UsageReport
}

// Redeployer triggers a redeploy: "sent" when the platform accepted it,
// "aborted" when ShouldAbort refused it. A refusal by the platform is an
// error.
type Redeployer interface {
	TriggerRedeploy(ctx context.Context, req *Request) (string, error)
}

// DestinationLister lists the destinations a credential can see; it never
// fails.
type DestinationLister interface {
	ListDestinations(ctx context.Context, req *Request) DestinationListing
}

// NameUsage is how a destination uses one name (Coolify services). Every
// field is a hint read from the platform's configuration.
type NameUsage struct {
	Owned             bool
	Referenced        bool
	GeneratedOnce     bool
	CopiedIntoCompose bool
	ShadowedIn        []string
	UnknownIn         []string
	NotDeliveredTo    []string
}

// UsageReport is what InspectUsage found. Names holds a verdict for every
// name asked about, in the order asked; a name with no hint has a zero
// NameUsage.
type UsageReport struct {
	Checked bool
	Reason  string
	Names   []NamedUsage
}

// NamedUsage is one name's usage.
type NamedUsage struct {
	Name  string
	Usage NameUsage
}

// Get is the name's usage, and whether the report has it.
func (u *UsageReport) Get(name string) (NameUsage, bool) {
	if u == nil {
		return NameUsage{}, false
	}
	for _, n := range u.Names {
		if n.Name == name {
			return n.Usage, true
		}
	}
	return NameUsage{}, false
}

// set is Map.prototype.set: a repeated name keeps its first place and
// takes the last usage.
func (u *UsageReport) set(name string, usage NameUsage) {
	for i := range u.Names {
		if u.Names[i].Name == name {
			u.Names[i].Usage = usage
			return
		}
	}
	u.Names = append(u.Names, NamedUsage{name, usage})
}

// RemoteState is ReadRemote's answer.
type RemoteState struct {
	Values map[string]*string
	// Rewrite is the names to write even when the value matches.
	Rewrite map[string]bool
}

// DefaultTimeout is DEFAULT_TIMEOUT_MS.
const DefaultTimeout = 10 * time.Second

// CanonicalDestinationIdentity is the Connection-independent canonical
// destination identity (ADR-0031 §1): JSON.stringify([platform, base, key]).
func CanonicalDestinationIdentity(platform Platform, baseIdentity, destinationKey string) string {
	return string(stringify([]any{string(platform), baseIdentity, destinationKey}))
}

// IsPlatform reports whether value is an allowlisted platform.
func IsPlatform(value string) bool {
	return slices.Contains(Platforms, Platform(value))
}

// GetAdapter is the adapter for platform.
func GetAdapter(platform string) (Adapter, error) {
	switch Platform(platform) {
	case GitHubActions:
		return GitHubActionsAdapter, nil
	case Coolify:
		return CoolifyAdapter, nil
	case Convex:
		return ConvexAdapter, nil
	}
	return nil, &AdapterError{Message: "Unknown platform adapter: " + platform}
}
