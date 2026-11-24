// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/write"
)

// OAuth connections (ADR-0062): an item whose use gives an access token for
// somebody else's API. The connection's parameters and client secret are a
// value version, stored as a seed of one-time codes is (seeds.go): in a row
// that reads as deleted to whoever does not know it, what is sealed as its
// value being another envelope, the payload saying what it is (its member
// oauth). Its tokens are in oauth_connections (go/server/oauth), sealed on
// their own.
//
// A retrieval keeps connections apart (State.Connections) and captures no
// ciphertext of them: no path that delivers values has the client secret or
// a token to deliver. Only an exercise opens the access token, and nothing
// in this package opens the client secret or the refresh token.

// Connection is what a retrieval reads of a connection.
type Connection struct {
	Params oauthparams.Params
	// text is the parameters as they are sealed.
	text       string
	Status     string
	Reason     string
	Paused     bool
	Refreshing bool
	HasToken   bool
	Generation int64
	// ExpiresAt is when the access token expires, in microseconds; 0: not
	// known. Lifetime is how long the last one lasted when it was given, in
	// seconds; 0: not known.
	ExpiresAt, Lifetime int64
	Account, Label      string
}

// The states of a connection.
const (
	NotConnected   = "not_connected"
	Connected      = "connected"
	Failing        = "failing"
	NeedsReconnect = "needs_reconnect"
	Revoked        = "revoked"
)

// connectionItem is a connection as a retrieval resolves it; ok is false for
// one whose parameters this server does not know.
func connectionItem(r query.ConnectionsOfEnvironmentRow, source string, now int64) (_ Item, ok bool) {
	p, ok := oauthparams.Parse(r.Params)
	if !ok {
		return Item{}, false
	}
	text, err := p.Text()
	if err != nil {
		return Item{}, false
	}
	c := &Connection{Params: p, text: text, Status: NotConnected, Reason: r.Reason.String, Paused: r.PausedAt.Valid, Generation: r.Generation.Int64,
		HasToken: r.HasToken != 0, ExpiresAt: r.AccessExpiresAt.Int64, Lifetime: r.AccessLifetime.Int64, Account: r.Account.String, Label: r.AccountLabel.String,
		Refreshing: r.ClaimUntil.Valid && r.ClaimUntil.Int64 > now}
	if r.Status.Valid {
		c.Status = r.Status.String
	}
	return Item{Name: r.ItemName, Sensitive: true, Source: source, ValueRowID: r.ID, VersionID: r.CurrentVersionID.String, Connection: c}, true
}

// JS is a connection as a listing of items carries it.
func (c *Connection) JS() jsvalue.Object {
	o := jsvalue.Object{{Key: "preset", Value: c.Params.Provider}, {Key: "grant", Value: c.Params.Grant}, {Key: "status", Value: c.State()}, {Key: "paused", Value: c.Paused}}
	if c.Label != "" {
		o = append(o, jsvalue.Member{Key: "account", Value: c.Label})
	}
	return o
}

// State is the connection's status, a refresh in progress included.
func (c *Connection) State() string {
	if c.Refreshing && (c.Status == Connected || c.Status == Failing || c.Status == NotConnected) {
		return "refreshing"
	}
	return c.Status
}

// marked is whether a stored version says it holds something other than a
// value: a seed of one-time codes, an OAuth connection. An envelope's base64
// holds no quote, so a value's payload is not parsed for it.
func marked(payload string) bool {
	if _, seed := seedParams(payload); seed {
		return true
	}
	if !strings.Contains(payload, `"oauth"`) {
		return false
	}
	var v struct {
		OAuth json.RawMessage `json:"oauth"`
	}
	return json.Unmarshal([]byte(payload), &v) != nil || v.OAuth != nil
}

// insertConnection writes a new version of a value row: the parameters, and
// the client secret sealed.
func insertConnection(ctx context.Context, q *query.Queries, orgKEK []byte, organizationID, valueID, versionID string, p oauthparams.Params, clientSecret string, previous sql.NullString, actor string, at int64) error {
	text, err := p.Text()
	if err != nil {
		return err
	}
	plain := []byte(clientSecret)
	defer clear(plain)
	sealed, err := envelope.EncryptOAuthClient(orgKEK, organizationID, valueID, versionID, text, plain)
	if err != nil {
		return err
	}
	env, err := json.Marshal(sealed.Payload)
	if err != nil {
		return err
	}
	payload := string(env[:len(env)-1]) + `,"oauth":` + text + "}"
	dek, err := json.Marshal(sealed.WrappedDEK)
	if err != nil {
		return err
	}
	if err := q.InsertValueVersion(ctx, query.InsertValueVersionParams{
		ID: versionID, ValueID: valueID, Payload: sql.NullString{String: payload, Valid: true},
		WrappedDek: sql.NullString{String: string(dek), Valid: true}, PreviousVersionID: previous,
		CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
	}); err != nil {
		return err
	}
	return q.SetCurrentSeedVersion(ctx, query.SetCurrentSeedVersionParams{Version: sql.NullString{String: versionID, Valid: true},
		Now: sql.NullInt64{Int64: at, Valid: true}, ID: valueID})
}

// ConnectionInput is a connection to write.
type ConnectionInput struct {
	Params       oauthparams.Params
	ClientSecret string
}

// CreateConnection writes a connection for an item that has no value, in its
// job: the checks of SetValue, then that nothing is there (RESOURCE_CONFLICT
// as VERSION_CONFLICT, with what is), the version, an empty row of
// oauth_connections, and value.written. It returns the value row and the
// version.
func CreateConnection(ctx context.Context, tx *storage.Tx, rootKEK []byte, p *auth.Principal, t Target, item string, in ConnectionInput, requestID string, at int64) (valueID, versionID string, reports []auth.PendingReport, err error) {
	if err := checkItemName(item); err != nil {
		return "", "", nil, err
	}
	if err := checkNotExpired(t.Env, at); err != nil {
		return "", "", nil, err
	}
	orgKEK, err := orgKEKIn(ctx, tx, rootKEK, t.OrganizationID)
	if err != nil {
		return "", "", nil, err
	}
	defer clear(orgKEK)
	sensitive, err := sensitivity(ctx, tx, t.Project)
	if err != nil {
		return "", "", nil, err
	}
	if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
		return "", "", nil, err
	}
	if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
		return "", "", nil, err
	}
	if !sensitive(item) {
		return "", "", nil, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "not-sensitive"}},
			Message: item + " is not sensitive in the Contract, and an OAuth connection is always a Secret: mark the item sensitive first"}
	}
	q := query.New(tx)
	rows, err := q.ValueRowsOfItems(ctx, query.ValueRowsOfItemsParams{EnvironmentID: t.Env.ID, ItemNames: []string{item}})
	if err != nil {
		return "", "", nil, err
	}
	var row valueRow
	if len(rows) > 0 {
		row = rows[0]
		if !deleted(row.DeletedAt, row.Seed) && row.CurrentVersionID.Valid {
			return "", "", nil, &domainerr.Error{Code: "VERSION_CONFLICT", Details: jsvalue.Object{{Key: "currentVersionId", Value: nullable(row.CurrentVersionID)}},
				Message: item + " has a value here: delete it before making it an OAuth connection"}
		}
	} else {
		row = valueRow{ID: ids.New("val"), ItemName: item}
		if err := q.InsertValueRow(ctx, query.InsertValueRowParams{ID: row.ID, EnvironmentID: t.Env.ID, ItemName: item, CreatedAt: at}); err != nil {
			return "", "", nil, err
		}
	}
	versionID = ids.New("ver")
	if err := insertConnection(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, in.Params, in.ClientSecret, sql.NullString{}, p.Identity.ID, at); err != nil {
		return "", "", nil, err
	}
	if err := q.PutOAuthConnection(ctx, query.PutOAuthConnectionParams{ValueID: row.ID, VersionID: versionID}); err != nil {
		return "", "", nil, err
	}
	return row.ID, versionID, reports, recordConnection(ctx, tx, p, t, item, versionID, "", in.Params, requestID)
}

// UpdateConnection writes a new version of a connection, in its job: the same
// checks, the version, and value.written. The caller seals its tokens again
// for it.
func UpdateConnection(ctx context.Context, tx *storage.Tx, orgKEK []byte, p *auth.Principal, t Target, valueID, item, previous string, in ConnectionInput, requestID string, at int64) (versionID string, err error) {
	versionID = ids.New("ver")
	if err := insertConnection(ctx, query.New(tx), orgKEK, t.OrganizationID, valueID, versionID, in.Params, in.ClientSecret,
		sql.NullString{String: previous, Valid: true}, p.Identity.ID, at); err != nil {
		return "", err
	}
	return versionID, recordConnection(ctx, tx, p, t, item, versionID, previous, in.Params, requestID)
}

func recordConnection(ctx context.Context, tx *storage.Tx, p *auth.Principal, t Target, item, versionID, previous string, params oauthparams.Params, requestID string) error {
	actor, action := p.Identity.ID, "config.value.write"
	var prev any
	if previous != "" {
		prev = previous
	}
	md := jsvalue.Object{{Key: "sensitive", Value: true}, {Key: "oauth", Value: true}, {Key: "preset", Value: params.Provider},
		{Key: "grant", Value: params.Grant}, {Key: "server", Value: params.Server()},
		{Key: "endpointHosts", Value: strings.Join(params.EndpointHosts(), ",")}, {Key: "clientId", Value: params.ClientID},
		{Key: "scopes", Value: strings.Join(params.Scopes, " ")}}
	if len(params.Hosts) > 0 {
		md = append(md, jsvalue.Member{Key: "hosts", Value: strings.Join(params.Hosts, ",")})
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Type: "value.written", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
		Resource: jsvalue.Object{
			{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item},
			{Key: "versionId", Value: versionID}, {Key: "previousVersionId", Value: prev},
		},
		RequestID: &requestID, Metadata: md,
	})
	return err
}

// checkDeletion refuses a machine the deletion of a connection a person has
// connected: what it was, and whose, is theirs to end.
func checkDeletion(ctx context.Context, q *query.Queries, p *auth.Principal, environmentID, item string) error {
	if p.Identity.Kind == "human" {
		return nil
	}
	once, err := q.OAuthConnectionOnceConnected(ctx, query.OAuthConnectionOnceConnectedParams{EnvironmentID: environmentID, ItemName: item})
	if err != nil || once == 0 {
		return err
	}
	return &domainerr.Error{Code: "PERMISSION_DENIED", Message: item + " is an OAuth connection a person connected: a person deletes it",
		Details: jsvalue.Object{{Key: "reason", Value: "person-required"}}}
}

// ConnectionSecret opens a connection's client secret: for go/server/oauth,
// which sends it to the token and revocation endpoints the parameters pin,
// and to nothing else. It opens only with the parameters it was sealed with.
func ConnectionSecret(orgKEK []byte, organizationID, valueID, versionID, paramsText, payload, wrappedDEK string) (string, error) {
	var v envelope.EncryptedValue
	if err := json.Unmarshal([]byte(payload), &v.Payload); err != nil {
		return "", fmt.Errorf("values: the payload of %s is not an envelope: %w", versionID, err)
	}
	if err := json.Unmarshal([]byte(wrappedDEK), &v.WrappedDEK); err != nil {
		return "", fmt.Errorf("values: the wrapped DEK of %s is not an envelope: %w", versionID, err)
	}
	plain, err := envelope.DecryptOAuthClient(orgKEK, organizationID, valueID, versionID, paramsText, v)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}

// OrgKEK is the Organization's KEK, read in db, for go/server/oauth.
func OrgKEK(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID string) ([]byte, error) {
	return orgKEKIn(ctx, db, rootKEK, organizationID)
}

// Tokens gets an OAuth connection a new access token (go/server/oauth).
type Tokens interface {
	// Refresh replaces the access token of generation seen, and returns once
	// another one is stored. Whoever asks for the same one shares one
	// refresh. A *NoToken says why there is none.
	Refresh(ctx context.Context, valueID string, seen int64) error
}

// NoToken is a refresh that gave no access token.
type NoToken struct {
	// Status is the connection's; Reason a fixed word.
	Status, Reason string
	// RetryAfter is when asking again may help; 0: it needs a person.
	RetryAfter time.Duration
}

func (e *NoToken) Error() string {
	return "oauth: no access token (" + e.Status + ", " + e.Reason + ")"
}

// tokenMargin is how long an access token must still last to be given when
// the request does not say, unless the provider's last shorter than that:
// what a request to the API, the clocks and the network take.
const tokenMargin = time.Minute

// errTokenGone is a connection that was disconnected, paused or changed
// between the snapshot and the exercise's own job.
var errTokenGone = errors.New("values: the OAuth connection changed meanwhile")

// needsRefresh is whether the access token c has does not do for a request
// that asks for minValidity, at now; enough is whether it does when no
// refresh can be had.
func (c *Connection) needsRefresh(minValidity time.Duration, now int64) (needs, enough bool) {
	if !c.HasToken {
		return true, false
	}
	if c.ExpiresAt == 0 {
		return false, true // the server says nothing about its end
	}
	left := time.Duration(c.ExpiresAt-now) * time.Microsecond
	enough = left > 0 && left >= minValidity
	margin := tokenMargin
	if c.Lifetime > 0 {
		margin = min(margin, time.Duration(c.Lifetime)*time.Second/4)
	}
	return !enough || left < margin, enough
}

// gapLeft is how long after the access token was given another one is not
// asked for, for want of a longer validity alone: a minute, or a quarter of a
// shorter life. 0 when that is over.
func (c *Connection) gapLeft(now int64) time.Duration {
	if c.Lifetime <= 0 || c.ExpiresAt == 0 {
		return 0
	}
	gap := min(tokenMargin, time.Duration(c.Lifetime)*time.Second/4)
	age := time.Duration(now-(c.ExpiresAt-c.Lifetime*1_000_000)) * time.Microsecond
	return min(max(gap-age, 0), gap)
}

// usable is why a connection cannot be used at all, "" when it can.
func (c *Connection) usable() string {
	switch {
	case c.Paused:
		return "connection-paused"
	case c.Status == NotConnected && c.Params.Grant == oauthparams.ClientCredentials:
		return ""
	case c.Status == NotConnected:
		return "connection-not-connected"
	case c.Status == NeedsReconnect:
		return "connection-needs-reconnect"
	case c.Status == Revoked:
		return "connection-revoked"
	}
	return ""
}

// captureToken reads, in the snapshot, the access token of a connection.
func captureToken(ctx context.Context, q *query.Queries, it Item) (sealedToken, error) {
	r, err := q.OAuthAccessToken(ctx, query.OAuthAccessTokenParams{ValueID: it.ValueRowID, VersionID: it.VersionID})
	if errors.Is(err, sql.ErrNoRows) || err == nil && !r.AccessToken.Valid {
		return sealedToken{}, nil
	}
	if err != nil {
		return sealedToken{}, err
	}
	return sealedToken{envelope: r.AccessToken.String, account: r.Account, generation: r.Generation, expiresAt: r.AccessExpiresAt.Int64}, nil
}

type sealedToken struct {
	envelope, account     string
	generation, expiresAt int64
}

// openToken opens an access token captured by a retrieval whose audit event
// was committed.
func (s *Service) openToken(st *State, it Item) (string, error) {
	t, ok := st.tokens[it.Name]
	if !ok || t.envelope == "" {
		return "", domainerr.New("INTERNAL", "An access token was not captured in the retrieval snapshot")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(t.envelope), &env); err != nil {
		return "", fmt.Errorf("values: the access token of %s is not an envelope: %w", it.ValueRowID, err)
	}
	kek, err := s.orgKEK(st)
	if err != nil {
		return "", err
	}
	defer clear(kek)
	plain, err := envelope.Open(kek, env, envelope.OAuthTokenContext(envelope.PurposeOAuthAccessToken, st.Org.ID, it.ValueRowID, it.VersionID,
		it.Connection.text, t.account, t.generation, t.expiresAt))
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}

// stillUsable checks, in the exercise's own job, that each connection is the
// one the snapshot saw, with the token it saw: not disconnected, paused,
// deleted, changed, connected again or refreshed since.
func stillUsable(ctx context.Context, tx *storage.Tx, selected []Item) error {
	for _, it := range selected {
		rows, err := query.New(tx).OAuthConnectionNow(ctx, it.ValueRowID)
		if err != nil {
			return err
		}
		if len(rows) == 0 || rows[0].VersionID != it.VersionID || rows[0].Generation != it.Connection.Generation ||
			rows[0].PausedAt.Valid || rows[0].Status == Revoked || rows[0].Status == NeedsReconnect {
			return errTokenGone
		}
	}
	return nil
}

// tokensGiven is the audit's record of access tokens: the connection, its
// version and which token of it (the generation), and when that one expires.
// Never the token, nor anything derived from it.
func tokensGiven(selected []Item) string {
	given := make([]string, len(selected))
	for i, it := range selected {
		until := "unknown"
		if it.Connection.ExpiresAt != 0 {
			until = audit.ISOTime(it.Connection.ExpiresAt)
		}
		given[i] = it.Name + "@" + it.VersionID + "#" + strconv.FormatInt(it.Connection.Generation, 10) + "=" + until
	}
	return strings.Join(given, ",")
}

// tokenJS is an access token as an exercise answers it.
func tokenJS(it Item, token string, now time.Time) jsvalue.Object {
	o := jsvalue.Object{{Key: "name", Value: it.Name}, {Key: "versionId", Value: it.VersionID}, {Key: "kind", Value: "oauth"}, {Key: "value", Value: token}}
	if at := it.Connection.ExpiresAt; at != 0 {
		o = append(o, jsvalue.Member{Key: "expiresAt", Value: audit.ISOTime(at)},
			jsvalue.Member{Key: "expiresInSeconds", Value: max(0, int64(time.UnixMicro(at).Sub(now)/time.Second))})
	}
	return o
}

// connectionProblem is the Contract's verdict on an item that is an OAuth
// connection: an access token is text of no known form.
func connectionProblem(it contract.Item) string {
	if it.Type == "string" {
		return ""
	}
	return "is an OAuth connection, whose access token fits the type string only"
}

// specialProblem is the verdict on an item whose value here is not a value.
func specialProblem(resolved Item, it contract.Item) string {
	if resolved.Connection != nil {
		return connectionProblem(it)
	}
	return codeProblem(it)
}

// ConnectionsIn are the OAuth connections an environment resolves, by item:
// for an issuance, which may not name a destination a connection's hosts do
// not.
func ConnectionsIn(ctx context.Context, db query.DBTX, environmentID, parentID string, now int64) (map[string]oauthparams.Params, error) {
	st := State{Env: query.LiveEnvironmentRow{ID: environmentID}}
	if parentID != "" && parentID != environmentID {
		st.Env.ParentEnvironmentID = sql.NullString{String: parentID, Valid: true}
	}
	r, err := resolve(ctx, query.New(db), &st, now)
	if err != nil {
		return nil, err
	}
	out := map[string]oauthparams.Params{}
	for _, it := range r.connections {
		out[it.Name] = it.Connection.Params
	}
	return out, nil
}

// CheckConnectionDestinations refuses destinations that widen where a
// connection's token may go.
func CheckConnectionDestinations(connections map[string]oauthparams.Params, items []string, selectors []authz.DestinationSelector) error {
	for _, name := range items {
		p, ok := connections[name]
		if !ok {
			continue
		}
		if i := slices.IndexFunc(selectors, func(sel authz.DestinationSelector) bool { return !p.Covers(sel) }); i >= 0 {
			return &domainerr.Error{Code: "VALIDATION_FAILED", Message: "The OAuth connection " + name + " does not allow " + selectors[i].String() + " among its hosts",
				Details: jsvalue.Object{{Key: "reason", Value: "connection-host"}, {Key: "item", Value: name}, {Key: "destination", Value: selectors[i].String()}}}
		}
	}
	return nil
}

// reasonOf is why a connection is as it is, for a refusal.
func reasonOf(c *Connection) jsvalue.Object {
	if c.Reason == "" {
		return nil
	}
	return jsvalue.Object{{Key: "cause", Value: c.Reason}}
}
