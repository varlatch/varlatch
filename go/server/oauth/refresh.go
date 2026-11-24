// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// Refreshing, in one place. A refresh token may be good for one use (RFC
// 9700 section 4.14.2: rotation), and a second use may end the whole grant.
// So:
//
//   - one refresh of a connection at a time: in this process a flight that
//     everyone who asks shares, behind the connection's gate; across
//     processes and restarts a claim in its row, taken in a write job before
//     anything is sent and kept until the answer is stored or its time is
//     over (claimFor, longer than a request lasts);
//   - what the answer gave is stored in one job, the new refresh token in
//     the place of the one that was used, and only then does anyone get the
//     access token. Until that job commits, the one that was used is what is
//     stored;
//   - an answer that is lost (the server fails, the process ends, the
//     network does) leaves the one that was used, which may have been
//     replaced at the provider. It is used again, soon: a provider that
//     replaced it and allows for lost answers gives new tokens, one that
//     does not says invalid_grant, and that is where not asking would have
//     ended as well. Then a person has to connect again (reason
//     refresh-answer-lost).
//
// A refresh runs to its end whoever asked is still there or not, and a stop
// of varlatchd waits for it: an answer is not lost to either.

const (
	// claimFor is how long a claim holds without an answer: longer than a
	// request may take, so that a claim that ended belongs to nobody who could
	// still store an answer, but for a process that stood still.
	claimFor = 30 * time.Second
	// refreshWait bounds how long who asks waits.
	refreshWait = 20 * time.Second
	// firstBackoff doubles with every failure in a row, up to maxBackoff.
	firstBackoff = 5 * time.Second
	maxBackoff   = 10 * time.Minute
	// storeTries is how often the answer's job is tried.
	storeTries = 5
)

// flight is a refresh in progress.
type flight struct {
	done chan struct{}
	err  error
}

// Refresh implements values.Tokens.
func (s *Service) Refresh(ctx context.Context, valueID string, seen int64) error {
	return s.refresh(ctx, valueID, seen, Request{}, false)
}

// RefreshNow refreshes a connection because somebody asked: whatever it has,
// and without waiting for the next try of one that fails.
func (s *Service) RefreshNow(ctx context.Context, req Request, item string, base *url.URL) (jsvalue.Object, error) {
	if err := write.CheckLive(ctx, s.store().Reader(), req.scope("")); err != nil {
		return nil, err
	}
	r, err := find(ctx, s.store().Reader(), req.Target.Env.ID, item)
	if err != nil {
		return nil, err
	}
	if r.OauthConnection.Status == values.Revoked && r.params.Grant == oauthparams.ClientCredentials {
		// Nobody consents to a client's own connection: asking for a token is
		// how it is connected again, by a person.
		if err := person(req.Principal, "The client's own connection"); err != nil {
			return nil, err
		}
		if err := s.Writer.Job(ctx, req.gates(gate(r.ValueID)), func(ctx context.Context, tx *storage.Tx) error {
			return query.New(tx).ReopenOAuthConnection(ctx, r.ValueID)
		}); err != nil {
			return nil, err
		}
	}
	err = s.refresh(ctx, r.ValueID, r.OauthConnection.Generation, req, true)
	var none *values.NoToken
	if err != nil && !errors.As(err, &none) {
		return nil, err
	}
	now, err := find(ctx, s.store().Reader(), req.Target.Env.ID, item)
	if err != nil {
		return nil, err
	}
	out := jsvalue.Object{{Key: "refreshed", Value: none == nil}, {Key: "connection", Value: s.js(now, base)}}
	if none != nil {
		out = append(out, jsvalue.Member{Key: "reason", Value: none.Reason})
		if none.RetryAfter > 0 {
			out = append(out, jsvalue.Member{Key: "retryAfterSeconds", Value: max(1, int64((none.RetryAfter+time.Second-1)/time.Second))})
		}
	}
	return out, nil
}

func (s *Service) refresh(ctx context.Context, valueID string, seen int64, req Request, force bool) error {
	wait := time.NewTimer(cmp.Or(s.Wait, refreshWait))
	defer wait.Stop()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return &values.NoToken{Status: values.Failing, Reason: "stopping", RetryAfter: firstBackoff}
		}
		f := s.flights[valueID]
		mine := f == nil
		if mine {
			f = &flight{done: make(chan struct{})}
			if s.flights == nil {
				s.flights = map[string]*flight{}
			}
			s.flights[valueID] = f
			s.running.Add(1)
			go func() {
				defer s.running.Done()
				err := s.fly(valueID, seen, req, force)
				s.mu.Lock()
				f.err = err
				delete(s.flights, valueID)
				s.mu.Unlock()
				close(f.done)
			}()
		}
		s.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
			return &values.NoToken{Status: values.Failing, Reason: "refreshing", RetryAfter: firstBackoff}
		}
		var busy *busyError
		if !errors.As(f.err, &busy) {
			if mine || f.err == nil || !force {
				return f.err
			}
			continue // what another one asked for, without our insistence
		}
		// Another process has the claim: look again in a moment.
		select {
		case <-time.After(min(busy.after, 250*time.Millisecond)):
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
			return &values.NoToken{Status: values.Failing, Reason: "refreshing", RetryAfter: max(busy.after, time.Second)}
		}
	}
}

// busyError is a claim another process holds.
type busyError struct{ after time.Duration }

func (*busyError) Error() string { return "oauth: another process refreshes this connection" }

// claimed is a refresh that may be sent.
type claimed struct {
	row     *row
	id      string
	client  clientOf
	refresh string
}

// fly is one refresh, in the background.
func (s *Service) fly(valueID string, seen int64, req Request, force bool) error {
	ctx, cancel := context.WithTimeout(audit.WithClock(context.Background(), s.now), 2*claimFor)
	defer cancel()
	if s.Admit != nil {
		leave, ok := s.Admit()
		if !ok {
			return &values.NoToken{Status: values.Failing, Reason: "maintenance", RetryAfter: firstBackoff}
		}
		defer leave()
	}
	first, err := byID(ctx, s.store().Reader(), valueID)
	if err != nil {
		return err
	}
	if first == nil {
		return &values.NoToken{Status: values.Revoked, Reason: "deleted"}
	}
	// A freeze, a deletion and a change of the Organization wait for a refresh
	// that was sent, as for every external effect, and one that waits for them
	// sees what they did.
	ctx, release, err := s.Writer.Gates.Acquire(ctx, write.Organization(first.OrganizationID, write.Shared), gate(valueID))
	if errors.Is(err, context.DeadlineExceeded) {
		return &values.NoToken{Status: first.OauthConnection.Status, Reason: "busy", RetryAfter: firstBackoff}
	}
	if err != nil {
		return err
	}
	defer release()
	var c *claimed
	var why error
	err = s.store().Write(ctx, func(tx *storage.Tx) (err error) {
		c, why, err = s.claim(ctx, tx, valueID, seen, force)
		return err
	})
	if err != nil || c == nil {
		return errors.Join(err, why)
	}
	if s.crashes("claimed") {
		return errCrashed
	}
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c.refresh}}
	if c.row.params.Grant == oauthparams.ClientCredentials {
		v = url.Values{"grant_type": {"client_credentials"}}
		if len(c.row.params.Scopes) > 0 {
			v.Set("scope", strings.Join(c.row.params.Scopes, " "))
		}
	}
	t, f := s.token(ctx, c.client, v)
	if s.crashes("answered") {
		return errCrashed
	}
	// The answer is kept whatever else happens: the job is tried again, the
	// answer being in memory only until then.
	for try := 1; ; try++ {
		var out error
		err := s.store().Write(ctx, func(tx *storage.Tx) (err error) {
			out, err = s.settle(ctx, tx, c, t, f, req)
			return err
		})
		if err == nil {
			s.crashes("stored")
			return out
		}
		if try == storeTries || ctx.Err() != nil {
			s.log().Error("the answer of an OAuth provider could not be stored: the refresh token it replaced is used again", "item", c.row.ItemName, "environmentId", c.row.EnvironmentID, "error", err)
			return err
		}
		select {
		case <-time.After(time.Duration(try) * 200 * time.Millisecond):
		case <-ctx.Done():
		}
	}
}

var errCrashed = errors.New("oauth: ended by a test")

func (s *Service) crashes(point string) bool { return s.crash != nil && s.crash(point) }

// claim decides, in a write job, whether a refresh may be sent, and that it
// is this one. Without one, why says why it may not, nil when somebody
// refreshed since; an error is the job's.
func (s *Service) claim(ctx context.Context, tx *storage.Tx, valueID string, seen int64, force bool) (out *claimed, why, err error) {
	r, err := byID(ctx, tx, valueID)
	if err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, &values.NoToken{Status: values.Revoked, Reason: "deleted"}, nil
	}
	c, now := r.OauthConnection, s.now()
	none := func(reason string, after time.Duration) (*claimed, error, error) {
		return nil, &values.NoToken{Status: c.Status, Reason: reason, RetryAfter: after}, nil
	}
	// Not for an Organization that is frozen, being deleted or gone, nor for
	// an environment that is.
	if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: r.OrganizationID, ProjectID: r.ProjectID, EnvironmentIDs: []string{r.EnvironmentID}}); err != nil {
		var frozen *authz.FrozenError
		var d *domainerr.Error
		switch {
		case errors.As(err, &frozen):
			return none("frozen", maxBackoff)
		case errors.As(err, &d):
			return none("not-live", maxBackoff)
		}
		return nil, nil, err
	}
	own := r.params.Grant == oauthparams.ClientCredentials
	switch {
	case r.EnvironmentExpiresAt.Valid && r.EnvironmentExpiresAt.Int64 <= now.UnixMicro():
		return none("environment-expired", maxBackoff)
	case c.PausedAt.Valid:
		return none("paused", 0)
	case c.Status == values.NeedsReconnect:
		return none(c.Reason.String, 0)
	case c.Status == values.Revoked, c.Status == values.NotConnected && !own:
		return none("not-connected", 0)
	case c.Generation != seen:
		return nil, nil, nil
	case c.ClaimID.Valid && c.ClaimUntil.Int64 > now.UnixMicro():
		return nil, &busyError{after: time.Duration(c.ClaimUntil.Int64-now.UnixMicro()) * time.Microsecond}, nil
	case !force && c.RetryAt.Valid && c.RetryAt.Int64 > now.UnixMicro():
		return none(c.Reason.String, time.Duration(c.RetryAt.Int64-now.UnixMicro())*time.Microsecond)
	}
	out = &claimed{row: r, id: ids.New("ocl")}
	q := query.New(tx)
	n, err := q.ClaimOAuthRefresh(ctx, query.ClaimOAuthRefreshParams{ClaimID: nullStr(out.id), ClaimUntil: nullInt(now.Add(claimFor).UnixMicro()),
		ValueID: valueID, Generation: c.Generation, Now: nullInt(now.UnixMicro())})
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, &busyError{after: time.Second}, nil
	}
	if !own && !c.RefreshToken.Valid {
		// Connected without one: the access token was all there was.
		if _, err := q.EndOAuthTokens(ctx, query.EndOAuthTokensParams{Reason: nullStr("no-refresh-token"), ValueID: valueID, ClaimID: nullStr(out.id)}); err != nil {
			return nil, nil, err
		}
		none, err := s.ended(ctx, tx, r, Request{}, "no-refresh-token")
		return nil, none, err
	}
	kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)
	if out.client, err = r.client(kek); err != nil {
		return nil, nil, err
	}
	if !own {
		out.refresh, err = r.openRefresh(kek)
	}
	return out, nil, err
}

// ended records that a person has to connect again.
func (s *Service) ended(ctx context.Context, tx query.DBTX, r *row, req Request, reason string) (*values.NoToken, error) {
	md := jsvalue.Object{{Key: "reason", Value: reason}}
	if r.OauthConnection.Account != "" {
		md = append(md, jsvalue.Member{Key: "account", Value: r.OauthConnection.AccountLabel})
	}
	return &values.NoToken{Status: values.NeedsReconnect, Reason: reason},
		s.record(ctx, tx, r, "sync.connection_checked", audit.Deny, req, "needs-reconnect", md)
}

// settle stores what became of a refresh, in its job: what is returned first
// is for whoever waits, and an error is the job's.
func (s *Service) settle(ctx context.Context, tx *storage.Tx, c *claimed, t tokens, f *failure, req Request) (error, error) {
	// The connection as it is now: it may have been changed, by another
	// process, or be gone.
	r, err := byID(ctx, tx, c.row.ValueID)
	if err != nil {
		return nil, err
	}
	if r == nil || r.OauthConnection.ClaimID.String != c.id || !r.params.SameServer(c.row.params) {
		// Disconnected, deleted, or connected again meanwhile: the answer is
		// of no use to anyone here.
		return &values.NoToken{Status: values.Revoked, Reason: "changed"}, nil
	}
	q, now, stored := query.New(tx), s.now(), r.OauthConnection
	id, claim := r.ValueID, nullStr(c.id)
	end := func(reason string) (error, error) {
		if _, err := q.EndOAuthTokens(ctx, query.EndOAuthTokensParams{Reason: nullStr(reason), ValueID: id, ClaimID: claim}); err != nil {
			return nil, err
		}
		return s.ended(ctx, tx, r, req, reason)
	}
	backoff := min(firstBackoff<<min(stored.Failures, 10), maxBackoff)
	failing := func(reason string) error {
		// Once an episode, and when its reason changes: not every try.
		if stored.Status == values.Failing && stored.Reason.String == reason {
			return nil
		}
		return s.record(ctx, tx, r, "sync.connection_checked", audit.Info, req, "failing", jsvalue.Object{{Key: "reason", Value: reason}})
	}
	if f != nil {
		if f.reason == "invalid_grant" && r.params.Grant == oauthparams.AuthorizationCode {
			reason := "refused-by-provider"
			if stored.Unanswered > 1 {
				// One before it was sent whose answer was not kept: the provider
				// may have replaced the refresh token then.
				reason = "refresh-answer-lost"
			}
			return end(reason)
		}
		backoff = max(backoff, f.retryAfter)
		answered := int64(0)
		if f.answered || f.unsent {
			answered = 1
		}
		s.noteRefusalIn(ctx, tx, r, req, f)
		if _, err := q.FailOAuthRefresh(ctx, query.FailOAuthRefreshParams{Reason: nullStr(f.reason), RetryAt: nullInt(now.Add(backoff).UnixMicro()), Answered: answered,
			ValueID: id, ClaimID: claim}); err != nil {
			return nil, err
		}
		return &values.NoToken{Status: values.Failing, Reason: f.reason, RetryAfter: backoff}, failing(f.reason)
	}
	kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	// An ID token that comes along is this account's, or the answer is not
	// this connection's (OpenID Connect section 12.2). It came from the pinned
	// token endpoint over TLS: its claims are read, its signature not checked,
	// so that a key server that is away loses no refresh token.
	if t.idToken != "" && stored.Account != "" && r.params.OpenID() {
		if sub, aud := claimsOf(t.idToken); sub != "" && (sub != stored.Account || !aud(r.params.ClientID)) {
			return end("account-mismatch")
		}
	}
	// No new refresh token: the one that was used stays.
	refresh := t.refresh
	if refresh == "" {
		refresh = c.refresh
		if stored.RefreshExpiresAt.Valid {
			left := (stored.RefreshExpiresAt.Int64 - t.at.UnixMicro()) / 1_000_000
			t.refreshLifetime = max(left, 1)
		}
	}
	if r.params.Grant == oauthparams.ClientCredentials {
		refresh = ""
	}
	if t.unusable != "" {
		// The refresh token was replaced all the same.
		old, err := r.openAccess(kek)
		if err != nil {
			return nil, err
		}
		p := query.KeepOAuthRefreshTokenParams{Reason: nullStr(t.unusable), RetryAt: nullInt(now.Add(backoff).UnixMicro()), ValueID: id, ClaimID: claim}
		if p.AccessToken, err = seal(kek, r.context(envelope.PurposeOAuthAccessToken, stored.Generation+1, stored.AccessExpiresAt.Int64, stored.Account), old); err != nil {
			return nil, err
		}
		if p.RefreshToken, err = seal(kek, r.context(envelope.PurposeOAuthRefreshToken, stored.Generation+1, 0, stored.Account), refresh); err != nil {
			return nil, err
		}
		if _, err := q.KeepOAuthRefreshToken(ctx, p); err != nil {
			return nil, err
		}
		return &values.NoToken{Status: values.Failing, Reason: t.unusable, RetryAfter: backoff}, failing(t.unusable)
	}
	sl, err := r.sealTokens(kek, t, refresh, stored.Generation+1, stored.Account)
	if err != nil {
		return nil, err
	}
	if !sl.refreshExpires.Valid && t.refresh == "" {
		sl.refreshExpires = stored.RefreshExpiresAt
	}
	granted := stored.GrantedScopes
	md := jsvalue.Object{{Key: "rotated", Value: t.refresh != "" && t.refresh != c.refresh}}
	if sl.expiresAt.Valid {
		md = append(md, jsvalue.Member{Key: "accessTokenExpiresAt", Value: audit.ISOTime(sl.expiresAt.Int64)})
	}
	if t.scopesGiven {
		granted.String, granted.Valid = t.scopes, true
		before, after := missing(r.params.Scopes, stored.GrantedScopes), missing(r.params.Scopes, granted)
		if len(after) > 0 && strings.Join(before, " ") != strings.Join(after, " ") {
			md = append(md, jsvalue.Member{Key: "missingScopes", Value: strings.Join(after, " ")})
		}
	}
	if stored.Unanswered > 1 {
		md = append(md, jsvalue.Member{Key: "afterLostAnswer", Value: true})
	}
	if _, err := q.SetOAuthTokens(ctx, query.SetOAuthTokensParams{
		AccessToken: sl.access, AccessExpiresAt: sl.expiresAt, AccessLifetime: sl.lifetime, RefreshToken: sl.refresh, RefreshExpiresAt: sl.refreshExpires,
		KeepaliveAt: sl.keptTo, GrantedScopes: granted, Now: nullInt(now.UnixMicro()), ValueID: id, ClaimID: claim,
	}); err != nil {
		return nil, err
	}
	return nil, s.record(ctx, tx, r, "sync.connection_credential_replaced", audit.Info, req, "refreshed", md)
}

// noteRefusalIn records an outbound refusal in the job.
func (s *Service) noteRefusalIn(ctx context.Context, tx query.DBTX, r *row, req Request, f *failure) {
	if f.refusal == nil {
		return
	}
	if e, ok := s.refusalEvent(r, req, f); ok {
		if _, err := audit.Record(ctx, tx, e); err != nil {
			s.log().Error("could not audit a refused OAuth request", "error", err)
		}
	}
}

// claimsOf reads an ID token's subject and audience, unverified.
func claimsOf(raw string) (sub string, audience func(string) bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil
	}
	var o map[string]any
	if json.Unmarshal(b, &o) != nil {
		return "", nil
	}
	sub, _ = o["sub"].(string)
	return shown(sub), func(clientID string) bool {
		switch a := o["aud"].(type) {
		case string:
			return a == clientID
		case []any:
			for _, x := range a {
				if x == any(clientID) {
					return true
				}
			}
		}
		return false
	}
}

// ---------------------------------------------------------------------------
// Keeping refresh tokens.

// Interval is the worker's, and dueLimit what one pass looks at.
const (
	Interval = time.Minute
	dueLimit = 500
)

// RunOnce refreshes the connections whose refresh token the provider would
// otherwise drop for want of use, forgets what is no connection's any more,
// and takes up the connections a migration brought back without their tokens. Nothing else refreshes without being asked: a connection nobody uses
// is not kept warm, only alive.
func (s *Service) RunOnce(ctx context.Context) error {
	ctx = audit.WithClock(ctx, s.now)
	if n, err := query.New(s.store().Reader()).OAuthRowsToForget(ctx, s.now().UnixMicro()); err != nil {
		return err
	} else if n != 0 {
		if err := s.store().Write(ctx, func(tx *storage.Tx) error {
			q := query.New(tx)
			if err := q.ForgetDeadOAuthConnections(ctx); err != nil {
				return err
			}
			if err := q.AdoptOAuthConnections(ctx); err != nil {
				return err
			}
			return q.PruneOAuthAuthorizations(ctx, s.now().UnixMicro())
		}); err != nil {
			return err
		}
	}
	due, err := query.New(s.store().Reader()).OAuthConnectionsDue(ctx, query.OAuthConnectionsDueParams{Now: nullInt(s.now().UnixMicro()), Lim: dueLimit})
	if err != nil {
		return err
	}
	for _, id := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r, err := byID(ctx, s.store().Reader(), id)
		if err != nil || r == nil {
			continue
		}
		// Not for one that may not be refreshed now: the claim decides it
		// again, in a job.
		if write.CheckLive(ctx, s.store().Reader(), write.Scope{OrganizationID: r.OrganizationID, ProjectID: r.ProjectID, EnvironmentIDs: []string{r.EnvironmentID}}) != nil {
			continue
		}
		var none *values.NoToken
		if err := s.Refresh(ctx, id, r.OauthConnection.Generation); err != nil && !errors.As(err, &none) {
			s.log().Error("OAuth connection keepalive error", "valueId", id, "error", err)
		}
	}
	return nil
}

// RunLoop runs a pass at once and then every interval, inside the maintenance
// admission.
func (s *Service) RunLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		func() {
			if s.Admit != nil {
				leave, ok := s.Admit()
				if !ok {
					return
				}
				defer leave()
			}
			if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
				s.log().Error("OAuth connections worker error", "error", err)
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
