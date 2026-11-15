// SPDX-License-Identifier: AGPL-3.0-or-later

package realtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// Defaults (Options).
const (
	// DefaultPoll is how often the hub looks for events committed by
	// another process (the admin commands write the same database); a
	// commit of this one wakes it at once (Notify).
	DefaultPoll = time.Second
	// DefaultValidate is how often every stream's session is checked even
	// when nothing is published, so a stream closes within about a second
	// of its session ending (a sign-out records no audit event of its own),
	// expiring, or its identity being disabled. One indexed read per stream.
	DefaultValidate = time.Second
	// DefaultBuffer is how many publications wait for a stream's client
	// before it counts as slow and is disconnected. A publication is what
	// one wake of the hub sends a stream: one event per signal it may see.
	DefaultBuffer = 16
	// DefaultPerSession is how many streams one browser session may hold:
	// beyond that, its oldest is closed (a page in many tabs).
	DefaultPerSession = 8
	// batch is how many events one pass reads (syncNewMirrorEvents' LIMIT).
	batch = 200
)

// Why a stream closed: the close event's reason.
const (
	ReasonSessionEnded      = "session-ended"
	ReasonCredentialRevoked = "credential-revoked"
	ReasonMembershipRemoved = "membership-removed"
	ReasonSlowClient        = "slow-client"
	ReasonReplaced          = "replaced"
	ReasonShutdown          = "shutdown"
)

// ErrNotLive refuses a stream for a session that is not live (ended,
// expired, or its identity disabled).
var ErrNotLive = errors.New("realtime: the session is not live")

// ErrClosed refuses a stream once the hub has closed.
var ErrClosed = errors.New("realtime: closed")

// Options configures a Hub. Store is required.
type Options struct {
	Store      *storage.DB
	Log        *slog.Logger
	Now        func() time.Time
	Poll       time.Duration
	Validate   time.Duration
	Buffer     int
	PerSession int
}

// Hub reads the committed audit events, works out their signals and sends
// each to the streams allowed to see it. It never waits for a stream: a
// stream whose buffer is full is disconnected (a slow client), so one
// client cannot hold up the others or the server.
type Hub struct {
	opts Options
	wake chan struct{}

	mu      sync.Mutex
	streams map[*Stream]struct{}
	closed  bool
	seq     uint64

	// start is the position Run publishes after: the last event committed
	// when Run started or the first stream subscribed, whichever came
	// first (startCursor).
	startMu  sync.Mutex
	start    int64
	startSet bool
}

// New makes a hub; Run starts it.
func New(opts Options) *Hub {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Poll <= 0 {
		opts.Poll = DefaultPoll
	}
	if opts.Validate <= 0 {
		opts.Validate = DefaultValidate
	}
	if opts.Buffer <= 0 {
		opts.Buffer = DefaultBuffer
	}
	if opts.PerSession <= 0 {
		opts.PerSession = DefaultPerSession
	}
	return &Hub{opts: opts, wake: make(chan struct{}, 1), streams: map[*Stream]struct{}{}}
}

// Notify wakes the hub after a commit: storage.Options.OnCommit. It never
// blocks.
func (h *Hub) Notify() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// Run publishes until ctx ends. It starts after the last event committed
// before it or before the first stream subscribed, whichever came first: a
// stream receives the signals of everything committed after it opened, and
// nothing earlier is replayed. (Run starts in a goroutine, so a stream may
// subscribe before Run reads its starting point: reading it then would
// skip what was committed in between, a membership removal that must
// close the stream included.)
func (h *Hub) Run(ctx context.Context) error {
	cursor, err := h.startCursor(ctx)
	if err != nil {
		return err
	}
	poll := time.NewTicker(h.opts.Poll)
	defer poll.Stop()
	validate := time.NewTicker(h.opts.Validate)
	defer validate.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-h.wake:
		case <-poll.C:
		case <-validate.C:
			h.validateAll(ctx)
			continue
		}
		if cursor, err = h.publish(ctx, cursor); err != nil && ctx.Err() == nil {
			h.opts.Log.Error("realtime: publishing signals failed; the next commit retries", "error", err)
		}
	}
}

// publish reads every event after cursor, in passes of 200, and sends
// what they signal as one publication per stream: the signals of all the
// passes merged (the latest event of each Organization and identity, the
// union of their domains), as one longer pass would have them. It returns
// the new cursor.
func (h *Hub) publish(ctx context.Context, cursor int64) (int64, error) {
	q := query.New(h.opts.Store.Reader())
	if !h.anyStreams() {
		// Nobody to tell: skip what was committed.
		last, err := q.LastAuditPosition(ctx)
		if err != nil {
			return cursor, err
		}
		return max(cursor, last), nil
	}
	var merged []Signal
	closures := Closures{RemovedMembers: map[string]bool{}}
	next := cursor
	for {
		p, err := h.pass(ctx, next)
		if err != nil {
			return cursor, err
		}
		merged = mergeSignals(merged, p.signals)
		closures.RevokedCredentials = append(closures.RevokedCredentials, p.closures.RevokedCredentials...)
		for id := range p.closures.RemovedMembers {
			closures.RemovedMembers[id] = true
		}
		next = p.next
		if p.read < batch {
			break
		}
	}
	if next == cursor {
		return cursor, nil
	}
	if err := h.dispatch(ctx, merged, closures); err != nil {
		return cursor, err
	}
	return next, nil
}

// mergeSignals adds a later pass's signals to earlier ones: per kind and
// key, the later event and the union of domains, in first-seen order.
func mergeSignals(earlier, later []Signal) []Signal {
	index := make(map[[2]string]int, len(earlier))
	for i, s := range earlier {
		index[[2]string{s.Kind, s.Key}] = i
	}
	for _, s := range later {
		k := [2]string{s.Kind, s.Key}
		i, ok := index[k]
		if !ok {
			index[k] = len(earlier)
			earlier = append(earlier, s)
			continue
		}
		e := &earlier[i]
		e.LastEventID, e.OccurredAt = s.LastEventID, s.OccurredAt
		domains := append([]string{}, e.Domains...)
		for _, d := range s.Domains {
			if !slices.Contains(domains, d) {
				domains = append(domains, d)
			}
		}
		e.Domains = domains
	}
	return earlier
}

// passResult is one pass: what it read and what it publishes.
type passResult struct {
	read     int
	next     int64
	events   []Event
	signals  []Signal
	closures Closures
}

// pass reads up to 200 events after cursor, in the order of their
// positions, and works out their signals and closures.
func (h *Hub) pass(ctx context.Context, cursor int64) (passResult, error) {
	q := query.New(h.opts.Store.Reader())
	rows, err := q.AuditEventsAfter(ctx, query.AuditEventsAfterParams{After: cursor, MaxEvents: batch})
	if err != nil || len(rows) == 0 {
		return passResult{next: cursor}, err
	}
	events := make([]Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, Event{
			Position: r.EventOrder, ID: r.ID, Type: r.EventType, OccurredAt: r.OccurredAt,
			Actor: r.ActorIdentityID.String, CredentialID: r.CredentialID.String,
			OrganizationID: r.OrganizationID.String, Resource: r.Resource.String,
		})
	}
	var lookupErr error
	signals := Signals(events, func(ids []string) map[string]bool {
		gone, err := q.DeletedOrganizationsAmong(ctx, ids)
		if err != nil {
			lookupErr = err
		}
		m := make(map[string]bool, len(gone))
		for _, id := range gone {
			m[id] = true
		}
		return m
	})
	if lookupErr != nil {
		return passResult{next: cursor}, lookupErr
	}
	return passResult{
		read: len(rows), next: rows[len(rows)-1].EventOrder,
		events: events, signals: signals, closures: ClosuresOf(events),
	}, nil
}

func (h *Hub) anyStreams() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.streams) > 0
}

func (h *Hub) snapshot() []*Stream {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Stream, 0, len(h.streams))
	for s := range h.streams {
		out = append(out, s)
	}
	return out
}

// live checks a stream's session: live, its identity's, the identity
// enabled.
func (h *Hub) live(ctx context.Context, q *query.Queries, session, identity string) (bool, error) {
	_, err := q.StreamSessionLive(ctx, query.StreamSessionLiveParams{ID: session, IdentityID: identity, Now: h.opts.Now().UnixMicro()})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// dispatch sends a pass's signals. For each stream it checks first, at the
// time of sending, that its session is still live and which Organizations
// its identity is a member of now; a changeSignal goes only to members of
// its Organization, an identitySignal only to that identity's streams.
func (h *Hub) dispatch(ctx context.Context, signals []Signal, closures Closures) error {
	q := query.New(h.opts.Store.Reader())
	revokedSessions := map[string]bool{}
	for _, id := range closures.RevokedCredentials {
		session, err := q.SessionOfCredential(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if session.Valid {
			revokedSessions[session.String] = true
		}
	}
	messages := make([]Message, len(signals))
	for i, s := range signals {
		messages[i] = s.message()
	}
	if len(signals) == 0 && len(revokedSessions) == 0 && len(closures.RemovedMembers) == 0 {
		return nil
	}
	members := map[string]map[string]bool{}
	for _, st := range h.snapshot() {
		ok, err := h.live(ctx, q, st.session, st.identity)
		if err != nil {
			return err
		}
		if !ok {
			st.close(ReasonSessionEnded)
			continue
		}
		if revokedSessions[st.session] {
			st.close(ReasonCredentialRevoked)
			continue
		}
		orgs, seen := members[st.identity]
		if !seen {
			ids, err := q.MemberOrganizationIDs(ctx, st.identity)
			if err != nil {
				return err
			}
			orgs = make(map[string]bool, len(ids))
			for _, id := range ids {
				orgs[id] = true
			}
			members[st.identity] = orgs
		}
		if closures.RemovedMembers[st.identity] {
			// Removed from an Organization: nothing more of this
			// publication or of what is queued is sent, only the
			// identitySignal that tells the dashboard, then the stream
			// closes; it reconnects scoped to the Organizations it still
			// has, and refreshes.
			var final []Message
			for i, s := range signals {
				if s.Kind == Identity && s.Key == st.identity {
					final = append(final, messages[i])
				}
			}
			st.closeWith(ReasonMembershipRemoved, final)
			continue
		}
		var publication []Message
		for i, s := range signals {
			if s.Kind == Change && orgs[s.Key] || s.Kind == Identity && s.Key == st.identity {
				publication = append(publication, messages[i])
			}
		}
		if len(publication) > 0 {
			st.send(publication)
		}
	}
	return nil
}

// validateAll closes the streams whose session is no longer live.
func (h *Hub) validateAll(ctx context.Context) {
	q := query.New(h.opts.Store.Reader())
	for _, st := range h.snapshot() {
		ok, err := h.live(ctx, q, st.session, st.identity)
		if err != nil {
			if ctx.Err() == nil {
				h.opts.Log.Error("realtime: checking a stream's session failed", "error", err)
			}
			return
		}
		if !ok {
			st.close(ReasonSessionEnded)
		}
	}
}

// startCursor is the position Run publishes after, read once: at Run's
// start or the first Subscribe, whichever comes first.
func (h *Hub) startCursor(ctx context.Context) (int64, error) {
	h.startMu.Lock()
	defer h.startMu.Unlock()
	if !h.startSet {
		last, err := query.New(h.opts.Store.Reader()).LastAuditPosition(ctx)
		if err != nil {
			return 0, err
		}
		h.start, h.startSet = last, true
	}
	return h.start, nil
}

// Subscribe opens a stream for a browser session of identity, after
// checking the session is live. The caller must Unsubscribe it when the
// response ends. The hub's starting point is fixed before the stream
// exists, so whatever commits after Subscribe returns reaches it.
func (h *Hub) Subscribe(ctx context.Context, session, identity string) (*Stream, error) {
	ok, err := h.live(ctx, query.New(h.opts.Store.Reader()), session, identity)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotLive
	}
	if _, err := h.startCursor(ctx); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	var same []*Stream
	for s := range h.streams {
		if s.session == session {
			same = append(same, s)
		}
	}
	for len(same) >= h.opts.PerSession {
		oldest := same[0]
		for _, s := range same[1:] {
			if s.seq < oldest.seq {
				oldest = s
			}
		}
		oldest.close(ReasonReplaced)
		delete(h.streams, oldest)
		same = remove(same, oldest)
	}
	h.seq++
	s := &Stream{
		seq: h.seq, session: session, identity: identity,
		out: make(chan []Message, h.opts.Buffer), done: make(chan struct{}),
	}
	h.streams[s] = struct{}{}
	return s, nil
}

func remove(list []*Stream, s *Stream) []*Stream {
	for i, x := range list {
		if x == s {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// Unsubscribe forgets a stream whose response has ended.
func (h *Hub) Unsubscribe(s *Stream) {
	s.close("")
	h.mu.Lock()
	delete(h.streams, s)
	h.mu.Unlock()
}

// Close closes every stream (the server is stopping) and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	all := make([]*Stream, 0, len(h.streams))
	for s := range h.streams {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		s.close(ReasonShutdown)
	}
}

// Streams is how many streams are open.
func (h *Hub) Streams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.streams)
}

// Message is one server-sent event: its name and its JSON data.
type Message struct {
	Event string
	Data  []byte
}

// message is a signal's event: "change" with the Organization's id, or
// "identity" (the stream's own identity, so no id).
func (s Signal) message() Message {
	type wire struct {
		OrganizationID string   `json:"organizationId,omitempty"`
		LastEventID    string   `json:"lastEventId"`
		OccurredAt     string   `json:"occurredAt"`
		Domains        []string `json:"domains"`
	}
	w := wire{LastEventID: s.LastEventID, OccurredAt: s.OccurredAt, Domains: s.Domains}
	if s.Kind == Change {
		w.OrganizationID = s.Key
	}
	b, _ := json.Marshal(w)
	return Message{Event: s.Kind, Data: b}
}

// Stream is one browser connection's subscription.
type Stream struct {
	seq      uint64
	session  string
	identity string
	out      chan []Message

	mu     sync.Mutex
	done   chan struct{}
	ended  bool
	reason string
	final  []Message
}

// Messages are the stream's publications, in order: each the events of
// one publication.
func (s *Stream) Messages() <-chan []Message { return s.out }

// Done is closed when the stream must end.
func (s *Stream) Done() <-chan struct{} { return s.done }

// Ending reports why the stream ends ("" when its response ended first)
// and the only events still to be sent before the close event (a removal's
// identitySignal). Nothing queued before the end is sent after it: the
// queue is dropped.
func (s *Stream) Ending() (reason string, final []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason, s.final
}

// Ended reports whether the stream must end: checked before each event
// is written, so nothing queued is written once it has.
func (s *Stream) Ended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

// send queues a publication without waiting: a full buffer disconnects
// the client.
func (s *Stream) send(m []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	select {
	case s.out <- m:
	default:
		s.endLocked(ReasonSlowClient, nil)
	}
}

func (s *Stream) close(reason string) { s.closeWith(reason, nil) }

func (s *Stream) closeWith(reason string, final []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endLocked(reason, final)
}

func (s *Stream) endLocked(reason string, final []Message) {
	if s.ended {
		return
	}
	s.ended, s.reason, s.final = true, reason, final
	close(s.done)
	// The queue is dropped: what it holds was published before the end.
	for {
		select {
		case <-s.out:
		default:
			return
		}
	}
}
