// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
)

// Response scrubbing for requests the Broker substituted into (ADR-0039
// Decisions 16 to 23), apps/cli/src/scrub.ts. Every header value and every
// body byte of such a response passes one matcher registered with exactly
// the values exercised for that request; nothing else reaches the Agent.
//
// Framing is decided from the response headers before any header is sent:
// a small identity body is read whole and relayed exactly when nothing
// matched; anything else is decoded (gzip, deflate, br), scrubbed as a
// stream, and re-framed. A failure before headers is a 502; after headers
// the response is aborted without a terminating chunk, and held bytes are
// discarded, never released.

// ReplyHeader is BROKER_REPLY_HEADER: it marks a reply the Broker made
// itself (a refusal, the proxy authentication challenge), never one from
// a destination, so a client can tell the two apart by origin.
const ReplyHeader = "varlatch-broker"

// Limits is ScrubLimits.
type Limits struct {
	// MaxDecodedBytes bounds the decoded content of one response.
	MaxDecodedBytes int64
	// IdleMillis is the longest time without a byte from upstream, from
	// the request being sent.
	IdleMillis int64
	// BufferedBytes is the largest declared identity body read whole.
	BufferedBytes int64
}

// DefaultLimits is SCRUB_LIMITS.
var DefaultLimits = Limits{MaxDecodedBytes: 64 * 1024 * 1024, IdleMillis: 120_000, BufferedBytes: 2 * 1024 * 1024}

// Event is what the run's diagnostics hear about (BrokerEvent and
// ScrubEvent): names, rules, destinations and counts, never a value.
type Event struct {
	// Kind is blocked, failed, stray, tunnel, scrubbed, unscrubbable,
	// incomplete-prefix or aborted.
	Kind        string
	Status      int
	Rule        string
	Message     string
	Item        string
	Surface     string
	Destination string
	Count       int
	Length      int
	Reason      string
}

// errBeforeHeaders is BeforeHeaders: nothing reached the Agent yet, so the
// caller answers 502 with its message.
type errBeforeHeaders struct{ message string }

func (e errBeforeHeaders) Error() string { return e.message }

// errCutoff is Cutoff: an idle or disconnect cutoff.
type errCutoff struct{ message string }

func (e errCutoff) Error() string { return e.message }

// hopByHop are the per-connection headers never relayed from upstream on a
// scrubbed response.
var hopByHop = []string{"connection", "keep-alive", "transfer-encoding", "proxy-connection", "trailer", "upgrade"}

// representation are the headers that describe bytes the Agent may no
// longer receive.
var representation = []string{"etag", "content-md5", "digest", "content-digest", "repr-digest"}

var decoders = map[string]func(io.Reader) (io.Reader, error){
	"gzip": func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) },
	// zlib.createInflate: the zlib format (RFC 1950).
	"deflate": func(r io.Reader) (io.Reader, error) { return zlib.NewReader(r) },
	"br":      func(r io.Reader) (io.Reader, error) { return brotli.NewReader(r), nil },
}

// ContentCoding is contentCoding: the single content coding of a response,
// "" for none, ok false when it cannot be inspected.
func ContentCoding(headers []Pair) (coding string, ok bool) {
	var codings []string
	for _, h := range headers {
		if strings.ToLower(h.Name) != "content-encoding" {
			continue
		}
		for _, c := range strings.Split(h.Value, ",") {
			if c = strings.ToLower(jsTrim(c)); c != "" && c != "identity" {
				codings = append(codings, c)
			}
		}
	}
	if len(codings) == 0 {
		return "", true
	}
	if _, known := decoders[codings[0]]; len(codings) == 1 && known {
		return codings[0], true
	}
	return "", false
}

// Scrubber is Scrubber: the exercised values of one request, what replaces
// each, and the counts of what was replaced.
type Scrubber struct {
	entries     []matcher.SecretEntry
	replacement func(item string) []byte
	report      func(Event)
	counts      map[string]int
}

// NewScrubber is new Scrubber: it reports each item too short to scrub.
func NewScrubber(entries []matcher.SecretEntry, replacement func(item string) []byte, report func(Event)) *Scrubber {
	s := &Scrubber{entries: entries, replacement: replacement, report: report, counts: map[string]int{}}
	var seen []string
	for _, item := range s.matcher().Skipped {
		if !slices.Contains(seen, item) {
			seen = append(seen, item)
			report(Event{Kind: "unscrubbable", Item: item})
		}
	}
	return s
}

func (s *Scrubber) matcher() *matcher.StreamMatcher {
	return matcher.NewStreamMatcher(s.entries, s.replacement)
}

func (s *Scrubber) count(m *matcher.StreamMatcher) {
	for item, n := range m.Replaced {
		s.counts[item] += n
	}
}

// HeaderValue is headerValue: one header value, whole, read as latin1.
func (s *Scrubber) HeaderValue(value string) (string, error) {
	m := s.matcher()
	raw, ok := latin1Bytes(value)
	if !ok {
		return "", errors.New("not a latin1 value")
	}
	head, err := m.Push(raw)
	if err != nil {
		return "", err
	}
	end, err := m.End()
	if err != nil {
		return "", err
	}
	s.count(m)
	if len(m.Replaced) == 0 {
		return value, nil
	}
	return latin1(append(head, end.Output...)), nil
}

// finish reports each item scrubbed and how often, in the order
// localeCompare gives their names.
func (s *Scrubber) finish() {
	items := make([]string, 0, len(s.counts))
	for item := range s.counts {
		items = append(items, item)
	}
	slices.SortFunc(items, localeCompare)
	for _, item := range items {
		s.report(Event{Kind: "scrubbed", Item: item, Count: s.counts[item]})
	}
}

// latin1Bytes is a JavaScript string as latin1 bytes, false when a
// character is above U+00FF.
func latin1Bytes(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xff {
			return nil, false
		}
		out = append(out, byte(r))
	}
	return out, true
}

// localeCompare is String.prototype.localeCompare for item names (ICU's
// root collation on [A-Za-z0-9_]): punctuation before digits before
// letters, letters without case first, then lower case before upper.
func localeCompare(a, b string) int {
	weight := func(c rune) int {
		switch {
		case c >= '0' && c <= '9':
			return 100 + int(c-'0')
		case c >= 'a' && c <= 'z':
			return 200 + int(c-'a')
		case c >= 'A' && c <= 'Z':
			return 200 + int(c-'A')
		}
		return int(c) // punctuation and the rest: before digits for ASCII
	}
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if wa, wb := weight(ra[i]), weight(rb[i]); wa != wb {
			return wa - wb
		}
	}
	if len(ra) != len(rb) {
		return len(ra) - len(rb)
	}
	for i := range ra {
		la, lb := ra[i] >= 'a' && ra[i] <= 'z', rb[i] >= 'a' && rb[i] <= 'z'
		if la != lb {
			if la {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

// Upstream is the destination's response as the relay reads it.
type Upstream struct {
	Status  int
	Reason  string
	Headers []Pair
	Body    io.ReadCloser
}

// AgentResponse is the Agent's side of a response: headers once, then the
// body, framed by the writer; Abort ends the connection without a
// terminating chunk.
type AgentResponse interface {
	WriteHead(status int, reason string, headers []Pair, length int64) error
	Write(p []byte) error
	End() error
	Abort()
}

var digitsOnly = regexp.MustCompile(`^\d+$`)

// Relay is relayScrubbed: one upstream response to the Agent through the
// scrubber. It returns errBeforeHeaders when nothing has been sent; after
// headers it aborts the response itself and returns nil. touch restarts
// the idle watchdog on every upstream byte; stop ends it.
func Relay(method string, up Upstream, res AgentResponse, s *Scrubber, limits Limits, touch, stop func(), report func(Event)) error {
	reason, err := s.HeaderValue(up.Reason)
	if err != nil {
		up.Body.Close()
		return errBeforeHeaders{"the response could not be scanned"}
	}
	var headers []Pair
	for _, h := range up.Headers {
		lower := strings.ToLower(h.Name)
		// The Broker's own marker is never relayed from a destination: it
		// could spoof a refusal.
		if slices.Contains(hopByHop, lower) || lower == ReplyHeader {
			continue
		}
		v, err := s.HeaderValue(h.Value)
		if err != nil {
			up.Body.Close()
			return errBeforeHeaders{"the response could not be scanned"}
		}
		headers = append(headers, Pair{h.Name, v})
	}
	named := func(name string) []string {
		var out []string
		for _, h := range headers {
			if strings.ToLower(h.Name) == name {
				out = append(out, h.Value)
			}
		}
		return out
	}
	without := func(names ...string) []Pair {
		var out []Pair
		for _, h := range headers {
			if !slices.Contains(names, strings.ToLower(h.Name)) {
				out = append(out, h)
			}
		}
		return out
	}

	// No body: the headers are still scrubbed.
	if method == "HEAD" || up.Status == 204 || up.Status == 304 {
		_, _ = io.Copy(io.Discard, up.Body)
		up.Body.Close()
		stop()
		if err := res.WriteHead(up.Status, reason, headers, -2); err != nil {
			return nil
		}
		_ = res.End()
		s.finish()
		return nil
	}

	coding, ok := ContentCoding(headers)
	if !ok {
		up.Body.Close()
		return errBeforeHeaders{"the response's content coding (" + strings.Join(named("content-encoding"), ", ") + ") cannot be inspected; not relayed"}
	}
	lengths := named("content-length")
	declared := int64(-1)
	if len(lengths) == 1 && digitsOnly.MatchString(jsTrim(lengths[0])) {
		declared, _ = strconv.ParseInt(jsTrim(lengths[0]), 10, 64)
	}

	if coding == "" && declared >= 0 && declared <= limits.BufferedBytes {
		// Buffered: read and scan the whole body before any header is sent.
		var body bytes.Buffer
		buf := make([]byte, 32*1024)
		for {
			n, err := up.Body.Read(buf)
			if n > 0 {
				touch()
				body.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				up.Body.Close()
				var cut errCutoff
				if errors.As(err, &cut) {
					return errBeforeHeaders{cut.message}
				}
				return errBeforeHeaders{"the destination closed the response early"}
			}
		}
		up.Body.Close()
		stop()
		m := s.matcher()
		head, err := m.Push(body.Bytes())
		var end matcher.EndReport
		if err == nil {
			end, err = m.End()
		}
		if err != nil {
			return errBeforeHeaders{"the response could not be scanned"}
		}
		if end.IncompletePrefix != nil {
			report(Event{Kind: "incomplete-prefix", Item: end.IncompletePrefix.Item, Length: end.IncompletePrefix.Length})
		}
		out := append(head, end.Output...)
		s.count(m)
		relayed := body.Bytes()
		if len(m.Replaced) > 0 {
			headers = append(without(append(slices.Clone(representation), "content-length")...), Pair{"Content-Length", strconv.Itoa(len(out))})
			relayed = out
		}
		if err := res.WriteHead(up.Status, reason, headers, int64(len(relayed))); err != nil {
			return nil
		}
		if err := res.Write(relayed); err == nil {
			_ = res.End()
		}
		s.finish()
		return nil
	}

	// Streaming: committed to chunked framing and identity content.
	headers = without(append(slices.Clone(representation), "content-length", "accept-ranges", "content-encoding")...)
	m := s.matcher()
	var source io.Reader = touchingReader{up.Body, touch}
	// Sent now, not with the first body byte: a failure before any decoded
	// byte (a corrupt gzip trailer read in one piece) still reaches the
	// Agent as a started, unterminated response, not as an empty reply.
	if err := res.WriteHead(up.Status, reason, headers, -1); err != nil {
		up.Body.Close()
		m.Abort()
		return nil
	}
	fail := func(err error) error {
		stop()
		m.Abort()
		up.Body.Close()
		res.Abort()
		s.count(m)
		s.finish()
		message := "the destination's response failed mid-stream"
		var cut errCutoff
		if errors.As(err, &cut) {
			message = cut.message
		}
		report(Event{Kind: "aborted", Reason: message})
		return nil
	}
	if coding != "" {
		decoded, err := decoders[coding](source)
		if err != nil {
			return fail(err)
		}
		source = decoded
	}
	var decodedBytes int64
	buf := make([]byte, 32*1024)
	for {
		n, err := source.Read(buf)
		if n > 0 {
			decodedBytes += int64(n)
			if decodedBytes > limits.MaxDecodedBytes {
				return fail(errCutoff{"the response exceeds " + strconv.FormatInt(limits.MaxDecodedBytes, 10) + " bytes of decoded content"})
			}
			out, perr := m.Push(buf[:n])
			if perr != nil {
				return fail(perr)
			}
			if len(out) > 0 {
				if werr := res.Write(out); werr != nil {
					return fail(errCutoff{"the Agent disconnected"})
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
	}
	end, err := m.End()
	if err != nil {
		return fail(err)
	}
	if end.IncompletePrefix != nil {
		report(Event{Kind: "incomplete-prefix", Item: end.IncompletePrefix.Item, Length: end.IncompletePrefix.Length})
	}
	stop()
	up.Body.Close()
	s.count(m)
	if err := res.Write(end.Output); err == nil {
		_ = res.End()
	}
	s.finish()
	return nil
}

// touchingReader restarts the idle watchdog on every byte read.
type touchingReader struct {
	r     io.Reader
	touch func()
}

func (t touchingReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.touch()
	}
	return n, err
}
