// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The Agent's side of the Broker speaks HTTP/1.1 through this reader and
// writer rather than net/http's server: the Broker relays header names,
// their order and a reason phrase exactly as written, and refuses rather
// than guesses wherever a request could be read two ways (a request
// smuggled past the checks is a request the Broker never inspected).
//
// What it refuses with 400, as Node.js's parser does: obs-fold or any line
// folding, a line ending in a bare LF or holding a bare CR, a header name
// that is not a token or a space before its colon, a header value with a
// control character (CR, LF and NUL included; a tab and bytes above 0x7f
// are kept), Content-Length with Transfer-Encoding, a repeated
// Content-Length (even an equal one), a Content-Length that is not digits,
// a Transfer-Encoding that is not exactly "chunked", a method Node.js does
// not know, an HTTP/1.1 request without Host. Stricter than Node.js
// (go/README.md): a version other than HTTP/1.1 or HTTP/1.0, a request
// line without exactly one space between its parts, a request-target with
// a byte outside visible ASCII, a malformed chunk, and over 2,000 header
// fields (431, where Node.js drops the rest).
//
// Bounds: the request line and headers together 16 KiB (431, Node.js's
// maxHeaderSize), the head within 60 seconds and the whole request within
// 300 seconds (408, Node.js's headersTimeout and requestTimeout), an idle
// kept-alive connection 5 seconds, a body BodyLimit (413, from the
// request handler), a chunk-size line 4 KiB and trailers within the head's
// bound.

const (
	maxHeadBytes    = 16 * 1024
	maxHeaderFields = 2000
	maxChunkLine    = 4 * 1024
)

// The timeouts: variables so that a test can shorten them.
var (
	headTimeout    = 60 * time.Second
	requestTimeout = 300 * time.Second
	keepAliveIdle  = 5 * time.Second
)

// methods are Node.js's http.METHODS.
var methods = []string{"ACL", "BIND", "CHECKOUT", "CONNECT", "COPY", "DELETE", "GET", "HEAD", "LINK", "LOCK", "M-SEARCH", "MERGE", "MKACTIVITY",
	"MKCALENDAR", "MKCOL", "MOVE", "NOTIFY", "OPTIONS", "PATCH", "POST", "PROPFIND", "PROPPATCH", "PURGE", "PUT", "QUERY", "REBIND", "REPORT",
	"SEARCH", "SOURCE", "SUBSCRIBE", "TRACE", "UNBIND", "UNLINK", "UNLOCK", "UNSUBSCRIBE"}

// errBadRequest, errTooLarge and errTimeout are the head's refusals: 400,
// 431 and 408, written as Node.js writes them.
var (
	errBadRequest = errors.New("bad request")
	errTooLarge   = errors.New("request header fields too large")
	errTimeout    = errors.New("request timeout")
)

// rawRefusal is the reply Node.js writes for a request it cannot parse.
func rawRefusal(err error) string {
	switch {
	case errors.Is(err, errTooLarge):
		return "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
	case errors.Is(err, errTimeout):
		return "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n"
	}
	return "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
}

// head is a request's line and headers as sent. Header values are
// JavaScript strings, one character per byte, as Node.js reads them.
type head struct {
	method, target, version string
	headers                 []Pair
	// framing: "none", "length" (with length) or "chunked".
	framing string
	length  int64
}

func (h *head) http10() bool { return h.version == "HTTP/1.0" }

// first is the first value of a header, as Node.js keeps one for the
// headers it does not join (Proxy-Authorization, Host).
func (h *head) first(name string) (string, bool) {
	for _, p := range h.headers {
		if strings.EqualFold(p.Name, name) {
			return p.Value, true
		}
	}
	return "", false
}

// wantsClose is whether the connection ends after this request.
func (h *head) wantsClose() bool {
	for _, p := range h.headers {
		if strings.EqualFold(p.Name, "connection") {
			for _, t := range strings.Split(p.Value, ",") {
				if strings.EqualFold(strings.TrimSpace(t), "close") {
					return true
				}
				if h.http10() && strings.EqualFold(strings.TrimSpace(t), "keep-alive") {
					return false
				}
			}
		}
	}
	return h.http10()
}

func isTokenByte(c byte) bool {
	return c > 0x20 && c < 0x7f && !strings.ContainsRune(`"(),/:;<=>?@[\]{}`, rune(c))
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			return false
		}
	}
	return true
}

// lineReader reads CRLF-terminated lines within a byte budget.
type lineReader struct {
	r      *bufio.Reader
	budget int
	// tooLarge is the error once the budget is spent (431 for the head,
	// 400 for a chunk-size line).
	tooLarge error
}

// line is one line without its CRLF. A bare LF, or a CR not followed by
// LF, is a bad request.
func (l *lineReader) line() (string, error) {
	var b []byte
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return "", err
		}
		l.budget--
		if l.budget < 0 {
			return "", l.tooLarge
		}
		switch c {
		case '\n':
			return "", errBadRequest
		case '\r':
			n, err := l.r.ReadByte()
			if err != nil {
				return "", err
			}
			l.budget--
			if n != '\n' {
				return "", errBadRequest
			}
			return string(b), nil
		}
		b = append(b, c)
	}
}

// readHead reads one request's line and headers. io.EOF before any byte
// is a connection the client closed.
func readHead(r *bufio.Reader) (*head, error) {
	l := &lineReader{r: r, budget: maxHeadBytes, tooLarge: errTooLarge}
	line, err := l.line()
	// Empty lines before the request line are ignored, as Node.js does.
	for err == nil && line == "" {
		line, err = l.line()
	}
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !slices.Contains(methods, parts[0]) || (parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0") || parts[1] == "" {
		return nil, errBadRequest
	}
	for i := 0; i < len(parts[1]); i++ {
		if c := parts[1][i]; c <= 0x20 || c >= 0x7f {
			return nil, errBadRequest
		}
	}
	h := &head{method: parts[0], target: parts[1], version: parts[2], framing: "none"}
	for {
		line, err := l.line()
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		if len(h.headers) >= maxHeaderFields {
			return nil, errTooLarge
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, errBadRequest // obs-fold
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 || !isToken(line[:colon]) {
			return nil, errBadRequest
		}
		value := strings.Trim(line[colon+1:], " \t")
		for i := 0; i < len(value); i++ {
			if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
				return nil, errBadRequest
			}
		}
		h.headers = append(h.headers, Pair{line[:colon], latin1([]byte(value))})
	}
	var lengths, codings []string
	host := false
	for _, p := range h.headers {
		switch strings.ToLower(p.Name) {
		case "content-length":
			lengths = append(lengths, p.Value)
		case "transfer-encoding":
			codings = append(codings, p.Value)
		case "host":
			host = true
		}
	}
	switch {
	case len(lengths) > 0 && len(codings) > 0, len(lengths) > 1, len(codings) > 1:
		return nil, errBadRequest
	case len(codings) == 1:
		if !strings.EqualFold(strings.Trim(codings[0], " \t"), "chunked") {
			return nil, errBadRequest
		}
		h.framing = "chunked"
	case len(lengths) == 1:
		if lengths[0] == "" || strings.Trim(lengths[0], "0123456789") != "" || len(lengths[0]) > 15 {
			return nil, errBadRequest
		}
		h.length, _ = strconv.ParseInt(lengths[0], 10, 64)
		h.framing = "length"
	}
	if !host && !h.http10() && h.method != "CONNECT" {
		return nil, errNoHost
	}
	return h, nil
}

// errNoHost is an HTTP/1.1 request without Host: Node.js answers it 400
// from its response machinery (a Date and a chunked empty body).
var errNoHost = errors.New("no host")

// readBody reads a request's body within limit: over is true (and the
// body nil) when it is larger, and the rest is never read.
func readBody(r *bufio.Reader, h *head, limit int64) (body []byte, over bool, err error) {
	switch h.framing {
	case "length":
		if h.length > limit {
			return nil, true, nil
		}
		body = make([]byte, h.length)
		_, err = io.ReadFull(r, body)
		return body, false, err
	case "chunked":
		for {
			l := &lineReader{r: r, budget: maxChunkLine, tooLarge: errBadRequest}
			line, err := l.line()
			if err != nil {
				return nil, false, err
			}
			sizeText, _, _ := strings.Cut(line, ";")
			sizeText = strings.TrimRight(sizeText, " \t")
			if sizeText == "" || len(sizeText) > 15 || strings.Trim(strings.ToLower(sizeText), "0123456789abcdef") != "" {
				return nil, false, errBadRequest
			}
			size, _ := strconv.ParseInt(sizeText, 16, 64)
			if size == 0 {
				// Trailers, read and dropped, within the head's bound.
				t := &lineReader{r: r, budget: maxHeadBytes, tooLarge: errTooLarge}
				for {
					line, err := t.line()
					if err != nil {
						return nil, false, err
					}
					if line == "" {
						return body, false, nil
					}
				}
			}
			if int64(len(body))+size > limit {
				return nil, true, nil
			}
			chunk := make([]byte, size+2)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return nil, false, err
			}
			if chunk[size] != '\r' || chunk[size+1] != '\n' {
				return nil, false, errBadRequest
			}
			body = append(body, chunk[:size]...)
		}
	}
	return nil, false, nil
}

// statusText is Node.js's http.STATUS_CODES for the statuses the Broker
// writes itself.
var statusText = map[int]string{
	200: "OK", 400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 407: "Proxy Authentication Required",
	413: "Payload Too Large", 502: "Bad Gateway", 503: "Service Unavailable",
}

// nodeDate is the Date header Node.js adds to a response.
func nodeDate() string { return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") }

// nodeReply writes a reply the Broker makes itself as Node.js writes
// res.writeHead(status, headers) and res.end(body): the status line, the
// headers in order, Date, and the body chunked (as it is, then the
// connection's end, for HTTP/1.0).
func nodeReply(w *bufio.Writer, http10 bool, status int, headers []Pair, body string) error {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + statusText[status] + "\r\n")
	for _, h := range headers {
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	b.WriteString("Date: " + nodeDate() + "\r\n")
	if http10 {
		b.WriteString("\r\n" + body)
	} else {
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		if body != "" {
			b.WriteString(strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n")
		}
		b.WriteString("0\r\n\r\n")
	}
	raw, ok := latin1Bytes(b.String())
	if !ok {
		raw = []byte(b.String())
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	return w.Flush()
}

// agentResponse is AgentResponse on the Agent's connection.
type agentResponse struct {
	w       *bufio.Writer
	http10  bool
	chunked bool
	// closeAfter: the connection ends after this response.
	closeAfter bool
	aborted    func()
	started    bool
}

// WriteHead writes the status line and headers: length >= 0 is a body of
// that length (headers that hold Content-Length keep theirs), -1 a body of
// unknown length (chunked, or until the connection ends for HTTP/1.0), -2
// no body.
func (a *agentResponse) WriteHead(status int, reason string, headers []Pair, length int64) error {
	a.started = true
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + reason + "\r\n")
	hasDate, hasLength := false, false
	for _, h := range headers {
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
		switch strings.ToLower(h.Name) {
		case "date":
			hasDate = true
		case "content-length":
			hasLength = true
		}
	}
	if !hasDate {
		b.WriteString("Date: " + nodeDate() + "\r\n")
	}
	switch {
	case length >= 0 && !hasLength:
		b.WriteString("Content-Length: " + strconv.FormatInt(length, 10) + "\r\n")
	case length == -1 && !a.http10:
		b.WriteString("Transfer-Encoding: chunked\r\n")
		a.chunked = true
	case length == -1:
		a.closeAfter = true
	}
	if a.closeAfter {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	raw, ok := latin1Bytes(b.String())
	if !ok {
		return errors.New("a header holds a character above U+00FF")
	}
	if _, err := a.w.Write(raw); err != nil {
		return err
	}
	return a.w.Flush()
}

func (a *agentResponse) Write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if a.chunked {
		if _, err := a.w.WriteString(strconv.FormatInt(int64(len(p)), 16) + "\r\n"); err != nil {
			return err
		}
	}
	if _, err := a.w.Write(p); err != nil {
		return err
	}
	if a.chunked {
		if _, err := a.w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return a.w.Flush()
}

func (a *agentResponse) End() error {
	if a.chunked {
		if _, err := a.w.WriteString("0\r\n\r\n"); err != nil {
			return err
		}
	}
	return a.w.Flush()
}

// Abort ends the connection without a terminating chunk.
func (a *agentResponse) Abort() { a.aborted() }
