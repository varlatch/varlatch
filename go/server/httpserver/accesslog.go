// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// AccessRecord is one line of the access log: a JSON object per request
// varlatchd answered, written when the answer is complete. It supplies the
// conformance harness's `request-log` operation (scripts/conformance/
// README.md, the target contract) and G9a's requests per address.
//
// Path is the URL path only: a query string can carry a code or token and
// is never logged. ForwardedFor is the X-Forwarded-For header as received,
// present only when the request had one: it is caller-supplied and only
// says what the caller claimed, which the proxy probe needs to tell its
// forged requests apart.
type AccessRecord struct {
	Arrived      time.Time `json:"arrived"`
	Completed    time.Time `json:"completed"`
	Client       string    `json:"client"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	Status       int       `json:"status"`
	Bytes        int64     `json:"bytes"`
	Window       bool      `json:"window"` // counted in the request window
	ForwardedFor *string   `json:"forwardedFor,omitempty"`
	RequestID    string    `json:"requestId"`
}

// AccessLog writes records as JSON lines. It is safe for concurrent use.
type AccessLog struct {
	mu sync.Mutex
	w  *bufio.Writer
	f  io.Writer
}

// NewAccessLog writes to w; nil discards every record.
func NewAccessLog(w io.Writer) *AccessLog {
	if w == nil {
		return nil
	}
	return &AccessLog{w: bufio.NewWriter(w), f: w}
}

func (l *AccessLog) write(rec *AccessRecord) {
	if l == nil {
		return
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
	// One record at a time reaches the file whole: readers (the harness's
	// request-log) see complete lines.
	_ = l.w.Flush()
}

// recorder captures what a handler answered.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Flush passes flushes through (server-sent events, step 3.5).
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection's writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
