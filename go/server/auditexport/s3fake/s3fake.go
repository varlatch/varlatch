// SPDX-License-Identifier: AGPL-3.0-or-later

// Package s3fake is a local stand-in for an S3 bucket with Object Lock,
// for the audit export's tests and its parity fixture: the requests the
// probe makes (a conditional PutObject, HEAD, GetObjectRetention), path
// style only, answered as S3 answers them. What it does depends on the
// access key and the bucket, so every finding of the probe can be reached
// (services/varlatchd/test/go-audit-export-fixture.test.ts has the same
// server in TypeScript):
//
//   - key KeyGood may do everything; KeyNoRead may not read objects (HEAD
//     and GetObjectRetention answer 403); KeyNoRetentionRead may not read
//     retention; any other key is refused (InvalidAccessKeyId);
//   - bucket BucketLocked keeps what it is given; BucketOverwrite ignores
//     If-None-Match; BucketNoMetadata drops the sha256 metadata;
//     BucketNoLock keeps no retention; BucketWeak keeps governance
//     whatever mode was asked; any other bucket does not exist.
//
// It records each request's access key, which the G3 checks compare: a
// key read from a sealed envelope is the one the fixture sealed. It keeps
// what it is given (Object), can be taken down (SetDown: every request
// answers 503) and can hold an object nobody uploaded (Plant), for the
// worker's tests.
package s3fake

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The keys and buckets the server knows.
const (
	KeyGood            = "AKIAFIXTUREGOOD"
	KeyNoRead          = "AKIAFIXTURENOREAD"
	KeyNoRetentionRead = "AKIAFIXTURENORETENTION"
	BucketLocked       = "export-bucket"
	BucketOverwrite    = "overwrite-bucket"
	BucketNoMetadata   = "nometa-bucket"
	BucketNoLock       = "nolock-bucket"
	BucketWeak         = "weak-bucket"
)

// Object is what the server keeps of an upload.
type Object struct {
	Body                             []byte
	SHA256, ContentType, Mode, Until string
}

// Request is one request the server answered.
type Request struct {
	Method, Bucket, Key, AccessKey string
	Retention                      bool // ?retention
	Status                         int
}

// Server is the fake.
type Server struct {
	*httptest.Server
	// Hold, when set before a request arrives, makes every request wait
	// until it is closed; Held receives once per waiting request (tests:
	// a call blocked mid-effect).
	Hold chan struct{}
	Held chan struct{}

	mu       sync.Mutex
	objects  map[string]Object
	requests []Request
	down     bool
}

// New starts a server; Close stops it.
func New() *Server {
	s := &Server{objects: map[string]Object{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Requests are the requests answered so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Object is the object kept under bucket/key, if any.
func (s *Server) Object(bucket, key string) (Object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[bucket+"/"+key]
	return o, ok
}

// Keys are the names kept in bucket, in no order.
func (s *Server) Keys(bucket string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name := range s.objects {
		if b, k, _ := strings.Cut(name, "/"); b == bucket {
			out = append(out, k)
		}
	}
	return out
}

// Plant keeps an object under bucket/key as if it had been uploaded.
func (s *Server) Plant(bucket, key string, o Object) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[bucket+"/"+key] = o
}

// SetDown makes every request answer 503 ServiceUnavailable while down.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

var credential = regexp.MustCompile(`Credential=([^/]+)/`)

type apiError struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func fail(w http.ResponseWriter, r *http.Request, status int, code string) int {
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return status
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	b, _ := xml.Marshal(apiError{Code: code, Message: code})
	_, _ = w.Write(append([]byte(xml.Header), b...))
	return status
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if s.Hold != nil {
		if s.Held != nil {
			s.Held <- struct{}{}
		}
		<-s.Hold
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	m := credential.FindStringSubmatch(r.Header.Get("Authorization"))
	access := ""
	if m != nil {
		access = m[1]
	}
	_, retention := r.URL.Query()["retention"]
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.answer(w, r, bucket, key, access, retention, body)
	s.requests = append(s.requests, Request{Method: r.Method, Bucket: bucket, Key: key, AccessKey: access, Retention: retention, Status: status})
}

func (s *Server) answer(w http.ResponseWriter, r *http.Request, bucket, key, access string, retention bool, body []byte) int {
	if s.down {
		return fail(w, r, http.StatusServiceUnavailable, "ServiceUnavailable")
	}
	switch access {
	case KeyGood, KeyNoRead, KeyNoRetentionRead:
	default:
		return fail(w, r, http.StatusForbidden, "InvalidAccessKeyId")
	}
	switch bucket {
	case BucketLocked, BucketOverwrite, BucketNoMetadata, BucketNoLock, BucketWeak:
	default:
		return fail(w, r, http.StatusNotFound, "NoSuchBucket")
	}
	name := bucket + "/" + key
	switch {
	case r.Method == http.MethodPut:
		if _, taken := s.objects[name]; taken && r.Header.Get("If-None-Match") == "*" && bucket != BucketOverwrite {
			return fail(w, r, http.StatusPreconditionFailed, "PreconditionFailed")
		}
		o := Object{Body: body, SHA256: r.Header.Get("X-Amz-Meta-Sha256"), ContentType: r.Header.Get("Content-Type"),
			Mode: r.Header.Get("X-Amz-Object-Lock-Mode"), Until: r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")}
		switch bucket {
		case BucketNoMetadata:
			o.SHA256 = ""
		case BucketNoLock:
			o.Mode, o.Until = "", ""
		case BucketWeak:
			if o.Mode != "" {
				o.Mode = "GOVERNANCE"
			}
		}
		s.objects[name] = o
		w.Header().Set("ETag", `"fixture"`)
		w.WriteHeader(http.StatusOK)
		return http.StatusOK
	case r.Method == http.MethodHead:
		if access == KeyNoRead {
			return fail(w, r, http.StatusForbidden, "AccessDenied")
		}
		o, ok := s.objects[name]
		if !ok {
			return fail(w, r, http.StatusNotFound, "NotFound")
		}
		if o.SHA256 != "" {
			w.Header().Set("X-Amz-Meta-Sha256", o.SHA256)
		}
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Last-Modified", time.Unix(0, 0).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		return http.StatusOK
	case r.Method == http.MethodGet && retention:
		if access == KeyNoRead || access == KeyNoRetentionRead {
			return fail(w, r, http.StatusForbidden, "AccessDenied")
		}
		o, ok := s.objects[name]
		if !ok {
			return fail(w, r, http.StatusNotFound, "NoSuchKey")
		}
		if o.Mode == "" {
			return fail(w, r, http.StatusNotFound, "NoSuchObjectLockConfiguration")
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `%s<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
			xml.Header, o.Mode, o.Until)
		return http.StatusOK
	}
	return fail(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed")
}
