// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The transport is what Node.js's fetch (undici) does for the TypeScript
// CLI, observed from outside (internal docs/design/go-cli.md, decisions 2
// and 4):
//
//   - undici's timing, since the TypeScript code sets none: 10 s to
//     connect, 300 s for the response headers and 300 s between body
//     chunks, no overall deadline;
//   - fetch's redirects (at most 20; 303, and 301 or 302 after a POST,
//     become a GET without a body or its headers; Authorization dropped when
//     the origin changes; a target with credentials refused), its "bad
//     port" list, and its refusals (a URL that does not parse, one with
//     credentials, a scheme other than http and https), whose messages
//     never show a URL's user name and password;
//   - HTTP/1.1, as undici speaks it, and the header fetch adds that a
//     recording keeps: Accept: */*;
//   - trust: the system's roots, plus the certificates in
//     NODE_EXTRA_CA_CERTS when it is set (Node.js trusts its bundled
//     Mozilla roots plus that file); and no proxy from the environment
//     (Node.js's fetch reads none). Both are accepted differences in
//     go/README.md.
const (
	connectTimeout = 10 * time.Second
	headersTimeout = 300 * time.Second
	bodyTimeout    = 300 * time.Second
	maxRedirects   = 20
)

// badPorts is the Fetch standard's "bad port" list, which undici refuses
// to connect to ("fetch failed", cause "bad port").
var badPorts = []int{
	0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104,
	109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
	526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049,
	3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
}

// Env is the environment the transport reads (NODE_EXTRA_CA_CERTS).
type Env interface {
	LookupEnv(key string) (string, bool)
}

// Transport sends requests as fetch does. The zero value is not usable;
// NewTransport makes one.
type Transport struct {
	client      *http.Client
	bodyTimeout time.Duration
}

var (
	sharedMu        sync.Mutex
	sharedTransport = map[string]*Transport{}
)

// NewTransport is the transport for env: one per distinct
// NODE_EXTRA_CA_CERTS, so every client of a run shares its connections, as
// Node.js's global dispatcher does.
func NewTransport(env Env) *Transport {
	extra := ""
	if env != nil {
		extra, _ = env.LookupEnv("NODE_EXTRA_CA_CERTS")
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if t, ok := sharedTransport[extra]; ok {
		return t
	}
	t := newTransport(extra, headersTimeout, bodyTimeout)
	sharedTransport[extra] = t
	return t
}

// newTransport is a transport with its own connections and timeouts.
func newTransport(extra string, headers, body time.Duration) *Transport {
	dialer := &net.Dialer{Timeout: connectTimeout}
	ht := &http.Transport{
		Proxy:                 nil, // fetch reads no proxy from the environment
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: headers,
		// HTTP/1.1 only, as undici's fetch speaks it (an empty TLSNextProto
		// turns HTTP/2 off).
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:      16,
		IdleConnTimeout:   4 * time.Second, // undici's keep-alive default
		TLSClientConfig:   &tls.Config{RootCAs: rootPool(extra), MinVersion: tls.VersionTLS12},
	}
	return &Transport{
		client: &http.Client{
			Transport: ht,
			// fetch's redirects are followed by Do itself, by fetch's rules.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		bodyTimeout: body,
	}
}

// rootPool is the system's roots plus the PEM certificates in the file
// NODE_EXTRA_CA_CERTS names. A file that cannot be read or holds no
// certificate adds nothing (Node.js warns once and goes on without it).
func rootPool(extra string) *x509.CertPool {
	if extra == "" {
		return nil // the system's roots
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if data, err := os.ReadFile(extra); err == nil {
		pool.AppendCertsFromPEM(data)
	}
	return pool
}

// Response is an answer as the client reads it: the status, the headers
// (each name's values joined with ", ", as Headers.get gives them, decoded
// as Latin-1 the way undici decodes them) and the body.
type Response struct {
	Status  int
	header  http.Header
	Body    []byte
	BodyErr error // the body could not be read in full ("terminated")
}

// Header is Headers.get(name): the values joined with ", ", and false
// when there is none (null).
func (r *Response) Header(name string) (string, bool) {
	values := r.header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return latin1(strings.Join(values, ", ")), true
}

// latin1 is a header value's bytes as undici gives them: each byte one
// character.
func latin1(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			var b strings.Builder
			for j := 0; j < len(s); j++ {
				b.WriteRune(rune(s[j]))
			}
			return b.String()
		}
	}
	return s
}

// Request is one request: method, absolute URL (as the client joins the
// server and the path), headers and an optional JSON body.
type Request struct {
	Method  string
	URL     string
	Headers [][2]string // in order; a later one replaces an earlier one of the same name
	Body    []byte      // nil for none
}

// Do sends req as fetch(url, {method, headers, body}) and reads the whole
// answer, following redirects as fetch does.
func (t *Transport) Do(ctx context.Context, req Request) (*Response, error) {
	target, err := checkURL(req.URL)
	if err != nil {
		return nil, err
	}
	method, body := req.Method, req.Body
	headers := http.Header{}
	for _, h := range req.Headers {
		headers.Set(h[0], h[1])
	}
	if headers.Get("Accept") == "" {
		headers.Set("Accept", "*/*")
	}
	for redirects := 0; ; redirects++ {
		res, err := t.once(ctx, method, target, headers, body)
		if err != nil {
			return nil, err
		}
		location := res.Header.Get("Location")
		if !isRedirect(res.StatusCode) || location == "" {
			return read(ctx, res, t.bodyTimeout), nil
		}
		_ = res.Body.Close()
		next, ok := resolve(target, location)
		if !ok {
			return nil, fetchFailed("network error", errors.New("invalid redirect location"))
		}
		if next.Username != "" || next.Password != "" {
			// fetch refuses a redirect to a URL with credentials before
			// sending anything there ("cross origin not allowed for request
			// mode cors"): the credential is never sent to it.
			return nil, fetchFailed("network error", errors.New("redirect to a URL with credentials"))
		}
		if next.Protocol != "http:" && next.Protocol != "https:" {
			return nil, fetchFailed("network error", errors.New("redirect to a URL that is not HTTP(S)"))
		}
		if redirects+1 > maxRedirects {
			return nil, fetchFailed("network error", errors.New("redirect count exceeded"))
		}
		if res.StatusCode == 303 && method != "GET" && method != "HEAD" || (res.StatusCode == 301 || res.StatusCode == 302) && method == "POST" {
			method, body = "GET", nil
			for _, name := range []string{"Content-Encoding", "Content-Language", "Content-Location", "Content-Type"} {
				headers.Del(name)
			}
		}
		if origin(next) != origin(target) {
			headers = headers.Clone()
			headers.Del("Authorization")
			headers.Del("Proxy-Authorization")
			headers.Del("Cookie")
		}
		target = next
	}
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

func origin(u whatwg.URL) string { return u.Protocol + "//" + u.Host }

// checkURL is fetch's own refusals before it connects: a URL that does not
// parse, one with credentials. A URL is shown without its user name and
// password (diagnostics never print credential values), and where it holds
// an at-sign the explanation follows it, since the CLI's fail-safe keeps
// what follows the last at-sign (go/README.md, "Diagnostics never print
// credential values"). A URL that does not parse and holds none keeps
// fetch's wording.
func checkURL(raw string) (whatwg.URL, error) {
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		shown := clientctx.MaskUserinfo(raw)
		if clientctx.HasAtSign(shown) {
			return u, &FetchError{Message: shown + ": can't be parsed as a URL"}
		}
		return u, &FetchError{Message: "Failed to parse URL from " + shown}
	}
	if u.Username != "" || u.Password != "" {
		return u, &FetchError{Message: href(u) + ": a server URL with a user name or password can't be used; remove them and try again"}
	}
	return u, nil
}

// href is the URL serialized, its user name and password, if any, shown
// as [redacted].
func href(u whatwg.URL) string {
	path, query := u.RequestTarget()
	auth := ""
	if u.Username != "" || u.Password != "" {
		auth = "[redacted]@"
	}
	s := u.Protocol + "//" + auth + u.Host + path
	if query != "" || u.Search == "?" {
		s += "?" + query
	}
	return s + u.Hash
}

// resolve is a Location header against the URL it answered.
func resolve(base whatwg.URL, location string) (whatwg.URL, bool) {
	loc := whatwg.Trim(location)
	if u, ok := whatwg.ParseURL(loc); ok && hasScheme(loc) {
		return u, true
	}
	path, _ := base.RequestTarget()
	var abs string
	switch {
	case strings.HasPrefix(loc, "//"):
		abs = base.Protocol + loc
	case strings.HasPrefix(loc, "/"):
		abs = origin(base) + loc
	case strings.HasPrefix(loc, "?"):
		abs = origin(base) + path + loc
	case strings.HasPrefix(loc, "#"):
		abs = origin(base) + path + base.Search + loc
	default:
		dir := path[:strings.LastIndexByte(path, '/')+1]
		abs = origin(base) + dir + loc
	}
	return whatwg.ParseURL(abs)
}

func hasScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return true
}

// once sends one request, without following a redirect.
func (t *Transport) once(ctx context.Context, method string, target whatwg.URL, headers http.Header, body []byte) (*http.Response, error) {
	scheme := strings.TrimSuffix(target.Protocol, ":")
	if scheme != "http" && scheme != "https" {
		return nil, fetchFailed("network error", errors.New("unknown scheme"))
	}
	if slices.Contains(badPorts, connectPort(target.Host, scheme)) {
		return nil, fetchFailed("network error", errors.New("bad port"))
	}
	path, query := target.RequestTarget()
	u := &url.URL{Scheme: scheme, Host: target.Host, Opaque: path, RawQuery: query}
	if strings.HasPrefix(path, "//") {
		// An Opaque path starting with "//" would be sent in absolute form.
		u = &url.URL{Scheme: scheme, Host: target.Host, Path: path, RawQuery: query}
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/", reader)
	if err != nil {
		return nil, fetchFailed("network error", err)
	}
	req.URL, req.Host = u, target.Host
	req.Header = headers.Clone()
	if body != nil {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	res, err := t.client.Do(req)
	if err != nil {
		return nil, fetchFailed(networkCode(err), err)
	}
	return res, nil
}

// connectPort is the port a URL connects to.
func connectPort(hostport, scheme string) int {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		if scheme == "https" {
			return 443
		}
		return 80
	}
	n, _ := strconv.Atoi(p)
	return n
}

// read reads the whole body, failing ("terminated") when the connection
// ends early or no chunk comes for bodyTimeout.
func read(ctx context.Context, res *http.Response, bodyTimeout time.Duration) *Response {
	defer res.Body.Close()
	out := &Response{Status: res.StatusCode, header: res.Header}
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)
	type result struct {
		n   int
		err error
	}
	results := make(chan result, 1)
	for {
		go func() {
			n, err := res.Body.Read(chunk)
			results <- result{n, err}
		}()
		timer := time.NewTimer(bodyTimeout)
		var r result
		select {
		case r = <-results:
			timer.Stop()
		case <-timer.C:
			_ = res.Body.Close()
			<-results
			out.Body, out.BodyErr = buf.Bytes(), &BodyError{Message: "terminated"}
			return out
		case <-ctx.Done():
			timer.Stop()
			_ = res.Body.Close()
			<-results
			out.Body, out.BodyErr = buf.Bytes(), &BodyError{Message: "terminated"}
			return out
		}
		buf.Write(chunk[:r.n])
		if r.err == io.EOF {
			out.Body = buf.Bytes()
			return out
		}
		if r.err != nil {
			out.Body, out.BodyErr = buf.Bytes(), &BodyError{Message: "terminated"}
			return out
		}
	}
}
