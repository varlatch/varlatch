// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// MaxResponseBytes bounds what the adapters read of one answer. The
// TypeScript adapters read answers whole; an answer past this bound is a
// transport failure here.
const MaxResponseBytes = 32 << 20

// response is an answer, read whole.
type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) ok() bool { return r.status >= 200 && r.status <= 299 }

// json is res.json(): the answer's JSON, or a SyntaxError.
func (r *response) json() (any, error) {
	v, err := parseJSON(r.body)
	if err != nil {
		return nil, &ScriptError{Name: "SyntaxError", Message: "the answer is not JSON"}
	}
	return v, nil
}

// jsonBody is the answer's JSON, or nil when it is not JSON (undefined).
func (r *response) jsonBody() (any, bool) {
	v, err := parseJSON(r.body)
	return v, err == nil
}

// text is res.text(): UTF-8, a leading byte order mark dropped.
func (r *response) text() string {
	return string(bytes.TrimPrefix(r.body, []byte("\xef\xbb\xbf")))
}

// send is one request through the caller's client, as the TypeScript
// adapters' fetch: redirects refused, the request's own timeout, and any
// failure before an answer an *AdapterError named as fetch would reject.
// The client is the caller's; only its redirect rule is replaced, in a copy
// that keeps its transport.
func send(ctx context.Context, req *Request, method, rawURL string, header [][2]string, body []byte) (*response, error) {
	if req.Client == nil {
		return nil, &AdapterError{Message: "TypeError", Retryable: true, Cause: errors.New("no HTTP client")}
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, ok := requestURL(rawURL)
	if !ok {
		return nil, &AdapterError{Message: "TypeError", Retryable: true, Cause: errors.New("invalid URL")}
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(rctx, method, target.String(), reader)
	if err != nil {
		return nil, &AdapterError{Message: "TypeError", Retryable: true, Cause: err}
	}
	hr.URL = target
	for _, h := range header {
		hr.Header.Set(h[0], h[1])
	}
	client := *req.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirect }
	res, err := client.Do(hr)
	if err != nil {
		return nil, &AdapterError{Message: transportName(ctx, err), Retryable: true, Cause: err}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, MaxResponseBytes+1))
	if err == nil && len(data) > MaxResponseBytes {
		err = errors.New("answer too large")
	}
	if err != nil {
		return nil, &AdapterError{Message: transportName(ctx, err), Retryable: true, Cause: err}
	}
	return &response{status: res.StatusCode, header: res.Header, body: data}, nil
}

// requestURL is the URL as fetch sends it: parsed and serialized as
// `new URL` does, the path and query exactly as fetch writes them, no
// fragment, and no credentials.
func requestURL(raw string) (*url.URL, bool) {
	u, ok := whatwg.ParseURL(raw)
	if !ok || u.Username != "" || u.Password != "" || (u.Protocol != "https:" && u.Protocol != "http:") {
		return nil, false
	}
	path, q := u.RequestTarget()
	out := &url.URL{Scheme: u.Protocol[:len(u.Protocol)-1], Host: u.Host, RawQuery: q}
	if !strings.HasPrefix(path, "//") {
		out.Opaque = path
		return out, true
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		out.Path, out.RawPath = decoded, path
	} else {
		out.Path = path
	}
	return out, true
}

// encodeURIComponent is JavaScript's: a lone surrogate is a URIError.
func encodeURIComponent(s string) (string, error) {
	const keep = "-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); {
		if _, ok := surrogateAt(s, i); ok {
			return "", &ScriptError{Name: "URIError", Message: "URI malformed"}
		}
		r, size := decodeRune(s[i:])
		if r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(keep, r)) {
			b.WriteByte(byte(r))
		} else {
			var enc [4]byte
			n := utf8.EncodeRune(enc[:], r)
			for _, c := range enc[:n] {
				b.WriteByte('%')
				b.WriteByte("0123456789ABCDEF"[c>>4])
				b.WriteByte("0123456789ABCDEF"[c&0xf])
			}
		}
		i += size
	}
	return b.String(), nil
}

// decodeRune decodes one rune; a byte that is not UTF-8 is U+FFFD, as a
// JavaScript string would hold it.
func decodeRune(s string) (rune, int) { return utf8.DecodeRuneInString(s) }
