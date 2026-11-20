// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// requestTimeout bounds one request until its answer's headers arrive;
// the caller's context bounds the whole update.
const requestTimeout = 30 * time.Second

// maxRedirects is how many redirects one download may follow (GitHub
// answers a release file with one, to its storage host).
const maxRedirects = 5

// client is the HTTP client of a Source: HTTPS only, to the Source's
// hosts only, redirects included, a proxy from the environment as any
// download, and TLS verified against roots (the system's when nil).
func (s Source) client() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = requestTimeout
	if s.roots != nil {
		transport.TLSClientConfig.RootCAs = s.roots
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errors.New("too many redirects")
			}
			return s.allowed(req.URL)
		},
	}
}

// allowed is nil when u may be requested: HTTPS to one of the Source's
// hosts, on the default port unless the Source names one.
func (s Source) allowed(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing %s: not HTTPS", redact(u))
	}
	if u.User != nil || !slices.Contains(s.Hosts, strings.ToLower(u.Host)) {
		return fmt.Errorf("refusing %s: not a host releases come from (%s)", redact(u), strings.Join(s.Hosts, ", "))
	}
	return nil
}

// redact is u without its query: a storage host's signed query is long and
// says nothing to a person.
func redact(u *url.URL) string {
	c := *u
	c.RawQuery, c.User, c.Fragment = "", nil, ""
	return c.String()
}

// errNotFound is a 404 answer.
var errNotFound = errors.New("not found")

// unreachableError is a failure to reach a host or get its answer: the
// update ends with 69 (EX_UNAVAILABLE), as an unreachable server does.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// get fetches rawURL, at most limit bytes of its body. A cut-off answer,
// one longer than limit, or any status but 200 is an error.
func (s Source) get(ctx context.Context, rawURL string, limit int64, accept string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := s.allowed(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := s.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && strings.HasPrefix(ue.Err.Error(), "refusing ") {
			return nil, ue.Err // a redirect the policy refused
		}
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, new(*net.OpError)) {
			return nil, &unreachableError{fmt.Errorf("could not reach %s: %w", redact(u), err)}
		}
		return nil, &unreachableError{fmt.Errorf("could not download %s: %w", redact(u), err)}
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", redact(u), errNotFound)
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusForbidden && res.Header.Get("X-Ratelimit-Remaining") == "0":
		return nil, errors.New("GitHub's API rate limit is reached for this address; try again later")
	case res.StatusCode >= 500:
		return nil, &unreachableError{fmt.Errorf("%s answered %d", redact(u), res.StatusCode)}
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s answered %d", redact(u), res.StatusCode)
	}
	if res.ContentLength > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", redact(u), limit)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, &unreachableError{fmt.Errorf("downloading %s: %w", redact(u), err)}
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", redact(u), limit)
	}
	if res.ContentLength >= 0 && int64(len(body)) != res.ContentLength {
		return nil, &unreachableError{fmt.Errorf("downloading %s: cut off", redact(u))}
	}
	return body, nil
}
