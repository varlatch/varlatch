// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// GitHubHosts are the hosts a release file comes from: github.com answers
// a download with a redirect to its storage hosts.
var GitHubHosts = []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

// DownloadURL is where a release's file is published.
func DownloadURL(version, name string) string {
	return "https://github.com/" + Repository + "/releases/download/v" + url.PathEscape(version) + "/" + url.PathEscape(name)
}

// ErrNotFound is a 404 answer.
var ErrNotFound = errors.New("release: not found")

// UnreachableError is a failure to reach a host or to get its whole answer;
// another attempt may succeed.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// Downloader fetches release files over HTTPS from a fixed set of hosts,
// redirects included: a request or redirect anywhere else, or to plain
// HTTP, is refused before it is made.
type Downloader struct {
	// Hosts are the allowed hosts, as host[:port].
	Hosts []string
	// Transport makes the requests (varlatchd: its outbound policy's);
	// it is required.
	Transport http.RoundTripper
	// UserAgent is sent with every request.
	UserAgent string
	// Stall bounds each request until its answer's headers arrive, and
	// then each wait for more of its body: a host that stops sending
	// fails the download within it (0: requestTimeout, 30 s).
	Stall time.Duration
}

// maxRedirects is how many redirects one download may follow.
const maxRedirects = 5

func (d Downloader) allowed(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("release: refusing %s: not HTTPS", strip(u))
	}
	if u.User != nil || !slices.Contains(d.Hosts, strings.ToLower(u.Host)) {
		return fmt.Errorf("release: refusing %s: not a host releases come from (%s)", strip(u), strings.Join(d.Hosts, ", "))
	}
	return nil
}

// strip is u without its query and credentials: a storage host's signed
// query is long and says nothing to a person.
func strip(u *url.URL) string {
	c := *u
	c.RawQuery, c.User, c.Fragment = "", nil, ""
	return c.String()
}

// Get fetches rawURL, at most limit bytes of its body. A cut-off answer,
// one longer than limit, or any status but 200 is an error.
//
// Redirects are followed here, never by the HTTP client: each Location is
// resolved against the request it answers, checked against the allowed
// hosts (HTTPS only), and fetched as a new request through the same
// Transport, at most maxRedirects times. Every hop is then a first request
// of its own to a transport such as varlatchd's outbound policy, which
// refuses a request the client made from a redirect response, and checks
// each destination's addresses when it connects.
func (d Downloader) Get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	if d.Transport == nil {
		return nil, errors.New("release: a Downloader needs a Transport")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport:     d.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	stall := d.Stall
	if stall <= 0 {
		stall = requestTimeout // fetch.go's bound, as for a TUF download
	}
	for hop := 0; ; hop++ {
		if err := d.allowed(u); err != nil {
			return nil, err
		}
		// Each hop under its own context, cancelled when the host sends
		// nothing for stall: the headers, then every wait for the body.
		hopCtx, cancel := context.WithCancel(ctx)
		var stalled atomic.Bool
		timer := time.AfterFunc(stall, func() { stalled.Store(true); cancel() })
		done := func() { timer.Stop(); cancel() }
		req, err := http.NewRequestWithContext(hopCtx, http.MethodGet, u.String(), nil)
		if err != nil {
			done()
			return nil, err
		}
		if d.UserAgent != "" {
			req.Header.Set("User-Agent", d.UserAgent)
		}
		res, err := client.Do(req)
		if err != nil {
			done()
			if stalled.Load() {
				return nil, &UnreachableError{fmt.Errorf("release: %s did not answer within %s", strip(u), stall)}
			}
			return nil, &UnreachableError{fmt.Errorf("release: could not download %s: %w", strip(u), err)}
		}
		switch res.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			location := res.Header.Get("Location")
			_ = res.Body.Close()
			done()
			if location == "" {
				return nil, fmt.Errorf("release: %s answered %d without a location", strip(u), res.StatusCode)
			}
			if hop >= maxRedirects {
				return nil, errors.New("release: too many redirects")
			}
			next, err := u.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("release: %s redirected to an address that is not a URL", strip(u))
			}
			u = next
			continue
		}
		res.Body = progress{res.Body, func() { timer.Reset(stall) }}
		body, err := d.read(u, res, limit)
		_ = res.Body.Close()
		done()
		if err != nil && stalled.Load() {
			return nil, &UnreachableError{fmt.Errorf("release: %s stopped sending for %s", strip(u), stall)}
		}
		return body, err
	}
}

// progress calls moved whenever a read returns bytes.
type progress struct {
	io.ReadCloser
	moved func()
}

func (p progress) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if n > 0 {
		p.moved()
	}
	return n, err
}

// read is a final answer's body.
func (d Downloader) read(u *url.URL, res *http.Response, limit int64) ([]byte, error) {
	switch {
	case res.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", strip(u), ErrNotFound)
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		return nil, &UnreachableError{fmt.Errorf("release: %s answered %d", strip(u), res.StatusCode)}
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("release: %s answered %d", strip(u), res.StatusCode)
	}
	if res.ContentLength > limit {
		return nil, fmt.Errorf("release: %s is larger than %d bytes", strip(u), limit)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, &UnreachableError{fmt.Errorf("release: downloading %s: %w", strip(u), err)}
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("release: %s is larger than %d bytes", strip(u), limit)
	}
	if res.ContentLength >= 0 && int64(len(body)) != res.ContentLength {
		return nil, &UnreachableError{fmt.Errorf("release: downloading %s: cut off", strip(u))}
	}
	return body, nil
}
