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
func (d Downloader) Get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := d.allowed(u); err != nil {
		return nil, err
	}
	if d.Transport == nil {
		return nil, errors.New("release: a Downloader needs a Transport")
	}
	var refused error
	client := &http.Client{
		Transport: d.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				refused = errors.New("release: too many redirects")
				return refused
			}
			refused = d.allowed(req.URL)
			return refused
		},
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.AfterFunc(requestTimeout, cancel) // fetch.go's bound, as for a TUF download
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}
	res, err := client.Do(req)
	timer.Stop()
	if err != nil {
		if refused != nil {
			return nil, refused
		}
		return nil, &UnreachableError{fmt.Errorf("release: could not download %s: %w", strip(u), err)}
	}
	defer res.Body.Close()
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
