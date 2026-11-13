// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	// requestTimeout bounds one TUF download, whatever the caller's context.
	requestTimeout = 30 * time.Second
	// attempts is how often a download is tried on a network error or a
	// 429/5xx response.
	attempts = 3
)

// ctxFetcher downloads TUF metadata and targets under a context. sigstore-go
// passes its own options' context only to background tasks, and go-tuf's
// default fetcher makes requests without one, so a stalled download would
// outlive an installer's deadline. It otherwise behaves as go-tuf's
// DefaultFetcher, whose errors the TUF updater relies on (a 404 ends the
// walk through root versions).
type ctxFetcher struct {
	ctx    context.Context
	client *http.Client
}

func (f *ctxFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	var err error
	for attempt := 1; ; attempt++ {
		if cerr := f.ctx.Err(); cerr != nil {
			return nil, cerr
		}
		var data []byte
		var retry bool
		data, retry, err = f.download(urlPath, maxLength)
		if err == nil {
			return data, nil
		}
		if !retry || attempt == attempts {
			return nil, err
		}
		select {
		case <-f.ctx.Done():
			return nil, f.ctx.Err()
		case <-time.After(time.Duration(attempt) * time.Second):
		}
	}
}

// download makes one request; retry reports whether another try may help.
func (f *ctxFetcher) download(urlPath string, maxLength int64) (data []byte, retry bool, err error) {
	ctx, cancel := context.WithTimeout(f.ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "varlatch")
	res, err := f.client.Do(req)
	if err != nil {
		// A cancelled or expired caller context is final; a network error
		// or a request timeout may pass.
		return nil, f.ctx.Err() == nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		retry := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
		return nil, retry, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
	}
	if header := res.Header.Get("Content-Length"); header != "" {
		length, err := strconv.ParseInt(header, 10, 64)
		if err != nil {
			return nil, false, err
		}
		if length > maxLength {
			return nil, false, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
		}
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, maxLength+1))
	if err != nil {
		return nil, f.ctx.Err() == nil && !errors.Is(err, context.Canceled), err
	}
	if int64(len(data)) > maxLength {
		return nil, false, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, len(data), maxLength)}
	}
	return data, false, nil
}
