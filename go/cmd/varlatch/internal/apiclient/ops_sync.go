// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// The client the Platform Adapters (go/lib/sync) reach the platforms with,
// for `sync push` and `sync check` (slice 5.8b of internal
// docs/design/go-cli.md); their disclosure is ops_values.go's
// DiscloseSecrets.

// PlatformDial, when set, dials every connection of the platform client
// instead of a plain dialer. Only tests set it (the transcript replay routes
// the platforms' host names to its fake); a release binary leaves it nil.
var PlatformDial func(ctx context.Context, network, address string) (net.Conn, error)

// PlatformClient is the client the Platform Adapters get: a plain
// http.Client (step 4's decision 6), as the TypeScript adapters' global
// fetch reaches the platforms. It trusts what the API client trusts (the
// system's roots and NODE_EXTRA_CA_CERTS) and, like fetch, reads no proxy
// from the environment. The adapters set their own redirect rule and
// timeouts per request.
func PlatformClient(env Env) *http.Client {
	extra := ""
	if env != nil {
		extra, _ = env.LookupEnv("NODE_EXTRA_CA_CERTS")
	}
	dial := (&net.Dialer{Timeout: connectTimeout}).DialContext
	if PlatformDial != nil {
		dial = PlatformDial
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil, // fetch reads no proxy from the environment
		DialContext:         dial,
		TLSHandshakeTimeout: connectTimeout,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig:     &tls.Config{RootCAs: rootPool(extra), MinVersion: tls.VersionTLS12},
	}}
}
