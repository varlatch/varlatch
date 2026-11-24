// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package cli

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"
)

// In a crashpoint build only (G5's interruption gate), the tests' fake of
// Tailscale's API: its origin and the certificate it serves with.
var tailscaleAPIOverride = os.Getenv("VARLATCH_TEST_TAILSCALE_API")

func tailscaleHTTPClient() *http.Client {
	c := &http.Client{Timeout: time.Minute}
	if path := os.Getenv("VARLATCH_TEST_TAILSCALE_CA"); path != "" {
		if pem, err := os.ReadFile(path); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
			c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
		}
	}
	return c
}
