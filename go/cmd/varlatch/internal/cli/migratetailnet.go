// SPDX-License-Identifier: Apache-2.0

//go:build !crashpoint

package cli

import (
	"net/http"
	"time"
)

// tailscaleAPIOverride is Tailscale's API (empty: tailcontrol's default);
// a crashpoint build's tests point it at their fake.
var tailscaleAPIOverride = ""

// tailscaleHTTPClient is the client the handoff's control plane uses.
func tailscaleHTTPClient() *http.Client { return &http.Client{Timeout: time.Minute} }
