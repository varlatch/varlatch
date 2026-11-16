// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import "net/http"

// SetClient replaces the policy's client for the parity test's recording
// one (webhooks_test cannot reach the unexported field).
func (s *Service) SetClient(c *http.Client) { s.client = c }
