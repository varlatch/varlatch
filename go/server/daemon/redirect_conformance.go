// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package daemon

import (
	"log/slog"

	"github.com/varlatch/varlatch/go/server/outbound"
)

func init() {
	conformanceWarnings = func(log *slog.Logger) {
		if r := outbound.ConformanceRedirects(); r != "" {
			log.Warn("CONFORMANCE BUILD: outbound requests to these hosts go to the conformance harness's fake services instead (VARLATCH_CONFORMANCE_OUTBOUND_HOSTS); never run this build for real use", "redirects", r)
		}
	}
}
