// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"slices"

	"github.com/varlatch/varlatch/go/server/api"
)

// Capabilities is the TypeScript server's list (packages/protocol/src/
// errors.ts CAPABILITIES), in its order; meta_test.go checks the two agree.
// /v1/meta lists it as the TypeScript server does, leaving out what this
// installation does not offer (see meta). The browser session and
// server-sent events capabilities (auth.session, realtime.sse) join with
// steps 3.4 and 3.5.
var Capabilities = []string{
	"contracts.push",
	"contracts.managed",
	"tailnet.constraints",
	"audit.ndjson",
	"values.changeset",
	"secrets.requested-disclosure",
	"secrets.disclosure-purpose",
	"environments.personal",
	"environments.preview",
	"capabilities.broker",
	"credentials.agent",
	"webhooks.audit",
	"values.references",
	"values.rotation",
	"auth.oidc",
	"access.update",
	"grants.replace",
	"search.items",
	"sync.targets",
	"installation.backups",
	"identity.lifecycle",
	"identity.credentials.issue",
	"retrieval.manifest",
	"retrieval.strict",
	"retrieval.preflight",
	"capabilities.targets",
	"contracts.revision-by-id",
	"projects.rename",
	"invitations.manage",
	"organizations.rename",
	"audit.filters",
	"auth.device",
	"audit.attribution",
	"environments.tailnet-required",
	"tailnet.browser-reads",
	"identity.whoami",
	"installation.release",
	"disclosure.purpose.export",
	"sync.pause-wait",
	"members.lifecycle",
	"projects.delete",
	"organizations.delete",
	"identity.reach",
	"security.credential-review",
	"account.passkeys",
	"security.controls",
	"security.report",
	"security.approval-keys",
	"organizations.permissions",
	"installation.outbound",
	"cli.download",
	"security.refused-destinations",
	"organizations.incident-freeze",
	"audit.storage-export",
	"security.enforce.requirement-protection",
	"security.enforce.credential-lifetime",
	"security.enforce.passkey-verification",
	"security.enforce.admin-step-up",
}

// SemanticsVersions are the Contract Semantics versions the server
// evaluates (packages/contract/src/semantics.ts SEMANTICS_VERSIONS).
var SemanticsVersions = []int{1, 2, 3}

// SyncPlatforms are the outbound sync adapters, in the TypeScript server's
// order (packages/sync/src/types.ts PLATFORMS).
var SyncPlatforms = []api.SyncPlatform{api.SyncPlatformGithubActions, api.SyncPlatformCoolify, api.SyncPlatformConvex}

// operations implements the generated StrictServerInterface. The embedded
// interface is nil: only the methods defined here are ever called, since
// every other operation's route is the stub (operationMux), which answers
// before the generated handler runs.
type operations struct {
	api.StrictServerInterface
	s *Server
}

var loopbackHosts = map[string]bool{"127.0.0.1": true, "[::1]": true, "localhost": true}

// GetMeta is /v1/meta, unauthenticated, as the TypeScript server answers
// it: the capabilities less the ones this installation does not offer
// (sync.targets with sync off; auth.device without an https public URL, or
// plain http on loopback; tailnet.browser-reads without a browser endpoint
// and cli.download without serving the CLI, neither of which this build
// has), the sync adapters while sync is on, and the installation's ID once
// it exists.
func (o *operations) GetMeta(ctx context.Context, _ api.GetMetaRequestObject) (api.GetMetaResponseObject, error) {
	s := o.s
	hidden := map[string]bool{"tailnet.browser-reads": true, "cli.download": true}
	if !s.opts.Sync {
		hidden["sync.targets"] = true
	}
	if u := s.opts.PublicURL; u == nil || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHosts[hostOf(u.Host)]) {
		hidden["auth.device"] = true
	}
	caps := slices.DeleteFunc(slices.Clone(Capabilities), func(c string) bool { return hidden[c] })
	semantics := slices.Clone(SemanticsVersions)
	meta := api.Meta{ApiMajor: 1, ServerVersion: s.opts.Version, SemanticsVersions: &semantics, Capabilities: caps}
	if s.opts.Sync {
		adapters := slices.Clone(SyncPlatforms)
		if s.opts.SyncAdapters != nil {
			adapters = adapters[:0]
			for _, a := range s.opts.SyncAdapters {
				adapters = append(adapters, api.SyncPlatform(a))
			}
		}
		meta.SyncAdapters = &adapters
	}
	// The TypeScript server leaves the ID out when reading it fails.
	if id, err := s.opts.Backend.InstallationID(ctx); err == nil && id != "" {
		meta.InstallationId = &id
	}
	return api.GetMeta200JSONResponse(meta), nil
}

// hostOf is a URL host without its port, as URL.hostname gives it
// (brackets kept for IPv6, like the TypeScript server's LOOPBACK_HOSTS).
func hostOf(host string) string {
	if i := len(host) - 1; i >= 0 && host[i] != ']' {
		for j := i; j >= 0; j-- {
			if host[j] == ':' {
				return host[:j]
			}
			if host[j] == ']' {
				break
			}
		}
	}
	return host
}
