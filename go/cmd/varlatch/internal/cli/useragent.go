// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"runtime"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// The CLI's User-Agent on every request to varlatchd (apps/cli/src/
// userAgent.ts): `varlatch-cli/<version> (<platform>; <arch>)`, with a third
// token, `assisted`, in assisted mode (ADR-0043 Decision 3). varlatchd keeps
// only its summary, as the label of a credential issued at login and as
// the client of every audit event, so the platform and processor use
// Node.js's names, which that summary reads. `varlatch mcp` has its own,
// `varlatch-mcp/<version> (<platform>; <arch>)` (packages/mcp-server/src/
// run.ts), so the audit tells an MCP host's requests from the CLI's.

// FormatUserAgent is userAgent.ts's formatUserAgent.
func FormatUserAgent(version string, assisted bool, platform, arch string) string {
	extra := ""
	if assisted {
		extra = "; assisted"
	}
	return "varlatch-cli/" + version + " (" + platform + "; " + arch + extra + ")"
}

// FormatMCPUserAgent is run.ts's mcpUserAgent.
func FormatMCPUserAgent(version, platform, arch string) string {
	return "varlatch-mcp/" + version + " (" + platform + "; " + arch + ")"
}

// NodePlatform is process.platform's name for this system.
func NodePlatform() string { return nodePlatform(runtime.GOOS) }

// NodeArch is process.arch's name for this processor.
func NodeArch() string { return nodeArch(runtime.GOARCH) }

func nodePlatform(goos string) string {
	if goos == "windows" {
		return "win32"
	}
	return goos // linux, darwin, freebsd, ... as Node names them
}

func nodeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	}
	return goarch // arm64, arm, ...
}

// UserAgent is this invocation's User-Agent for every request the CLI sends.
func (r *Run) UserAgent() string {
	return FormatUserAgent(buildinfo.Version, r.Assisted.On, NodePlatform(), NodeArch())
}
