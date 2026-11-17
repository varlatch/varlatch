// SPDX-License-Identifier: Apache-2.0

package cli

// The CLI's exit statuses (ADR-0043 Decision 10), apps/cli/src/exitCodes.ts.
// Meanings scripts already rely on are frozen: `validate` 1 (invalid) and 2
// (incomplete), `scan` 1 for every failure, `types --check` 1 (stale),
// `sync check` 1 (drift) and 2 (not everything checked), strict startup 78,
// `varlatch run` passing the command's own status through once it has
// started, and `login --wait` 75 for a sign-in still pending at its
// deadline. Any other failure is 1.
const (
	ExitOK          = 0
	ExitFailure     = 1
	ExitUsage       = 64  // EX_USAGE: the command line is wrong
	ExitUnavailable = 69  // EX_UNAVAILABLE: the server cannot be reached, or is in maintenance
	ExitTempfail    = 75  // EX_TEMPFAIL: still pending; run it again
	ExitDenied      = 77  // EX_NOPERM: not authenticated, or the server denied the request
	ExitConfig      = 78  // EX_CONFIG: strict startup found a violation, or assisted mode cannot mask
	ExitInterrupted = 130 // Ctrl-C stopped a wait for a step-up approval
)

// APIErrorExit is exitCodes.ts's apiErrorExit: the status for an error
// answer from the server, by its HTTP status and error code.
func APIErrorExit(status int, code string) int {
	switch code {
	case "APPROVAL_INVALID", "STEP_UP_REQUIRED":
		// An approval that does not fit, or one the CLI did not wait for (ADR-0054 Decision 3).
		return ExitDenied
	case "ORGANIZATION_FROZEN":
		// Frozen for an incident: asking again will not help until it is lifted.
		return ExitDenied
	case "PASSKEY_VERIFICATION_REQUIRED":
		// A verified passkey sign-in is needed (ADR-0054 Decision 7).
		return ExitDenied
	case "CONTROL_MODE_UNAVAILABLE":
		// A mode this server does not offer yet: an ordinary failure, not a denial.
		return ExitFailure
	}
	if status == 401 || status == 403 {
		return ExitDenied
	}
	if code == "MAINTENANCE" || status == 502 || status == 503 || status == 504 {
		return ExitUnavailable
	}
	return ExitFailure
}
