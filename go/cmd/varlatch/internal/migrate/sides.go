// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"time"
)

// LastTypeScriptRelease is the one release a migration starts from (O1):
// the last TypeScript release, whose export writes the bundle this
// varlatchd imports.
const LastTypeScriptRelease = "0.23.0"

// The last TypeScript release's published image: a migration starts from
// that image only, by its registry digest (decision 20). The digest is
// filled in when 0.23.0 is published (the release's Step 7 items); while
// it is empty this varlatch refuses to migrate.
const (
	LastTypeScriptRepository = "ghcr.io/varlatch/varlatchd"
	LastTypeScriptDigest     = ""
)

// imagePin is the image a migration starts from: the constants above, or
// the tests' own.
type imagePin struct {
	Repository, Digest string
}

// testPin replaces the constants in a crashpoint build only (G5's
// interruption gate, crashpoint.go); nil in a release.
var testPin *imagePin

// Source is the old installation, driven as processes (go-step7 decision
// 2): its CLI's commands inside its containers, and its host CLI. A
// Source never opens a database itself.
type Source interface {
	// Discover finds the installation and says what it runs.
	Discover(ctx context.Context) (SourceInfo, error)
	// Gate is the installation's maintenance gate now (nil for none).
	Gate(ctx context.Context) (*Gate, error)
	// RootKEK is the text of its Root KEK file. The caller clears it.
	RootKEK() ([]byte, error)
	// Backup makes a fresh backup and uploads it; VerifyBackup downloads
	// it and verifies it.
	Backup(ctx context.Context) (archiveID string, err error)
	VerifyBackup(ctx context.Context, archiveID string) error
	// Barrier opens (or continues) the migration barrier and waits for
	// the drain, at most drain.
	Barrier(ctx context.Context, drain time.Duration) (BarrierRecord, error)
	// Export writes the source bundle (a dry run's from a snapshot of
	// the running installation), its digests keyed by runKey, given on
	// a pipe; the bundle's path on this host.
	Export(ctx context.Context, runKey []byte, dryRun bool) (string, error)
	// Release lifts the barrier; MarkMigratedOut turns it into the
	// permanent migrated-out gate.
	Release(ctx context.Context, gateID string) error
	MarkMigratedOut(ctx context.Context, gateID string) error
	// Dir is the directory the source's journal is written in.
	Dir() string
	// CleanLeftovers removes what a run killed before it could clean up
	// left of the source's on this host (the bundles), by their exact
	// names only.
	CleanLeftovers() error
	// Ingress is what the source's address is served by: its public URL
	// and, by shape, what serves it here.
	Ingress(ctx context.Context) (IngressInfo, error)
	// StopIngress and StartIngress stop and start what serves the
	// address (Caddy for public ingress, the dashboard's port for an own
	// proxy); the Coolify shape has nothing here to stop or start.
	StopIngress(ctx context.Context, kind Ingress) error
	StartIngress(ctx context.Context, kind Ingress) error
}

// Ingress is a source's ingress shape (decision 12).
type Ingress string

// The shapes.
const (
	Public  Ingress = "public"  // the installation's Caddy terminates HTTPS on 80 and 443; varlatchd's own ACME takes over
	Proxy   Ingress = "proxy"   // the operator's reverse proxy targets the dashboard's loopback port; varlatchd binds it
	Coolify Ingress = "coolify" // Coolify's proxy routes the domain by application: the operator moves it, at the prompt
)

// Ingresses are the shapes.
var Ingresses = []Ingress{Public, Proxy, Coolify}

// IngressInfo is a source's: its public URL (the origin people open, the
// passkeys' RP ID its host), whether its Caddy runs, and the dashboard's
// address on this host.
type IngressInfo struct {
	PublicURL  string
	Caddy      bool
	WebAddress string
}

// SourceInfo is what a migration starts from.
type SourceInfo struct {
	Kind    string `json:"kind"` // "compose"
	Dir     string `json:"dir"`
	Release string `json:"release"`
	Image   string `json:"image"`
	Digest  string `json:"digest"`
	// DigestRepository is the repository the digest is the registry's
	// for (the image's own: Discover takes no other's).
	DigestRepository string `json:"digestRepository"`
}

// Gate is a source's maintenance gate.
type Gate struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Target is the new installation, through `varlatchd admin migrate`.
type Target interface {
	// Describe is the target's state: its data directory, whether it
	// holds a database, and its journal's id and phase.
	Describe(ctx context.Context) (TargetInfo, TargetState, error)
	// Keys writes the source's keys into the target's key files (or
	// finds them the same); each is given on a pipe.
	Keys(ctx context.Context, rootKEK, bek []byte) (rootKEKState, bekState string, err error)
	// WriteJournal writes the journal in the data directory.
	WriteJournal(ctx context.Context, j *Journal) error
	// Import builds the target's database from a bundle; in scratch
	// (a directory of its own) for the dry run, else in the data
	// directory.
	Import(ctx context.Context, bundle, scratch string) (CopyRecord, error)
	// Check runs the checks against the bundle, runKey on a pipe.
	Check(ctx context.Context, bundle, scratch string, runKey []byte) (CheckSummary, error)
	// Discard removes the database migration id built in the data
	// directory (before the switch only).
	Discard(ctx context.Context, id string) error
	// Start and Stop start and stop the target's service: done, or, where
	// that is the operator's (an image's service), a *HumanStep unless it
	// is so already.
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	// OpenLive opens the running target: through its control socket, it
	// ends the transfer's gate and writes its journal open.
	OpenLive(ctx context.Context, id string) error
}

// HumanStep is a step only the operator takes (go-step7 decision 20: what
// needs Docker or Coolify is a human's): its exact instruction.
type HumanStep struct {
	Instruction string
}

func (h *HumanStep) Error() string { return h.Instruction }

// Prober asks a public URL which installation serves it: GET /v1/meta's
// installationId and serverVersion.
type Prober interface {
	Probe(ctx context.Context, publicURL string) (installationID, serverVersion string, err error)
}

// TargetInfo is the target, as the journal records it.
type TargetInfo struct {
	// Kind is "host" (a host install) or "image" (the image's service,
	// through its bind paths).
	Kind    string `json:"kind,omitempty"`
	Config  string `json:"config"`
	DataDir string `json:"dataDir"`
	// Release is the target's varlatchd's; PublicURL, Listen and
	// ListenHTTPS its configuration's.
	Release     string `json:"release"`
	PublicURL   string `json:"publicUrl"`
	Listen      string `json:"listen"`
	ListenHTTPS string `json:"listenHttps"`
	// Tailnet is its tailnet settings and node, nil when tailnet = off.
	Tailnet *TargetTailnet `json:"tailnet,omitempty"`
}

// TargetState is what the target holds: its journal's head (nil for
// none) and whether its data directory holds a database.
type TargetState struct {
	Journal  *JournalHead
	Database bool
	// Gate is whether the transfer's gate stands; Barrier a reverse's
	// barrier's phase ("" for none); Running whether the target's
	// varlatchd runs.
	Gate    bool
	Barrier string
	Running bool
}

// JournalHead is what the target's journal says.
type JournalHead struct {
	ID    string `json:"id"`
	Phase Phase  `json:"phase"`
	// WindowEnded is the upgrade that ended the rollback window on the Go
	// side, when one did.
	WindowEnded *WindowEndedRecord `json:"windowEnded,omitempty"`
}

// CheckSummary is a check run's outcome: passed, and per check whether it
// passed and how many it checked (the full report is varlatchd's).
type CheckSummary struct {
	Passed bool          `json:"passed"`
	Checks []CheckResult `json:"checks"`
	// Faults are the failing checks' first faults, as varlatchd names
	// them (tables, classes, ids; never a value).
	Faults []string `json:"faults,omitempty"`
}

// CheckResult is one check's.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Checked int64  `json:"checked"`
}
