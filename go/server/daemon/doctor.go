// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/custody"
	"github.com/varlatch/varlatch/go/server/doctor"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

const doctorUsage = "Usage: varlatchd admin doctor [--json] [--config <file>]"

// doctorArgs checks `admin doctor`'s arguments (--config taken out): only
// --json; --live is the daemon's own form, never given by a person.
func doctorArgs(rest []string) (asJSON bool, msg string) {
	for _, a := range rest {
		switch a {
		case "--json":
			asJSON = true
		default:
			return false, doctorUsage
		}
	}
	return asJSON, ""
}

// runDoctor is `varlatchd admin doctor` (step 6, slice 6.5): the host's
// checks, read by this process, and the server's, which the running
// varlatchd answers on its control socket (`doctor --live`). Without a
// running varlatchd the server's checks are unknown: doctor never takes
// the data directory's lock and never opens the database. It writes
// nothing. Exit 1 when a mandatory check fails.
func runDoctor(cfg *config.Config, path string, asJSON bool, stdout, stderr io.Writer) int {
	ctx := context.Background()
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	r := doctor.Run(ctx, doctor.Inputs{Config: cfg, ConfigPath: path, Live: doctorLive(cfg, stderr)})
	if asJSON {
		b, err := json.Marshal(r)
		if err != nil {
			fmt.Fprintf(stderr, "varlatchd admin doctor: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		writeDoctorText(stdout, r)
	}
	if r.Failed() {
		return ExitFailure
	}
	return ExitOK
}

// writeDoctorText is doctor's report as text: one line a check, with what
// was seen and what to do.
func writeDoctorText(w io.Writer, r doctor.Report) {
	fmt.Fprintf(w, "varlatchd %s, schema %d, data directory %s (%s)\n", r.Facts.ServerVersion, r.Facts.SchemaVersion, r.Facts.DataDir,
		map[string]string{"daemon": "the running varlatchd answered", "offline": "no running varlatchd answered"}[r.Via])
	for _, c := range r.Checks {
		mark := map[string]string{doctor.Pass: "PASS   ", doctor.Fail: "FAIL   ", doctor.Unknown: "UNKNOWN"}[c.Status]
		fmt.Fprintf(w, "%s %s: %s", mark, c.ID, c.Title)
		if c.Class == doctor.Advisory {
			fmt.Fprint(w, " (advisory)")
		}
		fmt.Fprintln(w)
		if c.Detail != "" {
			fmt.Fprintf(w, "        %s\n", c.Detail)
		}
		if c.Remedy != "" && c.Status != doctor.Pass {
			fmt.Fprintf(w, "        to do: %s\n", c.Remedy)
		}
	}
}

// doctorLive asks the running varlatchd for what only it knows, through
// its control socket; nil when none answers (nothing else is tried: no
// lock, no database).
func doctorLive(cfg *config.Config, stderr io.Writer) *doctor.Live {
	owner, _, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return nil
	}
	conn, err := net.DialTimeout("unix", filepath.Join(cfg.DataDir, ControlSocket), 5*time.Second)
	if err != nil {
		return nil
	}
	uc := conn.(*net.UnixConn)
	if peer, ok := peerUID(uc); !ok || !serverPeerAllowed(peer, owner) {
		_ = uc.Close()
		fmt.Fprintf(stderr, "varlatchd admin doctor: the process on the control socket is not the data directory's owner (uid %d) or root; it was not asked\n", owner)
		return nil
	}
	var out, said bytes.Buffer
	if viaSocket(uc, "varlatchd admin doctor", []string{"doctor", "--live"}, &out, &said) != ExitOK {
		return nil
	}
	var live doctor.Live
	if json.Unmarshal(out.Bytes(), &live) != nil {
		return nil
	}
	return &live
}

// runDoctorLive is the daemon's answer to `doctor --live`: readiness, the
// storage engine's metrics, public HTTPS's and the tailnet's state, and
// the custody attestations. It reads only.
func runDoctorLive(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	if len(rest) != 1 || rest[0] != "--live" || env.store == nil {
		fmt.Fprintln(stderr, doctorUsage)
		return 64
	}
	b := &backend{store: env.store, rootKEK: env.rootKEK}
	live := doctor.Live{Storage: env.store.Metrics(), WALBound: env.store.Settings().WALBound}
	live.Schema, live.KEK, live.Installation = b.Ready(ctx)
	if live.Installation {
		live.InstallationID, _ = b.InstallationID(ctx)
	}
	if env.admission != nil {
		live.Maintenance = env.admission.Isolated()
	}
	if env.public != nil {
		live.Public = json.RawMessage(jsvalue.Stringify(env.public.Report()))
	}
	if env.tailnet != nil {
		live.Tailnet, live.TailnetClosed = true, env.tailnet.Closed()
	}
	if st, err := custody.StatusOf(ctx, env.store.Reader()); err != nil {
		live.CustodyError = err.Error()
	} else {
		live.Custody = &st
	}
	enc, err := json.Marshal(live)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin doctor: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(enc))
	return ExitOK
}
