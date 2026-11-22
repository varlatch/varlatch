// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// killPoints are VL_RH_KILL's names for the crashpoint build's pauses
// (cmd/varlatch/internal/migrate/crashpoint.go).
var killPoints = map[string]string{"barrier": "barrier held", "transfer": "transfer started"}

// killCase (VL_RH_KILL): a migration killed (SIGKILL) where the
// crashpoint build pauses, then --status and --abort, on a fresh
// installation (B6: the archive restored again): the source must answer
// again as it was.
func killCase(t *testing.T, rel release, s3 *s3Server) {
	const item = 12
	point := killPoints[prof.kill]
	in := newSource(t, rel, s3, "kill-"+prof.kill)
	registerSecrets(in)
	log := filepath.Join(in.state, "crashpoints.log")
	cmd := exec.Command(filepath.Join(binDir, "varlatch"), in.migrateArgs()...)
	cmd.Dir = in.dir
	cmd.Env = append(os.Environ(), in.migrateEnvVars(rel, true, rel.pin())...)
	cmd.Env = append(cmd.Env, "VARLATCH_MIGRATE_LOG="+log, "VARLATCH_MIGRATE_PAUSE="+point)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reached := false
	for deadline := time.Now().Add(10 * time.Minute); time.Now().Before(deadline) && !reached; time.Sleep(50 * time.Millisecond) {
		if b, _ := os.ReadFile(log); bytes.Contains(b, []byte("paused "+point+"\n")) {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-done
			reached = true
		}
		select {
		case err := <-done:
			if !reached {
				record(t, item, "killed at "+point, false, fmt.Sprintf("migrate ended (%v) before pausing there: %s", err, lastLines(out.String(), 4)))
				return
			}
		default:
		}
	}
	if !reached {
		_ = cmd.Process.Kill()
		<-done
	}
	record(t, item, "killed at "+point, reached, lastLines(out.String(), 3))
	if !reached {
		return
	}
	st := run(in.dir, in.migrateEnvVars(rel, true, rel.pin()), nil, filepath.Join(binDir, "varlatch"), "migrate", "--status", "--from", in.dir)
	measure(fmt.Sprintf("item %d: --status after the kill at %s", item, point), lastLines(st.stdout, 3))
	ab := in.migrateEnv(rel, true, rel.pin(), "--abort")
	record(t, item, "--abort after the kill", ab.code == 0, ab.String())
	code, body := in.get("/v1/meta")
	record(t, item, "the source answers as it was", code == 200 && strings.Contains(body, `"serverVersion":"0.23.0"`) && strings.Contains(body, in.installationID), fmt.Sprintf("%d %s", code, trim(body)))
}
