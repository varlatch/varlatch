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
// crashpoint build pauses, twice, each on a fresh installation (B6: the
// archive restored again): once then --abort, after which the source must
// answer again as it was, and once then --resume, which at the barrier
// undoes and at the transfer goes on to open.
func killCase(t *testing.T, rel release, s3 *s3Server) {
	t.Run("abort", func(t *testing.T) { killThenAbort(t, rel, s3) })
	t.Run("resume", func(t *testing.T) { killThenResume(t, rel, s3) })
}

const killItem = 12

// killedAt runs a migration of in and kills it at the point, on a
// recorded check. It says whether it was killed there.
func killedAt(t *testing.T, in *installation, rel release, what string) bool {
	t.Helper()
	point := killPoints[prof.kill]
	log := filepath.Join(in.state, "crashpoints.log")
	cmd := exec.Command(filepath.Join(binDir, "varlatch"), in.migrateArgs()...)
	cmd.Dir = in.dir
	cmd.Env = append(os.Environ(), in.migrateEnvVars(rel, true, rel.pin())...)
	cmd.Env = append(cmd.Env, "VARLATCH_MIGRATE_LOG="+log, "VARLATCH_MIGRATE_PAUSE="+point)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	began := time.Now()
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
				record(t, killItem, what+"killed at "+point, false, fmt.Sprintf("migrate ended (%v) before pausing there: %s", err, lastLines(out.String(), 4)))
				return false
			}
		default:
		}
	}
	if !reached {
		_ = cmd.Process.Kill()
		<-done
	}
	measureSteps(in.dir, cmd.Path, cmd.Args[1:], out.String(), time.Since(began))
	record(t, killItem, what+"killed at "+point, reached, lastLines(out.String(), 3))
	if o := out.String(); strings.Contains(o, "panic:") || strings.Contains(o, "goroutine ") {
		measure(fmt.Sprintf("item %d: %smigrate's output before the kill at %s (a stack in it)", killItem, what, point), lastLines(o, 60))
	}
	if !reached {
		return false
	}
	st := run(in.dir, in.migrateEnvVars(rel, true, rel.pin()), nil, filepath.Join(binDir, "varlatch"), "migrate", "--status", "--from", in.dir)
	measure(fmt.Sprintf("item %d: %s--status after the kill at %s", killItem, what, point), lastLines(st.stdout, 3))
	return true
}

func killThenAbort(t *testing.T, rel release, s3 *s3Server) {
	in := newSource(t, rel, s3, "kill-"+prof.kill)
	registerSecrets(in)
	if !killedAt(t, in, rel, "") {
		return
	}
	ab := in.migrateEnv(rel, true, rel.pin(), "--abort")
	record(t, killItem, "--abort after the kill", ab.code == 0, ab.String())
	measure(fmt.Sprintf("item %d: --abort after the kill", killItem), ab.took.Round(time.Millisecond).String())
	code, body := in.get("/v1/meta")
	record(t, killItem, "the source answers as it was", sourceAnswers(in.installationID)(code, body), fmt.Sprintf("%d %s", code, trim(body)))
	if prof.kill == "transfer" {
		// The target ran: what its stop took of --abort's time.
		in.recordStops(t, killItem, "--abort after the kill")
	}
}

// killThenResume is the other way on from the same kill: --resume. On a
// restored archive the CLI reads before the kill, and must read the same
// after it.
func killThenResume(t *testing.T, rel release, s3 *s3Server) {
	const what = "for --resume: "
	in := newSource(t, rel, s3, "resume-"+prof.kill)
	registerSecrets(in)
	var rd *reader
	var before reads
	if prof.restore != "" {
		if rd = newReader(t, in); rd == nil {
			return
		}
		var err error
		if before, err = rd.read(); !record2(t, killItem, what+"the CLI reads the source", err == nil, rd.describe(before, err)) {
			return
		}
	}
	if !killedAt(t, in, rel, what) {
		return
	}
	re := in.migrateEnv(rel, true, rel.pin(), "--resume")
	measure(fmt.Sprintf("item %d: --resume after the kill", killItem), re.took.Round(time.Millisecond).String()+" "+lastLines(re.stdout, 4))
	phase := fmt.Sprint(in.journal()["phase"])
	code, body := in.get("/v1/meta")
	if prof.kill == "barrier" {
		// Nothing had moved: it is undone, and said as a failure.
		record(t, killItem, "--resume undoes a migration killed at the barrier", re.code != 0 && strings.Contains(re.stderr, "reopened unchanged") && phase == "released",
			fmt.Sprintf("%s; phase %s", re.String(), phase))
		record(t, killItem, "after --resume the source answers as it was", sourceAnswers(in.installationID)(code, body), fmt.Sprintf("%d %s", code, trim(body)))
	} else {
		record(t, killItem, "--resume opens a migration killed in the transfer", re.code == 0 && phase == "open", fmt.Sprintf("%s; phase %s", re.String(), phase))
		record(t, killItem, "after --resume the public URL answers from the target",
			code == 200 && strings.Contains(body, in.installationID) && !strings.Contains(body, `"serverVersion":"0.23.0"`), fmt.Sprintf("%d %s", code, trim(body)))
		ready := in.inside(`fetch("http://127.0.0.1:8686/readyz").then(async r => console.log(r.status, await r.text())).catch(e => console.log("error", e.message))`)
		record(t, killItem, "after --resume the source's /readyz says migrated-out", strings.Contains(ready.stdout, "migrated-out"), trim(ready.stdout))
		if re.code != 0 {
			return
		}
	}
	if rd == nil {
		return
	}
	where := "the source"
	if prof.kill == "barrier" {
		isolated, detail := in.isolatedRunning()
		record(t, killItem, "after --resume the copy reaches nothing", isolated, detail)
	} else {
		where = "Go"
		forwardParity(t, in, "--resume after the kill")
		isolated, detail := in.goRunsIsolated(rd)
		record(t, killItem, "after --resume Go runs with sync and the audit export off", isolated, detail)
	}
	got, err := rd.read()
	record(t, killItem, "after --resume the CLI reads the same on "+where, err == nil && sameReads(before, got), rd.compare(before, got, err))
	in.memoryLogs(t, rd)
}
