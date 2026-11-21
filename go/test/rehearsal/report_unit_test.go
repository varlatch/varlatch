// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"strings"
	"testing"
	"time"
)

func TestReportAndFailureRedaction(t *testing.T) {
	// Reset global report and secret state after this unit test so it never
	// affects other tests in the package.
	report.Lock()
	savedMeas := report.Measurements
	savedDiff := report.Differences
	report.Measurements = nil
	report.Differences = nil
	report.Unlock()
	secrets.Lock()
	savedSecrets := append([]string(nil), secrets.values...)
	secrets.values = nil
	secrets.Unlock()
	t.Cleanup(func() {
		report.Lock()
		report.Measurements = savedMeas
		report.Differences = savedDiff
		report.Unlock()
		secrets.Lock()
		secrets.values = savedSecrets
		secrets.Unlock()
	})

	regSecret := secret("rh-registered-" + strings.Repeat("7", 12))
	tok := "vlt_" + "cli_" + strings.Repeat("ab", 10)
	hexKey := strings.Repeat("deadbeef", 8)

	measure("migrate's stdout", "output "+regSecret+" token="+tok+" key="+hexKey)
	report.Lock()
	gotMeas := report.Measurements["migrate's stdout"]
	report.Unlock()
	for _, leak := range []string{regSecret, tok, hexKey} {
		if strings.Contains(gotMeas, leak) {
			t.Errorf("measure() leaked %q into report.Measurements: %q", leak, gotMeas)
		}
	}
	if !strings.Contains(gotMeas, "[redacted]") || !strings.Contains(gotMeas, "[token]") || !strings.Contains(gotMeas, "deadbeef[...]") {
		t.Errorf("measure() did not apply expected redaction markers: %q", gotMeas)
	}

	differs(1, "stand-in "+regSecret, "real "+tok, "bearing "+hexKey)
	report.Lock()
	gotDiff := report.Differences[len(report.Differences)-1]
	report.Unlock()
	if strings.Contains(gotDiff.StandIn, regSecret) || strings.Contains(gotDiff.Real, tok) || strings.Contains(gotDiff.Bearing, hexKey) {
		t.Errorf("differs() leaked a secret: %+v", gotDiff)
	}

	r := ran{
		code:   1,
		stdout: "line1\ncredential: " + tok + "\nsecret: " + regSecret,
		stderr: "boom with " + tok + " and " + hexKey,
		took:   42 * time.Millisecond,
	}
	if s := r.String(); strings.Contains(s, tok) || strings.Contains(s, hexKey) {
		t.Errorf("ran.String() leaked secret/token: %q", s)
	}
	msg := formatFailure("bootstrap", r)
	for _, leak := range []string{regSecret, tok, hexKey} {
		if strings.Contains(msg, leak) {
			t.Errorf("formatFailure() leaked %q into test.log output: %q", leak, msg)
		}
	}
}
