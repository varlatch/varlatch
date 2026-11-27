// SPDX-License-Identifier: Apache-2.0

package tailcontrol_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
)

// A policy file as an operator writes it: HuJSON, with comments and
// trailing commas.
const hujsonPolicy = `{
	// The tailnet's own names.
	"hosts": {
		"vault":   "100.64.0.10", // an alias equal to the machine name
		"Build-Box": "100.64.0.11",
	},
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["vault:443"]},
	],
}`

// The policy file is read only with the OAuth client's optional
// policy_file:read scope; without it nothing is requested, and the error
// says the file is unreadable, never that it has no alias.
func TestTailscalePolicyHosts(t *testing.T) {
	f := tailcontroltest.NewTailscale(tailcontroltest.Node{ID: "1", Name: "vault", Online: true})
	defer f.Close()
	f.Policy = hujsonPolicy
	ts := tailscaleOf(t, f, f.ClientSecret)
	var _ tailcontrol.PolicyReader = ts

	// devices:core only (the documented client): unreadable, no read sent.
	hosts, err := ts.PolicyHosts(ctx)
	if !errors.Is(err, tailcontrol.ErrPolicyNoScope) || !errors.Is(err, tailcontrol.ErrPolicyUnreadable) || hosts != nil || f.PolicyReads != 0 {
		t.Fatalf("without the scope: %v, %v, %d reads", hosts, err, f.PolicyReads)
	}
	if !strings.Contains(err.Error(), "policy_file:read") {
		t.Errorf("the error does not name the scope: %v", err)
	}

	// With the scope: the aliases, read from HuJSON; the devices still list.
	f.Scope = "devices:core policy_file:read"
	hosts, err = ts.PolicyHosts(ctx)
	if err != nil || !slices.Equal(hosts, []string{"Build-Box", "vault"}) || f.PolicyReads != 1 {
		t.Fatalf("with the scope: %v, %v, %d reads", hosts, err, f.PolicyReads)
	}
	if d, err := ts.Devices(ctx); err != nil || len(d) != 1 {
		t.Fatalf("devices with the extra scope: %v, %v", d, err)
	}
	if alias, ok := tailcontrol.PolicyAlias(hosts, "build-box"); !ok || alias != "Build-Box" {
		t.Errorf("PolicyAlias is not case-insensitive: %q, %v", alias, ok)
	}
	if _, ok := tailcontrol.PolicyAlias(hosts, "vault-1"); ok {
		t.Error("PolicyAlias matched another name")
	}

	// A policy file without hosts: none.
	f.Policy = `{"acls": [], /* none */}`
	if hosts, err := ts.PolicyHosts(ctx); err != nil || len(hosts) != 0 {
		t.Fatalf("no hosts: %v, %v", hosts, err)
	}

	// The API refuses the read although the token has the scope: unreadable.
	f.PolicyForbidden = true
	if _, err := ts.PolicyHosts(ctx); !errors.Is(err, tailcontrol.ErrPolicyUnreadable) || errors.Is(err, tailcontrol.ErrPolicyNoScope) || !strings.Contains(err.Error(), "although the OAuth client has the policy_file:read scope") {
		t.Errorf("a 403: %v", err)
	}
	f.PolicyForbidden = false

	// An answer that is not a policy file: an error, not "unreadable".
	f.Policy = `{"hosts": [`
	if _, err := ts.PolicyHosts(ctx); err == nil || errors.Is(err, tailcontrol.ErrPolicyUnreadable) {
		t.Errorf("a broken policy file: %v", err)
	}

	// policy_file:read is the one extra scope allowed: write access, or the
	// read scope alone, is refused before any use.
	for _, scope := range []string{"devices:core policy_file", "policy_file:read", "devices:core policy_file:read auth_keys", "devices:core devices:core", "devices:core policy_file:read policy_file:read"} {
		f.Scope = scope
		before := len(f.Used)
		if _, err := ts.Devices(ctx); err == nil || !strings.Contains(err.Error(), "devices:core scope and no other") {
			t.Errorf("scope %q: %v", scope, err)
		}
		if len(f.Used) != before {
			t.Errorf("scope %q: the token was used", scope)
		}
	}
}

// A name the tailnet policy file defines is never given out (2026-11-27):
// once the budget is spent with no device listed under the name, the
// failure says the likely cause and the fix.
func TestRenameReleasedNamesThePolicyFile(t *testing.T) {
	shortRelease(t, 150*time.Millisecond)
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	f.SetBlocked("vault")
	ts := tailscaleOf(t, f, f.ClientSecret)
	if _, err := tailcontrol.RenameReleased(ctx, ts, "1", "vault-vl-abc-o", nil); err != nil {
		t.Fatal(err)
	}
	_, err := tailcontrol.RenameReleased(ctx, ts, "2", "vault", nil)
	var un *tailcontrol.UnreleasedError
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &un) || !un.Unlisted || un.Name != "vault" || !errors.As(err, &rb) || rb.Got != "vault-1" {
		t.Fatalf("not an unreleased, unlisted name: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"did not release", `no device is listed under "vault"`, "policy file", `hosts alias "vault"`, "rename that alias"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "\u2014") {
		t.Errorf("an em dash: %s", msg)
	}
	// A name another device lists is that device's, said as before: no
	// word of the policy file.
	f.SetBlocked()
	_, err = tailcontrol.RenameReleased(ctx, ts, "1", "vault-1", nil)
	if err == nil || strings.Contains(err.Error(), "policy file") {
		t.Errorf("a listed holder: %v", err)
	}
}
