// SPDX-License-Identifier: Apache-2.0

package tailcontrol_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
)

var ctx = context.Background()

func TestCanonical(t *testing.T) {
	for name, want := range map[string]bool{
		"vault": true, "vault-1": true, "a": true, "0": true, strings.Repeat("a", 63): true,
		"": false, "Vault": false, "-vault": false, "vault-": false, "vault.lan": false, "vault_1": false,
		"vaul t": false, "vaült": false, strings.Repeat("a", 64): false,
	} {
		if got := tailcontrol.Canonical(name); got != want {
			t.Errorf("Canonical(%q) = %v", name, got)
		}
	}
}

func TestTempName(t *testing.T) {
	op, err := tailcontrol.NewOperationID()
	if err != nil || len(op) != 10 || !tailcontrol.Canonical(op) || strings.Contains(op, "-") {
		t.Fatalf("operation id %q, %v", op, err)
	}
	n, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
	o, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleOld)
	if n != "vault-vl-"+op+"-n" || o != "vault-vl-"+op+"-o" {
		t.Errorf("%q %q", n, o)
	}
	// A long name is cut, the operation id and role kept, no hyphen left at the cut.
	long := strings.Repeat("a", 40) + "-" + strings.Repeat("b", 22)
	got, err := tailcontrol.TempName(long, op, tailcontrol.RoleOld)
	if err != nil || len(got) > tailcontrol.MaxNameLen || !tailcontrol.Canonical(got) || !strings.HasSuffix(got, "-vl-"+op+"-o") {
		t.Errorf("long name: %q (%d), %v", got, len(got), err)
	}
	cut := strings.Repeat("c", 47) + "-" + strings.Repeat("d", 15) // the cut lands just after the hyphen
	if got, err := tailcontrol.TempName(cut, op, tailcontrol.RoleNew); err != nil || strings.Contains(got, "--") || !tailcontrol.Canonical(got) {
		t.Errorf("cut at a hyphen: %q, %v", got, err)
	}
	for _, c := range []struct{ name, op, role string }{
		{"Vault", op, tailcontrol.RoleNew}, {"vault", "ABC", tailcontrol.RoleNew}, {"vault", "a-b", tailcontrol.RoleNew},
		{"vault", "", tailcontrol.RoleNew}, {"vault", op, "x"}, {"vault", strings.Repeat("a", 60), tailcontrol.RoleNew},
	} {
		if got, err := tailcontrol.TempName(c.name, c.op, c.role); err == nil {
			t.Errorf("TempName(%q, %q, %q) = %q", c.name, c.op, c.role, got)
		}
	}
}

func TestCheckNames(t *testing.T) {
	devices := []tailcontrol.Device{
		{ID: "1", Name: "vault", Online: true},
		{ID: "2", Name: "build", Online: true},
		{ID: "3", Name: "vault-vl-abc-o"},                // offline, holding a temporary name
		{ID: "4", Name: "VAULT-VL-DEF-N", Expired: true}, // expired, a case variant of one
	}
	ok := func(p tailcontrol.NamePlan) {
		t.Helper()
		if err := tailcontrol.CheckNames(devices, p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := func(p tailcontrol.NamePlan, want ...string) {
		t.Helper()
		err := tailcontrol.CheckNames(devices, p)
		if err == nil {
			t.Fatalf("%+v: accepted", p)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%+v: %v; want %q", p, err, w)
			}
		}
	}
	ok(tailcontrol.NamePlan{Name: "vault", Holder: "1", Temporary: []string{"vault-vl-xyz-n", "vault-vl-xyz-o"}})
	ok(tailcontrol.NamePlan{Name: "free", Temporary: []string{"free-vl-xyz-n"}})
	bad(tailcontrol.NamePlan{Name: "vault", Holder: "2"}, `held by vault (1, online)`, "expected holder 2 does not hold")
	bad(tailcontrol.NamePlan{Name: "build"}, `held by build (2, online), and no device may hold it`)
	bad(tailcontrol.NamePlan{Name: "vault", Holder: "1", Temporary: []string{"vault-vl-abc-o"}}, `held by vault-vl-abc-o (3, offline)`)
	bad(tailcontrol.NamePlan{Name: "vault", Holder: "1", Temporary: []string{"vault-vl-def-n"}}, `held by VAULT-VL-DEF-N (4, expired)`)
	bad(tailcontrol.NamePlan{Name: "Vault", Holder: "1"}, "not in canonical form")
	// A case variant beside the holder, held by another node: refused.
	withVariant := append(devices, tailcontrol.Device{ID: "5", Name: "Vault"})
	if err := tailcontrol.CheckNames(withVariant, tailcontrol.NamePlan{Name: "vault", Holder: "1"}); err == nil || !strings.Contains(err.Error(), "held by Vault (5, offline)") {
		t.Errorf("a case variant held by another node: %v", err)
	}
	// The expected holder with a case variant of the name: refused.
	variantHolder := []tailcontrol.Device{{ID: "1", Name: "VAULT", Online: true}}
	if err := tailcontrol.CheckNames(variantHolder, tailcontrol.NamePlan{Name: "vault", Holder: "1"}); err == nil || !strings.Contains(err.Error(), "only as a case variant") {
		t.Errorf("the holder's case variant: %v", err)
	}
}

func tailscaleOf(t *testing.T, f *tailcontroltest.Tailscale, secret string) *tailcontrol.Tailscale {
	t.Helper()
	ts, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: f.URL, ClientID: f.ClientID, ClientSecret: secret, HTTP: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestTailscaleListsRenamesAndReadsBack(t *testing.T) {
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "101", NodeID: "nOld1CNTRL", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "102", NodeID: "nNew2CNTRL", Name: "vault-vl-abc-n", Online: true},
		tailcontroltest.Node{ID: "103", NodeID: "nGone3CNTRL", Name: "gone", Expires: time.Now().Add(-time.Hour)},
	)
	defer f.Close()
	ts := tailscaleOf(t, f, f.ClientSecret)
	devices, err := ts.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 3 || devices[0].Name != "vault" || devices[0].NodeID != "nOld1CNTRL" || !devices[0].Online || devices[0].Expired ||
		!devices[2].Expired || devices[2].Online {
		t.Fatalf("devices %+v", devices)
	}
	// The swap's two renames, each read back.
	if _, err := tailcontrol.RenameAndReadBack(ctx, ts, "101", "vault-vl-abc-o"); err != nil {
		t.Fatal(err)
	}
	d, err := tailcontrol.RenameAndReadBack(ctx, ts, "102", "vault")
	if err != nil || d.Name != "vault" || d.NodeID != "nNew2CNTRL" {
		t.Fatalf("%+v, %v", d, err)
	}
	// Every operation made a token of its own and used it once.
	if f.Exchanges != 5 {
		t.Errorf("%d token exchanges for 5 operations", f.Exchanges)
	}
	for _, n := range f.Used {
		if n != 1 {
			t.Errorf("a token was used %d times", n)
		}
	}
}

// A listing's time is Tailscale's, from its answer's Date header.
func TestTailscaleListingIsDated(t *testing.T) {
	f := tailcontroltest.NewTailscale(tailcontroltest.Node{ID: "1", NodeID: "n1", Name: "vault"})
	defer f.Close()
	ts, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: f.URL, ClientID: f.ClientID, ClientSecret: f.ClientSecret, HTTP: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	devices, at, err := ts.DevicesAt(ctx)
	if err != nil || len(devices) != 1 || at.IsZero() || time.Since(at).Abs() > time.Minute {
		t.Fatalf("%+v at %v, %v", devices, at, err)
	}
}

func TestTailscaleRefusals(t *testing.T) {
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "101", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "102", Name: "vault-new", Online: true},
	)
	defer f.Close()
	f.EchoCredentials = true
	ts := tailscaleOf(t, f, f.ClientSecret)
	secretFree := func(err error) {
		t.Helper()
		if err == nil {
			t.Fatal("no error")
		}
		for tok := range f.Used {
			if strings.Contains(err.Error(), tok) {
				t.Errorf("the error quotes a token: %v", err)
			}
		}
		if strings.Contains(err.Error(), f.ClientSecret) {
			t.Errorf("the error quotes the client secret: %v", err)
		}
	}
	// A name another device holds: refused, named, no credential quoted.
	_, err := tailcontrol.RenameAndReadBack(ctx, ts, "102", "vault")
	secretFree(err)
	var op *tailcontrol.OpError
	if !errors.As(err, &op) || op.Op != "rename" || op.Device != "102" || !errors.Is(err, tailcontrol.ErrNameTaken) {
		t.Errorf("taken: %v", err)
	}
	// A rename applied otherwise than asked: the read-back fails.
	f.RewriteRename = func(s string) string { return s + "-1" }
	_, err = tailcontrol.RenameAndReadBack(ctx, ts, "102", "vault-x")
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &rb) || rb.Want != "vault-x" || rb.Got != "vault-x-1" || !strings.Contains(err.Error(), "read back 102") {
		t.Errorf("read back: %v", err)
	}
	f.RewriteRename = nil
	// A name not in canonical form is never sent.
	if _, err := tailcontrol.RenameAndReadBack(ctx, ts, "102", "Vault"); err == nil || f.Nodes()[1].Name != "vault-x-1" {
		t.Errorf("a non-canonical name: %v, %+v", err, f.Nodes())
	}
	// A wrong secret: refused, the secret not quoted although the server echoes it.
	wrongSecret := f.ClientSecret + "x"
	_, err = tailscaleOf(t, f, wrongSecret).Devices(ctx)
	secretFree(err)
	if err == nil || strings.Contains(err.Error(), wrongSecret) || !strings.Contains(err.Error(), "list devices") {
		t.Errorf("a wrong secret: %v", err)
	}
	// A scope the control plane fills with the request's credentials: refused,
	// and quoted scrubbed.
	f.EchoScope = true
	before := len(f.Used)
	_, err = ts.Devices(ctx)
	if err == nil || strings.Contains(err.Error(), f.ClientSecret) || strings.Contains(err.Error(), "tskey-api-") ||
		!strings.Contains(err.Error(), "devices:core scope and no other") || !strings.Contains(err.Error(), "[redacted]") || len(f.Used) != before {
		t.Errorf("an echoed scope: %v", err)
	}
	f.EchoScope = false
	// A client with more than devices:core, or without it: refused before any use.
	for _, scope := range []string{"devices:core auth_keys", "all", "devices:core:read", ""} {
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

func headscaleOf(t *testing.T, f *tailcontroltest.Headscale, key string) *tailcontrol.HeadscaleAPI {
	t.Helper()
	hs, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{BaseURL: f.URL, APIKey: key, HTTP: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestHeadscaleAPI(t *testing.T) {
	f := tailcontroltest.NewHeadscale(50*time.Minute,
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
		tailcontroltest.Node{ID: "3", Name: "old", Expires: time.Now().Add(-time.Minute)},
	)
	defer f.Close()
	hs := headscaleOf(t, f, f.Key)
	if _, err := hs.Devices(ctx); err == nil || !strings.Contains(err.Error(), "not checked") {
		t.Errorf("before Open: %v", err)
	}
	if err := hs.Open(ctx); err != nil {
		t.Fatal(err)
	}
	devices, err := hs.Devices(ctx)
	if err != nil || len(devices) != 3 || devices[0].Name != "vault" || !devices[0].Online || devices[0].Expired || !devices[2].Expired {
		t.Fatalf("%+v, %v", devices, err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, hs, "1", "vault-vl-abc-o"); err != nil {
		t.Fatal(err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, hs, "2", "vault"); err != nil {
		t.Fatal(err)
	}
	// The exact name of another node: refused.
	if _, err := tailcontrol.RenameAndReadBack(ctx, hs, "3", "vault"); !errors.Is(err, tailcontrol.ErrNameTaken) || strings.Contains(err.Error(), f.Key) {
		t.Errorf("taken: %v", err)
	}
	// Headscale keeps a case variant beside the name (set here outside
	// tailcontrol, which never asks for one); CheckNames is what catches it,
	// before any rename.
	if err := hs.Rename(ctx, "3", "VAULT"); err == nil || !strings.Contains(err.Error(), "not in canonical form") {
		t.Errorf("tailcontrol asked for a case variant: %v", err)
	}
	variant := tailcontroltest.NewHeadscale(50*time.Minute,
		tailcontroltest.Node{ID: "2", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "3", Name: "VAULT", Expires: time.Now().Add(-time.Minute)},
	)
	defer variant.Close()
	vh := headscaleOf(t, variant, variant.Key)
	if err := vh.Open(ctx); err != nil {
		t.Fatal(err)
	}
	now, _ := vh.Devices(ctx)
	if err := tailcontrol.CheckNames(now, tailcontrol.NamePlan{Name: "vault", Holder: "2"}); err == nil || !strings.Contains(err.Error(), "held by VAULT (3, expired)") {
		t.Errorf("the case variant: %v", err)
	}
	// Close expires the key; nothing works with it after.
	if err := hs.Close(ctx); err != nil || !f.KeyExpired() {
		t.Fatalf("close: %v, expired %v", err, f.KeyExpired())
	}
	if err := hs.Close(ctx); err != nil {
		t.Errorf("closing twice: %v", err)
	}
	again := headscaleOf(t, f, f.Key)
	if err := again.Open(ctx); err == nil || strings.Contains(err.Error(), f.Key) {
		t.Errorf("an expired key: %v", err)
	}
}

// An earlier Headscale's keys (<prefix>.<secret>, listed by their plain
// prefix, expired by it) work as 0.28's masked ones do.
func TestHeadscaleAPILegacyKeys(t *testing.T) {
	f := tailcontroltest.NewHeadscaleLegacy(50*time.Minute, tailcontroltest.Node{ID: "1", Name: "vault", Online: true})
	defer f.Close()
	hs := headscaleOf(t, f, f.Key)
	if err := hs.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if devices, err := hs.Devices(ctx); err != nil || len(devices) != 1 {
		t.Fatalf("%+v, %v", devices, err)
	}
	if err := hs.Close(ctx); err != nil || !f.KeyExpired() {
		t.Fatalf("close: %v, expired %v", err, f.KeyExpired())
	}
}

// Headscale's timestamps: RFC 3339 from its API, protobuf Timestamps from
// its CLI's JSON (0.29.7), null or the zero time or the epoch when unset.
func TestHeadscaleTimestamps(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		json     string
		lastSeen time.Time
		expired  bool
	}{
		{`{"id":"1","given_name":"vault","last_seen":{"seconds":1795262400,"nanos":5},"expiry":null}`, time.Unix(1795262400, 5).UTC(), false},
		{`{"id":1,"given_name":"vault","last_seen":null,"expiry":{"seconds":0}}`, time.Time{}, false},
		{`{"id":1,"given_name":"vault","expiry":{"seconds":1700000000}}`, time.Time{}, true},
		{`{"id":"1","givenName":"vault","lastSeen":"2026-11-21T11:59:00Z","expiry":"0001-01-01T00:00:00Z"}`, time.Date(2026, 11, 21, 11, 59, 0, 0, time.UTC), false},
		{`{"id":"1","givenName":"vault","lastSeen":"0001-01-01T00:00:00Z"}`, time.Time{}, false},
	} {
		out := "[" + c.json + "]"
		cli := &tailcontrol.HeadscaleCLI{Run: func(context.Context, ...string) ([]byte, error) { return []byte(out), nil }, Now: func() time.Time { return now }}
		devices, err := cli.Devices(ctx)
		if err != nil || len(devices) != 1 || !devices[0].LastSeen.Equal(c.lastSeen) || devices[0].Expired != c.expired {
			t.Errorf("%s: %+v %v", c.json, devices, err)
		}
	}
}

func TestHeadscaleAPIKeyMustExpireWithinTheHour(t *testing.T) {
	for _, life := range []time.Duration{2 * time.Hour, 90 * 24 * time.Hour} {
		f := tailcontroltest.NewHeadscale(life, tailcontroltest.Node{ID: "1", Name: "vault"})
		err := headscaleOf(t, f, f.Key).Open(ctx)
		f.Close()
		if err == nil || !strings.Contains(err.Error(), "more than an hour from now") || strings.Contains(err.Error(), f.Key) {
			t.Errorf("a key living %v: %v", life, err)
		}
	}
	f := tailcontroltest.NewHeadscale(time.Hour, tailcontroltest.Node{ID: "1", Name: "vault"})
	defer f.Close()
	if err := headscaleOf(t, f, f.Key).Open(ctx); err != nil {
		t.Errorf("a key of an hour: %v", err)
	}
	// A key the server does not list (another server's), and a wrong key: refused.
	wrongKey := "zzzz" + f.Key[4:]
	if err := headscaleOf(t, f, wrongKey).Open(ctx); err == nil || strings.Contains(err.Error(), wrongKey) {
		t.Errorf("a wrong key: %v", err)
	}
}

func TestHeadscaleCLI(t *testing.T) {
	f := tailcontroltest.NewHeadscale(time.Hour,
		tailcontroltest.Node{ID: "7", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "8", Name: "vault-vl-abc-n"},
	)
	defer f.Close()
	cli := &tailcontrol.HeadscaleCLI{Run: f.Run}
	devices, err := cli.Devices(ctx)
	if err != nil || len(devices) != 2 || devices[0].ID != "7" || devices[0].Name != "vault" || !devices[0].Online || devices[1].Online {
		t.Fatalf("%+v, %v", devices, err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, cli, "7", "vault-vl-abc-o"); err != nil {
		t.Fatal(err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, cli, "8", "vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, cli, "7", "vault"); !errors.Is(err, tailcontrol.ErrNameTaken) || !strings.Contains(err.Error(), "rename 7") {
		t.Errorf("taken: %v", err)
	}
	if err := cli.Rename(ctx, "seven", "x"); err == nil || !strings.Contains(err.Error(), "is a number") {
		t.Errorf("a non-numeric id: %v", err)
	}
	// A name that would read as an option is not canonical, and never sent.
	for _, name := range []string{"--help", "-x", "Vault"} {
		if err := cli.Rename(ctx, "7", name); err == nil || !strings.Contains(err.Error(), "not in canonical form") {
			t.Errorf("%q: %v", name, err)
		}
	}
	// The binary, when named, is an absolute path to an executable file.
	for _, bin := range []string{"headscale", "./headscale", "/nonexistent/headscale", t.TempDir()} {
		if err := (&tailcontrol.HeadscaleCLI{Binary: bin}).Validate(); err == nil {
			t.Errorf("binary %q accepted", bin)
		}
	}
	if err := (&tailcontrol.HeadscaleCLI{}).Validate(); err != nil {
		t.Errorf("PATH's headscale: %v", err)
	}
}

func TestOnlyHTTPS(t *testing.T) {
	for _, base := range []string{"http://api.tailscale.example", "ftp://x", "api.tailscale.com", "https://"} {
		if _, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: base, ClientID: "id", ClientSecret: "secret-value", HTTP: &http.Client{}}); err == nil {
			t.Errorf("Tailscale at %q accepted", base)
		}
		if _, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{BaseURL: base, APIKey: "key-value", HTTP: &http.Client{}}); err == nil {
			t.Errorf("Headscale at %q accepted", base)
		}
	}
	if _, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{APIKey: "key-value", HTTP: &http.Client{}}); err == nil {
		t.Error("Headscale without a URL accepted")
	}
	if _, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{ClientID: "id", ClientSecret: "secret-value", HTTP: &http.Client{}}); err != nil {
		t.Errorf("Tailscale's own API: %v", err)
	}
	// No http.Client: refused, never a default one (the outbound guard).
	if _, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{ClientID: "id", ClientSecret: "secret-value"}); err == nil || !strings.Contains(err.Error(), "no http.Client") {
		t.Errorf("Tailscale without a client: %v", err)
	}
	if _, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{BaseURL: "https://hs.example", APIKey: "key-value"}); err == nil || !strings.Contains(err.Error(), "no http.Client") {
		t.Errorf("Headscale without a client: %v", err)
	}
}

// TestPrintingHoldsNoCredential: a control plane, or its configuration,
// printed in every way fmt prints, even as an unexported field of another
// struct, shows no credential.
func TestPrintingHoldsNoCredential(t *testing.T) {
	const secret, key = "client-secret-for-printing", "api-key-for-printing"
	tcfg := tailcontrol.TailscaleConfig{BaseURL: "https://ts.example", ClientID: "id", ClientSecret: secret, HTTP: &http.Client{}}
	hcfg := tailcontrol.HeadscaleAPIConfig{BaseURL: "https://hs.example", APIKey: key, HTTP: &http.Client{}}
	ts, err := tailcontrol.NewTailscale(tcfg)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := tailcontrol.NewHeadscaleAPI(hcfg)
	if err != nil {
		t.Fatal(err)
	}
	type holder struct {
		ts  *tailcontrol.Tailscale
		hs  *tailcontrol.HeadscaleAPI
		tsv tailcontrol.Tailscale
		hsv tailcontrol.HeadscaleAPI
	}
	h := holder{ts, hs, *ts, *hs}
	for _, v := range []any{ts, hs, *ts, *hs, h, &h, tcfg, hcfg, &tcfg, &hcfg} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, secret) || strings.Contains(out, key) {
				t.Errorf("%s of %T: %s", verb, v, out)
			}
		}
	}
}

// TestConfigsMarshalNoCredential: a configuration marshalled as JSON (logged,
// journaled) holds no credential.
func TestConfigsMarshalNoCredential(t *testing.T) {
	const secret, key = "client-secret-for-json", "api-key-for-json"
	for _, v := range []any{
		tailcontrol.TailscaleConfig{BaseURL: "https://ts.example", ClientID: "id", ClientSecret: secret},
		&tailcontrol.TailscaleConfig{ClientSecret: secret},
		tailcontrol.HeadscaleAPIConfig{BaseURL: "https://hs.example", APIKey: key},
		&tailcontrol.HeadscaleAPIConfig{APIKey: key},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%T: %v", v, err)
		}
		if strings.Contains(string(b), secret) || strings.Contains(string(b), key) {
			t.Errorf("%T: %s", v, b)
		}
	}
}

func TestReadBackIsRetriedOnce(t *testing.T) {
	defer func(d time.Duration) { tailcontrol.ReadBackRetry = d }(tailcontrol.ReadBackRetry)
	tailcontrol.ReadBackRetry = 10 * time.Millisecond
	f := tailcontroltest.NewTailscale(tailcontroltest.Node{ID: "1", Name: "vault", Online: true})
	defer f.Close()
	f.LagRenames = true
	ts := tailscaleOf(t, f, f.ClientSecret)
	if d, err := tailcontrol.RenameAndReadBack(ctx, ts, "1", "vault-vl-abc-o"); err != nil || d.Name != "vault-vl-abc-o" {
		t.Fatalf("a rename shown on the second reading: %+v, %v", d, err)
	}
	// A rename that never shows is still a failure, after the one retry.
	f.LagRenames = false
	f.RewriteRename = func(s string) string { return s + "-1" }
	_, err := tailcontrol.RenameAndReadBack(ctx, ts, "1", "vault")
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &rb) || rb.Got != "vault-1" {
		t.Errorf("a rename never shown: %v", err)
	}
	// A context ended while waiting to read again: the read-back fails with both causes.
	f.RewriteRename = nil
	f.LagRenames = true
	tailcontrol.ReadBackRetry = time.Hour
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := tailcontrol.RenameAndReadBack(short, ts, "1", "vault-x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the deadline while waiting: %v", err)
	}
}
