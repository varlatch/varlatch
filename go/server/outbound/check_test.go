// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

// destinationsDB is a database with configured destinations: acme's
// webhooks and a Coolify Connection, beta's webhook, a revoked one and a
// deleted Organization's.
func destinationsDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		for _, q := range []string{
			`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}'), ('org_b', 'beta', 'Beta', '{}')`,
			`INSERT INTO organizations (id, slug, name, deleted_at, org_kek_destroyed_at) VALUES ('org_g', 'gone', 'Gone', 1, 1)`,
			`INSERT INTO webhooks (id, organization_id, url, secret_envelope, created_at, cursor_occurred_at) VALUES
				('whk_1', 'org_a', 'https://public.test/x', '{}', 1, 0),
				('whk_2', 'org_a', 'https://private.test/x', '{}', 2, 0),
				('whk_3', 'org_a', 'https://private.test:8443/y', '{}', 3, 0),
				('whk_4', 'org_a', 'https://10.0.0.9/z', '{}', 4, 0),
				('whk_5', 'org_a', 'https://meta.test/m', '{}', 5, 0),
				('whk_6', 'org_a', 'https://missing.test/m', '{}', 6, 0),
				('whk_7', 'org_b', 'https://private.test/b', '{}', 7, 0),
				('whk_8', 'org_g', 'https://private.test/g', '{}', 8, 0)`,
			`INSERT INTO webhooks (id, organization_id, url, secret_envelope, created_at, cursor_occurred_at, revoked_at) VALUES ('whk_9', 'org_a', 'https://private.test/r', '{}', 9, 0, 10)`,
			`INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES ('pcn_1', 'org_a', 'coolify', 'https://private.test', 'Lab', '{}')`,
			// GitHub Connections: RunCheck leaves them out, CheckGitHub lists the live ones.
			`INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES
				('pcn_g1', 'org_a', 'github-actions', 'acme', 'Acme on GitHub', '{}'),
				('pcn_g2', 'org_b', 'github-actions', 'beta', 'Beta on GitHub', '{}'),
				('pcn_g3', 'org_g', 'github-actions', 'gone', 'Gone', '{}')`,
			`INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, revoked_at) VALUES ('pcn_g4', 'org_a', 'github-actions', 'old', 'Old', '{}', 1)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return store.Reader()
}

func checkDNS() *fakeDNS {
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("public.test", v4("93.184.216.34"))
	dns.set("private.test", v4("10.0.0.1"))
	dns.set("meta.test", v4("169.254.169.254"))
	return dns
}

// The check's report, as net/outbound-check.ts makes it: the verdicts in
// the rows' order (webhooks, then Connections), every name resolved once
// per scan, the suggestion for the names a hostname entry opens and why the
// others are left out, and the exit code.
func TestRunCheck(t *testing.T) {
	reader := destinationsDB(t)
	dns := checkDNS()
	p := New(nil, Options{Resolve: dns.resolve})
	now := func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) }
	r, err := p.RunCheck(context.Background(), reader, "", now)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range r.Destinations {
		got = append(got, d.ID+" "+d.Verdict+" "+string(d.Reason)+d.Error)
	}
	want := []string{
		"whk_1 public ", "whk_2 refused private_address", "whk_3 refused private_address", "whk_4 refused private_address",
		"whk_5 refused host_only_address", "whk_6 unresolved ENOTFOUND", "whk_7 refused private_address", "pcn_1 refused private_address",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("destinations:\n%q\nwant\n%q", got, want)
	}
	if dns.count("private.test") != 1 {
		t.Errorf("private.test was resolved %d times in one scan", dns.count("private.test"))
	}
	if r.Suggested == nil || *r.Suggested != "private.test,private.test:8443" || r.ExitCode != 1 || r.CheckedAt != "2026-11-16T12:00:00.000Z" {
		t.Errorf("suggested %v, exit %d, at %s", r.Suggested, r.ExitCode, r.CheckedAt)
	}
	if len(r.Apart) != 2 || !strings.HasPrefix(r.Apart[0].Why, "a literal private address: only a CIDR entry opens it, such as 10.0.0.9/32;") ||
		!strings.HasPrefix(r.Apart[1].Why, "resolves to a loopback, link-local") {
		t.Errorf("apart %+v", r.Apart)
	}
	lines := strings.Join(r.Lines(), "\n")
	for _, s := range []string{
		"VARLATCH_OUTBOUND_ALLOW: (not set)",
		"acme  webhook  whk_1  https://public.test:443  [93.184.216.34]  public",
		"acme  Coolify  pcn_1 \"Lab\"  https://private.test:443  [10.0.0.1]  REFUSED (private_address)",
		"acme  webhook  whk_6  https://missing.test:443  [-]  not resolved (ENOTFOUND)",
		"Suggested (then restart varlatchd):\n  VARLATCH_OUTBOUND_ALLOW=private.test,private.test:8443",
		"Not suggested, decide yourself:\n  10.0.0.9:443 (webhook whk_4): a literal private address",
	} {
		if !strings.Contains(lines, s) {
			t.Errorf("the lines lack %q:\n%s", s, lines)
		}
	}
	// One Organization (by slug), and an allow list that opens it.
	entries, _ := ParseAllow("private.test,private.test:8443,10.0.0.9/32")
	r, _ = New(entries, Options{Resolve: dns.resolve}).RunCheck(context.Background(), reader, "acme", now)
	if len(r.Destinations) != 7 || r.Suggested != nil || r.ExitCode != 1 || len(r.Apart) != 1 {
		t.Errorf("acme with an allow list: %d destinations, suggested %v, exit %d, apart %v", len(r.Destinations), r.Suggested, r.ExitCode, r.Apart)
	}
	if !strings.Contains(strings.Join(r.Lines(), "\n"), "allowed by private.test") {
		t.Errorf("%s", strings.Join(r.Lines(), "\n"))
	}
	// Nothing configured: exit 0, and the line that says so.
	if r, _ := p.RunCheck(context.Background(), nil, "", now); r.ExitCode != 0 || !strings.Contains(strings.Join(r.Lines(), "\n"), "No destinations configured.") {
		t.Errorf("no database: %+v", r)
	}
}

// The GitHub Connections' destination, GitHub's API, checked as the
// others are: every live Connection's, one Organization's with org, and
// refused when the name resolves to a private address.
func TestCheckGitHub(t *testing.T) {
	reader := destinationsDB(t)
	dns := checkDNS()
	dns.set("api.github.com", v4("140.82.121.6"))
	p := New(nil, Options{Resolve: dns.resolve})
	got, err := p.CheckGitHub(context.Background(), reader, "")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range got {
		ids = append(ids, d.Organization+" "+d.ID+" "+string(d.Kind)+" "+d.Scheme+"://"+d.Host+":"+strconv.Itoa(d.Port)+" "+d.Verdict)
	}
	if want := "acme pcn_g1 github https://api.github.com:443 public|beta pcn_g2 github https://api.github.com:443 public"; strings.Join(ids, "|") != want {
		t.Errorf("GitHub destinations %q, want %q", ids, want)
	}
	if got, _ := p.CheckGitHub(context.Background(), reader, "beta"); len(got) != 1 || got[0].ID != "pcn_g2" {
		t.Errorf("beta: %+v", got)
	}
	r := Report{Destinations: got}
	if lines := strings.Join(r.Lines(), "\n"); !strings.Contains(lines, `acme  GitHub  pcn_g1 "Acme on GitHub"  https://api.github.com:443  [140.82.121.6]  public`) {
		t.Errorf("the lines:\n%s", lines)
	}
	dns.set("api.github.com", v4("10.1.2.3"))
	if got, _ := New(nil, Options{Resolve: dns.resolve}).CheckGitHub(context.Background(), reader, "acme"); len(got) != 1 || got[0].Verdict != "refused" || got[0].Reason != "private_address" {
		t.Errorf("a private answer: %+v", got)
	}
	if got, err := p.CheckGitHub(context.Background(), nil, ""); err != nil || len(got) != 0 {
		t.Errorf("no database: %v %v", got, err)
	}
}

// The report names the setting as its caller says, with its suggestion.
func TestReportLinesFor(t *testing.T) {
	v := "private.test"
	r := Report{Suggested: &v}
	s := Setting{Name: "outbound_allow (/etc/varlatchd.conf)", Suggest: func(v string) []string { return []string{"Set:", "  outbound_allow = " + v} }}
	lines := strings.Join(r.LinesFor(s), "\n")
	if !strings.HasPrefix(lines, "outbound_allow (/etc/varlatchd.conf): (not set)\n") || !strings.HasSuffix(lines, "\n\nSet:\n  outbound_allow = private.test") ||
		strings.Contains(lines, "VARLATCH_OUTBOUND_ALLOW") {
		t.Errorf("the lines:\n%s", lines)
	}
}

// A page's scan is shared while it runs and reused for ScanTTL; concurrent
// lookups of one name share one.
func TestSharedCheck(t *testing.T) {
	reader := destinationsDB(t)
	var lookups atomic.Int64
	release := make(chan struct{})
	dns := checkDNS()
	slow := func(ctx context.Context, name string) ([]Answer, error) {
		lookups.Add(1)
		<-release
		return dns.resolve(ctx, name)
	}
	p := New(nil, Options{Resolve: slow})
	var mu sync.Mutex
	clock := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	var wg sync.WaitGroup
	reports := make([]Report, 5)
	for i := range reports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i], _ = p.SharedCheck(context.Background(), reader, "", now)
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	// One scan: each name once (public, private, meta, missing).
	if n := lookups.Load(); n != 4 {
		t.Errorf("%d lookups for five concurrent pages", n)
	}
	for _, r := range reports {
		if len(r.Destinations) != 8 {
			t.Fatalf("a shared report: %d destinations", len(r.Destinations))
		}
	}
	p.SharedCheck(context.Background(), reader, "", now)
	if lookups.Load() != 4 {
		t.Error("a scan within its TTL was not reused")
	}
	mu.Lock()
	clock = clock.Add(ScanTTL)
	mu.Unlock()
	p.SharedCheck(context.Background(), reader, "", now)
	if lookups.Load() != 8 {
		t.Errorf("after the TTL: %d lookups", lookups.Load())
	}
	// Another Organization is another scan.
	p.SharedCheck(context.Background(), reader, "beta", now)
	if lookups.Load() != 9 {
		t.Errorf("beta's scan: %d lookups", lookups.Load())
	}
}
