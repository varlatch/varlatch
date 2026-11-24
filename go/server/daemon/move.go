// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/write"
)

// The host commands of moving an installation (ADR-0059 step 6, slice 6.9,
// decision 13; issue #103), which `varlatch move` and `varlatch admin
// reenroll` run:
//
//	varlatchd admin reenroll (--all | --identity <id>...) [--hours <1-168>] [--json]
//	varlatchd admin public-url-changed --from <the previous public URL>
//	varlatchd admin move-facts
//	varlatchd admin config check
//
// reenroll and public-url-changed write, through the daemon's socket, else
// offline under the lock (control.go); move-facts reads the same way;
// config check reads the configuration file only. The links reenroll
// prints are its standard output and nothing else: never logged, never in
// an audit event (only their expiry), never in the move's journal.

const (
	reenrollUsage         = "Usage: varlatchd admin reenroll (--all | --identity <id> ...) [--hours <1-168>] [--json]"
	publicURLChangedUsage = "Usage: varlatchd admin public-url-changed --from <the previous public URL>"
	moveFactsUsage        = "Usage: varlatchd admin move-facts"
	configCheckUsage      = "Usage: varlatchd admin config check"
)

// isMoveCommand is whether sub is one of the commands above that run
// through the socket (config check never does).
func isMoveCommand(sub string) bool {
	return sub == "reenroll" || sub == "public-url-changed" || sub == "move-facts"
}

type reenrollArgs struct {
	all   bool
	ids   []string
	hours int
	json  bool
}

// parseReenroll checks reenroll's arguments: "" when well formed.
func parseReenroll(rest []string) (reenrollArgs, string) {
	var a reenrollArgs
	for i := 0; i < len(rest); i++ {
		switch f := rest[i]; {
		case f == "--all" && !a.all:
			a.all = true
		case f == "--json" && !a.json:
			a.json = true
		case f == "--identity" && i+1 < len(rest) && rest[i+1] != "":
			a.ids = append(a.ids, rest[i+1])
			i++
		case f == "--hours" && a.hours == 0 && i+1 < len(rest):
			h, err := strconv.Atoi(rest[i+1])
			if err != nil || h < 1 || h > int(auth.ReenrollTTLMax/time.Hour) {
				return a, reenrollUsage + " (--hours: a whole number of hours from 1 to 168)"
			}
			a.hours = h
			i++
		default:
			return a, reenrollUsage
		}
	}
	if a.all == (len(a.ids) > 0) {
		return a, reenrollUsage
	}
	return a, ""
}

// parsePublicURLChanged checks public-url-changed's arguments.
func parsePublicURLChanged(rest []string) (string, string) {
	if len(rest) != 2 || rest[0] != "--from" {
		return "", publicURLChangedUsage
	}
	u, err := parseHTTPURL(rest[1])
	if err != nil {
		return "", publicURLChangedUsage
	}
	return u, ""
}

func parseHTTPURL(raw string) (string, error) {
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return "", fmt.Errorf("not an http(s) URL")
	}
	return raw, nil
}

// moveUsage is a move command's usage error ("" when its arguments are
// well formed), checked before anything is sent or opened.
func moveUsage(sub string, rest []string) string {
	switch sub {
	case "reenroll":
		_, msg := parseReenroll(rest)
		return msg
	case "public-url-changed":
		_, msg := parsePublicURLChanged(rest)
		return msg
	case "move-facts":
		if len(rest) != 0 {
			return moveFactsUsage
		}
	}
	return ""
}

type reenrollLink struct {
	IdentityID        string `json:"identityId"`
	Name              string `json:"name"`
	InstallationAdmin bool   `json:"installationAdmin"`
	Link              string `json:"link"`
	ExpiresAt         string `json:"expiresAt"`
}

// runMoveCommand runs reenroll, public-url-changed or move-facts with env,
// in the daemon or offline.
func runMoveCommand(ctx context.Context, env *hostEnv, sub string, rest []string, stdout, stderr io.Writer) int {
	what := "varlatchd admin " + sub
	fail := func(err error) int {
		fmt.Fprintf(stderr, "%s: %s\n", what, err.Error())
		return ExitFailure
	}
	svc := auth.New(env.store, auth.Options{PublicURL: env.cfg.PublicURL})
	switch sub {
	case "move-facts":
		facts, err := svc.MoveFacts(ctx)
		if err != nil {
			return fail(err)
		}
		var publicURL *string
		if env.cfg.PublicURL != nil {
			s := strings.TrimSuffix(env.cfg.PublicURL.String(), "/")
			publicURL = &s
		}
		return printJSON(stdout, stderr, what, struct {
			PublicURL *string `json:"publicUrl"`
			auth.MoveFacts
		}{publicURL, facts})

	case "public-url-changed":
		from, _ := parsePublicURLChanged(rest)
		if env.cfg.PublicURL == nil {
			fmt.Fprintf(stderr, "%s: varlatchd.conf sets no public_url; set the new public URL and restart varlatchd first\n", what)
			return ExitConfig
		}
		// Every person exclusive, in id order, before their passkeys and
		// sessions go, as the TypeScript code locks them.
		people, err := svc.PeopleIDs(ctx)
		if err != nil {
			return fail(err)
		}
		gates := make([]write.Gate, len(people))
		for i, id := range people {
			gates[i] = write.Person(id, write.Exclusive)
		}
		ctx, release, err := env.gates.Acquire(ctx, gates...)
		if err != nil {
			return fail(err)
		}
		defer release()
		done, err := svc.CompletePublicURLChange(ctx, from, env.cfg.PublicURL.String())
		if err != nil {
			return fail(err)
		}
		return printJSON(stdout, stderr, what, map[string]any{
			"from": done.From, "to": done.To, "passkeysRemoved": done.PasskeysRemoved,
			"sessionsEnded": done.SessionsEnded, "browserCredentialsRevoked": done.BrowserCredentialsRevoked,
		})

	case "reenroll":
		a, _ := parseReenroll(rest)
		// The people shared (every one with --all), as recovery takes its
		// subject: a link waits for a change that holds a person (a
		// retirement) to end.
		subjects := a.ids
		if a.all {
			var err error
			if subjects, err = svc.PeopleIDs(ctx); err != nil {
				return fail(err)
			}
		}
		var gates []write.Gate
		for _, id := range subjects {
			gates = append(gates, write.Person(id, write.Shared))
		}
		if len(gates) > 0 {
			var release func()
			var err error
			if ctx, release, err = env.gates.Acquire(ctx, gates...); err != nil {
				return fail(err)
			}
			defer release()
		}
		in := auth.Reenroll{All: a.all, IdentityIDs: a.ids, TTL: time.Duration(a.hours) * time.Hour}
		grants, err := svc.IssueReenrollmentGrants(ctx, in)
		if err != nil {
			return fail(err)
		}
		base := issuer(env.cfg)
		links := make([]reenrollLink, len(grants))
		for i, g := range grants {
			links[i] = reenrollLink{IdentityID: g.IdentityID, Name: g.Name, InstallationAdmin: g.InstallationAdmin, Link: base + "/enroll#" + g.Token, ExpiresAt: auth.ISO(g.ExpiresAt)}
		}
		if a.json {
			return printJSON(stdout, stderr, what, map[string]any{"links": links})
		}
		var b strings.Builder
		b.WriteString("One-time re-enrollment links. Each adds a passkey to that person's existing identity;\n")
		b.WriteString("send each only to its person, over a channel you trust:\n")
		for _, l := range links {
			admin := ""
			if l.InstallationAdmin {
				admin = " (Installation Admin)"
			}
			fmt.Fprintf(&b, "  %s%s [%s]\n    %s\n", l.Name, admin, l.IdentityID, l.Link)
		}
		expires := "-"
		if len(links) > 0 {
			expires = links[0].ExpiresAt
		}
		fmt.Fprintf(&b, "Expire: %s.\n", expires)
		_, _ = io.WriteString(stdout, b.String())
		return ExitOK
	}
	return adminUsage(stderr, "unknown command "+sub)
}

// configFacts are what `admin config check` reports of a configuration:
// what `varlatch move` reads and checks, without parsing the file itself.
type configFacts struct {
	PublicURL *string `json:"publicUrl"`
	// Ingress is how browsers reach the installation (go/README.md, "The
	// ingress modes side by side"): "public" (listen_https), "local"
	// (public_url on this machine, or none), else "external" (a proxy).
	Ingress     string  `json:"ingress"`
	Listen      string  `json:"listen"`
	ListenHTTPS *string `json:"listenHttps"`
	Tailnet     bool    `json:"tailnet"`
	DataDir     string  `json:"dataDir"`
	// ActsAsOwner is actsAsOwner (privileges.go).
	ActsAsOwner bool `json:"actsAsOwner"`
}

// runConfigCheck is `admin config check`: the configuration file parsed
// (an invalid one already refused with 78), and its facts as JSON.
func runConfigCheck(cfg *config.Config, stdout, stderr io.Writer) int {
	f := configFacts{Listen: cfg.Listen, Tailnet: cfg.Tailnet != nil, DataDir: cfg.DataDir, Ingress: "local", ActsAsOwner: actsAsOwner}
	if cfg.PublicURL != nil {
		s := strings.TrimSuffix(cfg.PublicURL.String(), "/")
		f.PublicURL = &s
		host := cfg.PublicURL.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && !strings.HasSuffix(host, ".localhost") && (ip == nil || !ip.IsLoopback()) {
			f.Ingress = "external"
		}
	}
	if cfg.PublicHTTPS != nil {
		f.Ingress = "public"
		l := cfg.PublicHTTPS.Listen
		f.ListenHTTPS = &l
	}
	b, err := json.Marshal(f)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin config check: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}
