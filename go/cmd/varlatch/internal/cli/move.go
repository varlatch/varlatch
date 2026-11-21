// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Moving a Go installation to another public URL (ADR-0059 step 6, slice
// 6.9, decision 13; issue #103; the TypeScript CLI's move.ts and setup's
// move steps): `varlatch move` and `varlatch admin reenroll`. The public
// URL is the passkeys' relying party, so a move is a re-enrollment event:
// an archive first (the way back), then the new public_url in
// varlatchd.conf and varlatchd restarted, the new name's certificate
// (public ingress), the old address's passkeys removed (`varlatchd admin
// public-url-changed`, once), and one re-enrollment link per person
// (`varlatchd admin reenroll`), shown on the terminal only. The tailnet
// node is never touched: a move to the tailnet ingress is refused.
//
// The links are the one thing a move prints that is a credential: each
// lets whoever holds it add a passkey to that person's identity. They are
// printed by showReenrollLinks alone (the fail-safe shows exactly that
// link's token), never written to the move's journal, and never printed in
// assisted mode, where a coding agent reads the output.

const moveUsage = `Usage:
  varlatch move --public-url <url> [--ingress public|external] [--listen-https <address>] [--reenroll-hours <1-168>]
                [--yes] [--no-wait] [--config <file>]  # another public URL: archive, move, re-enrollment links
  varlatch move [--no-wait] [--config <file>]           # finish the move in progress
  varlatch move --abandon [--config <file>]             # give up an open move: back to the old address
               (a Go installation's, on its host, as root: varlatchd.conf (default /etc/varlatch/varlatchd.conf)
                gets the new public_url and varlatchd.service is restarted. A Compose installation's move is the
                TypeScript CLI's, varlatch-ts)`

// MoveHelp is moveUsage, for the transcripts' accepted difference.
const MoveHelp = moveUsage

// defaultConfig is a host install's varlatchd.conf.
const defaultConfig = "/etc/varlatch/varlatchd.conf"

// moveJournal is the move's journal, beside varlatchd.conf: where an
// interrupted move stands, so a rerun neither takes a second archive nor
// removes passkeys people enrolled at the new address in between. Never a
// link or a key: addresses, the archive's path, times, and the
// configuration before and after (key file paths, no key).
const moveJournal = "move.json"

// Timing of a move's waits; variables for the tests.
var (
	moveReadyTimeout  = 2 * time.Minute
	moveCertTimeout   = 5 * time.Minute
	moveEnrollTimeout = 30 * time.Minute
	movePoll          = 2 * time.Second
)

type moveState struct {
	From        string `json:"from"`
	FromIngress string `json:"fromIngress"`
	To          string `json:"to"`
	ToIngress   string `json:"toIngress"`
	Archive     string `json:"archive"`
	StartedAt   string `json:"startedAt"`
	// PasskeysRetiredAt is set once the old address's passkeys were
	// removed; LinksIssuedAt once the re-enrollment links were printed.
	PasskeysRetiredAt string `json:"passkeysRetiredAt,omitempty"`
	LinksIssuedAt     string `json:"linksIssuedAt,omitempty"`
	// PreviousConfig is varlatchd.conf before the move (for --abandon),
	// Config after it.
	PreviousConfig string `json:"previousConfig"`
	Config         string `json:"config"`
}

// confFacts are `varlatchd admin config check`'s answer.
type confFacts struct {
	PublicURL   *string `json:"publicUrl"`
	Ingress     string  `json:"ingress"`
	Listen      string  `json:"listen"`
	ListenHTTPS *string `json:"listenHttps"`
	Tailnet     bool    `json:"tailnet"`
}

type moveFacts struct {
	PublicURL          *string `json:"publicUrl"`
	People             int     `json:"people"`
	InstallationAdmins int     `json:"installationAdmins"`
	AdminsWithPasskey  int     `json:"adminsWithPasskey"`
	Passkeys           int     `json:"passkeys"`
	Sessions           int     `json:"sessions"`
	TailnetConstraints int     `json:"tailnetConstraints"`
	PendingInvitations int     `json:"pendingInvitations"`
}

type reenrollLink struct {
	IdentityID        string `json:"identityId"`
	Name              string `json:"name"`
	InstallationAdmin bool   `json:"installationAdmin"`
	Link              string `json:"link"`
	ExpiresAt         string `json:"expiresAt"`
}

// moveFail ends a move with message, nothing changed unless it says so.
func moveFail(message string, code int) error { return Fail("varlatch move: "+message, code) }

// varlatchdJSON runs `varlatchd args... --config config` for a move and
// parses its JSON answer into v; a failure shows varlatchd's own lines and
// ends the command with its status.
func (r *Run) varlatchdJSON(prefix string, args []string, config string, v any) error {
	answer, said, code, err := r.varlatchd(prefix, args, config)
	if err != nil {
		return err
	}
	if code != 0 {
		return r.varlatchdEnded(prefix, said, code)
	}
	if err := json.Unmarshal(bytes.TrimSpace(answer), v); err != nil {
		return Fail(prefix+": varlatchd answered "+strings.Join(args[:2], " ")+" with no JSON document; is it the same release as this varlatch?", ExitFailure)
	}
	return nil
}

// linkPattern is a re-enrollment link as varlatchd prints it: the public
// URL, /enroll#, and the grant's token.
var linkPattern = regexp.MustCompile(`^https?://[^\s#/]+(/[^\s#]*)?/enroll#(vlt_reenroll_[A-Za-z0-9_-]+)$`)

// showReenrollLinks prints the links, each with its person (the only
// writer that shows a re-enrollment token, one link per call), then when
// they expire.
func (r *Run) showReenrollLinks(links []reenrollLink, indent string) error {
	for _, l := range links {
		m := linkPattern.FindStringSubmatch(l.Link)
		if m == nil {
			return Fail("varlatch: varlatchd answered a re-enrollment link this varlatch does not recognise; nothing of it was printed", ExitFailure)
		}
		admin := ""
		if l.InstallationAdmin {
			admin = " (Installation Admin)"
		}
		if err := r.out(indent + Printable(l.Name) + admin + " [" + Printable(l.IdentityID) + "]\n"); err != nil {
			return err
		}
		if err := r.outShowing(indent+"  "+l.Link+"\n", m[2]); err != nil {
			return err
		}
	}
	expires := "-"
	if len(links) > 0 {
		expires = Printable(links[0].ExpiresAt)
	}
	return r.out(indent + "They expire " + expires + ". New ones: `varlatch admin reenroll --all` (revokes these).\n")
}

// notAssisted refuses a command that prints re-enrollment links in
// assisted mode: a coding agent reads the output, and a link adds a
// passkey to a person's identity.
func (r *Run) notAssisted(prefix string) error {
	if r.Assisted.On {
		return Fail(prefix+": not in assisted mode: it prints re-enrollment links, each of which adds a passkey to a person's identity, so a person runs it in a terminal; nothing was changed", ExitConfig)
	}
	return nil
}

const reenrollUsage = "Usage: varlatch admin reenroll (--all | --identity <id>...) [--hours <1-168>] [--config <file>]"

// reenrollCommand is `varlatch admin reenroll`: one-time links that add a
// passkey to existing people, issued by this host's varlatchd (host-exec
// authority, as recovery), each shown with its person.
func reenrollCommand(r *Run) error {
	if i := indexOf(r.Args, "--dir"); i >= 0 {
		return composeRefusal(r, "admin")
	}
	parsed, err := strictOptions("admin reenroll", r.Args[1:], OptionSpec{Values: []string{"--hours", "--config"}, Lists: []string{"--identity"}, Booleans: []string{"--all"}, OnceBooleans: true}, reenrollUsage)
	if err != nil {
		return err
	}
	ids := parsed.Lists["--identity"]
	if parsed.Has("--all") == (len(ids) > 0) {
		return UsageOnly(reenrollUsage)
	}
	if err := r.notAssisted("varlatch admin reenroll"); err != nil {
		return err
	}
	args := []string{"admin", "reenroll", "--json"}
	if parsed.Has("--all") {
		args = append(args, "--all")
	}
	for _, id := range ids {
		args = append(args, "--identity", id)
	}
	if h, ok := parsed.Values["--hours"]; ok {
		args = append(args, "--hours", h)
	}
	var doc struct {
		Links []reenrollLink `json:"links"`
	}
	if err := r.varlatchdJSON("varlatch admin", args, parsed.Values["--config"], &doc); err != nil {
		return err
	}
	if err := r.out("One-time re-enrollment links. Each adds a passkey to that person's existing identity;\nsend each only to its person, over a channel you trust:\n"); err != nil {
		return err
	}
	return r.showReenrollLinks(doc.Links, "  ")
}

func indexOf(args []string, s string) int {
	for i, a := range args {
		if a == s {
			return i
		}
	}
	return -1
}

// movePartial is `move`'s partial (as admin's, hostadmin.go): a Go
// installation's move, every form of it; the TypeScript CLI's `--dir`
// names a Compose installation and is refused with the command to use.
func movePartial(r *Run) (bool, error) { return true, moveCommand(r) }

// moveCommand is `varlatch move`.
func moveCommand(r *Run) error {
	if indexOf(r.Args, "--dir") >= 0 {
		return UsageError("varlatch move: --dir names a Compose installation, which the Go CLI does not manage; run this with the TypeScript CLI, varlatch-ts, until `varlatch migrate` moves the installation (ADR-0059 step 7)")
	}
	parsed, err := strictOptions("move", r.Args, OptionSpec{
		Values:   []string{"--public-url", "--ingress", "--listen-https", "--reenroll-hours", "--config"},
		Booleans: []string{"--yes", "--no-wait", "--abandon"}, OnceBooleans: true,
	}, moveUsage)
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return moveFail("a Go installation runs on Linux; run this on its host", ExitUsage)
	}
	if err := r.notAssisted("varlatch move"); err != nil {
		return err
	}
	if r.Getenv("VARLATCH_IMAGE") != "" {
		return moveFail("in the container, a move is by hand: take an archive (varlatchd admin backup run), set the new public_url in the mounted varlatchd.conf and recreate the container, then run `varlatchd admin public-url-changed --from <the old URL>` and `varlatch admin reenroll --all` in it. Nothing was changed.", ExitUsage)
	}
	hours := 0
	if h, ok := parsed.Values["--reenroll-hours"]; ok {
		n, err := strconv.Atoi(h)
		if err != nil || n < 1 || n > 168 {
			return moveFail("--reenroll-hours must be a whole number of hours from 1 to 168. Nothing changed.", ExitUsage)
		}
		hours = n
	}
	config := defaultConfig
	if c, ok := parsed.Values["--config"]; ok {
		if config, err = filepath.Abs(c); err != nil {
			return moveFail(err.Error(), ExitUsage)
		}
	}
	m := &mover{r: r, config: config, journal: filepath.Join(filepath.Dir(config), moveJournal), hours: hours, wait: !parsed.Has("--no-wait")}
	state, err := m.readState()
	if err != nil {
		return err
	}
	if parsed.Has("--abandon") {
		for name := range parsed.Values {
			if name != "--config" {
				return UsageOnly(moveUsage)
			}
		}
		if parsed.Has("--yes") || parsed.Has("--no-wait") {
			return UsageOnly(moveUsage)
		}
		return m.abandon(state)
	}
	if state == nil {
		if state, err = m.start(parsed); err != nil || state == nil {
			return err
		}
	} else if err := m.resume(state, parsed); err != nil {
		return err
	}
	return m.finish(state)
}

type mover struct {
	r       *Run
	config  string
	journal string
	hours   int
	wait    bool
}

func (m *mover) say(line string) error { return m.r.out(line + "\n") }

func (m *mover) readState() (*moveState, error) {
	raw, err := os.ReadFile(m.journal)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, moveFail("cannot read "+m.journal+": "+err.Error()+"; run this as root (sudo varlatch move ...)", ExitConfig)
	}
	var s moveState
	if json.Unmarshal(raw, &s) != nil || s.From == "" || s.To == "" || s.Config == "" {
		return nil, moveFail(m.journal+" is unreadable, so the move's progress is unknown. Nothing was changed. It records the configuration before the move (\"previousConfig\") and after it (\"config\"): put the one varlatchd should run in varlatchd.conf and restart varlatchd, then remove it; rerun `varlatch move` only with a readable journal.", ExitFailure)
	}
	return &s, nil
}

func (m *mover) writeState(s *moveState) error {
	raw, _ := json.MarshalIndent(s, "", "  ")
	if err := writeFileAtomic(m.journal, append(raw, '\n'), 0o600); err != nil {
		return moveFail("cannot write "+m.journal+": "+err.Error(), ExitFailure)
	}
	return nil
}

// facts is `varlatchd admin config check` of path.
func (m *mover) facts(path string) (confFacts, error) {
	var f confFacts
	err := m.r.varlatchdJSON("varlatch move", []string{"admin", "config", "check"}, path, &f)
	return f, err
}

// target is where the move goes, validated, or why it cannot.
func target(cur confFacts, publicURL, ingress string) (string, string, error) {
	if ingress == "" {
		ingress = cur.Ingress
	}
	switch ingress {
	case "tailnet":
		return "", "", moveFail("moving to the tailnet ingress is not supported: the tailnet node keeps its own name and state. Move to the public or external ingress, or set up a new installation on the tailnet and restore an archive into it. Nothing changed.", ExitUsage)
	case "public", "external":
	case "local":
		return "", "", moveFail("this installation answers on this machine only (public_url names localhost): a move is to the public or external ingress; pass --ingress public or --ingress external. Nothing changed.", ExitUsage)
	default:
		return "", "", moveFail("--ingress must be one of public, external", ExitUsage)
	}
	if publicURL == "" {
		return "", "", moveFail("pass --public-url <the new address people will open>", ExitUsage)
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", "", moveFail("--public-url must be an https:// address with no path, such as https://vault.example.com", ExitUsage)
	}
	to := "https://" + strings.ToLower(u.Host)
	if strings.HasSuffix(to, ":443") {
		to = strings.TrimSuffix(to, ":443")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return "", "", moveFail("--public-url names an IP address, which browsers refuse as a passkey's relying party; use a host name", ExitUsage)
	}
	if cur.PublicURL != nil && to == *cur.PublicURL {
		if ingress == cur.Ingress {
			return "", "", moveFail("this installation already answers at "+to+" ("+ingress+" ingress): nothing to move.", ExitUsage)
		}
		return "", "", moveFail("the address stays "+to+": changing only the ingress is not a move (every passkey keeps working); change listen_https in varlatchd.conf and restart varlatchd instead.", ExitUsage)
	}
	return to, ingress, nil
}

// movedConfig is varlatchd.conf with the new public_url and, when the
// ingress changes, its listeners: to the public ingress, listen_https
// (listenHTTPS, :443 by default); to the external one, the public HTTPS
// settings taken out. Nothing of the tailnet is touched.
func movedConfig(text, to, fromIngress, toIngress, listenHTTPS string) string {
	out := setConfValue(text, "public_url", to)
	switch {
	case toIngress == "public" && fromIngress != "public":
		if listenHTTPS == "" {
			listenHTTPS = ":443"
		}
		out = setConfValue(out, "listen_https", listenHTTPS)
	case toIngress == "external" && fromIngress == "public":
		for _, key := range []string{"listen_https", "listen_http_redirect", "acme_email", "acme_ca", "acme_ca_root"} {
			out = unsetConfValue(out, key)
		}
	}
	return out
}

// confLine is the index of key's setting in lines ("key = value", not a
// comment), or -1.
func confLine(lines []string, key string) int {
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimPrefix(l, "\uFEFF"))
		if strings.HasPrefix(t, "#") {
			continue
		}
		if name, _, ok := strings.Cut(t, "="); ok && strings.TrimSpace(name) == key {
			return i
		}
	}
	return -1
}

func setConfValue(text, key, value string) string {
	lines := strings.Split(text, "\n")
	line := key + " = " + value
	if i := confLine(lines, key); i >= 0 {
		if strings.HasPrefix(lines[i], "\uFEFF") {
			line = "\uFEFF" + line
		}
		lines[i] = line
		return strings.Join(lines, "\n")
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text + line + "\n"
}

func unsetConfValue(text, key string) string {
	lines := strings.Split(text, "\n")
	for i := confLine(lines, key); i >= 0; i = confLine(lines, key) {
		lines = append(lines[:i], lines[i+1:]...)
	}
	return strings.Join(lines, "\n")
}

// writeFileAtomic replaces path with data: a file beside it, synced, then
// renamed over it, keeping the old file's owner when it had one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	old, statErr := os.Stat(path)
	if statErr == nil {
		mode = old.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".move-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if statErr == nil {
		keepOwner(tmp, old)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// start begins a new move: the target checked against the installation,
// the plan shown and confirmed, the archive taken, the new configuration
// checked by varlatchd, then the journal and the configuration written.
// nil, nil when the operator declined.
func (m *mover) start(parsed *ParsedOptions) (*moveState, error) {
	text, err := os.ReadFile(m.config)
	if err != nil {
		return nil, moveFail("cannot read "+m.config+": "+err.Error()+"; run this as root (sudo varlatch move ...) on the installation's host", ExitConfig)
	}
	cur, err := m.facts(m.config)
	if err != nil {
		return nil, err
	}
	to, toIngress, err := target(cur, parsed.Values["--public-url"], parsed.Values["--ingress"])
	if err != nil {
		return nil, err
	}
	if cur.PublicURL == nil {
		return nil, moveFail(m.config+" sets no public_url yet: finish `varlatch setup` first.", ExitUsage)
	}
	var facts moveFacts
	if err := m.r.varlatchdJSON("varlatch move", []string{"admin", "move-facts"}, m.config, &facts); err != nil {
		return nil, err
	}
	if facts.PublicURL == nil || *facts.PublicURL != *cur.PublicURL {
		return nil, moveFail(m.config+" names "+*cur.PublicURL+", but varlatchd runs with another address: restart varlatchd before moving. Nothing changed.", ExitUsage)
	}
	if facts.InstallationAdmins == 0 {
		return nil, moveFail("no Installation Admin is enabled, so nobody could finish the move. Recover one first: `varlatchd admin recover --new-admin`. Nothing changed.", ExitUsage)
	}
	candidate := movedConfig(string(text), to, cur.Ingress, toIngress, parsed.Values["--listen-https"])
	// varlatchd checks the new configuration before anything changes.
	check := filepath.Join(filepath.Dir(m.config), "."+filepath.Base(m.config)+".move-check")
	if err := os.WriteFile(check, []byte(candidate), 0o600); err != nil {
		return nil, moveFail("cannot write beside "+m.config+": "+err.Error()+"; run this as root (sudo varlatch move ...)", ExitConfig)
	}
	next, err := m.facts(check)
	os.Remove(check)
	if err != nil {
		return nil, err
	}
	if next.PublicURL == nil || *next.PublicURL != to || next.Ingress != toIngress {
		return nil, moveFail("the new configuration would not serve "+to+" on the "+toIngress+" ingress; nothing changed", ExitFailure)
	}

	for _, line := range movePlan(*cur.PublicURL, cur.Ingress, to, toIngress, facts) {
		if err := m.say(line); err != nil {
			return nil, err
		}
	}
	if !parsed.Has("--yes") {
		if !isTerminal(m.r.Stdin) || !isTerminal(m.r.Stdout) {
			return nil, moveFail("not a terminal: pass --yes once you have read what a move does (run without --yes in a terminal to see it). Nothing changed.", ExitUsage)
		}
		ok, err := newTerminalPrompter(m.r).confirm("\nMove this installation to "+to+"?", false)
		if err != nil {
			return nil, err
		}
		if !ok {
			_ = m.say("Nothing changed.")
			return nil, ExitWith(ExitFailure)
		}
	}

	if err := m.say("\nTaking an archive (the way back) ..."); err != nil {
		return nil, err
	}
	var archive struct {
		Path string `json:"path"`
	}
	if err := m.r.varlatchdJSON("varlatch move", []string{"admin", "backup", "run", "--json"}, m.config, &archive); err != nil {
		return nil, err
	}
	if archive.Path == "" {
		return nil, moveFail("varlatchd made no archive; nothing changed", ExitFailure)
	}
	if err := m.say("  ✓ archive " + Printable(archive.Path) + " made and verified"); err != nil {
		return nil, err
	}
	state := &moveState{
		From: *cur.PublicURL, FromIngress: cur.Ingress, To: to, ToIngress: toIngress, Archive: archive.Path,
		StartedAt: time.Now().UTC().Format(time.RFC3339), PreviousConfig: string(text), Config: candidate,
	}
	if err := m.writeState(state); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(m.config, []byte(candidate), 0o644); err != nil {
		return nil, moveFail("cannot write "+m.config+": "+err.Error()+"; the move is recorded in "+m.journal+": rerun `varlatch move` as root", ExitFailure)
	}
	if err := m.say("  ✓ " + m.config + " names " + to); err != nil {
		return nil, err
	}
	return state, m.restart()
}

// movePlan is what the operator reads before confirming.
func movePlan(from, fromIngress, to, toIngress string, f moveFacts) []string {
	gone := ", which stops answering"
	if fromIngress == "external" {
		gone = " (your proxy may still route it)"
	}
	lines := []string{
		"Move " + from + " (" + fromIngress + " ingress) to " + to + " (" + toIngress + " ingress).",
		"",
		"Passkeys belong to the address, so a move is a re-enrollment event:",
		"  - every passkey stops working (" + strconv.Itoa(f.Passkeys) + " enrolled), and every browser session ends (" + strconv.Itoa(f.Sessions) + ");",
		"  - each of the " + strconv.Itoa(f.People) + " people gets a one-time link to enroll a new passkey on the same identity",
		"    (their access, memberships, and audit history stay as they are);",
		"  - CLI, agent, and machine credentials keep working: change the server address where they are",
		"    configured (varlatch.toml, CI, VARLATCH_SERVER), and people sign in again with",
		"    `varlatch login --server " + to + "`;",
		"  - passkeys and the dashboard no longer work at " + from + gone + ".",
		"",
		"First, an archive of the installation is taken and verified. Restoring it is the way back.",
		"The tailnet node, if any, is not touched: it keeps its name and state.",
	}
	if toIngress == "external" {
		lines = append(lines, "Point your reverse proxy at this installation's listener for "+to+".")
	}
	if f.PendingInvitations > 0 {
		lines = append(lines, "",
			strconv.Itoa(f.PendingInvitations)+" invitation link(s) are still open. They keep working, but they name the old address:",
			"send people the same link with the new address in front of /enroll#.")
	}
	return lines
}

// resume checks a move in progress against the command line and the
// configuration, and puts the new configuration back if it stopped
// before writing it.
func (m *mover) resume(s *moveState, parsed *ParsedOptions) error {
	if u := parsed.Values["--public-url"]; u != "" {
		if to, _, err := target(confFacts{Ingress: s.ToIngress}, u, s.ToIngress); err != nil || to != s.To {
			return moveFail("a move to "+s.To+" is in progress: finish it with `varlatch move` (no --public-url), or give it up with `varlatch move --abandon`.", ExitUsage)
		}
	}
	if i := parsed.Values["--ingress"]; i != "" && i != s.ToIngress {
		return moveFail("the move in progress goes to the "+s.ToIngress+" ingress, not "+i+".", ExitUsage)
	}
	text, err := os.ReadFile(m.config)
	if err != nil {
		return moveFail("cannot read "+m.config+": "+err.Error()+"; run this as root (sudo varlatch move ...)", ExitConfig)
	}
	if err := m.say("Resuming the move from " + s.From + " to " + s.To + " (archive " + Printable(s.Archive) + ")."); err != nil {
		return err
	}
	switch string(text) {
	case s.Config:
		// varlatchd already runs with it: no second restart.
		if m.servesNewAddress(s.To) {
			return m.awaitServing()
		}
	case s.PreviousConfig:
		// Stopped between the journal and the configuration.
		if err := writeFileAtomic(m.config, []byte(s.Config), 0o644); err != nil {
			return moveFail("cannot write "+m.config+": "+err.Error(), ExitFailure)
		}
	default:
		return moveFail(m.config+" changed since the move began. Put back what the move wrote (in "+m.journal+", \"config\"), or give the move up with `varlatch move --abandon`.", ExitUsage)
	}
	return m.restart()
}

// restart restarts varlatchd.service and waits for it to answer on its
// plain listener with the new configuration's address.
func (m *mover) restart() error {
	if err := m.say("Restarting varlatchd ..."); err != nil {
		return err
	}
	ctl, err := locateProgram("systemctl", m.r.Getenv("PATH"))
	if err != nil {
		return moveFail("systemctl: "+err.Error()+"; restart varlatchd yourself, then rerun `varlatch move`", ExitUnavailable)
	}
	cmd := exec.Command(ctl, "restart", "varlatchd.service")
	cmd.Env = varlatchdEnviron(m.r)
	out, said, err := runChild(cmd)
	if err != nil {
		for _, text := range [][]byte{out, said} {
			for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n") {
				if line != "" {
					_ = m.r.warn(line)
				}
			}
		}
		return moveFail("systemctl restart varlatchd.service failed; fix it, then rerun `varlatch move` (the move is recorded in "+m.journal+")", ExitFailure)
	}
	return m.awaitServing()
}

// servesNewAddress is whether a varlatchd answers on the plain listener
// with to as its address (through its socket: move-facts reports the
// running daemon's configuration).
func (m *mover) servesNewAddress(to string) bool {
	answer, _, code, err := m.r.varlatchd("varlatch move", []string{"admin", "config", "check"}, m.config)
	var f confFacts
	if err != nil || code != 0 || json.Unmarshal(bytes.TrimSpace(answer), &f) != nil || !readyz(f.Listen) {
		return false
	}
	var facts moveFacts
	answer, _, code, err = m.r.varlatchd("varlatch move", []string{"admin", "move-facts"}, m.config)
	return err == nil && code == 0 && json.Unmarshal(bytes.TrimSpace(answer), &facts) == nil && facts.PublicURL != nil && *facts.PublicURL == to
}

// awaitServing waits for varlatchd to answer on its plain listener and,
// on the public ingress, to serve a certificate for the new name.
func (m *mover) awaitServing() error {
	f, err := m.facts(m.config)
	if err != nil {
		return err
	}
	if err := waitFor(moveReadyTimeout, func() bool { return readyz(f.Listen) }); err != nil {
		return moveFail("varlatchd did not answer on "+f.Listen+" within "+moveReadyTimeout.String()+"; check `journalctl -u varlatchd`, then rerun `varlatch move`", ExitUnavailable)
	}
	if err := m.say("  ✓ varlatchd answers"); err != nil {
		return err
	}
	if f.Ingress == "public" && f.ListenHTTPS != nil {
		host := strings.TrimPrefix(*f.PublicURL, "https://")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		var issuer string
		if err := waitFor(moveCertTimeout, func() bool { issuer = certificateFor(*f.ListenHTTPS, host); return issuer != "" }); err != nil {
			return moveFail("no HTTPS certificate for "+host+" within "+moveCertTimeout.String()+": check that the name points at this host and that ports 80 and 443 reach it, then rerun `varlatch move`", ExitUnavailable)
		}
		if err := m.say("  ✓ HTTPS certificate for " + host + " (issued by " + Printable(issuer) + ")"); err != nil {
			return err
		}
	}
	return nil
}

// finish removes the old address's passkeys (once), prints the
// re-enrollment links (once), waits for an Installation Admin to enroll,
// and closes the move.
func (m *mover) finish(s *moveState) error {
	if s.PasskeysRetiredAt == "" {
		var done struct {
			PasskeysRemoved int `json:"passkeysRemoved"`
			SessionsEnded   int `json:"sessionsEnded"`
		}
		answer, said, code, err := m.r.varlatchd("varlatch move", []string{"admin", "public-url-changed", "--from", s.From}, m.config)
		if err != nil {
			return err
		}
		line := ""
		switch {
		case code == 0:
			if json.Unmarshal(bytes.TrimSpace(answer), &done) != nil {
				return Fail("varlatch move: varlatchd answered public-url-changed with no JSON document; is it the same release as this varlatch?", ExitFailure)
			}
			line = "  ✓ " + strconv.Itoa(done.PasskeysRemoved) + " passkey(s) for " + s.From + " removed, " + strconv.Itoa(done.SessionsEnded) + " browser session(s) ended"
		case strings.Contains(string(said), "were already removed when the installation moved to "+s.To):
			// The removal committed, and the move stopped before its journal
			// recorded it: the step is done.
			line = "  ✓ the passkeys for " + s.From + " were already removed (the move had stopped after removing them)"
		default:
			return m.r.varlatchdEnded("varlatch move", said, code)
		}
		s.PasskeysRetiredAt = time.Now().UTC().Format(time.RFC3339)
		if err := m.writeState(s); err != nil {
			return err
		}
		if err := m.say(line); err != nil {
			return err
		}
	}
	if s.LinksIssuedAt == "" {
		args := []string{"admin", "reenroll", "--all", "--json"}
		if m.hours > 0 {
			args = append(args, "--hours", strconv.Itoa(m.hours))
		}
		var doc struct {
			Links []reenrollLink `json:"links"`
		}
		if err := m.r.varlatchdJSON("varlatch move", args, m.config, &doc); err != nil {
			return err
		}
		// The journal records that the links were issued, never a link.
		s.LinksIssuedAt = time.Now().UTC().Format(time.RFC3339)
		if err := m.writeState(s); err != nil {
			return err
		}
		if err := m.say("\nOne-time links, one per person: each enrolls a new passkey on that person's existing identity.\nSend each only to its person, over a channel you trust. Open yours first.\n"); err != nil {
			return err
		}
		if err := m.r.showReenrollLinks(doc.Links, "    "); err != nil {
			return err
		}
	} else if err := m.say("Links were issued at " + s.LinksIssuedAt + ". New ones: `varlatch admin reenroll --all` (revokes those)."); err != nil {
		return err
	}
	admins := func() bool {
		var f moveFacts
		answer, _, code, err := m.r.varlatchd("varlatch move", []string{"admin", "move-facts"}, m.config)
		return err == nil && code == 0 && json.Unmarshal(bytes.TrimSpace(answer), &f) == nil && f.AdminsWithPasskey > 0
	}
	if !admins() {
		if !m.wait {
			_ = m.say("Rerun `varlatch move` once an Installation Admin has enrolled, to finish.")
			return ExitWith(ExitTempfail)
		}
		if err := m.say("Waiting for an Installation Admin to enroll ..."); err != nil {
			return err
		}
		if waitFor(moveEnrollTimeout, admins) != nil {
			_ = m.say("No Installation Admin has enrolled yet. Rerun `varlatch move` to keep waiting; nothing else is repeated.")
			return ExitWith(ExitTempfail)
		}
	}
	if err := m.say("  ✓ an Installation Admin has a passkey at " + s.To); err != nil {
		return err
	}
	if err := os.Remove(m.journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return moveFail("cannot remove "+m.journal+": "+err.Error(), ExitFailure)
	}
	return m.say("\nMoved: " + s.From + " → " + s.To + ". The archive from before the move is " + Printable(s.Archive) + ".")
}

// abandon gives up an open move: varlatchd.conf goes back to the old
// address and varlatchd restarts. Before the old passkeys were removed
// that is all; after, the archive brings them back.
func (m *mover) abandon(s *moveState) error {
	if s == nil {
		return moveFail("no move in progress: nothing to give up.", ExitUsage)
	}
	if err := writeFileAtomic(m.config, []byte(s.PreviousConfig), 0o644); err != nil {
		return moveFail("cannot write "+m.config+": "+err.Error()+"; run this as root (sudo varlatch move ...)", ExitConfig)
	}
	if err := os.Remove(m.journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return moveFail("cannot remove "+m.journal+": "+err.Error(), ExitFailure)
	}
	if err := m.say("The move to " + s.To + " is given up: " + m.config + " names " + s.From + " again."); err != nil {
		return err
	}
	if s.PasskeysRetiredAt != "" {
		if err := m.say("The passkeys of " + s.From + " were removed at " + s.PasskeysRetiredAt + ". To get them back, restore the archive the move took, " +
			Printable(s.Archive) + ": `varlatch admin backup restore --in " + Printable(s.Archive) + "` with varlatchd stopped (docs/operations/backup.md)."); err != nil {
			return err
		}
	}
	return m.restart()
}

// waitFor polls ok every movePoll until it holds or timeout passes.
func waitFor(timeout time.Duration, ok func() bool) error {
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		time.Sleep(movePoll)
	}
	return nil
}

// local is a listener's address as this host dials it: an unspecified
// host is the loopback address.
func local(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

// readyz is whether varlatchd's plain listener answers /readyz with 200.
func readyz(listen string) bool {
	c := &http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + local(listen) + "/readyz")
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode == http.StatusOK
}

// certificateFor is the issuer of the certificate varlatchd's HTTPS
// listener serves for host, "" while it serves none. Whether a browser
// trusts it is the CA's: only that it names host is checked here.
func certificateFor(listenHTTPS, host string) string {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", local(listenHTTPS), &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return ""
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 || certs[0].VerifyHostname(host) != nil {
		return ""
	}
	issuer := certs[0].Issuer.CommonName
	if issuer == "" {
		issuer = certs[0].Issuer.String()
	}
	return issuer
}

// locateProgram is a program on PATH; as root, one only root can change
// (as findVarlatchd).
func locateProgram(name, pathList string) (string, error) {
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		if !isExecutableFile(candidate) {
			continue
		}
		if !asRoot() {
			return candidate, nil
		}
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", errors.New(candidate + " cannot be resolved")
		}
		for _, p := range []string{real, filepath.Dir(real), dir} {
			if why := onlyRootCanChange(p); why != "" {
				return "", errors.New(p + " " + why)
			}
		}
		return real, nil
	}
	return "", errors.New("not found on PATH")
}

// varlatchdEnded shows what varlatchd wrote on its standard error (the
// root hint after a 78 included: varlatchd adds it), each line through
// the fail-safe, and ends the command with varlatchd's status when it is
// not 0.
func (r *Run) varlatchdEnded(_ string, said []byte, code int) error {
	if err := r.warnLines(said); err != nil {
		return err
	}
	if code != 0 {
		return ExitWith(code)
	}
	return nil
}
