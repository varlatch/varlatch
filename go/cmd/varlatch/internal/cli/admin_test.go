// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRedactOutputShowingKeepsOnlyTheShownToken: invite's writer lets
// exactly its one enrollment token through; any other token and every
// value in flight is redacted as RedactOutput redacts it.
func TestRedactOutputShowingKeepsOnlyTheShownToken(t *testing.T) {
	shown := "vlt_invite_canaryTOKEN"
	line := "  https://v.example/enroll#" + shown + " vlt_cli_otherTOKEN s3cr3t-value\n"
	got := redactOutputShowing(line, shown, "s3cr3t-value")
	want := "  https://v.example/enroll#" + shown + " [redacted] [redacted]\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A longer token that starts with the shown one is another token.
	if got := redactOutputShowing("vlt_invite_canaryTOKENmore", shown); got != "[redacted]" {
		t.Errorf("a longer token was kept: %q", got)
	}
	// Nothing shown: RedactOutput's bytes.
	if got, want := redactOutputShowing(line, "", "s3cr3t-value"), RedactOutput(line, "s3cr3t-value"); got != want {
		t.Errorf("with nothing shown: %q, RedactOutput %q", got, want)
	}
	// A value in flight equal to the shown token is still redacted.
	if got := redactOutputShowing("#"+shown, shown, shown); got != "#[redacted]" {
		t.Errorf("a value in flight was shown: %q", got)
	}
}

// TestCredentialIssueNeverFollowsALink: --out naming a symbolic link,
// dangling or not, is refused before anything is issued, and nothing is
// written through it.
func TestCredentialIssueNeverFollowsALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	for _, existing := range []bool{false, true} {
		if existing {
			if err := os.WriteFile(target, []byte("kept\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(dir, "link")
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := checkOutPath(link)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("existing target %v: %v", existing, err)
		}
		// The exclusive create refuses it too, whatever checked before.
		f, err := os.OpenFile(link, os.O_WRONLY|os.O_CREATE|os.O_EXCL|createNoFollow, 0o600)
		if err == nil {
			_ = f.Close()
			t.Fatalf("existing target %v: created through the link", existing)
		}
		if existing {
			data, _ := os.ReadFile(target)
			if string(data) != "kept\n" {
				t.Fatalf("the link's target changed: %q", data)
			}
		} else if _, err := os.Lstat(target); err == nil {
			t.Fatal("a file was created at the dangling link's target")
		}
	}
}

// TestNodeDirname: path.dirname's POSIX answers, which credential issue's
// "the directory ... does not exist" names.
func TestNodeDirname(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	for in, want := range map[string]string{
		"token.txt":         ".",
		"missing/token.txt": "missing",
		"a/b/":              "a",
		"/token":            "/",
		"//x":               "//",
		"a//b":              "a/",
		"a/b//":             "a",
		"":                  ".",
	} {
		if got := nodeDirname(in); got != want {
			t.Errorf("nodeDirname(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInviteShowsOnlyAnInvitationToken: invite prints the server's token
// only when it is an invitation token in the servers' format and holds no
// secret the run knows. The bearer (VARLATCH_TOKEN or a stored
// credential), another stored credential and a value in flight never
// print, whatever their format.
func TestInviteShowsOnlyAnInvitationToken(t *testing.T) {
	invite := "vlt_invite_" + strings.Repeat("A", 21) + "-_" + strings.Repeat("z", 20)
	bearer := "vlt_invite_" + strings.Repeat("B", 43)
	stored := "vlt_invite_" + strings.Repeat("C", 43)
	value := "vlt_invite_" + strings.Repeat("D", 43)
	r := &Run{Secrets: &Secrets{Token: bearer, Stored: func() []string { return []string{"vlt_cli_storedAAAA", stored} }}}
	r.holdValue(value)
	for token, want := range map[string]bool{
		invite:                 true,
		bearer:                 false, // the bearer, as VARLATCH_TOKEN
		stored:                 false, // another stored credential
		"vlt_cli_storedAAAA":   false, // a stored credential in its own format
		value:                  false, // a value in flight
		invite[:len(invite)-1]: false, // 42 random characters
		invite + "A":           false, // 44
		"vlt_invite_" + strings.Repeat("A", 42) + "=": false,
		"not-a-token": false,
		"":            false,
	} {
		if got := r.showableInvite(token); got != want {
			t.Errorf("showableInvite(%q) = %v, want %v", token, got, want)
		}
	}
	// A token that holds a known secret inside it.
	r.Secrets.Remember(strings.Repeat("E", 20))
	if r.showableInvite("vlt_invite_" + strings.Repeat("E", 43)) {
		t.Error("a token holding a registered secret was shown")
	}
	// A token that is part of a known secret: registered, stored, or in flight.
	inside := func(c string) string { return "vlt_invite_" + strings.Repeat(c, 43) }
	r.Secrets.Remember("prefix-" + inside("F") + "-suffix")
	r.Secrets.Stored = func() []string { return []string{"x" + inside("G") + "y"} }
	r.holdValue("[" + inside("H") + "]")
	for _, c := range []string{"F", "G", "H"} {
		if r.showableInvite(inside(c)) {
			t.Errorf("a token inside a known secret (%s) was shown", c)
		}
	}
}

// TestInviteNeverPrintsAnotherSecret runs invite against a server that
// answers with the bearer (stored, or VARLATCH_TOKEN in the invitation
// format), another stored credential, or a token in no Varlatch format:
// none is printed, the run stops after its first line with InviteNotShown,
// exit 1. An invitation token is printed (the control).
func TestInviteNeverPrintsAnotherSecret(t *testing.T) {
	bearer := "vlt_cli_storedBEARERcanary"
	envBearer := "vlt_invite_" + strings.Repeat("e", 43)
	other := "vlt_invite_" + strings.Repeat("o", 43)
	invite := "vlt_invite_" + strings.Repeat("i", 43)
	var answer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method != "POST" || req.URL.Path != "/v1/organizations/acme/invitations" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"no"}}`))
			return
		}
		w.WriteHeader(201)
		body, _ := json.Marshal(map[string]string{"token": answer, "expiresAt": "2026-11-08T10:00:00.000Z"})
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	repo := filepath.Join(dir, "repo")
	for _, d := range []string{config, repo} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	creds := `{"servers": {"` + srv.URL + `": {"token": "` + bearer + `", "issuedAt": "1900-01-01T00:00:00.000Z", "expiresAt": "2100-01-01T00:00:00.000Z"}, "https://other.example": {"token": "` + other + `"}}}`
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "varlatch.toml"), []byte("server = \""+srv.URL+"\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	first := "Hand this one-time enrollment link to Mal (member):\n"
	for _, c := range []struct {
		name, answer, envToken string
	}{
		{"the stored bearer", bearer, ""},
		{"VARLATCH_TOKEN, the bearer, in the invitation format", envBearer, envBearer},
		{"another stored credential", other, ""},
		{"a token in no Varlatch format", "s3cr3t-not-an-invitation", ""},
	} {
		answer = c.answer
		env := MapEnv{"VARLATCH_CONFIG_DIR": config, "HOME": dir, "VARLATCH_ASSISTED": "0"}
		if c.envToken != "" {
			env["VARLATCH_TOKEN"] = c.envToken
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{"invite", "Mal"}, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if code != ExitFailure || stdout.String() != first || stderr.String() != InviteNotShown+"\n" {
			t.Errorf("%s: exit %d\nstdout %q\nstderr %q", c.name, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), c.answer) {
			t.Errorf("%s: printed", c.name)
		}
	}
	answer = invite
	var stdout, stderr bytes.Buffer
	code := Main([]string{"invite", "Mal"}, MapEnv{"VARLATCH_CONFIG_DIR": config, "HOME": dir, "VARLATCH_ASSISTED": "0"}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	if code != ExitOK || !strings.Contains(stdout.String(), "/enroll#"+invite+"\n") {
		t.Errorf("an invitation token: exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
	}
}
