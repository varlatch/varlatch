// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// signInFake is a client a guided sign-in talks to: it echoes the bearer it
// is given in every field of its answers, as a hostile server could.
type signInFake struct{ token string }

func (f signInFake) ExchangeCliCredential(context.Context, jsjson.Object) (any, error) {
	return jsjson.Object{{Key: "token", Value: "CLI_CANARY_9902"}, {Key: "id", Value: "crd " + f.token}, {Key: "expiresAt", Value: "expires " + f.token}}, nil
}

func (f signInFake) ListOrganizations(context.Context) (any, error) {
	return jsjson.Object{{Key: "items", Value: []any{jsjson.Object{{Key: "slug", Value: "org " + f.token}, {Key: "name", Value: f.token}}}}, {Key: "nextCursor", Value: nil}}, nil
}

// TestGuidedSignInPrintsNothingAServerSent: the guided sign-in prints only
// its own fixed line, the server by its display form (go/README.md,
// `server-display`: no user name or password), whatever the server's
// answers echo; it stores the issued credential.
func TestGuidedSignInPrintsNothingAServerSent(t *testing.T) {
	const handoff = "HANDOFF_CANARY_4410"
	var out, held []string
	var saved []jsjson.Object
	_, err := guidedSignIn("https://user:pw9secret@vault.example.com", signInParts{
		hold:         func(v string) { held = append(held, v) },
		browserLogin: func(string) (string, error) { return handoff, nil },
		client:       func(token string) guidedSignInAPI { return signInFake{token} },
		save:         func(c jsjson.Object) error { saved = append(saved, c); return nil },
		out:          func(l string) error { out = append(out, l); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	printed := strings.Join(out, "\n")
	for _, canary := range []string{handoff, "CLI_CANARY_9902", "pw9secret"} {
		if strings.Contains(printed, canary) {
			t.Fatalf("printed %q: %q", canary, printed)
		}
	}
	if printed != "Signed in to https://vault.example.com." {
		t.Fatalf("printed %q", printed)
	}
	if len(saved) != 1 || saved[0].Value("token") != "CLI_CANARY_9902" || saved[0].Value("credentialId") != "crd "+handoff {
		t.Fatalf("saved %v", saved)
	}
	// Both bearers are held as they are read, before any request with them.
	if strings.Join(held, ",") != handoff+",CLI_CANARY_9902" {
		t.Fatalf("held %q", held)
	}
	keys := []string{}
	for _, m := range saved[0] {
		keys = append(keys, m.Key)
	}
	if strings.Join(keys, ",") != "token,issuedAt,expiresAt,credentialId" {
		t.Fatalf("saved fields %v", keys)
	}
}

// TestValidatePublicURL is setup.ts's validatePublicUrl: an origin, https,
// or http on a loopback host only.
func TestValidatePublicURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://vault.example.com":          "https://vault.example.com",
		" https://Vault.Example.com/ ":       "https://vault.example.com",
		"https://vault.example.com:8443":     "https://vault.example.com:8443",
		"https://vault.example.com:443":      "https://vault.example.com",
		"http://localhost:3000":              "http://localhost:3000",
		"http://127.0.0.1":                   "http://127.0.0.1",
		"http://[::1]:8080":                  "http://[::1]:8080",
		"http://vault.example.com":           "",
		"https://vault.example.com/path":     "",
		"https://vault.example.com/?token=x": "",
		"https://vault.example.com/#x":       "",
		"vault.example.com":                  "",
		"":                                   "",
	} {
		got, err := validatePublicURL(raw)
		if want == "" && err == nil || want != "" && (err != nil || got != want) {
			t.Errorf("validatePublicURL(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}

// TestGuidedDeleteNeverRemovesALink: a .env that is a symbolic link is not
// deleted (go/README.md, `init-delete-link`): deleting the link would leave
// the values in the file it points to. A regular file that still holds
// what was read is deleted; one that changed is kept.
func TestGuidedDeleteNeverRemovesALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges there")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "values.txt")
	if err := os.WriteFile(target, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if deleted, isLink, err := deleteSource(link, []byte("A=1\n")); err != nil || deleted || !isLink {
		t.Fatalf("link: deleted %v, link %v, %v", deleted, isLink, err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("the link was removed")
	}
	plain := filepath.Join(dir, ".env.production")
	if err := os.WriteFile(plain, []byte("B=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := deleteSource(plain, []byte("B=1\n")); err != nil || deleted {
		t.Fatalf("changed file: deleted %v, %v", deleted, err)
	}
	if deleted, _, err := deleteSource(plain, []byte("B=2\n")); err != nil || !deleted {
		t.Fatalf("unchanged file: deleted %v, %v", deleted, err)
	}
}
