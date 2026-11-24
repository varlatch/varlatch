// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// goWriter writes on a Go installation as its operator and a client do. What
// it makes is the run's: an Organization of its own, an identity in it, and
// the administrator's passkey and CLI credential.
type goWriter struct {
	t    *testing.T
	item int
	what string
	dir  string // the run's own, 0700: the link is there for a moment
	base string // the public URL
	http *http.Client
	// admin runs `varlatchd admin` beside the running varlatchd.
	admin func(args ...string) ran
}

var enrollLink = regexp.MustCompile(`https?://\S+/enroll#\S+`)

// writes are those whose transaction SQLite may not keep in memory (64 KiB):
// a small one goes through where it has no directory for its temporary files
// (the image with a read-only root), and a larger one fails there. So: the
// administrator's CLI credential, a passkey, a machine identity, and a change
// set of five values and one of two hundred.
func (w *goWriter) writes() bool {
	w.t.Helper()
	record := func(name string, ok bool, detail string) bool {
		return record2(w.t, w.item, w.what+": on Go: "+name, ok, detail)
	}
	st := w.admin("bootstrap-status")
	id := firstAdmin(st.stdout)
	var cred ran
	if id == "" {
		cred = w.admin("bootstrap", "--cli-credential", "--name", "Rehearsal Admin")
	} else {
		secret(id)
		cred = w.admin("recover", "--identity", id, "--cli-credential", "--name", "rehearsal")
	}
	token := secret(strings.TrimSpace(lastLine(cred.stdout)))
	if !record("the administrator's CLI credential", cred.code == 0 && strings.HasPrefix(token, "vlt_"), cred.String()) {
		return false
	}
	if id == "" {
		if id = firstAdmin(w.admin("bootstrap-status").stdout); id == "" {
			return record("the administrator", false, "bootstrap-status names none")
		}
		secret(id)
	}
	ok := w.passkey(id)
	c := &apiClient{t: w.t, base: w.base, token: token, http: w.http}
	call := func(name, method, path string, body any) map[string]any {
		code, out := c.send(method, path, body)
		b, _ := json.Marshal(out)
		ok = record(name, code >= 200 && code < 300, fmt.Sprintf("%d %s", code, trim(redact(string(b))))) && ok
		return out
	}
	slug := "vl-rh-" + hexBytes(4)
	call("an Organization of the run's", "POST", "/v1/organizations", map[string]any{"name": "Rehearsal " + slug, "slug": slug})
	at := "/v1/organizations/" + slug
	if !ok {
		return false
	}
	call("a project", "POST", at+"/projects", map[string]any{"name": "Writes", "slug": "writes", "contractAuthority": "managed"})
	call("an environment", "POST", at+"/projects/writes/environments", map[string]any{"name": "development", "tier": "development"})
	call("a machine identity", "POST", at+"/identities", map[string]any{"name": "writes", "kind": "service"})
	for _, n := range []int{5, 200} {
		changes := make([]map[string]any, n)
		for i := range changes {
			changes[i] = map[string]any{"op": "set", "item": fmt.Sprintf("ITEM_%d_%d", n, i), "value": secret("rh-" + hexBytes(16) + strings.Repeat("x", 4000))}
		}
		out := call(fmt.Sprintf("a change set of %d values", n), "POST", at+"/projects/writes/environments/development/changes", map[string]any{"changes": changes})
		results, _ := out["results"].([]any)
		ok = record(fmt.Sprintf("every one of the %d is answered", n), len(results) == n, fmt.Sprint(len(results))) && ok
	}
	return ok
}

// firstAdmin is bootstrap-status's first enabled administrator, "" for none.
func firstAdmin(status string) string {
	var st struct {
		Admins []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"admins"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(lastLine(status))), &st) == nil {
		for _, a := range st.Admins {
			if a.Enabled {
				return a.ID
			}
		}
	}
	return ""
}

// passkey enrolls one from a link of the administrator's, with a software
// authenticator (enrollpasskey, beside the run's binaries).
func (w *goWriter) passkey(id string) bool {
	w.t.Helper()
	name := w.what + ": on Go: a passkey enrolled from the administrator's link"
	tool := filepath.Join(binDir, "enrollpasskey")
	if _, err := os.Stat(tool); err != nil {
		return record2(w.t, w.item, name, false, "no enrollpasskey beside the run's binaries (run.sh builds it)")
	}
	r := w.admin("recover", "--identity", id)
	link := enrollLink.FindString(r.stdout)
	if link == "" {
		return record2(w.t, w.item, name, false, "no link: "+r.String())
	}
	secret(link)
	_, fragment, _ := strings.Cut(link, "#")
	secret(fragment)
	path := filepath.Join(w.dir, "enroll-link")
	if err := os.WriteFile(path, []byte(link+"\n"), 0o600); err != nil {
		return record2(w.t, w.item, name, false, err.Error())
	}
	defer os.Remove(path)
	// The link's own origin, and the run's CA where it has one.
	e := run("", nil, nil, tool, "-link-file", path, "-insecure")
	return record2(w.t, w.item, name, e.code == 0, e.String())
}

// hostWriter writes on a host-install target (the box's and B6's).
func (in *installation) hostWriter(t *testing.T, item int, what string) *goWriter {
	hc := in.client
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &goWriter{t: t, item: item, what: what, dir: in.state, base: in.publicURL, http: hc,
		admin: func(args ...string) ran {
			return run("", nil, nil, filepath.Join(binDir, "varlatchd"), append(append([]string{"admin"}, args...), "--config", in.conf)...)
		}}
}
