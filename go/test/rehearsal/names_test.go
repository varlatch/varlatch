// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// The names of a restored copy (B6): what its people, Organizations, Projects,
// Environments, machines and hosts are called, read from its database as it is
// restored, kept in this process and in a file of the run's work directory (on
// the box on its tmpfs), never in a report. At the end the report and everything
// beside it is searched for each: how many were looked for is said, how many were
// found, never which.

//go:embed *.go run.sh
var ownSource embed.FS

var copyNames struct {
	sync.Mutex
	of   map[string]bool
	left map[string]bool
	err  error
}

const namesFile = "names"

// nameColumns are the columns a name is in, and, where it is an address, its host.
var nameColumns = []string{
	"SELECT name FROM organizations", "SELECT slug FROM organizations", "SELECT name FROM projects", "SELECT slug FROM projects",
	"SELECT name FROM environments", "SELECT name FROM identities", `SELECT name FROM "user"`, `SELECT email FROM "user"`,
	"SELECT name FROM platform_connections", "SELECT base_identity FROM platform_connections", "SELECT url FROM webhooks",
	"SELECT DISTINCT name FROM credentials WHERE name IS NOT NULL",
	"SELECT DISTINCT d.value FROM sync_targets t, jsonb_each_text(t.destination) d",
	"SELECT endpoint FROM audit_exports", "SELECT bucket FROM audit_exports", "SELECT name FROM groups", "SELECT slug FROM github_apps", "SELECT owner_login FROM github_apps",
	`SELECT name FROM passkey WHERE name IS NOT NULL`,
}

func (in *installation) readNames() error {
	for _, q := range nameColumns {
		r := in.psql("COPY (" + q + ") TO STDOUT")
		if r.code != 0 {
			// The query's own words alone: what the database says could be data.
			return errors.New("the names of the copy could not be read: " + q)
		}
		addNames(strings.Split(strings.ReplaceAll(r.stdout, "\r", ""), "\n"))
	}
	addNames(strings.Split(os.Getenv("VL_RH_NAMES"), ","))
	copyNames.Lock()
	defer copyNames.Unlock()
	if len(copyNames.of) == 0 {
		return errors.New("the copy has no name to look for")
	}
	lines := make([]string, 0, len(copyNames.of))
	for n := range copyNames.of {
		lines = append(lines, n)
	}
	slices.Sort(lines)
	return os.WriteFile(filepath.Join(workDir, namesFile), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// ownWords are the words of this harness's source, and some of everybody's: a
// name that is one of them says nothing of anybody.
var ownWords = sync.OnceValue(func() map[string]bool {
	words := map[string]bool{}
	for _, w := range strings.Fields("development production staging preview testing default website backend frontend service services server database admin administrator owner member deploy deployment internal private public shared personal machine laptop desktop github gitlab coolify vercel cloudflare") {
		words[w] = true
	}
	entries, _ := fs.ReadDir(ownSource, ".")
	word := regexp.MustCompile(`[a-z0-9][a-z0-9_-]*`)
	for _, e := range entries {
		b, _ := ownSource.ReadFile(e.Name())
		for _, w := range word.FindAllString(strings.ToLower(string(b)), -1) {
			words[w] = true
		}
	}
	return words
})

// addNames takes names of 4 characters or more, and the host of an address.
func addNames(list []string) {
	copyNames.Lock()
	defer copyNames.Unlock()
	if copyNames.of == nil {
		copyNames.of, copyNames.left = map[string]bool{}, map[string]bool{}
	}
	for _, n := range list {
		n = strings.ToLower(strings.TrimSpace(n))
		if u, err := url.Parse(n); err == nil && u.Hostname() != "" && u.Scheme != "" {
			n = u.Hostname()
		}
		switch {
		case utf8.RuneCountInString(n) < 4:
		case ownWords()[n], numbered.MatchString(n) && ownWords()[numbered.FindStringSubmatch(n)[1]]:
			copyNames.left[n] = true
		default:
			copyNames.of[n] = true
		}
	}
}

// numbered is a word and a number, as "run 12".
var numbered = regexp.MustCompile(`^([a-z]+)[ _-]?[0-9]+$`)

// named is whether text holds the name, as a word of its own.
func named(text, name string) bool {
	for at := 0; ; {
		i := strings.Index(text[at:], name)
		if i < 0 {
			return false
		}
		i += at
		before, _ := utf8.DecodeLastRuneInString(text[:i])
		after, _ := utf8.DecodeRuneInString(text[i+len(name):])
		if !wordRune(before) && !wordRune(after) {
			return true
		}
		at = i + 1
	}
}

func wordRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r > 0x7f && r != utf8.RuneError
}

// checkNames is the run's last record: the report as it will be written, and
// every file beside it (the log, the other runs').
func checkNames(t *testing.T) {
	copyNames.Lock()
	defer copyNames.Unlock()
	if copyNames.of == nil {
		return
	}
	report.Lock()
	b, err := json.Marshal(&report)
	report.Unlock()
	texts := []string{strings.ToLower(string(b))}
	walked := filepath.WalkDir(filepath.Dir(reportDir), func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || !d.Type().IsRegular() {
			return werr
		}
		b, rerr := os.ReadFile(path)
		texts = append(texts, strings.ToLower(string(b)))
		return rerr
	})
	found := 0
	for n := range copyNames.of {
		if slices.ContainsFunc(texts, func(text string) bool { return named(text, n) }) {
			found++
		}
	}
	err = errors.Join(err, walked)
	record(t, restoreItem, "no name of the copy's is in the report or the log", err == nil && len(copyNames.of) > 0 && found == 0,
		fmt.Sprintf("%d names looked for in %d texts, %d found (%d more are words of this harness or anybody's, and left out)", len(copyNames.of), len(texts), found, len(copyNames.left)))
}
