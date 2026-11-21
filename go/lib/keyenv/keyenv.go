// SPDX-License-Identifier: Apache-2.0

// Package keyenv refuses an environment that holds a key (ADR-0059
// Decision 8; internal docs/design/go-step6.md, decision 9, O2). Keys
// reach varlatchd only as files (root_kek_file, backup_key_file): a systemd
// credential on a host, a mounted secret in the container. Coolify, for
// one, passes every environment variable to every service of a stack, so a
// key in the environment is a key in every container of it.
//
// varlatchd serve refuses to start when its environment holds the Root KEK
// or the Backup Encryption Key; in the single-container image
// (ImageMarker), varlatchd admin and the CLI refuse to run the same way.
// All of them refuse a variable named for a key or a key's passphrase
// (Variables), whatever its value. That is all: names, and the configured
// keys' own values, never a guess at what looks like a key.
package keyenv

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// ImageMarker is set in the single-container image (go/image/Dockerfile).
const ImageMarker = "VARLATCH_IMAGE"

// Variables are names for a key or a key's passphrase (the TypeScript line
// used VARLATCH_KEK and VARLATCH_KEK_PASSPHRASE; the others are their
// obvious siblings), refused whatever their value and whatever their case.
var Variables = []string{
	"VARLATCH_KEK", "VARLATCH_KEK_PASSPHRASE", "VARLATCH_ROOT_KEK",
	"VARLATCH_BEK", "VARLATCH_BEK_PASSPHRASE", "VARLATCH_BACKUP_KEY",
}

// Key is a key and what to call it ("the Root KEK").
type Key struct {
	What  string
	Bytes []byte
}

// RootKEK and BEK are what Refusal calls the two keys.
const (
	RootKEK = "the Root KEK"
	BEK     = "the Backup Encryption Key"
)

// Refusal is why an environment cannot be run with ("" when it can): the
// first variable that holds one of keys (as hex in either case, or base64
// with or without padding, standard or URL-safe), or is one of Variables.
// It names the variable and never says its value.
//
// The encodings are those a key file may hold: envelope.ParseRootKEK (hex,
// or base64 in either alphabet) and backup.ParseKey (hex or standard
// base64). A new encoding either parser accepts belongs here too.
func Refusal(environ []string, keys ...Key) string {
	type form struct{ what, text string }
	var forms []form
	for _, k := range keys {
		if len(k.Bytes) == 0 {
			continue
		}
		h := hex.EncodeToString(k.Bytes)
		for _, text := range []string{h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(k.Bytes), base64.RawStdEncoding.EncodeToString(k.Bytes),
			base64.URLEncoding.EncodeToString(k.Bytes), base64.RawURLEncoding.EncodeToString(k.Bytes)} {
			forms = append(forms, form{k.What, text})
		}
	}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if slices.Contains(Variables, strings.ToUpper(name)) {
			return fmt.Sprintf("the environment variable %s is a key or passphrase variable name; keys reach varlatchd only as files (root_kek_file, backup_key_file): remove it from the environment and start again", name)
		}
		for _, f := range forms {
			if strings.Contains(value, f.text) {
				return fmt.Sprintf("the environment variable %s holds %s; keys reach varlatchd only as files (root_kek_file, backup_key_file): remove it from the environment and start again", name, f.what)
			}
		}
	}
	return ""
}

// Configured are the keys a varlatchd configuration file loads: those it
// names (root_kek_file, backup_key_file) and, for one it names none for,
// credentialsDir's (root-kek, backup-key: the credentials directory, as
// the configuration takes it; "" for none), each read when this process
// can read it: the CLI's view of them. A key it cannot read or parse is
// left out; so is everything when the configuration cannot be read. Clear
// each Bytes after use.
func Configured(confPath, credentialsDir string) []Key {
	f, err := os.Open(confPath)
	if err != nil {
		return nil
	}
	files := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			// A byte order mark, as config.Parse takes it off.
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, value, ok := strings.Cut(line, "="); ok {
			files[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	_ = f.Close()
	var keys []Key
	read := func(name, credential, what string, parse func(string) ([]byte, error)) {
		path := files[name]
		if path == "" && credentialsDir != "" {
			path = filepath.Join(credentialsDir, credential)
		}
		if path == "" {
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		key, err := parse(string(raw))
		clear(raw)
		if err == nil {
			keys = append(keys, Key{what, key})
		}
	}
	read("root_kek_file", "root-kek", RootKEK, envelope.ParseRootKEK)
	read("backup_key_file", "backup-key", BEK, backup.ParseKey)
	return keys
}
