// SPDX-License-Identifier: Apache-2.0

// Package keyenv refuses an environment that holds a key (ADR-0059
// Decision 8; internal docs/design/go-step6.md, decision 9, O2). Keys
// reach varlatchd only as files (root_kek_file, backup_key_file): a systemd
// credential on a host, a mounted secret in the container. Coolify, for
// one, passes every environment variable to every service of a stack, so a
// key in the environment is a key in every container of it.
//
// varlatchd serve refuses to start when its environment holds the Root KEK
// or the Backup Encryption Key; the CLI in the single-container image
// refuses to run the same way. Both refuse a variable the TypeScript line
// kept a key or its passphrase in (Variables), whatever its value.
package keyenv

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// Variables are the TypeScript line's names for a key or a key's
// passphrase, refused whatever their value (and whatever their case).
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
			return fmt.Sprintf("the environment variable %s is where the TypeScript line kept a key or its passphrase; keys reach varlatchd only as files (root_kek_file, backup_key_file): remove it from the environment and start again", name)
		}
		for _, f := range forms {
			if strings.Contains(value, f.text) {
				return fmt.Sprintf("the environment variable %s holds %s; keys reach varlatchd only as files (root_kek_file, backup_key_file): remove it from the environment and start again", name, f.what)
			}
		}
	}
	return ""
}

// Configured are the keys a varlatchd configuration file names
// (root_kek_file, backup_key_file), each read when this process can read
// it: the CLI's view of them. A key it cannot read or parse is left out;
// so is everything when the configuration cannot be read. Clear each
// Bytes after use.
func Configured(confPath string) []Key {
	f, err := os.Open(confPath)
	if err != nil {
		return nil
	}
	files := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, value, ok := strings.Cut(line, "="); ok {
			files[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	_ = f.Close()
	var keys []Key
	read := func(name, what string, parse func(string) ([]byte, error)) {
		path := files[name]
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
	read("root_kek_file", RootKEK, envelope.ParseRootKEK)
	read("backup_key_file", BEK, backup.ParseKey)
	return keys
}
