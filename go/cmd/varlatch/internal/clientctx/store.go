// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The user-level credential store, credentials.json (never in a
// repository), and settings.json next to it (ADR-0058 Decision 1): the
// same files, schema and modes as the TypeScript CLI (internal
// docs/design/go-cli.md, decision 11). Each is
//
//	{"servers": {"<server>": {"token": ..., "issuedAt": ..., ...}}}
//	{"defaultServer": "<server>"}
//
// written as JSON.stringify(value, null, 2) and a newline, readable by its
// owner only (0600), replaced atomically, keeping every key and entry this
// version does not know. A file that is missing, unreadable or not JSON
// reads as empty, so the next write replaces it.

// readJSONFile is JSON.parse(readFileSync(path, "utf8")) inside a try: the
// parsed value, and false when the file is missing, unreadable or not JSON.
func readJSONFile(path string) (any, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	text := jsval.DecodeUTF8(data)
	if strings.HasPrefix(text, "\uFEFF") {
		return nil, false // JSON.parse refuses a byte order mark; readFileSync keeps it
	}
	v, err := jsjson.Parse([]byte(text))
	if err != nil {
		return nil, false
	}
	return v, true
}

// existsSync is fs.existsSync: false on any error.
func existsSync(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// StoredServerKey is the form servers are stored under, in
// credentials.json and settings.json: the URL without trailing slashes.
func StoredServerKey(server string) string { return strings.TrimRight(server, "/") }

// readCredentialsFile is the parsed credentials.json, nil when there is
// none to read (also inside an agent-safe run, and for a file holding null).
func readCredentialsFile(env Env) (any, error) {
	blocked, err := operatorStoreBlocked(env)
	if err != nil || blocked {
		return nil, err
	}
	path, err := CredentialsPath(env)
	if err != nil {
		return nil, err
	}
	if !existsSync(path) {
		return nil, nil
	}
	v, _ := readJSONFile(path)
	return v, nil
}

// get is file?.servers?.[key] and the like: v[key] when v is not nullish.
func get(v any, key string) (any, bool) {
	if v == nil {
		return nil, false
	}
	return jsval.Get(v, key)
}

// Entry is one stored credential: the server as credentials.json keys it,
// and its entry as parsed (an object for any file a CLI wrote).
type Entry struct {
	Server     string
	Credential any
}

// ListCredentials is listCredentials(): Object.entries of the file's
// servers.
func ListCredentials(env Env) ([]Entry, error) {
	file, err := readCredentialsFile(env)
	if err != nil {
		return nil, err
	}
	servers, ok := get(file, "servers")
	if !ok || servers == nil {
		return nil, nil
	}
	return entries(servers), nil
}

// entries is Object.entries(v) for a JSON value that is not nullish.
func entries(v any) []Entry {
	var out []Entry
	switch x := v.(type) {
	case jsjson.Object:
		for _, m := range x {
			out = append(out, Entry{m.Key, m.Value})
		}
	case []any:
		for i, e := range x {
			out = append(out, Entry{strconv.Itoa(i), e})
		}
	case string:
		for i, u := range jsval.UTF16(x) {
			out = append(out, Entry{strconv.Itoa(i), jsval.FromUTF16([]uint16{u})})
		}
	}
	return out
}

// StoredServers is the servers with a stored credential.
func StoredServers(env Env) ([]string, error) {
	list, err := ListCredentials(env)
	if err != nil {
		return nil, err
	}
	servers := make([]string, len(list))
	for i, e := range list {
		servers[i] = e.Server
	}
	return servers, nil
}

// LoadCredential is loadCredential(server): the stored entry for server,
// nil when none (or a nullish one). It does not read VARLATCH_TOKEN.
func LoadCredential(server string, env Env) (any, error) {
	file, err := readCredentialsFile(env)
	if err != nil {
		return nil, err
	}
	servers, _ := get(file, "servers")
	v, _ := get(servers, StoredServerKey(server))
	return v, nil
}

// SaveCredential is saveCredential(server, credential): the entry for
// server replaced, every other key and entry kept.
func SaveCredential(server string, credential jsjson.Object, env Env) error {
	file, err := readCredentialsFile(env)
	if err != nil {
		return err
	}
	key := StoredServerKey(server)
	if file == nil {
		file = jsjson.Object{{Key: "servers", Value: jsjson.Object{}}}
	}
	switch f := file.(type) {
	case jsjson.Object:
		servers, ok := f.Get("servers")
		if !ok || servers == nil {
			servers = jsjson.Object{}
			f = f.Set("servers", servers)
		}
		switch s := servers.(type) {
		case jsjson.Object:
			f = f.Set("servers", s.Set(key, credential))
		case []any:
			// A property of an array: JSON.stringify writes its elements only.
			f = f.Set("servers", setIndex(s, key, credential))
		default:
			return &TypeError{Message: fmt.Sprintf("credentials.json: its servers are %s, not an object; the credential was not stored", describe(s))}
		}
		file = f
	case []any:
		// `parsed.servers ??= {}` gives the array a property; the file is
		// written as it was, and the credential is lost.
	default:
		return &TypeError{Message: fmt.Sprintf("credentials.json holds %s, not an object; the credential was not stored", describe(f))}
	}
	return writeCredentialsFile(file, env)
}

// setIndex is arr[key] = value: an element when key is an array index
// (holes as null), else a property JSON.stringify does not write.
func setIndex(arr []any, key string, value any) []any {
	n, err := strconv.ParseUint(key, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != key || n == 1<<32-1 {
		return arr
	}
	out := append([]any(nil), arr...)
	for uint64(len(out)) <= n {
		out = append(out, nil)
	}
	out[n] = value
	return out
}

// describe names a JSON value's type for a TypeError.
func describe(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "an array"
	}
	return "an object"
}

// DeleteCredential is deleteCredential(server): false when nothing truthy
// is stored for it; otherwise the entry is removed and, when it was the
// default server, the default is forgotten.
func DeleteCredential(server string, env Env) (bool, error) {
	file, err := readCredentialsFile(env)
	if err != nil {
		return false, err
	}
	key := StoredServerKey(server)
	servers, _ := get(file, "servers")
	entry, ok := get(servers, key)
	if !ok || !jsjson.Truthy(entry) {
		return false, nil
	}
	f := file.(jsjson.Object) // only an object's servers can hold an entry
	switch s := servers.(type) {
	case jsjson.Object:
		kept := jsjson.Object{}
		for _, m := range s {
			if m.Key != key {
				kept = append(kept, m)
			}
		}
		f = f.Set("servers", kept)
	case []any:
		out := append([]any(nil), s...)
		i, _ := strconv.Atoi(key)
		out[i] = nil // delete leaves a hole; JSON.stringify writes null
		f = f.Set("servers", out)
	default:
		return false, &TypeError{Message: "credentials.json: its servers are a string; the credential was not removed"}
	}
	if err := writeCredentialsFile(f, env); err != nil {
		return false, err
	}
	if def, err := DefaultServer(env); err != nil {
		return false, err
	} else if def != "" && def == key {
		if err := SetDefaultServer("", false, env); err != nil {
			return false, err
		}
	}
	return true, nil
}

func writeCredentialsFile(file any, env Env) error {
	blocked, err := operatorStoreBlocked(env)
	if err != nil {
		return err
	}
	if blocked {
		return &ContextError{Message: "This command runs inside agent-safe run " + AgentRunOf(env) + ", which never writes the operator's credential store."}
	}
	path, err := CredentialsPath(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	return writePrivateFile(path, string(jsjson.StringifyIndent(file, 2))+"\n")
}

// writePrivateFile is packages/context's writePrivateFile: text written to
// a temporary file in the same directory, created 0600 and flushed, then
// renamed over path. Readers see the old file or the new one, never a
// partial write, and the new file is never readable by anyone else.
func writePrivateFile(path, text string) error {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+strconv.Itoa(os.Getpid())+"."+hex.EncodeToString(random)+".tmp")
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// Settings (ADR-0058 Decision 1).

func readSettings(env Env) (jsjson.Object, error) {
	blocked, err := operatorStoreBlocked(env)
	if err != nil || blocked {
		return jsjson.Object{}, err
	}
	path, err := SettingsPath(env)
	if err != nil {
		return nil, err
	}
	if !existsSync(path) {
		return jsjson.Object{}, nil
	}
	v, _ := readJSONFile(path)
	if o, ok := v.(jsjson.Object); ok {
		return o, nil
	}
	return jsjson.Object{}, nil
}

func writeSettings(settings jsjson.Object, env Env) error {
	blocked, err := operatorStoreBlocked(env)
	if err != nil {
		return err
	}
	if blocked {
		return &ContextError{Message: "This command runs inside agent-safe run " + AgentRunOf(env) + ", which never writes the operator's settings."}
	}
	path, err := SettingsPath(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	return writePrivateFile(path, string(jsjson.StringifyIndent(settings, 2))+"\n")
}

// DefaultServer is the remembered default server, "" when none.
func DefaultServer(env Env) (string, error) {
	settings, err := readSettings(env)
	if err != nil {
		return "", err
	}
	if v, ok := settings.Value("defaultServer").(string); ok {
		return v, nil
	}
	return "", nil
}

// SetDefaultServer remembers server as the default (in its stored form);
// set false forgets the default. Other settings are kept.
func SetDefaultServer(server string, set bool, env Env) error {
	settings, err := readSettings(env)
	if err != nil {
		return err
	}
	if set {
		settings = settings.Set("defaultServer", StoredServerKey(server))
	} else {
		kept := jsjson.Object{}
		for _, m := range settings {
			if m.Key != "defaultServer" {
				kept = append(kept, m)
			}
		}
		settings = kept
	}
	return writeSettings(settings, env)
}

// RememberServerIfUnset makes server the default after a sign-in stored
// its credential, only when none is set (ADR-0058 Decision 1); it never
// replaces one. It reports whether it set it.
func RememberServerIfUnset(server string, env Env) (bool, error) {
	blocked, err := operatorStoreBlocked(env)
	if err != nil || blocked {
		return false, err
	}
	if def, err := DefaultServer(env); err != nil || def != "" {
		return false, err
	}
	return true, SetDefaultServer(server, true, env)
}

// IsTypeError reports whether err is a *TypeError.
func IsTypeError(err error) bool {
	var t *TypeError
	return errors.As(err, &t)
}
