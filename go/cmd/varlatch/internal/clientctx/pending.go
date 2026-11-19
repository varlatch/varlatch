// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Pending device sign-ins (packages/context's pending-sign-ins store; the
// design notes "Device-authorization sign-in"; internal docs/design/go-cli.md
// decision 11): `varlatch login --start` keeps the device code here and
// nowhere else, since it is the bearer that collects the credential. A 0600
// file in a 0700 directory, replaced atomically, one entry per server,
// deleted when its last entry goes. Both CLIs read and write it.

// PendingSignInsPath is pending-sign-ins.json in the configuration
// directory.
func PendingSignInsPath(env Env) (string, error) { return configFile(env, "pending-sign-ins.json") }

// ServerKey is packages/context's serverKey: the key a server's pending
// sign-in is stored under, which is not credentials.json's key: scheme,
// host and port (a default port dropped, as WHATWG serializes them), and
// the path without trailing slashes. A value that is not a URL is a
// TypeError, as `new URL` throws.
func ServerKey(server string) (string, error) {
	u, ok := whatwg.ParseURL(server)
	if !ok {
		return "", &TypeError{Message: "Invalid URL"}
	}
	path, _ := u.RequestTarget()
	return u.Protocol + "//" + u.Host + strings.TrimRight(path, "/"), nil
}

// refuseInAgentRun: never inside an agent-safe run, whatever
// VARLATCH_CONFIG_DIR says (ADR-0043 Decision 5). The CLI refuses before
// it gets here; this keeps a mistake from reading or writing the state.
func refuseInAgentRun(env Env) error {
	if run := AgentRunOf(env); run != "" {
		return &ContextError{Message: "This command runs inside agent-safe run " + run + ", which has no human sign-in."}
	}
	return nil
}

// readPendingFile is the file's servers: an object of entries by key. A
// file that does not exist, does not parse, or holds no object of servers
// holds nothing: a pending sign-in expires within minutes.
func readPendingFile(env Env) (jsjson.Object, error) {
	if err := refuseInAgentRun(env); err != nil {
		return nil, err
	}
	path, err := PendingSignInsPath(env)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return jsjson.Object{}, nil
		}
		return jsjson.Object{}, nil // readFileSync's failure, caught
	}
	parsed, err := jsjson.Parse(data)
	if err != nil {
		return jsjson.Object{}, nil
	}
	servers, _ := get(parsed, "servers")
	if o, ok := servers.(jsjson.Object); ok {
		return o, nil
	}
	return jsjson.Object{}, nil
}

// writePendingFile writes the servers, the directory set to 0700; with no
// entry left the file is deleted.
func writePendingFile(servers jsjson.Object, env Env) error {
	if err := refuseInAgentRun(env); err != nil {
		return err
	}
	path, err := PendingSignInsPath(env)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if len(servers) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writePrivateFile(path, string(jsjson.StringifyIndent(jsjson.Object{{Key: "servers", Value: servers}}, 2))+"\n")
}

// LoadPendingSignIn is the server's pending sign-in, nil when there is none.
func LoadPendingSignIn(server string, env Env) (jsjson.Object, error) {
	servers, err := readPendingFile(env)
	if err != nil {
		return nil, err
	}
	key, err := ServerKey(server)
	if err != nil {
		return nil, err
	}
	entry, _ := servers.Get(key)
	o, _ := entry.(jsjson.Object)
	return o, nil
}

// SavePendingSignIn stores the entry under its server's key, replacing an
// earlier one, and returns the replaced entry (nil for none).
func SavePendingSignIn(entry jsjson.Object, env Env) (jsjson.Object, error) {
	servers, err := readPendingFile(env)
	if err != nil {
		return nil, err
	}
	server, _ := entry.Get("server")
	key, err := ServerKey(jsjson.String(server))
	if err != nil {
		return nil, err
	}
	previous, _ := servers.Get(key)
	replaced, _ := previous.(jsjson.Object)
	if err := writePendingFile(servers.Set(key, entry), env); err != nil {
		return nil, err
	}
	return replaced, nil
}

// DeletePendingSignIn removes the server's entry, if any.
func DeletePendingSignIn(server string, env Env) error {
	servers, err := readPendingFile(env)
	if err != nil {
		return err
	}
	key, err := ServerKey(server)
	if err != nil {
		return err
	}
	if _, ok := servers.Get(key); !ok {
		return nil
	}
	return writePendingFile(without(servers, key), env)
}

// without is o less its key (delete o[key]).
func without(o jsjson.Object, key string) jsjson.Object {
	out := make(jsjson.Object, 0, len(o))
	for _, m := range o {
		if m.Key != key {
			out = append(out, m)
		}
	}
	return out
}
