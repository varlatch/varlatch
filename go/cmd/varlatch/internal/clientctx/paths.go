// SPDX-License-Identifier: Apache-2.0

// Package clientctx is the Go port of packages/context, the TypeScript CLI's
// context and credential store (ADR-0059 step 5; internal
// docs/design/go-cli.md, slice 5.1b and decision 11): where the CLI finds
// varlatch.toml and .varlatch/local.json, how it resolves the server and
// Environment (ADR-0017 §7; ADR-0058 Decision 1), and the user-level
// credentials.json and settings.json, read and written in the same places,
// formats and modes as the TypeScript CLI, so a sign-in made by either CLI
// works with the other.
//
// Files are parsed as the TypeScript code parses them, with no schema:
// whatever JSON a hand-edited file holds is read as JavaScript would read
// it (lib/jsjson values, internal/jsval), and where that code would throw
// an uncaught TypeError, these functions return a *TypeError.
package clientctx

import (
	"errors"
	"path/filepath"
)

// Env is the environment a command sees.
type Env interface {
	LookupEnv(key string) (string, bool)
}

func getenv(env Env, key string) string {
	v, _ := env.LookupEnv(key)
	return v
}

// ContextError is packages/context's ContextError: the CLI prints its
// message and exits 1.
type ContextError struct{ Message string }

func (e *ContextError) Error() string { return e.Message }

// TypeError is a JavaScript TypeError the TypeScript code throws and does
// not catch, on a file holding JSON of a shape it does not expect: Node.js
// prints the stack and exits 1. The Go CLI exits 1 with this message
// instead (go/README.md, the Go CLI's accepted differences).
type TypeError struct{ Message string }

func (e *TypeError) Error() string { return e.Message }

// defaultConfigDir is $XDG_CONFIG_HOME/varlatch, else <home>/.config/varlatch,
// on every platform (internal docs/design/go-cli.md, decision 4).
func defaultConfigDir(env Env) (string, error) {
	if xdg := getenv(env, "XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "varlatch"), nil
	}
	home, err := HomeDir(env)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "varlatch"), nil
}

// ConfigDir is the configuration directory: VARLATCH_CONFIG_DIR, else the
// default. An empty value counts as unset.
func ConfigDir(env Env) (string, error) {
	if dir := getenv(env, "VARLATCH_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	return defaultConfigDir(env)
}

func configFile(env Env, name string) (string, error) {
	dir, err := ConfigDir(env)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// CredentialsPath is credentials.json's path.
func CredentialsPath(env Env) (string, error) { return configFile(env, "credentials.json") }

// SettingsPath is settings.json's path.
func SettingsPath(env Env) (string, error) { return configFile(env, "settings.json") }

// AgentRunEnv is set by `varlatch run --agent-safe` in the Agent's
// environment (ADR-0043 Decision 5).
const AgentRunEnv = "VARLATCH_AGENT_RUN"

// AgentRunOf is the agent-safe run this process is inside, or "".
func AgentRunOf(env Env) string { return getenv(env, AgentRunEnv) }

// operatorStoreBlocked: inside an agent-safe run the default credential
// store (the operator's) is never read or written (ADR-0043 Decision 5);
// only a VARLATCH_CONFIG_DIR other than the default location counts. This
// keeps a command the Agent starts from falling back to the operator's
// credential by accident. It is not a boundary: a process running as the
// operator's OS user can still read the file (ADR-0022 Decision 16).
func operatorStoreBlocked(env Env) (bool, error) {
	if AgentRunOf(env) == "" {
		return false, nil
	}
	dir := getenv(env, "VARLATCH_CONFIG_DIR")
	if dir == "" {
		return true, nil
	}
	def, err := defaultConfigDir(env)
	var noHome *HomeDirectoryError
	if errors.As(err, &noHome) {
		// No default directory exists to be the operator's store, so the
		// override cannot be it: it is used as given.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	a, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	b, err := filepath.Abs(def)
	if err != nil {
		return false, err
	}
	return a == b, nil
}
