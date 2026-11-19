// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/toml"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Deterministic context resolution (ADR-0017 §7):
//
//	explicit --environment flag
//	  > VARLATCH_ENV
//	    > per-repo local selection (.varlatch/local.json, gitignored)
//	      > committed default (varlatch.toml)
//
// Never inferred from Git branches, usernames, hostnames, or the existence
// of personal environments. Repo context records choices; credentials live
// only in the user-level store.

// RepoConfigFile is the committed context file.
const RepoConfigFile = "varlatch.toml"

const (
	localDir       = ".varlatch"
	localStateFile = "local.json"
)

// RepoConfig is varlatch.toml: organization and project always, server and
// default_environment when given (non-empty strings).
type RepoConfig struct {
	Server             string
	Organization       string
	Project            string
	DefaultEnvironment string
}

// FindRepoRoot is the nearest directory from cwd upward holding
// varlatch.toml (anything by that name that exists), "" when none does.
func FindRepoRoot(cwd string) string {
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return ""
	}
	for {
		if existsSync(filepath.Join(dir, RepoConfigFile)) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// LoadRepoConfig reads varlatch.toml as smol-toml 1.9.0 does. A file it
// cannot read is the operating system's error (TypeScript lets that one
// escape); a document that is not TOML, or that lacks organization or
// project, is a *ContextError.
func LoadRepoConfig(repoRoot string) (RepoConfig, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, RepoConfigFile))
	if err != nil {
		return RepoConfig{}, err
	}
	source := jsval.DecodeUTF8(data)
	table, err := toml.ParseString(source)
	if err != nil {
		var parseErr *toml.Error
		if !errors.As(err, &parseErr) {
			return RepoConfig{}, err
		}
		if HasAtSign(source) {
			// smol-toml's message quotes the lines around the error, which can
			// hold part of a URL's user name and password without its at-sign
			// (a string that runs on past them), where neither masking layer
			// can see it. A file that holds an at-sign of any form, as the
			// fail-safe detects one, may hold credentials: its lines are left
			// out, the explanation and where it is kept (go/README.md, "the
			// excerpt is left out when the file may hold credentials").
			return RepoConfig{}, &ContextError{Message: fmt.Sprintf("Invalid %s: Invalid TOML document: %s, line %d, column %d "+
				"(the file may hold a URL's user name and password, so its lines are not shown)",
				RepoConfigFile, parseErr.What, parseErr.Line, parseErr.Column)}
		}
		// Without an at-sign the file holds no URL's user name and password:
		// smol-toml's message as it is.
		return RepoConfig{}, &ContextError{Message: "Invalid " + RepoConfigFile + ": " + parseErr.Message}
	}
	str := func(key string) string {
		v, _ := table.Get(key)
		s, _ := v.(string)
		return s
	}
	config := RepoConfig{Organization: str("organization"), Project: str("project")}
	if config.Organization == "" || config.Project == "" {
		return RepoConfig{}, &ContextError{Message: RepoConfigFile + ` must declare "organization" and "project"`}
	}
	config.Server = str("server")
	config.DefaultEnvironment = str("default_environment")
	return config, nil
}

// LocalStatePath is .varlatch/local.json in the repository.
func LocalStatePath(repoRoot string) string {
	return filepath.Join(repoRoot, localDir, localStateFile)
}

// LoadLocalState is .varlatch/local.json as parsed, an empty object when
// it is missing or not JSON, and nil for a file holding null. Its fields
// (selectedEnvironment, serverOverride, selectedTier, tierCachedAt) are
// whatever JSON the file holds; read them with LocalField.
func LoadLocalState(repoRoot string) any {
	path := LocalStatePath(repoRoot)
	if !existsSync(path) {
		return jsjson.Object{}
	}
	v, ok := readJSONFile(path)
	if !ok {
		return jsjson.Object{}
	}
	return v
}

// LocalField is local[name]: a *TypeError for a file holding null, as
// TypeScript's property read throws there.
func LocalField(local any, name string) (any, bool, error) {
	if local == nil {
		return nil, false, &TypeError{Message: ".varlatch/local.json holds null, not an object"}
	}
	v, ok := jsval.Get(local, name)
	return v, ok, nil
}

// SaveLocalState writes .varlatch/local.json (as writeFileSync does: in
// place, the default mode), and a .gitignore of "*" in .varlatch when there
// is none, so the directory ignores itself (ADR-0017 §5).
func SaveLocalState(repoRoot string, state jsjson.Object) error {
	dir := filepath.Join(repoRoot, localDir)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	ignore := filepath.Join(dir, ".gitignore")
	if !existsSync(ignore) {
		if err := os.WriteFile(ignore, []byte("*\n"), 0o666); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, localStateFile), append(jsjson.StringifyIndent(state, 2), '\n'), 0o666)
}

// The sources of a resolved Environment.
const (
	EnvironmentFlag             = "flag"
	EnvironmentEnvVar           = "env-var"
	EnvironmentLocalSelection   = "local-selection"
	EnvironmentCommittedDefault = "committed-default"
)

// The sources of a resolved server (ADR-0058 Decision 1). "default" and
// "only-credential" happen only outside a repository.
const (
	ServerFlag           = "flag"
	ServerEnvVar         = "env-var"
	ServerLocalOverride  = "local-override"
	ServerRepository     = "repository"
	ServerDefault        = "default"
	ServerOnlyCredential = "only-credential"
)

// Context is a resolved context. Server and Environment are strings,
// except that the local selection and override are whatever JSON
// .varlatch/local.json holds, which TypeScript passes on as they are.
type Context struct {
	Server            any
	ServerSource      string
	Organization      string
	Project           string
	Environment       any
	EnvironmentSource string
	RepoRoot          string
}

// ResolveOptions are resolveContext's options.
type ResolveOptions struct {
	Cwd string
	// Environment is the explicit --environment, "" when not given.
	Environment string
	// Server is the explicit --server, "" when not given.
	Server string
}

// ResolveContext is resolveContext().
func ResolveContext(options ResolveOptions, env Env) (*Context, error) {
	repoRoot := FindRepoRoot(options.Cwd)
	if repoRoot == "" {
		return nil, &ContextError{Message: "No " + RepoConfigFile + " found from " + options.Cwd + " upward. " +
			"Run inside a configured repository or create one with the CLI."}
	}
	repo, err := LoadRepoConfig(repoRoot)
	if err != nil {
		return nil, err
	}
	local := LoadLocalState(repoRoot)

	ctx := &Context{Organization: repo.Organization, Project: repo.Project, RepoRoot: repoRoot}
	switch {
	case options.Environment != "":
		ctx.Environment, ctx.EnvironmentSource = options.Environment, EnvironmentFlag
	case getenv(env, "VARLATCH_ENV") != "":
		ctx.Environment, ctx.EnvironmentSource = getenv(env, "VARLATCH_ENV"), EnvironmentEnvVar
	default:
		selected, _, err := LocalField(local, "selectedEnvironment")
		if err != nil {
			return nil, err
		}
		switch {
		case jsjson.Truthy(selected):
			ctx.Environment, ctx.EnvironmentSource = selected, EnvironmentLocalSelection
		case repo.DefaultEnvironment != "":
			ctx.Environment, ctx.EnvironmentSource = repo.DefaultEnvironment, EnvironmentCommittedDefault
		default:
			return nil, &ContextError{Message: "No environment selected. Pass --environment, set VARLATCH_ENV, run " +
				"`varlatch env use <name>`, or commit default_environment in varlatch.toml."}
		}
	}

	named, err := repositoryServer(options.Server, env, local, repo)
	if err != nil {
		return nil, err
	}
	if named == nil {
		// A repository never falls back to the remembered default: logging in
		// somewhere else must not move where its values go (ADR-0058 Decision 1).
		fallback, err := DefaultServer(env)
		if err != nil {
			return nil, err
		}
		message := "No server configured. Pass --server, set VARLATCH_SERVER, or commit \"server\" in " + RepoConfigFile
		if fallback != "" {
			message += `, for example: server = "` + MaskURLInValue(fallback) + `"`
		}
		return nil, &ContextError{Message: message + "."}
	}
	ctx.Server, ctx.ServerSource = named.Server, named.Source
	return ctx, nil
}

// ResolvedServer is a resolved server and where it came from.
type ResolvedServer struct {
	Server any
	Source string
}

func repositoryServer(flag string, env Env, local any, repo RepoConfig) (*ResolvedServer, error) {
	if flag != "" {
		return &ResolvedServer{flag, ServerFlag}, nil
	}
	if v := getenv(env, "VARLATCH_SERVER"); v != "" {
		return &ResolvedServer{v, ServerEnvVar}, nil
	}
	override, _, err := LocalField(local, "serverOverride")
	if err != nil {
		return nil, err
	}
	if jsjson.Truthy(override) {
		return &ResolvedServer{override, ServerLocalOverride}, nil
	}
	if repo.Server != "" {
		return &ResolvedServer{repo.Server, ServerRepository}, nil
	}
	return nil, nil
}

// ResolveServer is resolveServer(): the server a command talks to, for
// commands that need no Project (ADR-0058 Decision 1): --server,
// VARLATCH_SERVER, then inside a repository its local override and
// varlatch.toml, and nothing else; outside one, the remembered default,
// then the only stored credential. nil when none of these names a server.
// The overrides are read before any repository file; without one, an
// unreadable varlatch.toml is an error, as in ResolveContext.
func ResolveServer(cwd, server string, env Env) (*ResolvedServer, error) {
	if server != "" {
		return &ResolvedServer{server, ServerFlag}, nil
	}
	if v := getenv(env, "VARLATCH_SERVER"); v != "" {
		return &ResolvedServer{v, ServerEnvVar}, nil
	}
	if repoRoot := FindRepoRoot(cwd); repoRoot != "" {
		local := LoadLocalState(repoRoot)
		repo, err := LoadRepoConfig(repoRoot)
		if err != nil {
			return nil, err
		}
		return repositoryServer("", env, local, repo)
	}
	remembered, err := DefaultServer(env)
	if err != nil {
		return nil, err
	}
	if remembered != "" {
		return &ResolvedServer{remembered, ServerDefault}, nil
	}
	stored, err := StoredServers(env)
	if err != nil {
		return nil, err
	}
	if len(stored) == 1 {
		return &ResolvedServer{stored[0], ServerOnlyCredential}, nil
	}
	return nil, nil
}

// IsContextError reports whether err is a *ContextError, and its message.
func IsContextError(err error) (string, bool) {
	var c *ContextError
	if errors.As(err, &c) {
		return c.Message, true
	}
	return "", false
}
