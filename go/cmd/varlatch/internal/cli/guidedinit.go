// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/dotenv"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Guided `varlatch init` (slice 5.8a; ADR-0058 Decision 2; guidedInit.ts).
// Runs only on a terminal, outside assisted mode, when --org or --project
// is missing; asks only for what is missing. It plans every .env file
// before writing anything, leaves out the replacements the person
// declines, pushes one Contract revision for all files, asks separately
// before activating it, and offers to delete a file only when all of its
// values are stored and its items are in the active Contract. Every step
// prints the command it stands for; nothing it prints carries a value or a
// credential.

// guidedAPI is GuidedApi: the client calls the guided run makes.
// *apiclient.Client is one; the tests' fake is another.
type guidedAPI interface {
	ListOrganizations(ctx context.Context) (any, error)
	CreateOrganization(ctx context.Context, slug, name string) (any, error)
	ListProjects(ctx context.Context, org string) (any, error)
	CreateProject(ctx context.Context, org, slug, name, contractAuthority string) (any, error)
	ListEnvironments(ctx context.Context, org, project string) (any, error)
	CreateEnvironment(ctx context.Context, org, project string, body jsjson.Object) (any, error)
	GetActiveContract(ctx context.Context, org, project string) (any, error)
	PushContractRevision(ctx context.Context, org, project string, body jsjson.Object) (any, error)
	ActivateContractRevision(ctx context.Context, org, project, revisionID string) (any, error)
	EffectiveConfiguration(ctx context.Context, org, project, environment string, includeValues bool) (any, error)
	SetValue(ctx context.Context, org, project, environment, item, value string) (any, error)
}

// repoConfig is what varlatch.toml says.
type repoConfig struct {
	server, organization, project, defaultEnvironment string
}

// guidedDeps are GuidedInitDeps.
type guidedDeps struct {
	cwd    string
	prompt prompter
	out    func(string) error
	err    func(string) error
	// server is the server already resolved (flag, VARLATCH_SERVER,
	// default, only credential), "" when none.
	server string
	// validateServer validates and normalizes an address the person typed.
	validateServer func(raw string) (string, error)
	// signIn is a client for the server, signing in first when there is no
	// valid credential.
	signIn func(server string) (guidedAPI, error)
	// writeRepository writes varlatch.toml and the agent files, as init
	// with flags does.
	writeRepository func(repoConfig) error
	// holdValue registers a value the run handles (Run.holdValue).
	holdValue func(string)
	// organization, project and defaultEnvironment are the flags' ("" when
	// not given).
	organization, project, defaultEnvironment string
}

var (
	slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// notValues are the files that describe configuration rather than hold
	// it.
	notValues = regexp.MustCompile(`\.(example|sample|template|schema|defaults|dist)$`)
	notSlug   = regexp.MustCompile(`[^a-z0-9-]+`)
	edgeDash  = regexp.MustCompile(`^-+|-+$`)
)

// slugFrom is slugFrom: a name as a slug, "project" when it makes none.
func slugFrom(name string) string {
	slug := edgeDash.ReplaceAllString(notSlug.ReplaceAllString(jsLowerCase(name), "-"), "")
	if len(slug) > 63 {
		slug = slug[:63]
	}
	if slugPattern.MatchString(slug) {
		return slug
	}
	return "project"
}

// fileOrder is String#localeCompare: the ICU root collation Node.js's
// default locale gives it.
var fileOrder = collate.New(language.Und)

// findEnvFiles is findEnvFiles: the .env and .env.<name> files in the
// directory (a link followed), never examples or schemas, .env first and
// the rest in locale order.
func findEnvFiles(cwd string) ([]string, error) {
	entries, err := os.ReadDir(cwd)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := jsval.DecodeUTF8([]byte(e.Name()))
		if name != ".env" && !strings.HasPrefix(name, ".env.") || notValues.MatchString(name) {
			continue
		}
		if st, err := os.Stat(filepath.Join(cwd, name)); err == nil && st.Mode().IsRegular() {
			files = append(files, name)
		}
	}
	slices.SortStableFunc(files, func(a, b string) int {
		switch {
		case a == ".env":
			return -1
		case b == ".env":
			return 1
		}
		return fileOrder.CompareString(a, b)
	})
	return files, nil
}

// guidedPhase is what the run is doing, for a failure message that names
// the step and never the server's text; files: .env files were found, so a
// failure says every one of them is kept.
type guidedPhase struct {
	label string
	files bool
}

// guidedFile is FilePlan.
type guidedFile struct {
	file        string
	path        string
	environment any
	name        string // the environment's name
	bytes       []byte
	entries     []dotenv.Entry
	rows        []importRow
	// declined are the replacements the person declined.
	declined []string
}

// initCredentialedServer is INIT_CREDENTIALED_SERVER, for the flags path
// and the guided one (64).
const initCredentialedServer = "varlatch init: a server URL with a user name or password can't be written to varlatch.toml; give the server's address without them. Nothing was written."

// guidedInit is guidedInit: the exit status. An error is a failure a step
// ends the process with itself (main.ts's fail() and usageError()), given
// back as it is.
func guidedInit(raw guidedDeps) (int, error) {
	// Everything shown goes through Printable: organization, project and
	// environment names come from the server and must not act on the
	// terminal. The steps keep the original values for their API calls.
	deps := raw
	deps.out = func(line string) error { return raw.out(Printable(line)) }
	deps.err = func(line string) error { return raw.err(Printable(line)) }
	deps.prompt = printablePrompter{raw.prompt}
	phase := &guidedPhase{label: "setting up"}
	code, err := guidedSteps(deps, phase)
	if err == nil {
		return code, nil
	}
	var exit *exitError
	if errors.As(err, &exit) {
		return 0, err
	}
	// Value-free: an API error's code, a network failure's name, an import
	// error's own message (built from names only); never a server's text,
	// which could echo what was sent.
	var imp *importError
	var api *apiclient.APIError
	if errors.As(err, &imp) {
		_ = deps.err("varlatch init: " + phase.label + ": " + imp.message)
	} else {
		reason := ""
		switch network := apiclient.NetworkFailure(err); {
		case errors.As(err, &api):
			reason = safeCode(api.Code) + ", HTTP " + strconv.Itoa(api.Status)
		case network != "":
			reason = network
		default:
			reason = errorName(err)
		}
		_ = deps.err("varlatch init: " + phase.label + " failed (" + reason + ").")
	}
	if phase.files {
		_ = deps.err("varlatch init: every .env file is kept.")
	}
	switch {
	case imp != nil:
		return imp.code, nil
	case api != nil:
		code, _ := api.Code.(string)
		return APIErrorExit(api.Status, code), nil
	case apiclient.NetworkFailure(err) != "":
		return ExitUnavailable, nil
	}
	return ExitFailure, nil
}

// errnoCode is the shape of a system error's code (`/^E[A-Z]+$/`).
var errnoCode = regexp.MustCompile(`^E[A-Z]+$`)

// errorName is a thrown error's code when it is a system error's, else its
// name: TypeError for a value of another shape, Error otherwise.
func errorName(err error) string {
	var typeErr *clientctx.TypeError
	var fetch *apiclient.FetchError
	switch {
	case errors.As(err, &typeErr), errors.As(err, &fetch):
		return "TypeError"
	}
	if code := errnoName(err); errnoCode.MatchString(code) {
		return code
	}
	return "Error"
}

// errnoName is a system error's code as Node.js names it, "" for any
// other error.
func errnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		for _, known := range []struct {
			errno syscall.Errno
			name  string
		}{{syscall.EACCES, "EACCES"}, {syscall.EPERM, "EPERM"}, {syscall.ENOENT, "ENOENT"}, {syscall.EEXIST, "EEXIST"},
			{syscall.EISDIR, "EISDIR"}, {syscall.ENOTDIR, "ENOTDIR"}, {syscall.EROFS, "EROFS"}, {syscall.ENOSPC, "ENOSPC"}} {
			if errno == known.errno {
				return known.name
			}
		}
	}
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "EACCES"
	case errors.Is(err, fs.ErrNotExist):
		return "ENOENT"
	case errors.Is(err, fs.ErrExist):
		return "EEXIST"
	}
	return ""
}

// printablePrompter is the prompter with every question, option, default
// and line through Printable.
type printablePrompter struct{ p prompter }

func (p printablePrompter) choose(question string, options []string, preselected int) (int, error) {
	shown := make([]string, len(options))
	for i, o := range options {
		shown[i] = Printable(o)
	}
	return p.p.choose(Printable(question), shown, preselected)
}

func (p printablePrompter) confirm(question string, defaultYes bool) (bool, error) {
	return p.p.confirm(Printable(question), defaultYes)
}

func (p printablePrompter) text(question, defaultValue string) (string, error) {
	return p.p.text(Printable(question), Printable(defaultValue))
}

func (p printablePrompter) say(line string) error { return p.p.say(Printable(line)) }

// listItems is `(await call()).items` read as a list: the shapes the
// steps go on to `.map` and `.length`.
func listItems(answer any, expr string) ([]any, error) {
	items, ok, err := read(answer, answer != apiclient.Undefined, "items")
	if err != nil {
		return nil, err
	}
	list, isList := items.([]any)
	if !ok || !isList {
		return nil, &clientctx.TypeError{Message: expr + " is not a function"}
	}
	return list, nil
}

// jsField is `${v.key}`.
func jsField(v any, key string) string {
	got, ok := jsval.Get(v, key)
	return jsTemplate(got, ok)
}

func guidedSteps(deps guidedDeps, phase *guidedPhase) (int, error) {
	prompt, out := deps.prompt, deps.out
	bg := context.Background()
	command := func(line string) error { return out("  $ " + line) }

	// 1. Server and sign-in.
	server := deps.server
	if server == "" {
		for {
			typed, err := prompt.text("Your Varlatch installation's address (https://...)", "")
			if err != nil {
				return 0, err
			}
			if valid, err := deps.validateServer(typed); err == nil {
				server = valid
				break
			}
			// A fixed message: what was typed may hold a credential, and is
			// never echoed.
			if err := prompt.say("That is not an installation's address: use https://<host>[:port], or http://localhost for a local trial, without a path or query."); err != nil {
				return 0, err
			}
		}
	}
	// varlatch.toml is committed: a user name or password in the URL never
	// goes there, so the run stops before signing in or printing it.
	if clientctx.HasUserinfo(server) {
		_ = deps.err(initCredentialedServer)
		return ExitUsage, nil
	}
	if err := out("Server: " + shownServer(server)); err != nil {
		return 0, err
	}
	phase.label = "signing in"
	api, err := deps.signIn(server)
	if err != nil {
		return 0, err
	}
	phase.label = "reading or creating the organization"

	// 2. Organization.
	organization := deps.organization
	if organization == "" {
		answer, err := api.ListOrganizations(bg)
		if err != nil {
			return 0, err
		}
		orgs, err := listItems(answer, "orgs.map")
		if err != nil {
			return 0, err
		}
		choice := len(orgs)
		if len(orgs) > 0 {
			options := make([]string, 0, len(orgs)+1)
			for _, o := range orgs {
				options = append(options, jsField(o, "slug")+" ("+jsField(o, "name")+")")
			}
			if choice, err = prompt.choose("Organization:", append(options, "Create a new organization"), 0); err != nil {
				return 0, err
			}
		}
		if choice < len(orgs) {
			organization = jsField(orgs[choice], "slug")
		} else {
			slug, err := askSlug(prompt, "New organization's slug (lowercase letters, digits, hyphens)", "")
			if err != nil {
				return 0, err
			}
			name, err := prompt.text("Its name", slug)
			if err != nil {
				return 0, err
			}
			ok, err := prompt.confirm("Create organization "+slug+" ("+name+")?", true)
			if err != nil {
				return 0, err
			}
			if !ok {
				return stopped(deps, "No organization was created.")
			}
			if _, err := api.CreateOrganization(bg, slug, name); err != nil {
				return 0, err
			}
			if err := command("varlatch org create " + slug + " " + string(jsjson.Stringify(name))); err != nil {
				return 0, err
			}
			organization = slug
		}
	}

	// 3. Project.
	phase.label = "reading or creating the project"
	project := deps.project
	var projectInfo any
	answer, err := api.ListProjects(bg, organization)
	if err != nil {
		return 0, err
	}
	projects, err := listItems(answer, "projects.map")
	if err != nil {
		return 0, err
	}
	if project == "" {
		choice := len(projects)
		if len(projects) > 0 {
			options := make([]string, 0, len(projects)+1)
			for _, p := range projects {
				options = append(options, jsField(p, "slug")+" ("+jsField(p, "name")+")")
			}
			if choice, err = prompt.choose("Project:", append(options, "Create a new project"), 0); err != nil {
				return 0, err
			}
		}
		if choice < len(projects) {
			projectInfo = projects[choice]
			project = jsField(projectInfo, "slug")
		} else {
			slug, err := askSlug(prompt, "New project's slug", slugFrom(filepath.Base(deps.cwd)))
			if err != nil {
				return 0, err
			}
			name, err := prompt.text("Its name", slug)
			if err != nil {
				return 0, err
			}
			ok, err := prompt.confirm("Create project "+slug+" in "+organization+"? Its Contract comes from the repository.", true)
			if err != nil {
				return 0, err
			}
			if !ok {
				return stopped(deps, "No project was created.")
			}
			if projectInfo, err = api.CreateProject(bg, organization, slug, name, "git"); err != nil {
				return 0, err
			}
			if err := command("varlatch project create " + slug + " --org " + organization); err != nil {
				return 0, err
			}
			project = slug
		}
	} else {
		for _, p := range projects {
			if s, _ := jsval.Get(p, "slug"); s == project {
				projectInfo = p
				break
			}
		}
	}

	// 4. Environments.
	phase.label = "reading or creating the environments"
	answer, err = api.ListEnvironments(bg, organization, project)
	if err != nil {
		return 0, err
	}
	environments, err := listItems(answer, "environments.filter")
	if err != nil {
		return 0, err
	}
	if len(environments) == 0 {
		ok, err := prompt.confirm("The project has no environments. Create development (tier development) and production (tier production)?", true)
		if err != nil {
			return 0, err
		}
		if ok {
			for _, name := range []string{"development", "production"} {
				if _, err := api.CreateEnvironment(bg, organization, project, jsjson.Object{{Key: "name", Value: name}, {Key: "tier", Value: name}}); err != nil {
					return 0, err
				}
				if err := command("varlatch env-create " + name + " --tier " + name); err != nil {
					return 0, err
				}
			}
			if answer, err = api.ListEnvironments(bg, organization, project); err != nil {
				return 0, err
			}
			if environments, err = listItems(answer, "environments.filter"); err != nil {
				return 0, err
			}
		}
	}
	var shared []any
	for _, e := range environments {
		if k, _ := jsval.Get(e, "kind"); k == "shared" {
			shared = append(shared, e)
		}
	}
	defaultEnvironment := deps.defaultEnvironment
	if defaultEnvironment == "" {
		switch {
		case len(shared) > 1:
			pre := 0
			for i, e := range shared {
				if n, _ := jsval.Get(e, "name"); n == "development" {
					pre = i
					break
				}
			}
			options := make([]string, len(shared))
			for i, e := range shared {
				options[i] = jsField(e, "name") + " (" + jsField(e, "tier") + ")"
			}
			choice, err := prompt.choose("Default environment for this repository:", options, pre)
			if err != nil {
				return 0, err
			}
			defaultEnvironment = jsField(shared[choice], "name")
		case len(shared) == 1:
			defaultEnvironment = jsField(shared[0], "name")
		default:
			defaultEnvironment = "development"
		}
	}

	// 5. varlatch.toml and the agent files.
	phase.label = "writing varlatch.toml"
	if err := deps.writeRepository(repoConfig{server, organization, project, defaultEnvironment}); err != nil {
		return 0, err
	}
	extra := ""
	if defaultEnvironment != "development" {
		extra = " --default-environment " + defaultEnvironment
	}
	if err := command("varlatch init --org " + organization + " --project " + project + " --server " + shownServer(server) + extra); err != nil {
		return 0, err
	}

	// 6. .env files: plan everything first.
	files, err := findEnvFiles(deps.cwd)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 || len(shared) == 0 {
		if len(files) > 0 {
			if err := out("The project has no environments, so no .env file was imported."); err != nil {
				return 0, err
			}
		}
		return done(deps)
	}
	if err := out("Found " + strings.Join(files, ", ") + "."); err != nil {
		return 0, err
	}
	phase.files = true
	phase.label = "reading the Contract"
	authority, _ := jsval.Get(projectInfo, "contractAuthority")
	managed := authority == "managed"
	active, forbidden, err := activeContractOf(api, organization, project)
	if err != nil {
		return 0, err
	}
	canAddItems := !managed && !forbidden
	var semanticsVersion any = float64(contract.LatestSemanticsVersion)
	if jsjson.Truthy(active) {
		semanticsVersion = float64(1)
		if v, ok := jsval.Get(active, "semanticsVersion"); ok && v != nil {
			semanticsVersion = v
		}
	}
	var activeItems []any
	if active != nil {
		if items, ok := jsval.Get(active, "items"); ok && items != nil {
			list, isList := items.([]any)
			if !isList {
				return 0, &clientctx.TypeError{Message: "(active?.items ?? []).map is not a function"}
			}
			activeItems = list
		}
	}
	contracted := map[string]any{}
	for _, item := range activeItems {
		contracted[jsField(item, "name")] = item
	}
	switch {
	case forbidden:
		err = out("You cannot read this project's Contract: values only, and every .env file is kept, since whether its items are in the Contract is unknown.")
	case managed:
		err = out("This project's Contract is managed in the dashboard: values only; new items are added there.")
	}
	if err != nil {
		return 0, err
	}

	var plans []*guidedFile
	used := map[string]bool{}
	for _, file := range files {
		options := make([]string, 0, len(shared)+1)
		for _, e := range shared {
			options = append(options, jsField(e, "name")+" ("+jsField(e, "tier")+")")
		}
		options = append(options, "Skip this file")
		guess := defaultEnvironment
		if file != ".env" {
			guess = file[len(".env."):]
		}
		pre := len(options) - 1
		for i, e := range shared {
			if n := jsField(e, "name"); n == guess && !used[n] {
				pre = i
				break
			}
		}
		var environment any
		for {
			choice, err := prompt.choose("Import "+file+" into:", options, pre)
			if err != nil {
				return 0, err
			}
			if choice == len(options)-1 {
				break
			}
			candidate := shared[choice]
			if used[jsField(candidate, "name")] {
				if err := prompt.say("Another file already goes to " + jsField(candidate, "name") + "; one file per environment."); err != nil {
					return 0, err
				}
				continue
			}
			environment = candidate
			break
		}
		if environment == nil {
			if err := out(file + ": skipped; it is kept."); err != nil {
				return 0, err
			}
			continue
		}
		envName := jsField(environment, "name")
		path := filepath.Join(deps.cwd, file)
		src, entries, err := readSource(path, false)
		if err != nil {
			var imp *importError
			message := "cannot be read"
			if errors.As(err, &imp) {
				message = imp.message
			}
			if err := out(file + ": " + message + " It is kept."); err != nil {
				return 0, err
			}
			continue
		}
		if problems := checkEntries(entries); len(problems) > 0 {
			for _, p := range problems {
				if err := deps.err("varlatch init: " + file + " " + p); err != nil {
					return 0, err
				}
			}
			if err := out(file + ": " + strconv.Itoa(len(problems)) + " problem(s); nothing from it is imported, and it is kept."); err != nil {
				return 0, err
			}
			continue
		}
		if len(entries) == 0 {
			if err := out(file + " sets no values; nothing to import."); err != nil {
				return 0, err
			}
			continue
		}
		phase.label = "reading what " + envName + " already has"
		present, status, err := presentOf(api, organization, project, envName)
		if err != nil {
			return 0, err
		}
		if present == nil {
			if err := out(file + ": what " + envName + " already has cannot be read (" + strconv.Itoa(status) + "), so a value could be replaced unseen. Nothing from it is imported, and it is kept."); err != nil {
				return 0, err
			}
			continue
		}
		used[envName] = true
		rows, err := planRows(entries, contracted, present, semanticsVersion, canAddItems, nil)
		if err != nil {
			return 0, err
		}
		// The Secrets, and the values of unknown sensitivity, are in flight
		// from here on, as import holds them: no output or diagnostic shows
		// one.
		for _, row := range rows {
			if !row.contracted || row.sensitive != false {
				deps.holdValue(row.entry.Value)
			}
		}
		tier := jsField(environment, "tier")
		if err := out(file + " → " + organization + " / " + project + " / " + envName + " (" + tier + "): " + strconv.Itoa(len(rows)) + " value(s)"); err != nil {
			return 0, err
		}
		for _, line := range formatRows(rows, nil) {
			if err := out(line); err != nil {
				return 0, err
			}
		}
		var replacing []string
		for _, row := range rows {
			if row.existing == true {
				replacing = append(replacing, row.entry.Name)
			}
		}
		var declined []string
		if len(replacing) > 0 {
			if err := out(envName + " already has a different value for " + strings.Join(replacing, ", ") + "."); err != nil {
				return 0, err
			}
			them := "them"
			if len(replacing) == 1 {
				them = "it"
			}
			approved, err := prompt.confirm("Replace "+them+" with the values in "+file+"?", false)
			if err != nil {
				return 0, err
			}
			if approved && tier == "production" {
				typed, err := prompt.text("This is a production environment. Type "+envName+" to replace them", "")
				if err != nil {
					return 0, err
				}
				approved = typed == envName
				if !approved {
					if err := out("Not typed: they are left as they are."); err != nil {
						return 0, err
					}
				}
			}
			if !approved {
				declined = append(declined, replacing...)
			}
		}
		plans = append(plans, &guidedFile{file: file, path: path, environment: environment, name: envName, bytes: src.bytes, entries: entries, rows: rows, declined: declined})
	}
	if len(plans) == 0 {
		return done(deps)
	}

	// 7. Contract additions, once for all files.
	type addition struct {
		types []string
		files []string
	}
	additions := map[string]*addition{}
	var order []string // a Map's insertion order
	if canAddItems {
		for _, plan := range plans {
			for _, row := range plan.rows {
				if row.contracted || slices.Contains(plan.declined, row.entry.Name) {
					continue
				}
				a := additions[row.entry.Name]
				if a == nil {
					a = &addition{}
					additions[row.entry.Name] = a
					order = append(order, row.entry.Name)
				}
				if t := typeText(row.typ); !slices.Contains(a.types, t) {
					a.types = append(a.types, t)
				}
				a.files = append(a.files, plan.file)
			}
		}
	}
	chosenTypes := map[string]string{}
	var plain []string
	if len(additions) > 0 {
		if err := out("New items for the Contract (" + strconv.Itoa(len(additions)) + "), each a Secret unless you name it:"); err != nil {
			return 0, err
		}
		for _, name := range order {
			a := additions[name]
			if len(a.types) == 1 {
				chosenTypes[name] = a.types[0]
				continue
			}
			types := []string{"string"}
			for _, t := range a.types {
				if !slices.Contains(types, t) {
					types = append(types, t)
				}
			}
			choice, err := prompt.choose(name+": the files suggest different types ("+strings.Join(a.types, ", ")+"). Its type:", types, 0)
			if err != nil {
				return 0, err
			}
			chosenTypes[name] = types[choice]
		}
		for _, name := range order {
			if err := out("  " + name + "  " + chosenTypes[name]); err != nil {
				return 0, err
			}
		}
		named, err := prompt.text("Items that are not secret (comma-separated names), or Enter for none", "")
		if err != nil {
			return 0, err
		}
		for _, n := range strings.Split(named, ",") {
			n = strings.TrimFunc(n, isJSWhitespace)
			if n == "" {
				continue
			}
			if additions[n] != nil {
				if !slices.Contains(plain, n) {
					plain = append(plain, n)
				}
			} else if err := prompt.say(n + " is not a new item; ignored."); err != nil {
				return 0, err
			}
		}
	}

	// 8. Write: one revision, not activated, then the values.
	var revisionID string
	revisionActive, haveRevision := false, false
	if len(additions) > 0 {
		items := append([]any{}, activeItems...)
		for _, name := range order {
			items = append(items, jsjson.Object{
				{Key: "name", Value: name},
				{Key: "required", Value: jsjson.Object{{Key: "kind", Value: "never"}}},
				{Key: "sensitive", Value: !slices.Contains(plain, name)},
				{Key: "type", Value: chosenTypes[name]},
			})
		}
		next := jsjson.Object{{Key: "schemaVersion", Value: float64(contract.SchemaVersion)}}
		if active != nil {
			next = spread(active)
		}
		next = next.Set("items", items)
		phase.label = "pushing the Contract revision"
		pushed, err := api.PushContractRevision(bg, organization, project, jsjson.Object{
			{Key: "contract", Value: next},
			{Key: "provenance", Value: jsjson.Object{{Key: "adapter", Value: "varlatch-init"}}},
		})
		if err != nil {
			return 0, err
		}
		id, _ := jsval.Get(pushed, "id")
		activeAnswer, _ := jsval.Get(pushed, "active")
		revisionID, revisionActive, haveRevision = jsjson.String(id), jsjson.Truthy(activeAnswer), true
		mark := ""
		if revisionActive {
			mark = " [active]"
		}
		if err := out("Contract revision " + revisionID + " with " + strconv.Itoa(len(additions)) + " new item(s)" + mark + "."); err != nil {
			return 0, err
		}
	}
	phase.label = "storing values"
	approvedOf := func(plan *guidedFile) []dotenv.Entry {
		var approved []dotenv.Entry
		for _, e := range plan.entries {
			if !slices.Contains(plan.declined, e.Name) {
				approved = append(approved, e)
			}
		}
		return approved
	}
	namesOf := func(entries []dotenv.Entry) string {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name
		}
		return strings.Join(names, ", ")
	}
	for index, plan := range plans {
		target := &clientctx.Context{Organization: organization, Project: project, Environment: plan.name}
		stored, failure := storeEntries(api, target, approvedOf(plan))
		if failure != nil {
			// One summary for every file: what was stored, what failed, what
			// was never attempted.
			where := func(p *guidedFile) string {
				return organization + " / " + project + " / " + p.name + " (" + p.file + ")"
			}
			for _, earlier := range plans[:index] {
				_ = deps.err("varlatch init: stored in " + where(earlier) + ": " + namesOf(approvedOf(earlier)))
			}
			if len(stored) > 0 {
				_ = deps.err("varlatch init: stored in " + where(plan) + ": " + strings.Join(stored, ", "))
			}
			_ = deps.err("varlatch init: not stored in " + where(plan) + ": " + failure.name + " (" + failure.reason + ")")
			if len(failure.skipped) > 0 {
				_ = deps.err("varlatch init: not attempted in " + where(plan) + ": " + strings.Join(failure.skipped, ", "))
			}
			for _, later := range plans[index+1:] {
				if names := namesOf(approvedOf(later)); names != "" {
					_ = deps.err("varlatch init: not attempted in " + where(later) + ": " + names)
				}
			}
			if haveRevision && !revisionActive {
				_ = deps.err("varlatch init: Contract revision " + revisionID + " was not activated.")
			}
			_ = deps.err("varlatch init: every .env file is kept. Fix the cause, then import the rest with varlatch import <file> -e <environment>.")
			return failure.code, nil
		}
		if err := out("Stored " + strconv.Itoa(len(stored)) + " value(s) from " + plan.file + " in " + plan.name + "."); err != nil {
			return 0, err
		}
		withContract := ""
		if len(additions) > 0 {
			withContract = " --contract"
		}
		if err := command("varlatch import " + plan.file + " -e " + plan.name + withContract); err != nil {
			return 0, err
		}
		if len(plan.declined) > 0 {
			if err := out("Left as they were in " + plan.name + ": " + strings.Join(plan.declined, ", ") + "."); err != nil {
				return 0, err
			}
		}
	}

	// 9. Activation, asked on its own.
	activated := haveRevision && revisionActive
	switch {
	case haveRevision && !revisionActive:
		described := make([]string, len(order))
		for i, n := range order {
			kind := "secret"
			if slices.Contains(plain, n) {
				kind = "plain"
			}
			described[i] = n + " (" + chosenTypes[n] + ", " + kind + ")"
		}
		if err := out("Revision " + revisionID + " adds: " + strings.Join(described, ", ") + "."); err != nil {
			return 0, err
		}
		ok, err := prompt.confirm("Activate it? The Contract applies to the whole project, every environment.", true)
		if err != nil {
			return 0, err
		}
		if ok {
			phase.label = "activating Contract revision " + revisionID
			if _, err := api.ActivateContractRevision(bg, organization, project, revisionID); err != nil {
				return 0, err
			}
			activated = true
			if err := command("varlatch contract activate " + revisionID); err != nil {
				return 0, err
			}
		} else if err := out("Not activated. To activate it later: varlatch contract activate " + revisionID); err != nil {
			return 0, err
		}
	case canAddItems && len(additions) == 0:
		if err := out("Every item was already in the Contract; no revision was needed."); err != nil {
			return 0, err
		}
	}

	// 10. Deleting the sources: last, default no, only when nothing is left
	// behind.
	phase.label = "deleting .env files"
	// In the active Contract after this run: what it had, plus the additions
	// once activated.
	inActive := func(name string) bool {
		_, had := contracted[name]
		return had || activated && additions[name] != nil
	}
	for _, plan := range plans {
		var missing []string
		for _, row := range plan.rows {
			if !inActive(row.entry.Name) {
				missing = append(missing, row.entry.Name)
			}
		}
		why := ""
		switch {
		case len(plan.declined) > 0:
			why = "it holds values you chose not to store"
		case forbidden:
			why = "whether its items are in the Contract cannot be read"
		case len(missing) > 0 && managed:
			why = strings.Join(missing, ", ") + " still need adding to the Contract in the dashboard"
		case len(missing) > 0:
			why = "its new items are not in the active Contract"
		}
		if why != "" {
			if err := out(plan.file + " is kept: " + why + "."); err != nil {
				return 0, err
			}
			continue
		}
		ok, err := prompt.confirm("Delete "+plan.file+"? Its values are stored in "+plan.name+"; other copies (CI, teammates) are not affected.", false)
		if err != nil {
			return 0, err
		}
		if !ok {
			if err := out(plan.file + " is kept; delete it once you no longer need it."); err != nil {
				return 0, err
			}
			continue
		}
		deleted, link, err := deleteSource(plan.path, plan.bytes)
		if err != nil {
			return 0, err
		}
		switch {
		case deleted:
			err = out("Deleted " + plan.file + ".")
		case link:
			err = out(plan.file + " is a symbolic link, so it was not deleted: deleting the link would leave the values in the file it points to.")
		default:
			err = out(plan.file + " changed or disappeared since it was read; it was not deleted.")
		}
		if err != nil {
			return 0, err
		}
	}
	return done(deps)
}

// deleteSource is finishSource for a file guided init read: deleted only
// if the path still names a regular file holding the bytes read (opened
// without following a link, and that same file removed). A symbolic link
// is never removed (link: true): deleting it would leave the values in the
// file it points to (go/README.md, `init-delete-link`).
func deleteSource(path string, snapshot []byte) (deleted, link bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, false, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, true, nil
	}
	if !info.Mode().IsRegular() {
		return false, false, nil
	}
	f, err := openNoFollow(path)
	if err != nil {
		return false, false, nil
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = f.Close()
		return false, false, nil
	}
	deleted, err = finishSource(path, &source{bytes: snapshot, open: f, info: opened})
	return deleted, false, err
}

// askSlug is askSlug: a slug, asked again until it is one.
func askSlug(prompt prompter, question, defaultValue string) (string, error) {
	for {
		slug, err := prompt.text(question, defaultValue)
		if err != nil {
			return "", err
		}
		if slugPattern.MatchString(slug) {
			return slug, nil
		}
		if err := prompt.say("Use lowercase letters, digits and hyphens, starting and ending with a letter or digit."); err != nil {
			return "", err
		}
	}
}

func stopped(deps guidedDeps, message string) (int, error) {
	if err := deps.out(message + " No file was written."); err != nil {
		return 0, err
	}
	return ExitFailure, nil
}

func done(deps guidedDeps) (int, error) {
	if err := deps.out("Done. Run your application with its configuration: varlatch run -- <command>"); err != nil {
		return 0, err
	}
	return ExitOK, nil
}

// ---- Sign-in ------------------------------------------------------------------------

// signInParts are SignInParts: the calls the guided sign-in makes.
type signInParts struct {
	// browserLogin is the browser hand-off: prints the locally built address
	// to open, gives the session bearer.
	browserLogin func(server string) (string, error)
	// client is a client for the server with this bearer.
	client func(token string) guidedSignInAPI
	// save stores the verified credential, as varlatch login does.
	save func(credential jsjson.Object) error
	out  func(string) error
}

// guidedSignInAPI are the calls the guided sign-in makes with a bearer.
type guidedSignInAPI interface {
	ExchangeCliCredential(ctx context.Context, input jsjson.Object) (any, error)
	ListOrganizations(ctx context.Context) (any, error)
}

// guidedSignIn is guidedSignIn: varlatch login's browser hand-off, done
// here so that nothing a server sends is printed: only fixed lines and the
// address it built itself. Errors go to guidedInit's value-free handler.
func guidedSignIn(server string, parts signInParts) (guidedSignInAPI, error) {
	handoff, err := parts.browserLogin(server)
	if err != nil {
		return nil, err
	}
	issued, err := parts.client(handoff).ExchangeCliCredential(context.Background(), jsjson.Object{})
	if err != nil {
		return nil, err
	}
	token, tokenOK, err := read(issued, issued != apiclient.Undefined, "token")
	if err != nil {
		return nil, err
	}
	api := parts.client(jsTemplate(token, tokenOK))
	// Verifies the credential before it is stored.
	if _, err := api.ListOrganizations(context.Background()); err != nil {
		return nil, err
	}
	expiresAt, expiresOK := jsval.Get(issued, "expiresAt")
	id, idOK := jsval.Get(issued, "id")
	credential := jsjson.Object{{Key: "token", Value: token}, {Key: "issuedAt", Value: isoString(time.Now().UTC())}}
	if expiresOK && expiresAt != apiclient.Undefined {
		credential = append(credential, jsjson.Member{Key: "expiresAt", Value: expiresAt})
	}
	if idOK && id != apiclient.Undefined {
		credential = append(credential, jsjson.Member{Key: "credentialId", Value: id})
	}
	if err := parts.save(credential); err != nil {
		return nil, err
	}
	if err := parts.out("Signed in to " + shownServer(server) + "."); err != nil {
		return nil, err
	}
	return api, nil
}

// ---- The server's address --------------------------------------------------------

// loopbackHosts is setup.ts's LOOPBACK.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

// validatePublicURL is setup.ts's validatePublicUrl: the origin of an
// installation's address, https (or http on a loopback host), with no
// path, query or fragment. Its error is never shown: what was typed may
// hold a credential.
func validatePublicURL(raw string) (string, error) {
	u, ok := whatwg.ParseURL(strings.TrimFunc(raw, isJSWhitespace))
	if !ok {
		return "", errors.New("not a URL")
	}
	if u.Pathname != "/" || u.Search != "" || u.Hash != "" {
		return "", errors.New("use an origin without path or query")
	}
	host := u.Host
	hostname := host
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			hostname = host[:end+1]
		}
	} else if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		hostname = host[:colon]
	}
	if u.Protocol != "https:" && !(u.Protocol == "http:" && loopbackHosts[hostname]) {
		return "", errors.New("browsers only allow passkeys on HTTPS")
	}
	return u.Protocol + "//" + host, nil
}
