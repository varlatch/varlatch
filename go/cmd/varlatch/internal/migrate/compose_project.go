// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ComposeProject is an installation's Compose project as migrate drives
// it: every docker compose command names it (--project-name,
// --project-directory and a -f per file), never what Compose would find in
// the directory by itself. A directory can hold another Compose file than
// the one that runs: Coolify's holds its own docker-compose.yaml beside the
// repository's docker-compose.yml, which names another project.
type ComposeProject struct {
	Name string `json:"name"`
	// Dir and Files are as the containers' labels give them (absolute),
	// without migrate's own OverrideFile, which .env's COMPOSE_FILE names
	// while a reverse's database is in use.
	Dir   string   `json:"dir"`
	Files []string `json:"files"`
}

// The labels Compose puts on a container.
const (
	labelProject = "com.docker.compose.project"
	labelService = "com.docker.compose.service"
	labelFiles   = "com.docker.compose.project.config_files"
	labelDir     = "com.docker.compose.project.working_dir"
	labelOneOff  = "com.docker.compose.oneoff"
)

// composeContainer is what migrate reads of a Compose container of this
// host: whose it is, whether it runs, and the volumes it mounts.
type composeContainer struct {
	project, service, files, dir, oneOff string
	status                               string
	mounts                               []containerMount
}

type containerMount struct {
	Type        string
	Name        string
	Destination string
}

func (l composeContainer) isOneOff() bool { return strings.EqualFold(l.oneOff, "true") }

// volumeAt is the named volume mounted at target ("" for none).
func (l composeContainer) volumeAt(target string) string {
	for _, m := range l.mounts {
		if m.Destination == target && m.Type == "volume" {
			return m.Name
		}
	}
	return ""
}

// containersFormat prints them, each as JSON.
const containersFormat = `{{json (index .Config.Labels "` + labelProject + `")}} {{json (index .Config.Labels "` + labelService + `")}} {{json (index .Config.Labels "` + labelFiles +
	`")}} {{json (index .Config.Labels "` + labelDir + `")}} {{json (index .Config.Labels "` + labelOneOff + `")}} {{json .State.Status}} {{json .Mounts}}`

// composeNames and overrideNames are the files Compose reads by itself in
// a directory, in its order.
var (
	composeNames  = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}
	overrideNames = []string{"compose.override.yml", "compose.override.yaml", "docker-compose.override.yml", "docker-compose.override.yaml"}
)

// ProjectChangedError is an installation that is not, now, the Compose
// project a migration started from, or whose project another directory's
// containers own.
type ProjectChangedError struct{ msg string }

func (e *ProjectChangedError) Error() string { return e.msg }

// KeepProject is the project a migration's journal records (nil: a new
// migration takes what is there): the commands that go on with it use it,
// and refuse when the containers say another.
func (c *Compose) KeepProject(p *ComposeProject) { c.kept, c.resolved = p, nil }

// CheckProject reads the host's containers again and refuses a project
// that is not the journal's, not the one this run began with, or not this
// directory's alone. It comes before anything that changes a state.
func (c *Compose) CheckProject(ctx context.Context) error {
	_, _, err := c.verified(ctx)
	return err
}

// verified is the project, read again, and the host's Compose containers.
func (c *Compose) verified(ctx context.Context) (*ComposeProject, []composeContainer, error) {
	all, err := c.containers(ctx)
	if err != nil {
		return nil, nil, err
	}
	p, err := c.resolve(ctx, all)
	if err != nil {
		return nil, nil, err
	}
	if c.resolved != nil && !sameProject(p, c.resolved) {
		return nil, nil, &ProjectChangedError{fmt.Sprintf("the Compose project was %s when this began, and is %s now: nothing more was done", c.resolved, p)}
	}
	c.resolved = p
	return p, all, nil
}

// project is the installation's, as last verified.
func (c *Compose) project(ctx context.Context) (*ComposeProject, error) {
	if c.resolved != nil {
		return c.resolved, nil
	}
	p, _, err := c.verified(ctx)
	return p, err
}

func (c *Compose) resolve(ctx context.Context, all []composeContainer) (*ComposeProject, error) {
	live, err := c.liveProject(all)
	if err != nil {
		return nil, err
	}
	p := live
	if c.kept != nil {
		if live != nil && !sameProject(live, c.kept) {
			return nil, &ProjectChangedError{fmt.Sprintf("the migration's journal records the Compose project %s, and the containers of %s are now of %s: the installation was started another way since. "+
				"Put it back as the journal has it, then run this again (before the barrier, varlatch migrate --abort ends this migration instead, and a new one takes the installation as it is); nothing was done",
				c.kept, c.Directory, live)}
		}
		p = c.kept
	}
	if p == nil {
		// Without containers (a down of this run's), what it began with.
		p = c.resolved
	}
	if p == nil {
		if p, err = c.projectFromFiles(ctx); err != nil {
			return nil, err
		}
	}
	// Whatever named it (containers, the journal, files): no other
	// directory's containers are of that project.
	for _, l := range all {
		if l.project != p.Name {
			continue
		}
		if l.dir == "" || realPath(l.dir) != realPath(c.Directory) {
			return nil, &ProjectChangedError{fmt.Sprintf("the Compose project %s has a %s container made from %s (files %s), not from %s: it is another installation's project too, and migrate would act on it; nothing was done",
				p.Name, orWord(l.service, "nameless"), orWord(l.dir, "a directory it does not name"), orWord(l.files, "it does not name"), c.Directory)}
		}
		// A container that did not change may name files since renamed or
		// added to; one made from others that are still there is of another
		// installation under the same name.
		if files := withoutOverride(labelPaths(l)); len(files) > 0 && !slices.ContainsFunc(files, func(f string) bool { return isOf(p.Files, f) || !isFile(f) }) {
			return nil, &ProjectChangedError{fmt.Sprintf("the Compose project %s has a %s container made from %s, none of which is among the project's files (%s): migrate would act on another installation's container; nothing was done",
				p.Name, orWord(l.service, "nameless"), strings.Join(files, ", "), strings.Join(p.Files, ", "))}
		}
	}
	for _, f := range p.Files {
		if !isFile(f) {
			return nil, &ProjectChangedError{fmt.Sprintf("the Compose project %s is made from %s, which is not there (or not a file): nothing was done", p.Name, f)}
		}
	}
	return p, nil
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func isOf(files []string, f string) bool {
	return slices.ContainsFunc(files, func(x string) bool { return realPath(x) == realPath(f) })
}

func orWord(s, word string) string {
	if s == "" {
		return word
	}
	return s
}

func (p *ComposeProject) String() string {
	return fmt.Sprintf("%s (directory %s, files %s)", p.Name, p.Dir, strings.Join(p.Files, ", "))
}

func sameProject(a, b *ComposeProject) bool {
	return a.Name == b.Name && realPath(a.Dir) == realPath(b.Dir) && sameFiles(a.Files, b.Files)
}

// realPath is p without its symbolic links, as far as it exists.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

func sameFiles(a, b []string) bool {
	return slices.EqualFunc(a, b, func(x, y string) bool { return realPath(x) == realPath(y) })
}

// liveProject is the project of the containers made from Directory, by
// their labels: exactly one; nil when there are no containers. It is
// refused when they are of two projects, when one was made from this
// directory's files as another directory's project, or when their files,
// .env and the shell name different ones: never a guess.
func (c *Compose) liveProject(all []composeContainer) (*ComposeProject, error) {
	dir := realPath(c.Directory)
	var here []composeContainer
	for _, l := range all {
		switch {
		case l.isOneOff() || l.project == "" || l.dir == "":
		case realPath(l.dir) == dir:
			here = append(here, l)
		case l.service == service:
			for _, f := range labelPaths(l) {
				if realPath(filepath.Dir(f)) == dir {
					return nil, fmt.Errorf("a %s container of the Compose project %s is made from %s, but its project directory is %s, not %s: give that directory as --from", service, l.project, f, l.dir, c.Directory)
				}
			}
		}
	}
	if len(here) == 0 {
		return nil, nil
	}
	names := distinct(here, func(l composeContainer) string { return l.project })
	if len(names) > 1 {
		return nil, &ProjectChangedError{fmt.Sprintf("%s holds the containers of %d Compose projects (%s): a migration takes an installation of one; remove the other's containers first", c.Directory, len(names), strings.Join(names, ", "))}
	}
	p := &ComposeProject{Name: names[0], Dir: here[0].dir}
	var lists [][]string
	for _, l := range here {
		files := withoutOverride(labelPaths(l))
		if len(files) == 0 {
			return nil, fmt.Errorf("a %s container of the Compose project %s names no Compose file it was made from (%s)", l.service, p.Name, labelFiles)
		}
		if !slices.ContainsFunc(lists, func(x []string) bool { return sameFiles(x, files) }) {
			lists = append(lists, files)
		}
	}
	own, err := c.ownFiles()
	if err != nil && !errors.Is(err, errManyComposeFiles) && !errors.Is(err, errNoComposeFile) {
		return nil, err
	}
	if len(lists) == 1 {
		p.Files = lists[0]
	} else {
		// A container that did not change keeps the label of the files it
		// was first made from, so a file added since (Caddy's, an override)
		// is only on those made again. What Compose reads here settles it,
		// when some of them were made from exactly that.
		i := -1
		if own != nil {
			i = slices.IndexFunc(lists, func(x []string) bool { return sameFiles(x, own.files) })
		}
		if i < 0 {
			return nil, fmt.Errorf("the containers of the Compose project %s were made from different files (%s), and %s does not say which are its own. %s", p.Name, listsText(lists), c.Directory, c.restoreText(lists[0]))
		}
		p.Files = lists[i]
	}
	// What the directory and the shell say must be the same.
	if own != nil && !sameFiles(own.files, p.Files) {
		return nil, &ProjectChangedError{fmt.Sprintf("%s names the Compose files %s, but the containers of the project %s were made from %s. %s", own.from, strings.Join(own.files, ", "), p.Name, strings.Join(p.Files, ", "), c.restoreText(p.Files))}
	}
	if v, ok := c.shell("COMPOSE_FILE"); ok {
		given, err := c.splitFiles(v)
		if err != nil {
			return nil, err
		}
		if given = withoutOverride(given); !sameFiles(given, p.Files) {
			return nil, fmt.Errorf("COMPOSE_FILE in the environment names %s, but the containers of the project %s were made from %s: unset it, or name those", strings.Join(given, ", "), p.Name, strings.Join(p.Files, ", "))
		}
	}
	names2, err := c.namedProjects()
	if err != nil {
		return nil, err
	}
	for _, n := range names2 {
		if n.value != p.Name {
			return nil, fmt.Errorf("COMPOSE_PROJECT_NAME in %s is %s, but the containers of %s are of the Compose project %s", n.from, n.value, c.Directory, p.Name)
		}
	}
	if filepath.Dir(realPath(p.Files[0])) != dir {
		// The TypeScript CLI (the backup) is told the files only: Compose
		// takes the first one's directory for the project's.
		return nil, fmt.Errorf("the Compose project %s is made from %s, which is not in %s: give the directory of its first Compose file as --from", p.Name, p.Files[0], c.Directory)
	}
	return p, nil
}

// restoreText says how to make .env name files again without a container
// being made again, and what does make them again.
func (c *Compose) restoreText(files []string) string {
	value, err := c.fileList(files)
	if err != nil {
		value = strings.Join(files, ":")
	}
	return fmt.Sprintf("To keep the containers as they run, set COMPOSE_FILE=%s in %s: that makes none of them again. (docker compose up -d with other files instead makes the containers they change again.)", value, c.envPath())
}

// containers are the Compose containers of this host, running or not.
func (c *Compose) containers(ctx context.Context) ([]composeContainer, error) {
	for try := 0; ; try++ {
		r, err := c.Run.Run(ctx, c.Directory, c.dockerName(), []string{"ps", "-a", "-q", "--no-trunc", "--filter", "label=" + labelProject}, nil)
		if err != nil {
			return nil, err
		}
		if r.Code != 0 {
			return nil, failure("docker ps", r)
		}
		ids := strings.Fields(string(r.Answer))
		if len(ids) == 0 {
			return nil, nil
		}
		r, err = c.Run.Run(ctx, c.Directory, c.dockerName(), append([]string{"inspect", "--type", "container", "--format", containersFormat}, ids...), nil)
		if err != nil {
			return nil, err
		}
		if r.Code != 0 {
			// One removed since it was listed.
			if try < 2 && bytes.Contains(bytes.ToLower(r.Said), []byte("no such")) {
				continue
			}
			return nil, failure("docker inspect", r)
		}
		var out []composeContainer
		dec := json.NewDecoder(bytes.NewReader(r.Answer))
		for {
			var l composeContainer
			for i, v := range []any{&l.project, &l.service, &l.files, &l.dir, &l.oneOff, &l.status, &l.mounts} {
				err := dec.Decode(v)
				if i == 0 && errors.Is(err, io.EOF) {
					if len(out) != len(ids) {
						return nil, errors.New("docker inspect did not answer for every Compose container")
					}
					return out, nil
				}
				if err != nil {
					return nil, errors.New("docker inspect did not give the Compose containers' labels and mounts")
				}
			}
			out = append(out, l)
		}
	}
}

// labelPaths are a container's config_files, absolute. Compose joins them
// with commas, so a path that holds one is put together again from what is
// there: the first part that is a file by itself is one, else the shortest
// run of parts that is; a part of none is left as it is (and refused later,
// as a file that is not there).
func labelPaths(l composeContainer) []string {
	abs := func(f string) string {
		if !filepath.IsAbs(f) {
			f = filepath.Join(l.dir, f)
		}
		return filepath.Clean(f)
	}
	var out []string
	parts := strings.Split(l.files, ",")
	for i := 0; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		f, next := abs(parts[i]), i
		for k := i; k < len(parts); k++ {
			whole := abs(strings.Join(parts[i:k+1], ","))
			if isFile(whole) {
				f, next = whole, k
				break
			}
		}
		out, i = append(out, f), next
	}
	return out
}

// ownFiles is what Compose reads in Directory by itself, and what says so.
type ownFiles struct {
	files []string
	from  string
}

var (
	errNoComposeFile    = errors.New("no Compose file")
	errManyComposeFiles = errors.New("several Compose files")
)

// ownFiles: .env's COMPOSE_FILE, else the directory's one Compose file and
// its override. errManyComposeFiles and errNoComposeFile say that the
// directory itself does not settle it.
func (c *Compose) ownFiles() (*ownFiles, error) {
	v, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		return nil, err
	}
	if ok && v != "" {
		files, err := c.splitFiles(v)
		if err != nil {
			return nil, err
		}
		if files = withoutOverride(files); len(files) > 0 {
			return &ownFiles{files: files, from: c.envPath() + "'s COMPOSE_FILE"}, nil
		}
	}
	dir, err := filepath.Abs(c.Directory)
	if err != nil {
		return nil, err
	}
	base := present(dir, composeNames)
	switch len(base) {
	case 0:
		return nil, fmt.Errorf("%s holds %w (%s): --from names a Compose installation's directory", c.Directory, errNoComposeFile, strings.Join(composeNames, ", "))
	case 1:
	default:
		return nil, fmt.Errorf("%s holds %w (%s), and nothing says which is the installation's: name them in COMPOSE_FILE", c.Directory, errManyComposeFiles, strings.Join(baseNames(base), ", "))
	}
	overrides := present(dir, overrideNames)
	if len(overrides) > 1 {
		return nil, fmt.Errorf("%s holds %w (%s), and nothing says which is the installation's: name them in COMPOSE_FILE", c.Directory, errManyComposeFiles, strings.Join(baseNames(overrides), ", "))
	}
	return &ownFiles{files: append(base, overrides...), from: c.Directory}, nil
}

// projectFromFiles is the project of an installation without containers:
// the files COMPOSE_FILE names (the shell's, else .env's), else the
// directory's one Compose file and its override; its name is Compose's own
// for those.
func (c *Compose) projectFromFiles(ctx context.Context) (*ComposeProject, error) {
	dir, err := filepath.Abs(c.Directory)
	if err != nil {
		return nil, err
	}
	var files []string
	if v, ok := c.shell("COMPOSE_FILE"); ok && v != "" {
		if files, err = c.splitFiles(v); err != nil {
			return nil, err
		}
		files = withoutOverride(files)
	} else {
		own, err := c.ownFiles()
		if err != nil {
			return nil, err
		}
		files = own.files
	}
	p := &ComposeProject{Dir: dir, Files: files}
	r, err := c.Run.Run(ctx, c.Directory, c.dockerName(), append(c.globalArgs(p, files), "config", "--no-interpolate", "--format", "json"), nil)
	if err != nil {
		return nil, err
	}
	cfg, err := parseConfig(r)
	if err != nil {
		return nil, err
	}
	p.Name = cfg.Name
	return p, nil
}

// named is a COMPOSE_PROJECT_NAME, and what sets it.
type named struct{ value, from string }

func (c *Compose) namedProjects() ([]named, error) {
	var out []named
	if v, ok := c.shell("COMPOSE_PROJECT_NAME"); ok && v != "" {
		out = append(out, named{v, "the environment"})
	}
	v, ok, err := c.envValue("COMPOSE_PROJECT_NAME")
	if err != nil {
		return nil, err
	}
	if ok && v != "" {
		out = append(out, named{v, c.envPath()})
	}
	return out, nil
}

// shell is a variable of the environment docker runs in.
func (c *Compose) shell(name string) (string, bool) {
	value, ok := "", false
	for _, kv := range c.Env {
		if n, v, found := strings.Cut(kv, "="); found && n == name {
			value, ok = v, true
		}
	}
	return value, ok
}

// separator is what COMPOSE_FILE's paths are joined with, read and
// written: COMPOSE_PATH_SEPARATOR (the shell's, else .env's), else the
// system's list separator.
func (c *Compose) separator() (string, error) {
	if s, ok := c.shell("COMPOSE_PATH_SEPARATOR"); ok && s != "" {
		return s, nil
	}
	s, ok, err := c.envValue("COMPOSE_PATH_SEPARATOR")
	if err != nil {
		return "", err
	}
	if ok && s != "" {
		return s, nil
	}
	return string(os.PathListSeparator), nil
}

// splitFiles is a COMPOSE_FILE's paths, absolute; a relative one is
// Directory's.
func (c *Compose) splitFiles(v string) ([]string, error) {
	sep, err := c.separator()
	if err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(c.Directory)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range strings.Split(v, sep) {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !filepath.IsAbs(f) {
			f = filepath.Join(dir, f)
		}
		out = append(out, filepath.Clean(f))
	}
	return out, nil
}

// fileList is COMPOSE_FILE's value for files, by their names in Directory,
// joined as splitFiles splits it.
func (c *Compose) fileList(files []string) (string, error) {
	sep, err := c.separator()
	if err != nil {
		return "", err
	}
	var out []string
	for _, f := range files {
		if filepath.Dir(realPath(f)) == realPath(c.Directory) {
			f = filepath.Base(f)
		}
		if strings.Contains(f, sep) {
			return "", fmt.Errorf("the Compose file %s has a %q in its path, which COMPOSE_FILE cannot name", f, sep)
		}
		out = append(out, f)
	}
	return strings.Join(out, sep), nil
}

// globalArgs are docker's arguments that name the project, before its
// command.
func (c *Compose) globalArgs(p *ComposeProject, files []string) []string {
	args := []string{"compose"}
	if p.Name != "" {
		args = append(args, "--project-name", p.Name)
	}
	args = append(args, "--project-directory", p.Dir)
	for _, f := range files {
		args = append(args, "-f", f)
	}
	return args
}

// files are the project's files now: its own, and migrate's OverrideFile
// while .env's COMPOSE_FILE names it (a reverse's database).
func (c *Compose) files(p *ComposeProject) ([]string, error) {
	files := slices.Clone(p.Files)
	override, err := c.overrideNamed()
	if err != nil {
		return nil, err
	}
	if override != "" {
		files = append(files, override)
	}
	return files, nil
}

// overrideNamed is migrate's file when .env's COMPOSE_FILE names it.
func (c *Compose) overrideNamed() (string, error) {
	v, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil || !ok {
		return "", err
	}
	files, err := c.splitFiles(v)
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if filepath.Base(f) == OverrideFile {
			return f, nil
		}
	}
	return "", nil
}

// readsOnly is a compose command that changes nothing.
func readsOnly(args []string) bool {
	for i := 1; i < len(args); i++ {
		if args[i] == "--profile" {
			i++
			continue
		}
		return args[i] == "config" || args[i] == "ps" || args[i] == "images"
	}
	return false
}

// argv is a docker command's arguments: a compose command's name the
// project and its files. Every command that changes something is given
// only once the project is verified again (verified): none acts on an
// installation that is not the migration's, whatever happened since.
func (c *Compose) argv(ctx context.Context, args []string) ([]string, error) {
	if len(args) == 0 || args[0] != "compose" {
		return args, nil
	}
	resolve := c.project
	if !readsOnly(args) {
		resolve = func(ctx context.Context) (*ComposeProject, error) {
			p, _, err := c.verified(ctx)
			return p, err
		}
	}
	p, err := resolve(ctx)
	if err != nil {
		return nil, err
	}
	files, err := c.files(p)
	if err != nil {
		return nil, err
	}
	return append(c.globalArgs(p, files), args[1:]...), nil
}

// environment is what makes a program that runs docker compose itself in
// Directory (the TypeScript CLI's backup) use the same project and files.
func (c *Compose) environment(ctx context.Context) ([]string, error) {
	p, _, err := c.verified(ctx)
	if err != nil {
		return nil, err
	}
	files, err := c.files(p)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if strings.Contains(f, ":") {
			return nil, fmt.Errorf("the Compose file %s has a colon in its path, which COMPOSE_FILE cannot name: the backup cannot be run on it", f)
		}
	}
	return []string{"COMPOSE_PROJECT_NAME=" + p.Name, "COMPOSE_FILE=" + strings.Join(files, ":"), "COMPOSE_PATH_SEPARATOR=:"}, nil
}

// runTS runs the TypeScript CLI in Directory on the installation's project.
func (c *Compose) runTS(ctx context.Context, args []string) (Ran, error) {
	env, err := c.environment(ctx)
	if err != nil {
		return Ran{}, err
	}
	x, ok := c.Run.(EnvRunner)
	if !ok {
		return Ran{}, errors.New("this runner cannot give the TypeScript CLI the installation's Compose project")
	}
	return x.RunEnv(ctx, c.Directory, c.tsCLI(), args, nil, env)
}

// byHand is a docker compose command the operator runs: as short as it is
// when Compose finds the project in Directory by itself (its files, and a
// name from .env, the stock file or the directory), else naming it.
func (c *Compose) byHand(command string) string {
	p := c.resolved
	if p == nil {
		return "docker compose " + command
	}
	if own, err := c.ownFiles(); err == nil && sameFiles(own.files, p.Files) {
		name, set, _ := c.envValue("COMPOSE_PROJECT_NAME")
		if set && name == p.Name || !set && (p.Name == stockProject || p.Name == filepath.Base(realPath(c.Directory))) {
			return "docker compose " + command
		}
	}
	files, err := c.files(p)
	if err != nil {
		files = p.Files
	}
	return "docker " + strings.Join(c.globalArgs(p, files), " ") + " " + command
}

// stockProject is the stock Compose file's name.
const stockProject = "varlatch"

func present(dir string, names []string) []string {
	var out []string
	for _, n := range names {
		if isFile(filepath.Join(dir, n)) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

func baseNames(paths []string) []string {
	var out []string
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return out
}

func withoutOverride(files []string) []string {
	return slices.DeleteFunc(slices.Clone(files), func(f string) bool { return filepath.Base(f) == OverrideFile })
}

func distinct(ls []composeContainer, of func(composeContainer) string) []string {
	var out []string
	for _, l := range ls {
		if v := of(l); !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

func listsText(lists [][]string) string {
	var out []string
	for _, l := range lists {
		out = append(out, strings.Join(l, ", "))
	}
	return strings.Join(out, "; ")
}
