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

// composeLabels is what migrate reads of a container: these labels only.
type composeLabels struct {
	project, service, files, dir, oneOff string
}

// labelsFormat prints them, each as a JSON string (or null).
const labelsFormat = `{{json (index .Config.Labels "` + labelProject + `")}} {{json (index .Config.Labels "` + labelService + `")}} {{json (index .Config.Labels "` + labelFiles +
	`")}} {{json (index .Config.Labels "` + labelDir + `")}} {{json (index .Config.Labels "` + labelOneOff + `")}}`

// composeNames and overrideNames are the files Compose reads by itself in
// a directory, in its order.
var (
	composeNames  = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}
	overrideNames = []string{"compose.override.yml", "compose.override.yaml", "docker-compose.override.yml", "docker-compose.override.yaml"}
)

// KeepProject is the project a migration's journal records: the commands
// that go on with it use it, and refuse when the containers say another.
func (c *Compose) KeepProject(p *ComposeProject) { c.kept, c.resolved = p, nil }

// CheckProject resolves the project now (and refuses), before anything
// else of a command is done.
func (c *Compose) CheckProject(ctx context.Context) error {
	_, err := c.project(ctx)
	return err
}

// project is the installation's, resolved once.
func (c *Compose) project(ctx context.Context) (*ComposeProject, error) {
	if c.resolved != nil {
		return c.resolved, nil
	}
	p, err := c.resolve(ctx)
	if err != nil {
		return nil, err
	}
	c.resolved = p
	return p, nil
}

func (c *Compose) resolve(ctx context.Context) (*ComposeProject, error) {
	live, err := c.liveProject(ctx)
	if err != nil {
		return nil, err
	}
	p := live
	if c.kept != nil {
		if live != nil && !sameProject(live, c.kept) {
			return nil, fmt.Errorf("the migration's journal records the Compose project %s, and the containers of %s are now of %s: the installation was started another way since; "+
				"put it back (docker compose up with the journal's project and files), then run this again; nothing was done", c.kept, c.Directory, live)
		}
		p = c.kept
	}
	if p == nil {
		if p, err = c.projectFromFiles(ctx); err != nil {
			return nil, err
		}
	}
	for _, f := range p.Files {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("the Compose project %s is made from %s, which is not there (or not a file): nothing was done", p.Name, f)
		}
	}
	return p, nil
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
// refused when they are of two projects, when the project also runs from
// another directory, when one was made from this directory's files as
// another directory's project, or when their files, .env and the shell
// name different ones: never a guess.
func (c *Compose) liveProject(ctx context.Context) (*ComposeProject, error) {
	all, err := c.containerLabels(ctx)
	if err != nil {
		return nil, err
	}
	dir := realPath(c.Directory)
	var here, elsewhere []composeLabels
	for _, l := range all {
		switch {
		case strings.EqualFold(l.oneOff, "true") || l.project == "" || l.dir == "":
		case realPath(l.dir) == dir:
			here = append(here, l)
		default:
			elsewhere = append(elsewhere, l)
		}
	}
	for _, l := range elsewhere {
		if l.service != service {
			continue
		}
		for _, f := range labelPaths(l) {
			if realPath(filepath.Dir(f)) == dir {
				return nil, fmt.Errorf("a %s container of the Compose project %s is made from %s, but its project directory is %s, not %s: give that directory as --from", service, l.project, f, l.dir, c.Directory)
			}
		}
	}
	if len(here) == 0 {
		return nil, nil
	}
	names := distinct(here, func(l composeLabels) string { return l.project })
	if len(names) > 1 {
		return nil, fmt.Errorf("%s holds the containers of %d Compose projects (%s): a migration takes an installation of one; remove the other's containers first", c.Directory, len(names), strings.Join(names, ", "))
	}
	for _, l := range elsewhere {
		if l.project == names[0] {
			return nil, fmt.Errorf("the Compose project %s runs from %s and from %s: a migration takes an installation of one directory", names[0], c.Directory, l.dir)
		}
	}
	if dirs := distinct(here, func(l composeLabels) string { return realPath(l.dir) }); len(dirs) > 1 {
		return nil, fmt.Errorf("the Compose project %s names two directories (%s)", names[0], strings.Join(dirs, ", "))
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
			return nil, fmt.Errorf("the containers of the Compose project %s were made from different files (%s), and %s does not say which are its own: run docker compose up -d with the installation's files, so that they agree", p.Name, listsText(lists), c.Directory)
		}
		p.Files = lists[i]
	}
	// What the directory and the shell say must be the same.
	if own != nil && !sameFiles(own.files, p.Files) {
		return nil, fmt.Errorf("%s names the Compose files %s, but the containers of the project %s were made from %s: run docker compose up -d with the installation's files, so that they agree", own.from, strings.Join(own.files, ", "), p.Name, strings.Join(p.Files, ", "))
	}
	if v, ok := c.shell("COMPOSE_FILE"); ok {
		if given := withoutOverride(c.splitFiles(v)); !sameFiles(given, p.Files) {
			return nil, fmt.Errorf("COMPOSE_FILE in the environment names %s, but the containers of the project %s were made from %s: unset it, or name those", strings.Join(given, ", "), p.Name, strings.Join(p.Files, ", "))
		}
	}
	for _, n := range c.namedProjects() {
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

// containerLabels are the labels of every Compose container of this host,
// running or not.
func (c *Compose) containerLabels(ctx context.Context) ([]composeLabels, error) {
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
		r, err = c.Run.Run(ctx, c.Directory, c.dockerName(), append([]string{"inspect", "--type", "container", "--format", labelsFormat}, ids...), nil)
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
		var out []composeLabels
		dec := json.NewDecoder(bytes.NewReader(r.Answer))
		for {
			var l composeLabels
			for i, v := range []*string{&l.project, &l.service, &l.files, &l.dir, &l.oneOff} {
				err := dec.Decode(v)
				if i == 0 && errors.Is(err, io.EOF) {
					if len(out) != len(ids) {
						return nil, errors.New("docker inspect did not answer for every Compose container")
					}
					return out, nil
				}
				if err != nil {
					return nil, errors.New("docker inspect did not give the Compose containers' labels")
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
func labelPaths(l composeLabels) []string {
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
			if st, err := os.Stat(whole); err == nil && st.Mode().IsRegular() {
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
		if files := withoutOverride(c.splitFiles(v)); len(files) > 0 {
			return &ownFiles{files: files, from: filepath.Join(c.Directory, ".env") + "'s COMPOSE_FILE"}, nil
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
		files = withoutOverride(c.splitFiles(v))
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

func (c *Compose) namedProjects() []named {
	var out []named
	if v, ok := c.shell("COMPOSE_PROJECT_NAME"); ok && v != "" {
		out = append(out, named{v, "the environment"})
	}
	if v, ok, err := c.envValue("COMPOSE_PROJECT_NAME"); err == nil && ok && v != "" {
		out = append(out, named{v, filepath.Join(c.Directory, ".env")})
	}
	return out
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

// splitFiles is a COMPOSE_FILE's value as Compose splits it: at
// COMPOSE_PATH_SEPARATOR (the shell's, else .env's), else at the system's
// list separator; a relative path is Directory's.
func (c *Compose) splitFiles(v string) []string {
	sep := string(os.PathListSeparator)
	if s, ok, err := c.envValue("COMPOSE_PATH_SEPARATOR"); err == nil && ok && s != "" {
		sep = s
	}
	if s, ok := c.shell("COMPOSE_PATH_SEPARATOR"); ok && s != "" {
		sep = s
	}
	dir, err := filepath.Abs(c.Directory)
	if err != nil {
		dir = c.Directory
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
	return out
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
	v, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		return nil, err
	}
	files := slices.Clone(p.Files)
	if ok {
		for _, f := range c.splitFiles(v) {
			if filepath.Base(f) == OverrideFile {
				files = append(files, f)
				break
			}
		}
	}
	return files, nil
}

// argv is a docker command's arguments: a compose command's name the
// project and its files.
func (c *Compose) argv(ctx context.Context, args []string) ([]string, error) {
	if len(args) == 0 || args[0] != "compose" {
		return args, nil
	}
	p, err := c.project(ctx)
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
	p, err := c.project(ctx)
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
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil && st.Mode().IsRegular() {
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

func distinct(ls []composeLabels, of func(composeLabels) string) []string {
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
