// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serve refuses (78) a key file that is not a regular file, before it
// reads it or opens anything.
func TestServeRefusesAKeyFileThatIsNoFile(t *testing.T) {
	in := newInstall(t, "")
	if err := os.Remove(in.kekFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(in.kekFile, 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitConfig || !strings.Contains(stderr.String(), "the Root KEK file "+in.kekFile+" is not a regular file") {
		t.Fatalf("a directory for the Root KEK: %d %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("the database was made: %v", err)
	}

	bek := filepath.Join(in.dir, "backup-key")
	if err := os.Mkdir(bek, 0o700); err != nil {
		t.Fatal(err)
	}
	in = newInstall(t, "backup_key_file = "+bek+"\n")
	stderr = syncBuffer{}
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitConfig || !strings.Contains(stderr.String(), "the backup key file "+bek+" is not a regular file") {
		t.Fatalf("a directory for the backup key: %d %s", code, stderr.String())
	}
}

// A key file its group or others may read is said at each start, and
// varlatchd serves: an installation whose mount gives looser modes keeps
// serving across the upgrade that brought the check.
func TestServeWarnsOfALooseKeyFile(t *testing.T) {
	in := newInstall(t, "")
	if err := os.Chmod(in.kekFile, 0o644); err != nil {
		t.Fatal(err)
	}
	r := start(t, in)
	r.stop(t)
	if out := r.stderr.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "the Root KEK file "+in.kekFile+" is readable by its group or others (mode 0644)") {
		t.Fatalf("no warning: %s", out)
	}

	tight := newInstall(t, "")
	r = start(t, tight)
	r.stop(t)
	if out := r.stderr.String(); strings.Contains(out, "readable by its group or others") {
		t.Fatalf("a 0600 key file was warned of: %s", out)
	}
}

// keyFileProblem: a link to a regular file is followed (a mounted secret
// is often one); a file in $CREDENTIALS_DIRECTORY is systemd's copy, whose
// access systemd sets (an ACL shows as group bits), so only its type is
// judged; the image's 0400 passes.
func TestKeyFileProblem(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("k\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	image := write("image", 0o400)
	loose := write("loose", 0o640)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(image, link); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, "credentials")
	if err := os.Mkdir(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(creds, "root-kek")
	if err := os.WriteFile(credential, []byte("k\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, creds    string
		loose, refused bool
	}{
		{image, "", false, false},
		{link, "", false, false},
		{loose, "", true, false},
		{credential, creds, false, false},
		{credential, "", true, false},
		{creds, "", false, true},
		{filepath.Join(dir, "missing"), "", false, false}, // reading it says why
		{"", "", false, false},
	} {
		l, err := keyFileProblem("the key", c.path, c.creds)
		if (l != "") != c.loose || (err != nil) != c.refused {
			t.Errorf("%s (credentials %q): loose %q, refused %v", c.path, c.creds, l, err)
		}
	}
}
