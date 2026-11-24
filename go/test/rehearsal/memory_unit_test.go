// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// What the run's docker makes of each command the programs use, and what it
// refuses.
func TestPlanDocker(t *testing.T) {
	declared := func(image string) ([]string, error) {
		switch image {
		case "pg":
			return []string{"/var/lib/postgresql/data"}, nil
		case "missing":
			return nil, errors.New("pull it first")
		}
		return nil, nil
	}
	for _, c := range []struct {
		in, want, mkdir, look, oneOff, err string
	}{
		{"volume create --label a=b --label c=d x_pg", "volume create --driver local --opt type=none --opt o=bind --opt device=/m/x_pg --label a=b --label c=d x_pg", "/m/x_pg", "", "", ""},
		{"volume create", "", "", "", "", "without one plain name"},
		{"volume create ../x", "", "", "", "", "without one plain name"},
		{"volume create --driver other x", "", "", "", "", "--driver"},
		{"volume create --opt type=tmpfs x", "", "", "", "", "--opt"},
		{"volume rm x", "volume rm x", "", "", "", ""},
		{"volume ls -q", "volume ls -q", "", "", "", ""},
		{"run -d --name p --network none -e A=b pg", "run --log-driver none --ulimit core=0 -d --name p --network none -e A=b --read-only --tmpfs /var/lib/postgresql/data --tmpfs /run -v /m/p-tmp:/tmp pg", "/m/p-tmp", "", "", ""},
		{"run -d --name s -p 127.0.0.1:1:9000 --tmpfs /data --tmpfs /tmp minio server /data", "run --log-driver none --ulimit core=0 -d --name s -p 127.0.0.1:1:9000 --tmpfs /data --tmpfs /tmp --read-only --tmpfs /run minio server /data", "", "", "", ""},
		{"run --rm -i --read-only --mount type=volume,source=v,target=/state --entrypoint sh vl -c x", "run --log-driver none --ulimit core=0 -i --read-only --mount type=volume,source=v,target=/state --entrypoint sh --tmpfs /run --tmpfs /tmp --name once vl -c x", "", "", "once", ""},
		{"run --rm --name n --read-only --tmpfs /tmp -v k:/k:ro vl --rm", "run --log-driver none --ulimit core=0 --name n --read-only --tmpfs /tmp -v k:/k:ro --tmpfs /run vl --rm", "", "", "n", ""},
		{"run -v d:/var/lib/postgresql/data --tmpfs /tmp pg", "run --log-driver none --ulimit core=0 -v d:/var/lib/postgresql/data --tmpfs /tmp --read-only --tmpfs /run pg", "", "", "", ""},
		{"run --log-driver json-file vl", "", "", "", "", "--log-driver"},
		{"run --privileged vl", "", "", "", "", "--privileged"},
		{"run -d missing", "", "", "", "", "pull it first"},
		{"run -d", "", "", "", "", "docker run"},
		{"rm -fv a b", "rm -fv a b", "", "a b", "", ""},
		{"cp p:/state/x -", "cp p:/state/x -", "", "", "", ""},
		{"cp d p:/tmp/d.dump", "cp d p:/tmp/d.dump", "", "", "", ""},
		{"cp d p:/root/d", "", "", "", "", "docker cp"},
		{"cp d p:/tmp/../root/d", "", "", "", "", "docker cp"},
		{"commit p x", "", "", "", "", "docker commit"},
		{"exec -i p psql", "exec -i p psql", "", "", "", ""},
		{"ps -a", "ps -a", "", "", "", ""},
		{"compose --project-name x -f a --file=b down -v", "compose --project-name x -f a --file=b down -v", "", "*", "", ""},
		{"compose up -d postgres", "compose up -d postgres", "", "*", "", ""},
		{"compose exec -T postgres run --rm", "compose exec -T postgres run --rm", "", "", "", ""},
		{"compose --profile p run --rm -T --no-deps --entrypoint flock varlatchd -n --rm", "compose --profile p run --name once -T --no-deps --entrypoint flock varlatchd -n --rm", "", "", "once", ""},
		{"compose run -T varlatchd", "", "", "", "", "without --rm"},
		{"compose run --rm --name x varlatchd", "", "", "", "", "--name"},
		{"compose run --rm -d varlatchd", "", "", "", "", "-d"},
		{"compose --unknown x up", "", "", "", "", "--unknown"},
		{"", "", "", "", "", ""},
	} {
		p, err := planDocker(strings.Fields(c.in), "/m", "once", declared)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || strings.Join(p.args, " ") != c.want || p.mkdir != c.mkdir || strings.Join(p.look, " ") != c.look || p.oneOff != c.oneOff {
			t.Errorf("%s:\n got %s (%+v, %v)\nwant %s", c.in, strings.Join(p.args, " "), p, err, c.want)
		}
	}
}

func TestLayerFindings(t *testing.T) {
	fine := []looked{
		{Container: "a", Service: "postgres", Log: "none", ReadOnly: true, Wrote: []string{"C /run", "A /run/secrets"}},
		{Container: "w", Service: "varlatch-web", Log: "none", Wrote: []string{"C /etc", "C /etc/nginx", "C /etc/nginx/conf.d", "C /etc/nginx/conf.d/default.conf", "D /etc/x"}},
	}
	if bad := layerFindings(fine); len(bad) != 0 {
		t.Errorf("%q", bad)
	}
	for _, c := range []struct {
		l    looked
		want string
	}{
		{looked{Container: "a", Service: "postgres", Log: "none"}, "its layer is not read only"},
		{looked{Container: "a", Log: "json-file", LogBytes: 3, ReadOnly: true}, "3 bytes in its json-file log"},
		{looked{Container: "a", Log: "none", ReadOnly: true, Outside: []string{"the volume v on /d"}}, "the volume v on /d"},
		{looked{Container: "a", Log: "none", ReadOnly: true, Error: "docker diff: x"}, "docker diff: x"},
		{looked{Container: "w", Service: "varlatch-web", Log: "none", Wrote: []string{"C /var", "A /var/tmp", "A /var/tmp/x"}}, "wrote A /var/tmp/x"},
		{looked{Container: "w", Service: "varlatch-web", Log: "none", Wrote: []string{"A /etc/nginx/conf.d/default.conf.bak"}}, "wrote A /etc/nginx/conf.d/default.conf.bak"},
	} {
		if bad := layerFindings(append(slices.Clone(fine), c.l)); len(bad) != 1 || !strings.Contains(bad[0], c.want) {
			t.Errorf("%+v: %q, want %q", c.l, bad, c.want)
		}
	}
}

func TestSwapState(t *testing.T) {
	root := t.TempDir()
	write := func(path, text string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const head = "Filename Type Size Used Priority\n"
	write("sys/block/zram0/backing_dev", "none\n")
	write("sys/block/zram1/backing_dev", "/dev/sda2\n")
	write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-x\n")
	write("sys/class/block/dm-1/dm/uuid", "LVM-x\n")
	write("dev/dm-0", "")
	if err := os.MkdirAll(filepath.Join(root, "dev/mapper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../dm-0", filepath.Join(root, "dev/mapper/swap")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		swaps, want string
		safe        bool
	}{
		{"", "no swap", true},
		{"/dev/zram0 partition 1 0 100\n", "zram, in memory", true},
		{"/dev/zram1 partition 1 0 100\n", "writes back to /dev/sda2", false},
		{"/dev/zram2 partition 1 0 100\n", "writes back to", false},
		{"/dev/mapper/swap partition 1 0 1\n", "encrypted", true},
		{"/dev/dm-1 partition 1 0 1\n", "not encrypted", false},
		{"/dev/sda2 partition 1 0 1\n", "not encrypted", false},
		{"/swapfile file 1 0 1\n", "a swap file", false},
		{"/dev/zram0 partition 1 0 100\n/dev/sda2 partition 1 0 1\n", "not encrypted", false},
	} {
		write("proc/swaps", head+c.swaps)
		if said, safe := swapState(root); safe != c.safe || !strings.Contains(said, c.want) {
			t.Errorf("%q: %q, %v", c.swaps, said, safe)
		}
	}
	if said, safe := swapState(filepath.Join(root, "nowhere")); safe {
		t.Errorf("unreadable: %q taken as safe", said)
	}
}

func TestMemoryNeed(t *testing.T) {
	if data, total := memoryNeed(10<<20, memoryMargin); data != (320+400)<<20 || total != data+2<<30 {
		t.Errorf("%d, %d", data, total)
	}
	for v, want := range map[string]int64{"": 2 << 30, "1024": 1 << 30, "1536": 1536 << 20, "1023": 0, "-1": 0, "x": 0, "99999999999": 0} {
		if n, err := marginOf(v); n != want || (err == nil) != (want > 0) {
			t.Errorf("%q: %d, %v", v, n, err)
		}
	}
	if ok, err := onTmpfs("/proc"); ok || err != nil {
		t.Errorf("/proc taken as a tmpfs: %v, %v", ok, err)
	}
}

// Every step end migrate says is in the report, and nothing else.
func TestStepLines(t *testing.T) {
	got := stepLines("Step: a.\nStill going after 15s: a.\nDone in 22s: a.\nDone in\nFailed after 1m3s: b.\r\nLeft to you after 0s: c.\nUndoing: Done in 2s: d\n")
	if want := []string{"Done in 22s: a.", "Failed after 1m3s: b.", "Left to you after 0s: c."}; !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
	for args, want := range map[string]string{"migrate --ingress proxy": "the migration", "migrate --abort --from x": "--abort", "migrate --rollback": "--rollback", "migrate --resume": "--resume", "migrate --finish --delete-old-data": "--finish"} {
		if got := migrateMode(strings.Fields(args)); got != want {
			t.Errorf("%s: %s", args, got)
		}
	}
}

func TestEnvScan(t *testing.T) {
	dir := t.TempDir()
	names, log := filepath.Join(dir, "names"), filepath.Join(dir, "log")
	for p, s := range map[string]string{names: "VL_T_FOUND\nVL_T_ABSENT\nVL_T_SHORT\nVL_T_UNSET", log: "x a-value-in-the-log y short"} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VL_T_FOUND", "a-value-in-the-log")
	t.Setenv("VL_T_ABSENT", "a-value-that-is-not")
	t.Setenv("VL_T_SHORT", "short")
	if tried, found, err := scanFor(names, []string{log}); err != nil || tried != 2 || found != 1 {
		t.Errorf("%d tried, %d found, %v", tried, found, err)
	}
	if _, _, err := scanFor(names, []string{filepath.Join(dir, "none")}); err == nil {
		t.Error("a file that cannot be read is taken as clean")
	}
}
