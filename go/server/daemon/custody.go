// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/custody"
	"github.com/varlatch/varlatch/go/server/maintenance"
)

// The key custody host commands (cli.ts, ADR-0011, ADR-0035 D9):
//
//	varlatchd admin kek verify [--file <kek-file>]
//	varlatchd admin kek export [--file <kek-file>] [--out <blob.json>]
//	varlatchd admin kek restore --in <blob.json> --out <kek-file>
//	varlatchd admin kek split --shares <n> --threshold <k> [--file <kek-file>]
//	varlatchd admin kek combine --out <kek-file> [--share <share>]...
//	varlatchd admin custody attest --key root-kek|backup-key --method passphrase-escrow|shamir-split|copy
//	varlatchd admin custody status
//
// kek works on key files and reads the installation's canary from the
// database read-only, so it runs in the caller's process with or without
// a daemon, and on a fresh host before the database is restored (restore
// and combine then warn that the key was not checked). custody attest
// writes an audit event, through the socket or offline like every writing
// command; custody status reads them, read-only. As in the TypeScript CLI,
// kek and custody attest are refused during maintenance, and custody
// status is not. A passphrase comes from --passphrase-file, then
// VARLATCH_KEK_PASSPHRASE, then the terminal without echo.

const (
	kekUsage     = "Usage: varlatchd admin kek <verify | export | restore | split | combine>"
	custodyUsage = "Usage: varlatchd admin custody attest --key root-kek|backup-key --method passphrase-escrow|shamir-split|copy | custody status"
)

// kekArgs are a kek command's flags: each valued flag's last value, and
// every --share.
type kekArgs struct {
	values map[string]string
	shares []string
}

func parseKekArgs(rest []string) (kekArgs, string) {
	a := kekArgs{values: map[string]string{}}
	valued := map[string]bool{"--file": true, "--out": true, "--in": true, "--shares": true, "--threshold": true, "--share": true, "--passphrase-file": true}
	for i := 0; i < len(rest); i++ {
		f := rest[i]
		if !valued[f] {
			return a, "kek: unknown argument " + f
		}
		if i+1 >= len(rest) {
			return a, "kek: " + f + " needs a value"
		}
		if f == "--share" {
			a.shares = append(a.shares, rest[i+1])
		} else {
			a.values[f] = rest[i+1]
		}
		i++
	}
	return a, ""
}

// runKek runs `admin kek ...` in this process.
func runKek(cfg *config.Config, rest []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(msg string) int {
		fmt.Fprintln(stderr, msg)
		return ExitFailure
	}
	if len(rest) == 0 {
		return fail(kekUsage)
	}
	if maintenance.Open(cfg.DataDir, nil).Isolated() {
		return fail("varlatchd admin kek: " + MaintenanceRefusal)
	}
	a, msg := parseKekArgs(rest[1:])
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	keyFile := func() ([]byte, error) {
		path := a.values["--file"]
		if path == "" {
			path = cfg.RootKEKFile
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		k, err := envelope.ParseRootKEK(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s does not contain a 32-byte KEK", path)
		}
		return k, nil
	}
	passphrase := func(prompt string, confirm bool) (string, error) {
		if p := a.values["--passphrase-file"]; p != "" {
			raw, err := os.ReadFile(p)
			if err != nil {
				return "", err
			}
			s := string(raw)
			s = strings.TrimSuffix(s, "\n")
			return strings.TrimSuffix(s, "\r"), nil
		}
		if p := os.Getenv("VARLATCH_KEK_PASSPHRASE"); p != "" {
			return p, nil
		}
		first, ok, err := readHidden(prompt, stderr)
		if !ok {
			return "", errors.New("No TTY: supply the passphrase via --passphrase-file or VARLATCH_KEK_PASSPHRASE")
		}
		if err != nil {
			return "", err
		}
		if confirm {
			again, _, err := readHidden("Confirm passphrase: ", stderr)
			if err != nil {
				return "", err
			}
			if again != first {
				return "", errors.New("Passphrases do not match.")
			}
		}
		return first, nil
	}
	writeKey := func(path string, key []byte) error {
		return os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600)
	}
	// verifyRecovered checks a recovered key against the installation's
	// canary when there is a database; a fresh host gets a warning.
	verifyRecovered := func(key []byte, label string) error {
		inst, err := installationCanary(cfg)
		if err != nil || inst.id == "" {
			fmt.Fprintf(stderr, "WARNING: could not reach the database to verify the %s against the installation canary. Run `admin kek verify` once the database is restored.\n", label)
			return nil
		}
		if !envelope.VerifyCanary(key, inst.canary, inst.id) {
			return fmt.Errorf("The %s does not match this installation's canary; refusing to write it.", label)
		}
		fmt.Fprintf(stdout, "%s verified against the installation canary.\n", label)
		return nil
	}

	switch rest[0] {
	case "verify":
		key, err := keyFile()
		if err != nil {
			return fail(err.Error())
		}
		defer clear(key)
		inst, err := installationCanary(cfg)
		if err != nil {
			return fail(err.Error())
		}
		if inst.id == "" || !envelope.VerifyCanary(key, inst.canary, inst.id) {
			return fail("KEK verification failed.")
		}
		fmt.Fprintln(stdout, "KEK backup matches this installation.")
	case "export":
		key, err := keyFile()
		if err != nil {
			return fail(err.Error())
		}
		defer clear(key)
		p, err := passphrase("Escrow passphrase (min 12 chars): ", true)
		if err != nil {
			return fail(err.Error())
		}
		blob, err := custody.Export(key, p)
		if err != nil {
			return fail(err.Error())
		}
		b, err := json.MarshalIndent(blob, "", "  ")
		if err != nil {
			return fail(err.Error())
		}
		b = append(b, '\n')
		if out := a.values["--out"]; out != "" {
			if err := os.WriteFile(out, b, 0o600); err != nil {
				return fail(err.Error())
			}
			fmt.Fprintf(stdout, "Escrow blob written to %s.\n", out)
		} else {
			_, _ = stdout.Write(b)
		}
		fmt.Fprintln(stderr, "The blob is safe to store anywhere (even with database backups); only the passphrase must be custodied separately. Losing the passphrase makes the blob useless.")
	case "restore":
		in, out := a.values["--in"], a.values["--out"]
		if in == "" || out == "" {
			return fail("Usage: admin kek restore --in <blob.json> --out <kek-file>")
		}
		raw, err := os.ReadFile(in)
		if err != nil {
			return fail(err.Error())
		}
		blob, err := custody.ParseBlob(raw)
		if err != nil {
			return fail(err.Error())
		}
		p, err := passphrase("Escrow passphrase: ", false)
		if err != nil {
			return fail(err.Error())
		}
		key, err := custody.Restore(blob, p)
		if err != nil {
			return fail(err.Error())
		}
		defer clear(key)
		if err := verifyRecovered(key, "restored KEK"); err != nil {
			return fail(err.Error())
		}
		if err := writeKey(out, key); err != nil {
			return fail(err.Error())
		}
		fmt.Fprintf(stdout, "KEK written to %s (mode 0600).\n", out)
	case "split":
		n, errN := strconv.Atoi(a.values["--shares"])
		k, errK := strconv.Atoi(a.values["--threshold"])
		if errN != nil || errK != nil {
			return fail("Usage: admin kek split --shares <n> --threshold <k> [--file <kek-file>]")
		}
		key, err := keyFile()
		if err != nil {
			return fail(err.Error())
		}
		defer clear(key)
		shares, fp, err := custody.Split(key, n, k)
		if err != nil {
			return fail(err.Error())
		}
		fmt.Fprintf(stderr, "Any %d of these %d shares reconstruct the KEK; fewer reveal nothing.\nGive each share to a different custodian; never store two together.\nSplit fingerprint: %s\n\n", k, n, fp)
		for _, s := range shares {
			fmt.Fprintln(stdout, s)
		}
	case "combine":
		out := a.values["--out"]
		if out == "" {
			return fail("Usage: admin kek combine --out <kek-file> [--share <s>]...")
		}
		shares := a.shares
		if len(shares) == 0 {
			sc := bufio.NewScanner(stdin)
			for sc.Scan() {
				if l := strings.TrimSpace(sc.Text()); l != "" {
					shares = append(shares, l)
				}
			}
		}
		if len(shares) == 0 {
			return fail("Provide shares via --share flags or one per line on stdin.")
		}
		key, err := custody.Combine(shares)
		if err != nil {
			return fail(err.Error())
		}
		defer clear(key)
		if err := verifyRecovered(key, "combined KEK"); err != nil {
			return fail(err.Error())
		}
		if err := writeKey(out, key); err != nil {
			return fail(err.Error())
		}
		fmt.Fprintf(stdout, "KEK written to %s (mode 0600).\n", out)
	default:
		return fail(kekUsage)
	}
	return ExitOK
}

// custodyArgs checks `admin custody`'s arguments: the key and method of an
// attestation, or "" for status.
func custodyArgs(rest []string) (key, method, msg string) {
	if len(rest) == 1 && rest[0] == "status" {
		return "", "", ""
	}
	if len(rest) == 0 || rest[0] != "attest" {
		return "", "", custodyUsage
	}
	for i := 1; i < len(rest); i += 2 {
		if i+1 >= len(rest) {
			return "", "", custodyUsage
		}
		switch rest[i] {
		case "--key":
			key = rest[i+1]
		case "--method":
			method = rest[i+1]
		default:
			return "", "", custodyUsage
		}
	}
	return key, method, ""
}

// runCustodyStatus is `admin custody status`, read-only.
func runCustodyStatus(cfg *config.Config, stdout, stderr io.Writer) int {
	conn, err := openReadOnly(cfg)
	if err == nil && conn == nil {
		err = errors.New("Installation is not initialized")
	}
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin custody status: %s\n", err.Error())
		return ExitFailure
	}
	defer conn.Close()
	st, err := custody.StatusOf(context.Background(), conn)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin custody status: %s\n", err.Error())
		return ExitFailure
	}
	b, err := json.Marshal(st)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin custody status: %s\n", err.Error())
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}

// runCustodyAttest is `admin custody attest`, in the daemon or offline.
func runCustodyAttest(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	key, method, msg := custodyArgs(rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	a, err := custody.Attest(ctx, env.store, key, method)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin custody attest: %s\n", err.Error())
		return ExitFailure
	}
	b, _ := json.Marshal(a)
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}

// openReadOnly opens the data directory's database read-only; nil without
// one, so nothing is created.
func openReadOnly(cfg *config.Config) (*sql.DB, error) {
	path := cfg.DatabasePath()
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '%', '?', '#':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return sql.Open("sqlite", b.String()+"?mode=ro")
}

type canaryOf struct {
	id     string
	canary envelope.Envelope
}

// installationCanary reads the installation and its canary, read-only;
// an empty id when there is no database or no installation yet.
func installationCanary(cfg *config.Config) (canaryOf, error) {
	conn, err := openReadOnly(cfg)
	if err != nil || conn == nil {
		return canaryOf{}, err
	}
	defer conn.Close()
	var c canaryOf
	var raw string
	switch err := conn.QueryRow("SELECT id, kek_canary FROM installation LIMIT 1").Scan(&c.id, &raw); {
	case errors.Is(err, sql.ErrNoRows):
		return canaryOf{}, nil
	case err != nil:
		return canaryOf{}, fmt.Errorf("the installation's database cannot be read: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &c.canary); err != nil {
		return canaryOf{}, fmt.Errorf("the installation's canary is not an envelope: %w", err)
	}
	return c, nil
}
