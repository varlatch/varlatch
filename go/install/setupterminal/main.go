// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command setupterminal is a test tool, never shipped: it runs an
// interactive `varlatch setup` on a pseudo-terminal, as a person does, and
// acts only on what the terminal shows: it enrolls the first
// administrator's passkey from the link shown (enrollpasskey), and pastes
// back the two keys as shown. So the setup it runs ends only when the link
// and both keys are shown whole. go/install/test-setup.sh runs it.
//
//	setupterminal -enrollpasskey <path> -connect http://127.0.0.1:8686 \
//	  -public-url https://vault.varlatch.test [-link-file <file>] <varlatch>
//
// It answers: your own reverse proxy, -public-url, backups on this host,
// and yes to the disk and to the custody questions. It prints what the
// terminal showed with the link's token and the keys masked, and exits
// with setup's status, or 1 when something was not shown.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
)

var (
	linkShown = regexp.MustCompile(`(https?://\S+/enroll#\S+)\s`)
	keyShown  = map[string]*regexp.Regexp{
		"Root KEK":   regexp.MustCompile(`Root KEK: +([0-9a-f]{64})\s`),
		"backup key": regexp.MustCompile(`Backup key: +([0-9a-f]{64})\s`),
	}
	masks = []*regexp.Regexp{regexp.MustCompile(`vlt_[a-z]+_[A-Za-z0-9_-]+`), regexp.MustCompile(`[0-9a-f]{64}`)}
)

func main() {
	enroll := flag.String("enrollpasskey", "", "the enrollpasskey binary")
	connect := flag.String("connect", "", "enrollpasskey's -connect")
	publicURL := flag.String("public-url", "", "the address setup is told")
	linkFile := flag.String("link-file", "", "where the link shown is kept for enrollpasskey")
	flag.Parse()
	shown, code, err := run(flag.Arg(0), *enroll, *connect, *publicURL, *linkFile)
	for _, m := range masks {
		shown = m.ReplaceAllString(shown, "(masked by setupterminal)")
	}
	fmt.Print(shown)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setupterminal:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// question is one of setup's, by its text, and its answer.
type question struct{ text, answer string }

func run(varlatch, enroll, connect, publicURL, linkFile string) (string, int, error) {
	cmd := exec.Command(varlatch, "setup")
	cmd.Env = append(os.Environ(), "TERM=dumb")
	// Wide enough that the terminal wraps nothing.
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 500})
	if err != nil {
		return "", 1, err
	}
	defer terminal.Close()
	// Ends the reads below too.
	stop := time.AfterFunc(4*time.Minute, func() { _ = cmd.Process.Kill() })
	defer stop.Stop()

	questions := []question{
		{"How do people reach Varlatch?", "2"},
		{"The address people open", publicURL},
		{"Where do backups go?", "1"},
		{"Continue on this disk anyway?", "y"},
		{"Are both keys stored off this host", "y"},
		// The web upgrade (ADR-0065): its default, no.
		{"upgrade Varlatch to the next release from the web app?", ""},
	}
	var all, unanswered strings.Builder
	enrolled := false
	pasted := map[string]bool{}
	buf := make([]byte, 64*1024)
	for {
		n, err := terminal.Read(buf)
		all.Write(buf[:n])
		unanswered.Write(buf[:n])
		if err != nil {
			// Linux: EIO once setup has ended.
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return all.String(), 1, err
			}
			break
		}
		if m := linkShown.FindStringSubmatch(all.String()); m != nil && !enrolled {
			enrolled = true
			if err := enrollFrom(m[1], enroll, connect, linkFile); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return all.String(), 1, fmt.Errorf("the link shown enrolls no passkey: %w", err)
			}
		}
		at := unanswered.String()
		answer := func(text string) error {
			unanswered.Reset()
			_, err := terminal.WriteString(text + "\r")
			return err
		}
		for _, name := range []string{"Root KEK", "backup key"} {
			if pasted[name] || !strings.Contains(at, "Paste the "+name+" back") || !strings.Contains(at, "(input hidden): ") {
				continue
			}
			pasted[name] = true
			m := keyShown[name].FindStringSubmatch(all.String())
			if m == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return all.String(), 1, fmt.Errorf("the %s was asked back and was not shown", name)
			}
			if err := answer(m[1]); err != nil {
				return all.String(), 1, err
			}
		}
		for i, q := range questions {
			// Asked, and waiting: the question's line has not ended.
			if j := strings.LastIndex(at, q.text); q.text == "" || j < 0 || !waiting(at[j:]) {
				continue
			}
			questions[i].text = ""
			if err := answer(q.answer); err != nil {
				return all.String(), 1, err
			}
		}
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return all.String(), 1, err
	}
	code := cmd.ProcessState.ExitCode()
	switch {
	case !enrolled:
		return all.String(), 1, fmt.Errorf("no enrollment link was shown (setup ended with %d)", code)
	case len(pasted) != len(keyShown):
		return all.String(), 1, fmt.Errorf("the keys were not asked back (setup ended with %d)", code)
	case strings.Contains(all.String(), "[redacted]"):
		return all.String(), 1, errors.New("the terminal showed [redacted]")
	}
	return all.String(), code, nil
}

// waiting is whether a question's text ends as a prompt does.
func waiting(text string) bool {
	for _, end := range []string{": ", "? ", "] ", "> "} {
		if strings.HasSuffix(text, end) {
			return true
		}
	}
	return false
}

// enrollFrom enrolls a passkey from link, through a private file:
// enrollpasskey never takes a link as an argument.
func enrollFrom(link, enroll, connect, linkFile string) error {
	if err := os.WriteFile(linkFile, []byte(link+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(linkFile)
	out, err := exec.Command(enroll, "-link-file", linkFile, "-connect", connect).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
