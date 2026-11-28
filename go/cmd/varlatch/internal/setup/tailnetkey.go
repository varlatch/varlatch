// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// The tailnet auth key enrols the node once: varlatchd reads it only while
// the node has no state of its own. Setup's copy (TailnetAuthKey) is
// removed at the end of a run once the node has joined, so no join key
// stays on the host's disk; the configuration keeps naming the file, where
// a new key goes for a re-join (a lost tailnet/ state). Every step that
// joins with the key (the name probe, a takeover) comes before.

// tailnetPin is the tailnet pin's name in the data directory, and
// tailnetState the node's state, as varlatchd writes them (server/tailnet:
// PinFile, StateDir; the CLI does not import tsnet).
const (
	tailnetPin   = "tailnet-pin.json"
	tailnetState = "tailnet/tailscaled.state"
)

// tailnetJoined is whether the node in dataDir has joined a tailnet: its
// pin is taken (not enrolling), or it has state and no pin, which never
// enrols again.
func tailnetJoined(dataDir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, tailnetPin))
	if errors.Is(err, fs.ErrNotExist) {
		_, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(tailnetState)))
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	var p struct {
		Suffix    string `json:"suffix"`
		Enrolling bool   `json:"enrolling"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return false, fmt.Errorf("the tailnet pin %s is not readable: %w", tailnetPin, err)
	}
	return !p.Enrolling && p.Suffix != "", nil
}

// dropTailnetKey removes setup's copy of the tailnet auth key once the node
// has joined, or says why it stays.
func (r *run) dropTailnetKey() error {
	if r.j.Answers.Ingress != Tailnet {
		return nil
	}
	dest := r.path(TailnetAuthKey)
	if _, err := os.Lstat(dest); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	joined, err := tailnetJoined(r.path(DataDir))
	if err != nil || !joined {
		return r.o.Say("The tailnet node has not joined its tailnet yet, so " + TailnetAuthKey + " stays: run setup again once it has, and it is removed (varlatch doctor says when).")
	}
	if err := os.Remove(dest); err != nil {
		return fmt.Errorf("setup: removing %s: %w", TailnetAuthKey, err)
	}
	if err := syncDir(filepath.Dir(dest)); err != nil {
		return err
	}
	return r.o.Say("The tailnet node has joined: removed " + TailnetAuthKey + ", which only enrols it. To join again, put a new auth key there (root:" + User + ", 0640) and restart varlatchd; revoke the old key in the tailnet's admin console, or let it expire.")
}
