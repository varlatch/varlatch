// SPDX-License-Identifier: Apache-2.0

// Command fakegithub is a test tool, never shipped: it serves releases as
// GitHub does (fakerelease), signed by a test Sigstore of its own, for a
// varlatch built with -tags selfupdatetest. go/install/test-upgrade.sh runs
// it for `varlatch upgrade` on a host with systemd.
//
//	fakegithub -releases <directory> -source <directory>
//
// The releases' directory has one directory for each version, with the
// release's files under their published names. Into the other it writes
// what the varlatch reads (source.json and what it names), then prints
// "serving", and serves on loopback until it is ended. Every request it got
// is a line on its standard error.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/lib/release"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fakegithub:", err)
		os.Exit(1)
	}
}

func run() error {
	releases := flag.String("releases", "", "the directory of releases, one directory for each version")
	source := flag.String("source", "", "the directory to write source.json in")
	flag.Parse()
	if *releases == "" || *source == "" || flag.NArg() > 0 {
		return fmt.Errorf("usage: fakegithub -releases <directory> -source <directory>")
	}
	entries, err := os.ReadDir(*releases)
	if err != nil {
		return err
	}
	s := fakerelease.New()
	defer s.Close()
	for _, e := range entries {
		if !e.IsDir() || !release.ValidVersion(e.Name()) {
			return fmt.Errorf("%s is not a release's directory", filepath.Join(*releases, e.Name()))
		}
		files, err := os.ReadDir(filepath.Join(*releases, e.Name()))
		if err != nil {
			return err
		}
		r := &fakerelease.Release{Files: map[string][]byte{}}
		for _, f := range files {
			b, err := os.ReadFile(filepath.Join(*releases, e.Name(), f.Name()))
			if err != nil {
				return err
			}
			r.Files[f.Name()] = b
		}
		if len(r.Files) == 0 {
			return fmt.Errorf("the release %s has no files", e.Name())
		}
		s.Publish(e.Name(), r)
	}
	if _, err := s.WriteSourceConfig(*source); err != nil {
		return err
	}
	fmt.Println("serving")
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	<-done
	for _, path := range s.Requests() {
		fmt.Fprintln(os.Stderr, path)
	}
	return nil
}
