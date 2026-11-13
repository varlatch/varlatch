// SPDX-License-Identifier: Apache-2.0

// Command g9a runs ADR-0059's storage benchmark (gate G9a) with k6:
//
//	g9a plan [-scale f] [-wal-bound b] [-backup-step-pages n -backup-pause-ms ms]
//	                                         print a plan (the G9a profile)
//	g9a serve -plan p -data d -out o         seed, record the disk, serve the load
//	g9a report dir                           judge a run: exit 0 pass, 1 fail, 2 inconclusive
//
// run.sh drives all three around k6.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/varlatch/varlatch/go/bench/g9a"
)

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("g9a: ")
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "plan":
		fs := flag.NewFlagSet("plan", flag.ExitOnError)
		scale := fs.Float64("scale", 1, "multiply every duration and offset (a smoke run: < 1)")
		bound := fs.Int64("wal-bound", 0, "WAL bound in bytes (default: the shipped 64 MiB)")
		stepPages := fs.Int("backup-step-pages", 0, "pages per backup step (default: the engine's)")
		pauseMs := fs.Int("backup-pause-ms", 0, "pause between backup steps in ms (default: the engine's)")
		_ = fs.Parse(os.Args[2:])
		p := g9a.DefaultPlan()
		if *scale != 1 {
			p = p.Scaled(*scale)
		}
		if *bound > 0 {
			p.WALBound = *bound
		}
		p.BackupStepPages, p.BackupPauseMs = *stepPages, *pauseMs
		if err := p.Validate(); err != nil {
			log.Fatal(err)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		planPath := fs.String("plan", "", "plan file (required)")
		data := fs.String("data", "", "data directory for the database (required)")
		out := fs.String("out", "", "output directory (required)")
		listen := fs.String("listen", "127.0.0.1:8080", "address for the load")
		_ = fs.Parse(os.Args[2:])
		if *planPath == "" || *data == "" || *out == "" {
			fs.Usage()
			os.Exit(2)
		}
		p, err := g9a.ReadPlan(*planPath)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = g9a.Serve(ctx, g9a.ServeOptions{DataDir: *data, OutDir: *out, Plan: p, Listen: *listen, Logf: log.Printf})
		if err != nil {
			log.Fatal(err)
		}
	case "report":
		if len(os.Args) != 3 {
			usage()
		}
		r, err := g9a.WriteReport(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(r.Markdown())
		switch r.Verdict {
		case g9a.Pass:
		case g9a.Fail:
			os.Exit(1)
		default:
			os.Exit(2)
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: g9a plan [-scale f] [-wal-bound bytes] | g9a serve -plan p -data d -out o [-listen addr] | g9a report dir")
	os.Exit(3)
}
