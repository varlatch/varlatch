// SPDX-License-Identifier: Apache-2.0

// Command g9a runs ADR-0059's storage benchmark (gate G9a) with k6:
//
//	g9a plan [-scale f] [-wal-bound b] [-backup-step-pages n -backup-pause-ms ms]
//	         [-wal-fraction f] [-wal-attempts n]
//	                                         print a plan (the G9a profile)
//	g9a report dir                           judge a run: exit 0 pass, 1 fail, 2 inconclusive
//
// The run itself is served by varlatchd built with the g9a tag
// (varlatchd g9a -plan p -data d -out o); run.sh drives it around k6.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

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
		fraction := fs.Float64("wal-fraction", 0, "WAL-triggered backups start at this fraction of the bound (default 0.95)")
		attempts := fs.Int("wal-attempts", 0, "most WAL-triggered backups in their phase (default 5)")
		_ = fs.Parse(os.Args[2:])
		p := g9a.DefaultPlan()
		if *scale != 1 {
			p = p.Scaled(*scale)
		}
		if *bound > 0 {
			p.WALBound = *bound
		}
		p.BackupStepPages, p.BackupPauseMs = *stepPages, *pauseMs
		// Given flags apply to every WAL-triggered backup (Validate refuses
		// a fraction outside (0, 1] or fewer than one attempt).
		given := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
		for i := range p.Backups {
			w := &p.Backups[i].WALTriggered
			if !w.Set() {
				continue
			}
			if given["wal-fraction"] {
				w.Fraction = *fraction
			}
			if given["wal-attempts"] {
				w.MaxAttempts = *attempts
			}
		}
		if err := p.Validate(); err != nil {
			log.Fatal(err)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
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
	case "checkcost":
		// The converge engine's cost against converge-baseline.json
		// (g9a.CheckCost): exit 1 when it is out of it.
		if len(os.Args) != 3 {
			usage()
		}
		problems, applies, err := g9a.CheckCost(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		if !applies {
			fmt.Printf("converge cost not checked: %s\n", strings.Join(problems, "; "))
			return
		}
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "converge cost: %s\n", p)
		}
		if len(problems) > 0 {
			os.Exit(1)
		}
		fmt.Println("converge cost within the baseline (converge-baseline.json)")
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: g9a plan [-scale f] [-wal-bound bytes] [-wal-fraction f] [-wal-attempts n] | g9a report dir | g9a checkcost dir")
	os.Exit(3)
}
