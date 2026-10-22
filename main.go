// sanity-check scans shell and REPL history for literal credentials: API
// keys, passwords and tokens typed inline instead of read from the
// environment or a secret store.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var version = "dev"

// Finding is one distinct command that leaks a secret, with every place it
// appears.
type Finding struct {
	Command    string     `json:"command"`
	Confidence string     `json:"confidence"`
	Rules      []string   `json:"rules"`
	Locations  []Location `json:"locations"`
}

type Location struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
}

const usage = `sanity-check - find secrets leaked into shell history

Usage:
  sanity-check [flags]           scan every history file found on this machine
  sanity-check [flags] FILE...   scan specific files (format from --format)
  history | sanity-check -       scan stdin

Scans zsh, bash, fish, nushell (txt + sqlite), atuin, PowerShell, ksh, tcsh,
and psql/mysql/python/node/sqlite/redis/irb/mongosh REPL histories.

Exits 0 when nothing is found, 1 when secrets are found, 2 on error.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sanity-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		asJSON  = fs.Bool("json", false, "print findings as JSON")
		reveal  = fs.Bool("reveal", false, "print secrets unmasked (careful: puts them on screen)")
		list    = fs.Bool("list", false, "list the history files that would be scanned, then exit")
		high    = fs.Bool("high-only", false, "only report vendor-format tokens (fewer false positives)")
		only    = fs.String("source", "", "comma-separated sources to scan, e.g. zsh,atuin")
		format  = fs.String("format", "plain", "format of FILE arguments: "+strings.Join(formats, ", "))
		noColor = fs.Bool("no-color", false, "disable colour")
		showVer = fs.Bool("version", false, "print version")
	)
	fs.Usage = func() { fmt.Fprint(stderr, usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVer {
		fmt.Fprintln(stdout, "sanity-check", version)
		return 0
	}
	if !slices.Contains(formats, *format) {
		fmt.Fprintf(stderr, "sanity-check: unknown --format %q\n", *format)
		return 2
	}

	var sources []Source
	if fs.NArg() > 0 {
		for _, p := range fs.Args() {
			name := filepath.Base(p)
			if p == "-" {
				name = "stdin"
			}
			sources = append(sources, Source{Name: name, Format: *format, Path: p})
		}
	} else {
		sources = Discover()
		if *only != "" {
			want := strings.Split(*only, ",")
			sources = slices.DeleteFunc(sources, func(s Source) bool { return !slices.Contains(want, s.Name) })
		}
	}

	if *list {
		if *asJSON {
			return writeJSON(stdout, sources)
		}
		for _, s := range sources {
			fmt.Fprintf(stdout, "%-11s %s\n", s.Name, s.Path)
		}
		return 0
	}
	if len(sources) == 0 {
		fmt.Fprintln(stderr, "sanity-check: no history files found")
		return 0
	}

	byCmd := map[string]*Finding{}
	var order []string
	scanned, failed := 0, false
	for _, src := range sources {
		var entries []Entry
		var err error
		if src.Path == "-" {
			entries, err = ReadText(src, stdin)
		} else {
			entries, err = Read(src)
		}
		if err != nil {
			fmt.Fprintf(stderr, "sanity-check: %s: %v\n", src.Path, err)
			failed = true
			continue
		}
		scanned += len(entries)
		for _, e := range entries {
			hits := Scan(e.Command)
			if *high {
				hits = slices.DeleteFunc(hits, func(h Hit) bool { return h.Confidence != High })
			}
			if len(hits) == 0 {
				continue
			}
			shown := e.Command
			if !*reveal {
				shown = Redact(e.Command, hits)
			}
			f, ok := byCmd[e.Command]
			if !ok {
				f = &Finding{Command: shown, Confidence: Medium}
				for _, h := range hits {
					if !slices.Contains(f.Rules, h.Rule) {
						f.Rules = append(f.Rules, h.Rule)
					}
					if h.Confidence == High {
						f.Confidence = High
					}
				}
				byCmd[e.Command] = f
				order = append(order, e.Command)
			}
			f.Locations = append(f.Locations, Location{e.Source, e.Path, e.Line})
		}
	}

	findings := make([]Finding, 0, len(order))
	for _, k := range order {
		findings = append(findings, *byCmd[k])
	}
	// High confidence first, otherwise in the order they were found.
	slices.SortStableFunc(findings, func(a, b Finding) int {
		if a.Confidence == b.Confidence {
			return 0
		}
		if a.Confidence == High {
			return -1
		}
		return 1
	})

	if *asJSON {
		if code := writeJSON(stdout, findings); code != 0 {
			return code
		}
	} else {
		printText(stdout, stderr, findings, len(sources), scanned, color(stdout, *noColor))
	}
	switch {
	case failed:
		return 2
	case len(findings) > 0:
		return 1
	}
	return 0
}

func writeJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 2
	}
	return 0
}

func color(w io.Writer, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func printText(stdout, stderr io.Writer, findings []Finding, nSources, nCmds int, c bool) {
	paint := func(code, s string) string {
		if !c {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	for _, f := range findings {
		label := paint("33", "MEDIUM")
		if f.Confidence == High {
			label = paint("1;31", "HIGH  ")
		}
		loc := f.Locations[0]
		where := fmt.Sprintf("%s:%d", loc.Source, loc.Line)
		if n := len(f.Locations); n > 1 {
			where += fmt.Sprintf(" (+%d more)", n-1)
		}
		cmd := strings.ReplaceAll(f.Command, "\n", "⏎")
		fmt.Fprintf(stdout, "%s  %-24s %s\n        %s\n", label, strings.Join(f.Rules, ","), paint("2", where), cmd)
	}
	summary := fmt.Sprintf("%d command(s) with secrets, from %d commands in %d history file(s).", len(findings), nCmds, nSources)
	if len(findings) == 0 {
		summary = fmt.Sprintf("No secrets found in %d commands across %d history file(s).", nCmds, nSources)
	} else {
		summary += " Rotate these credentials, then remove the lines from history."
	}
	fmt.Fprintln(stderr, summary)
}
