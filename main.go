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
	Jev        *float64   `json:"jev,omitempty"` // TypeSafe's probability, with --jev
	Locations  []Location `json:"locations"`
}

// seenCmd is one distinct command, scanned once however often it recurs.
type seenCmd struct {
	hits []Hit
	locs []Location
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

With --jev, commands are also judged by Jev, TypeSafe's probability model
(needs TYPESAFE_API_KEY). Candidate commands are sent to api.typesafe.ai
exactly as typed, secrets included.

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

		useJev     = fs.Bool("jev", false, "also judge commands with Jev (TypeSafe); sends them unmasked to api.typesafe.ai")
		jevThresh  = fs.Float64("jev-threshold", 0.7, "Jev probability at or above which a command counts as a leak")
		jevLimit   = fs.Int("jev-limit", 200, "most recent keyword-only commands (no rule match) to ask Jev about")
		jevModel   = fs.String("jev-model", "", "Jev model (default $JEV_MODEL, else jev-latest)")
		jevWorkers = fs.Int("jev-workers", 20, "concurrent Jev requests")
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

	seen := map[string]*seenCmd{}
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
			c, ok := seen[e.Command]
			if !ok {
				c = &seenCmd{hits: Scan(e.Command)}
				if *high {
					c.hits = slices.DeleteFunc(c.hits, func(h Hit) bool { return h.Confidence != High })
				}
				seen[e.Command] = c
				order = append(order, e.Command)
			}
			c.locs = append(c.locs, Location{e.Source, e.Path, e.Line})
		}
	}

	// Jev judges medium-confidence hits and keyword-only commands. Vendor-format
	// tokens are certain, so they are not sent. --high-only skips Jev entirely.
	var scores map[string]float64
	if *useJev && !*high {
		client, err := newJevClient(*jevModel)
		if err != nil {
			fmt.Fprintln(stderr, "sanity-check:", err)
			return 2
		}
		var ask, keywordOnly []string
		for _, cmd := range order {
			hits := seen[cmd].hits
			switch {
			case len(hits) == 0:
				if jevKeyword.MatchString(cmd) {
					keywordOnly = append(keywordOnly, cmd)
				}
			case !slices.ContainsFunc(hits, func(h Hit) bool { return h.Confidence == High }):
				ask = append(ask, cmd)
			}
		}
		// History is read oldest first, so the tail is the most recent.
		if len(keywordOnly) > *jevLimit {
			keywordOnly = keywordOnly[len(keywordOnly)-*jevLimit:]
		}
		ask = append(ask, keywordOnly...)
		if len(ask) > 0 {
			fmt.Fprintf(stderr, "jev: sending %d commands to TypeSafe (unmasked)\n", len(ask))
			var progress io.Writer
			if isTTY(stderr) {
				progress = stderr
			}
			var nFailed int
			scores, nFailed, err = judgeAll(client, ask, max(*jevWorkers, 1), progress)
			if nFailed > 0 {
				fmt.Fprintf(stderr, "jev: %d of %d requests failed, those keep the rule-based verdict. First error: %v\n", nFailed, len(ask), err)
				if nFailed == len(ask) {
					failed = true
				}
			}
		}
	}

	findings := make([]Finding, 0, len(order))
	for _, cmd := range order {
		c := seen[cmd]
		score, judged := scores[cmd]
		var f Finding
		switch {
		case len(c.hits) > 0:
			f = Finding{Command: cmd, Confidence: Medium}
			for _, h := range c.hits {
				if !slices.Contains(f.Rules, h.Rule) {
					f.Rules = append(f.Rules, h.Rule)
				}
				if h.Confidence == High {
					f.Confidence = High
				}
			}
			// Jev overrules a medium-confidence rule match it disagrees with.
			if judged && score < *jevThresh {
				continue
			}
			if !*reveal {
				f.Command = Redact(cmd, c.hits)
			}
		case judged && score >= *jevThresh:
			// Found by Jev alone, so the secret's position is unknown: mask
			// anything that looks like a value.
			f = Finding{Command: cmd, Confidence: Medium, Rules: []string{"jev"}}
			if !*reveal {
				f.Command = maskValues(cmd)
			}
		default:
			continue
		}
		if judged {
			f.Jev = &score
		}
		f.Locations = c.locs
		findings = append(findings, f)
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
	return !disabled && os.Getenv("NO_COLOR") == "" && isTTY(w)
}

func isTTY(w io.Writer) bool {
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
		if f.Jev != nil {
			where += paint("2", fmt.Sprintf("  jev %.2f", *f.Jev))
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
