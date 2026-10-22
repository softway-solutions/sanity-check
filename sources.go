package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// Entry is one command read from a history source.
type Entry struct {
	Source  string // e.g. "zsh"
	Path    string
	Line    int // line number in a text file, row id in a database
	Command string
}

// Source is a history file of a known format.
type Source struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

var formats = []string{"zsh", "bash", "fish", "nushell", "nushell-sqlite", "atuin", "powershell", "tcsh", "plain", "mysql"}

// Discover returns every history file that exists on this machine, across all
// known shells and REPLs, de-duplicated by real path.
func Discover() []Source {
	home, _ := os.UserHomeDir()
	data := envOr("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	config := envOr("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	appdata := os.Getenv("APPDATA")
	h := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }

	var cands []Source
	add := func(name, format string, paths ...string) {
		for _, p := range paths {
			if p == "" {
				continue
			}
			matches, _ := filepath.Glob(p)
			for _, m := range matches {
				cands = append(cands, Source{name, format, m})
			}
		}
	}

	// HISTFILE is rarely exported, but honour it when it is.
	if hf := os.Getenv("HISTFILE"); hf != "" {
		f := "bash"
		if strings.Contains(filepath.Base(hf), "zsh") || strings.Contains(filepath.Base(hf), "zhist") {
			f = "zsh"
		}
		add(f, f, hf)
	}
	zdot := envOr("ZDOTDIR", home)
	add("zsh", "zsh", filepath.Join(zdot, ".zsh_history"), filepath.Join(zdot, ".zhistory"), h(".histfile"), h(".zsh_sessions", "*.history"))
	add("bash", "bash", h(".bash_history"), h(".bash_sessions", "*.history"))
	add("ksh", "plain", h(".sh_history"))
	add("tcsh", "tcsh", h(".history"))
	add("fish", "fish", filepath.Join(data, "fish", "*_history"))

	nuDirs := []string{filepath.Join(config, "nushell")}
	switch runtime.GOOS {
	case "darwin":
		nuDirs = append(nuDirs, h("Library", "Application Support", "nushell"))
	case "windows":
		nuDirs = append(nuDirs, filepath.Join(appdata, "nushell"))
	}
	for _, d := range nuDirs {
		add("nushell", "nushell", filepath.Join(d, "history.txt"))
		add("nushell", "nushell-sqlite", filepath.Join(d, "history.sqlite3"))
	}

	add("atuin", "atuin", envOr("ATUIN_DB_PATH", filepath.Join(data, "atuin", "history.db")))

	add("powershell", "powershell", filepath.Join(data, "powershell", "PSReadLine", "*_history.txt"))
	if appdata != "" {
		add("powershell", "powershell", filepath.Join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "*_history.txt"))
	}

	// REPLs and database clients, which often see passwords and tokens.
	add("psql", "plain", h(".psql_history"))
	add("mysql", "mysql", h(".mysql_history"))
	add("python", "plain", h(".python_history"))
	add("node", "plain", h(".node_repl_history"))
	add("sqlite", "plain", h(".sqlite_history"))
	add("redis-cli", "plain", h(".rediscli_history"))
	add("irb", "plain", h(".irb_history"))
	add("mongosh", "plain", h(".mongosh", "mongosh_repl_history"), h(".dbshell"))

	seen := map[string]bool{}
	var out []Source
	for _, c := range cands {
		real, err := filepath.EvalSymlinks(c.Path)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(real); err != nil || fi.IsDir() || seen[real] {
			continue
		}
		seen[real] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Read returns every command in src.
func Read(src Source) ([]Entry, error) {
	switch src.Format {
	case "atuin":
		return readSQL(src, "SELECT rowid, command FROM history WHERE deleted_at IS NULL")
	case "nushell-sqlite":
		return readSQL(src, "SELECT id, command_line FROM history")
	}
	f, err := os.Open(src.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadText(src, f)
}

var (
	zshExtended = regexp.MustCompile(`^: \d+:\d+;`)
	bashStamp   = regexp.MustCompile(`^#\d{9,}$`)
	tcshStamp   = regexp.MustCompile(`^#\+\d+$`)
	mysqlOctal  = regexp.MustCompile(`\\(\d{3})`)
)

// ReadText parses a line-oriented history file in src.Format.
func ReadText(src Source, r io.Reader) ([]Entry, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if src.Format == "zsh" {
		raw = unmetafy(raw)
	}
	var out []Entry
	emit := func(line int, cmd string) {
		if strings.TrimSpace(cmd) != "" {
			out = append(out, Entry{src.Name, src.Path, line, cmd})
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	n := 0
	var pending strings.Builder // zsh multi-line commands end lines with a backslash
	pendingLine := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		switch src.Format {
		case "zsh":
			if pending.Len() == 0 {
				pendingLine = n
				line = zshExtended.ReplaceAllString(line, "")
			}
			if strings.HasSuffix(line, `\`) {
				pending.WriteString(strings.TrimSuffix(line, `\`) + "\n")
				continue
			}
			pending.WriteString(line)
			emit(pendingLine, pending.String())
			pending.Reset()
		case "bash":
			if !bashStamp.MatchString(line) {
				emit(n, line)
			}
		case "tcsh":
			if !tcshStamp.MatchString(line) {
				emit(n, line)
			}
		case "fish":
			if rest, ok := strings.CutPrefix(line, "- cmd: "); ok {
				emit(n, fishUnescape(rest))
			}
		case "mysql":
			emit(n, mysqlOctal.ReplaceAllStringFunc(line, func(m string) string {
				var c int
				fmt.Sscanf(m[1:], "%o", &c)
				return string(rune(c))
			}))
		default:
			emit(n, line)
		}
	}
	if pending.Len() > 0 {
		emit(pendingLine, pending.String())
	}
	return out, sc.Err()
}

// unmetafy reverses zsh's history encoding: a 0x83 byte marks that the next
// byte was XORed with 0x20.
func unmetafy(b []byte) []byte {
	if bytes.IndexByte(b, 0x83) < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x83 && i+1 < len(b) {
			i++
			out = append(out, b[i]^0x20)
			continue
		}
		out = append(out, b[i])
	}
	return out
}

func fishUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func readSQL(src Source, query string) ([]Entry, error) {
	// Read-only, and never create the file if it vanished.
	u := url.URL{Scheme: "file", Path: src.Path, RawQuery: "mode=ro&_pragma=busy_timeout(3000)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var id int
		var cmd string
		if err := rows.Scan(&id, &cmd); err != nil {
			return nil, err
		}
		out = append(out, Entry{src.Name, src.Path, id, cmd})
	}
	return out, rows.Err()
}
