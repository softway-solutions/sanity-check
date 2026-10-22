package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func readString(t *testing.T, format, in string) []Entry {
	t.Helper()
	es, err := ReadText(Source{Name: format, Format: format, Path: "x"}, strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func commands(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Command)
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestZsh(t *testing.T) {
	in := "ls\n: 1700000000:0;echo hi\n: 1700000001:0;for x in a b; do\\\necho $x\\\ndone\n"
	es := readString(t, "zsh", in)
	eq(t, commands(es), []string{"ls", "echo hi", "for x in a b; do\necho $x\ndone"})
	if es[2].Line != 3 {
		t.Errorf("multi-line entry line = %d, want 3", es[2].Line)
	}
}

func TestZshMetafied(t *testing.T) {
	// "é" is 0xC3 0xA9; zsh writes 0xA9 as-is but 0x83-escapes bytes >= 0x83
	// that collide with its tokens. Test the raw mechanism.
	in := string([]byte{'a', 0x83, 'A' ^ 0x20, 'b', '\n'})
	eq(t, commands(readString(t, "zsh", in)), []string{"aAb"})
}

func TestBash(t *testing.T) {
	eq(t, commands(readString(t, "bash", "#1700000000\nls -la\n\ncd /\n")), []string{"ls -la", "cd /"})
}

func TestFish(t *testing.T) {
	in := "- cmd: echo one\n  when: 1700000000\n- cmd: printf 'a\\nb' \\\\ x\n  when: 1700000001\n  paths:\n    - foo\n"
	eq(t, commands(readString(t, "fish", in)), []string{"echo one", "printf 'a\nb' \\ x"})
}

func TestMysql(t *testing.T) {
	eq(t, commands(readString(t, "mysql", `select\0401;`)), []string{"select 1;"})
}

func TestSQLiteSources(t *testing.T) {
	dir := t.TempDir()
	atuin := filepath.Join(dir, "history.db")
	db, err := sql.Open("sqlite", atuin)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE history (id text primary key, command text not null, deleted_at integer)",
		"INSERT INTO history VALUES ('a', 'ls', NULL), ('b', 'gone', 1700000000)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	es, err := Read(Source{"atuin", "atuin", atuin})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, commands(es), []string{"ls"})

	nu := filepath.Join(dir, "history.sqlite3")
	db, _ = sql.Open("sqlite", nu)
	db.Exec("CREATE TABLE history (id integer primary key, command_line text)")
	db.Exec("INSERT INTO history (command_line) VALUES ('ls | first')")
	db.Close()
	es, err = Read(Source{"nushell", "nushell-sqlite", nu})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, commands(es), []string{"ls | first"})
}

func TestRunStdin(t *testing.T) {
	var out, errb strings.Builder
	in := "ls\nexport DB_PASSWORD=hunter2Xy9\n"
	code := run([]string{"--no-color", "-"}, strings.NewReader(in), &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, errb.String())
	}
	if strings.Contains(out.String(), "hunter2Xy9") || !strings.Contains(out.String(), "stdin:2") {
		t.Errorf("output = %q", out.String())
	}
	out.Reset()
	if code := run([]string{"-"}, strings.NewReader("ls\n"), &out, &errb); code != 0 {
		t.Errorf("clean input exit = %d", code)
	}
}
