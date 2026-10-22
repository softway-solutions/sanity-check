package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// stubJev serves /systemone, answering with score(state) and recording every
// state it was asked about.
func stubJev(t *testing.T, score func(state string) float64) *[]string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/systemone" || r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "bad request", 400)
			return
		}
		var body struct {
			State     string                    `json:"state"`
			Questions map[string]map[string]any `json:"questions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Questions["inline_secret"]["type"] != "noul" {
			http.Error(w, "no question", 422)
			return
		}
		mu.Lock()
		asked = append(asked, body.State)
		mu.Unlock()
		fmt.Fprintf(w, `{"model":"jev-1","answers":{"inline_secret":{"type":"noul","noul":%g}}}`, score(body.State))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("JEV_BASE_URL", srv.URL)
	t.Setenv("TYPESAFE_API_KEY", "test-key")
	return &asked
}

func runJSON(t *testing.T, in string, args ...string) ([]Finding, int, string) {
	t.Helper()
	var out, errb strings.Builder
	code := run(append(args, "--json", "-"), strings.NewReader(in), &out, &errb)
	var fs []Finding
	if err := json.Unmarshal([]byte(out.String()), &fs); err != nil {
		t.Fatalf("bad JSON %q (stderr %s)", out.String(), errb.String())
	}
	return fs, code, errb.String()
}

func TestJev(t *testing.T) {
	gh := fake("ghp_", 36)
	in := strings.Join([]string{
		"ls -la",                           // no keyword: never sent
		"gh auth login --with-token " + gh, // vendor format: kept, never sent
		"export DB_PASSWORD=hunter2Xy9",    // medium: Jev confirms
		"export LOG_SECRET=q8Zr2LmP4vKx9",  // medium: Jev overrules
		"mytool login q8Zr2LmP4vKx9Wq",     // no rule, keyword: Jev finds it
		"git log --author=me",              // no rule, keyword "auth": Jev clears it
	}, "\n")
	asked := stubJev(t, func(s string) float64 {
		switch {
		case strings.Contains(s, "DB_PASSWORD"), strings.Contains(s, "mytool"):
			return 0.95
		}
		return 0.1
	})

	fs, code, _ := runJSON(t, in, "--jev")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var got []string
	for _, f := range fs {
		got = append(got, strings.Join(f.Rules, ","))
		if strings.Contains(f.Command, "hunter2Xy9") || strings.Contains(f.Command, "q8Zr2LmP4vKx9Wq") || strings.Contains(f.Command, gh) {
			t.Errorf("secret not masked: %q", f.Command)
		}
	}
	eq(t, got, []string{"github-token", "secret-assignment", "jev"})
	if fs[1].Jev == nil || *fs[1].Jev != 0.95 || fs[0].Jev != nil {
		t.Errorf("jev scores: %v %v", fs[0].Jev, fs[1].Jev)
	}

	if len(*asked) != 4 {
		t.Errorf("asked %d commands, want 4: %q", len(*asked), *asked)
	}
	for _, a := range *asked {
		if strings.HasPrefix(a, "ls") || strings.Contains(a, gh) {
			t.Errorf("should not have asked about %q", a)
		}
	}
}

func TestJevLimitKeepsMostRecent(t *testing.T) {
	asked := stubJev(t, func(string) float64 { return 0 })
	runJSON(t, "login one\nlogin two\nlogin three\n", "--jev", "--jev-limit", "2")
	got := append([]string(nil), *asked...)
	if len(got) != 2 || strings.Contains(strings.Join(got, "|"), "one") {
		t.Errorf("asked %q, want the two most recent", got)
	}
}

func TestJevRetriesAndFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("retry-after", "0")
			http.Error(w, "slow down", 429)
			return
		}
		fmt.Fprint(w, `{"answers":{"inline_secret":{"type":"noul","noul":0.9}}}`)
	}))
	defer srv.Close()
	t.Setenv("JEV_BASE_URL", srv.URL)
	t.Setenv("TYPESAFE_API_KEY", "k")
	fs, _, _ := runJSON(t, "mytool login q8Zr2LmP4vKx9Wq\n", "--jev")
	if calls != 2 || len(fs) != 1 {
		t.Errorf("calls = %d, findings = %d", calls, len(fs))
	}

	// A server that always fails: rule results survive, exit is 2.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"nope"}`, 401)
	}))
	defer bad.Close()
	t.Setenv("JEV_BASE_URL", bad.URL)
	fs, code, stderr := runJSON(t, "export DB_PASSWORD=hunter2Xy9\n", "--jev")
	if code != 2 || len(fs) != 1 || !strings.Contains(stderr, "typesafe 401") {
		t.Errorf("code %d, findings %d, stderr %q", code, len(fs), stderr)
	}
}

func TestJevNeedsKey(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	var out, errb strings.Builder
	if code := run([]string{"--jev", "-"}, strings.NewReader("ls\n"), &out, &errb); code != 2 || !strings.Contains(errb.String(), "TYPESAFE_API_KEY") {
		t.Errorf("code %d, stderr %q", code, errb.String())
	}
}

func TestMaskValues(t *testing.T) {
	got := maskValues("mytool login q8Zr2LmP4vKx9Wq --host api.example.com")
	if strings.Contains(got, "q8Zr2LmP4vKx9Wq") || !strings.Contains(got, "api.example.com") || !strings.Contains(got, "mytool login") {
		t.Errorf("maskValues = %q", got)
	}
}
