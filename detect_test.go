package main

import (
	"strings"
	"testing"
)

// Fake credentials are assembled at runtime so this file never contains a
// string that secret scanners (including this one) would flag.
func fake(prefix string, n int) string { return prefix + strings.Repeat("aB3dE5", n)[:n] }

func TestScanFlags(t *testing.T) {
	cases := []struct {
		cmd  string
		rule string // "" means no hit expected
	}{
		{"gh auth login --with-token " + fake("ghp_", 36), "github-token"},
		{"export AWS_ACCESS_KEY_ID=AKIA" + strings.Repeat("Q7", 8), "aws-access-key-id"},
		{"curl -H 'x-api-key: " + fake("sk-ant-api03-", 40) + "'", "anthropic-key"},
		{"export OPENAI_API_KEY=" + fake("sk-proj-", 40), "openai-key"},
		{"export DB_PASSWORD=hunter2Xy9", "secret-assignment"},
		{"$env.GITHUB_TOKEN = 'q8Zr2LmP4vKx9'", "secret-assignment"},
		{"set -gx API_TOKEN q8Zr2LmP4vKx9", "fish-set-secret"},
		{"psql postgres://admin:S3cr3tPw@db.local/app", "url-credentials"},
		{"docker login --password q8Zr2LmP4vKx9 -u me", "secret-flag"},
		{"curl -H 'Authorization: Bearer q8Zr2LmP4vKx9w'", "auth-header"},
		{"curl -u admin:q8Zr2LmP4vKx9 https://x", "basic-auth-flag"},
		{"mysql -u root -pq8Zr2LmP4vKx9 app", "mysql-password"},
		{"sshpass -p 'q8Zr2LmP4vKx9' ssh host", "sshpass"},

		// References, placeholders and safe forms.
		{"export GITHUB_TOKEN=$(security find-generic-password -s github-token -a me -w)", ""},
		{"$env.GITHUB_TOKEN = (security find-generic-password -s gh -a me -w)", ""},
		{"export DB_PASSWORD=$DB_PASS", ""},
		{"export DB_PASSWORD=${DB_PASS}", ""},
		{"docker login --password-stdin", ""},
		{"gh auth login --with-token < token.txt", ""},
		{"curl -H 'Authorization: Bearer $TOKEN'", ""},
		{"export API_KEY=your_api_key_here", ""},
		{"export API_KEY=xxxxxxxxxxxx", ""},
		{"export API_KEY=<token>", ""},
		{"git config credential.helper osxkeychain", ""},
		{"echo $PASSWORD", ""},
		{"cd ~/Projects && ls", ""},
		{"kubectl create secret generic x --from-file=./secret.json", ""},
		{"npm run test", ""},
		{"psql postgres://admin:$PGPASS@db.local/app", ""},
		{"export TOKEN_FILE=/run/secrets/token", ""},
		{"$env.GEMINI_API_KEY = security find-generic-password -s gemini -a me -w", ""},
		{`{"model": "x", "max_tokens": 1024}`, ""},
		{`zsh -c 'read -rs "PW?New password: "; echo -n "$PW"'`, ""},
		{"curl -u ACxxxx1234:[AuthToken] https://api.twilio.com", ""},
	}
	for _, c := range cases {
		hits := Scan(c.cmd)
		switch {
		case c.rule == "" && len(hits) > 0:
			t.Errorf("unexpected %s in %q (value %q)", hits[0].Rule, c.cmd, hits[0].Secret)
		case c.rule != "" && len(hits) == 0:
			t.Errorf("missed %s in %q", c.rule, c.cmd)
		case c.rule != "" && hits[0].Rule != c.rule:
			t.Errorf("%q: got %s, want %s", c.cmd, hits[0].Rule, c.rule)
		}
	}
}

func TestRedact(t *testing.T) {
	cmd := "export DB_PASSWORD=hunter2Xy9 && psql"
	got := Redact(cmd, Scan(cmd))
	if strings.Contains(got, "hunter2Xy9") || !strings.Contains(got, "&& psql") {
		t.Errorf("Redact = %q", got)
	}
}
