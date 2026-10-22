package main

import (
	"math"
	"regexp"
	"strings"
)

// Confidence levels. High means the value matches a vendor's documented token
// format; medium means a secret-looking name or flag is followed by a literal.
const (
	High   = "high"
	Medium = "medium"
)

type rule struct {
	id         string
	confidence string
	re         *regexp.Regexp
	group      int  // capture group holding the secret
	literal    bool // value must pass looksLiteral (context rules)
}

// Hit is one secret found inside one command.
type Hit struct {
	Rule       string `json:"rule"`
	Confidence string `json:"confidence"`
	Secret     string `json:"-"`
	start, end int
}

var rules = []rule{
	// Vendor token formats. Order matters: more specific prefixes first, since
	// overlapping hits are dropped in favour of the earlier rule.
	{"private-key", High, regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----)`), 1, false},
	{"aws-access-key-id", High, regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`), 1, false},
	{"github-token", High, regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`), 1, false},
	{"github-pat", High, regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{22,255})\b`), 1, false},
	{"gitlab-token", High, regexp.MustCompile(`\b(gl(?:pat|dt|rt|ptt)-[A-Za-z0-9_-]{20,})`), 1, false},
	{"anthropic-key", High, regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{20,})`), 1, false},
	{"openai-key", High, regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})`), 1, false},
	{"stripe-key", High, regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})`), 1, false},
	{"slack-token", High, regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9-]{10,})`), 1, false},
	{"slack-webhook", High, regexp.MustCompile(`(https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,})`), 1, false},
	{"google-api-key", High, regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})`), 1, false},
	{"npm-token", High, regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), 1, false},
	{"pypi-token", High, regexp.MustCompile(`\b(pypi-[A-Za-z0-9_-]{50,})`), 1, false},
	{"huggingface-token", High, regexp.MustCompile(`\b(hf_[A-Za-z0-9]{30,})\b`), 1, false},
	{"sendgrid-key", High, regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})`), 1, false},
	{"digitalocean-token", High, regexp.MustCompile(`\b(do[por]_v1_[a-f0-9]{64})\b`), 1, false},
	{"jwt", High, regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`), 1, false},
	{"aws-secret-key", High, regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})\b`), 1, false},

	// Context rules: a credential-shaped name, flag or header followed by a
	// value that has to be a literal (not $VAR, $(cmd), a path, a placeholder).
	{"url-credentials", Medium, regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@'"]+:([^/\s@'"]+)@`), 1, true},
	{"secret-assignment", Medium, regexp.MustCompile(`(?i)(?:^|[\s;(.{"'])["']?([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|AUTH_?KEY|CREDENTIALS?)[A-Z0-9_]*)["']?\s*[=:]\s*("[^"]*"|'[^']*'|[^\s;|&)]+)`), 2, true},
	{"fish-set-secret", Medium, regexp.MustCompile(`(?i)\bset\s+(?:-[a-zA-Z]+\s+)*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY)[A-Z0-9_]*\s+("[^"]*"|'[^']*'|[^\s;|&)]+)`), 1, true},
	{"secret-flag", Medium, regexp.MustCompile(`(?i)(?:^|\s)--?(?:password|passwd|pass|pw|token|secret|api-?key|apikey|access-?token|auth-?token|client-?secret|secret-?key|access-?key)(?:=|\s+)("[^"]*"|'[^']*'|[^\s;|&)]+)`), 1, true},
	{"auth-header", Medium, regexp.MustCompile(`(?i)(?:authorization|x-api-key|api-key|x-auth-token|private-token|x-access-token)\s*:\s*(?:bearer\s+|token\s+|basic\s+)?([^\s'"]+)`), 1, true},
	{"basic-auth-flag", Medium, regexp.MustCompile(`(?:^|\s)(?:-u|--user)\s*['"]?[^\s:'"]+:([^\s'"]+)`), 1, true},
	{"mysql-password", Medium, regexp.MustCompile(`\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b.*?\s-p(["']?[^\s"']+)`), 1, true},
	{"sshpass", Medium, regexp.MustCompile(`\bsshpass\s+-p\s*("[^"]*"|'[^']*'|\S+)`), 1, true},
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

var secretCommands = map[string]bool{
	"security": true, "op": true, "pass": true, "gopass": true, "vault": true,
	"bw": true, "lpass": true, "doppler": true, "gcloud": true, "aws": true,
	"az": true, "cat": true, "kubectl": true, "keyring": true, "secret-tool": true,
}

var placeholders = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true,
	"api_key": true, "changeme": true, "example": true, "dummy": true, "test": true,
	"null": true, "none": true, "true": true, "false": true, "redacted": true,
	"your_token": true, "your-token": true, "yourtoken": true, "your_api_key": true,
	"your-api-key": true, "your_password": true, "mypassword": true, "foobar": true,
	"stdin": true, "prompt": true, "required": true, "optional": true,
}

// Scan returns every non-overlapping hit in cmd.
func Scan(cmd string) []Hit {
	var hits []Hit
	for _, r := range rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(cmd, -1) {
			s, e := m[2*r.group], m[2*r.group+1]
			if s < 0 {
				continue
			}
			val := cmd[s:e]
			if r.id == "secret-assignment" && strings.HasSuffix(strings.ToUpper(cmd[m[2]:m[3]]), "TOKENS") {
				continue
			}
			if r.literal {
				var ok bool
				if val, s, e, ok = literalValue(val, s, e); !ok {
					continue
				}
			}
			if overlaps(hits, s, e) {
				continue
			}
			hits = append(hits, Hit{Rule: r.id, Confidence: r.confidence, Secret: val, start: s, end: e})
		}
	}
	return hits
}

func overlaps(hits []Hit, s, e int) bool {
	for _, h := range hits {
		if s < h.end && h.start < e {
			return true
		}
	}
	return false
}

// literalValue unquotes a captured value and reports whether it is a real
// literal credential rather than a reference, path, or placeholder.
func literalValue(v string, s, e int) (string, int, int, bool) {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v, s, e = v[1:len(v)-1], s+1, e-1
	} else {
		v = strings.Trim(v, `"'`)
	}
	return v, s, e, looksLiteral(v)
}

func looksLiteral(v string) bool {
	if len(v) < 6 {
		return false
	}
	// References: shell/nushell/fish/PowerShell/Windows variables, command
	// substitution, templating, file inputs.
	for _, p := range []string{"$", "`", "(", "[", "%", "<", "{{", "${", "@", "/", "./", "../", "~/", "-"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	if strings.Contains(v, "$(") || strings.Contains(v, "${") || strings.Contains(v, "find-generic-password") {
		return false
	}
	// Prose and prompts, not credentials.
	if strings.ContainsAny(v, " \t\n;") {
		return false
	}
	// Numbers: max_tokens: 1000, PORT-like settings.
	if strings.Trim(v, "0123456789") == "" {
		return false
	}
	low := strings.ToLower(v)
	// A secret-store CLI invoked without $( ), e.g. nushell's
	// $env.KEY = security find-generic-password ...
	if secretCommands[low] {
		return false
	}
	if placeholders[low] || strings.HasPrefix(low, "your") || strings.HasPrefix(low, "<") ||
		strings.HasSuffix(low, "here") || strings.Contains(low, "example") {
		return false
	}
	// Runs of one character: xxxxxx, ******, ......
	if strings.Count(v, v[:1]) == len(v) {
		return false
	}
	// Identifiers and env-var names (FOO_TOKEN, some.key.path) are usually
	// a reference to a setting, not a value.
	if envName.MatchString(v) {
		return false
	}
	return entropy(v) >= 2.5
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// Redact replaces each secret in cmd with a short prefix and a mask.
func Redact(cmd string, hits []Hit) string {
	var b strings.Builder
	last := 0
	for _, h := range sortHits(hits) {
		b.WriteString(cmd[last:h.start])
		b.WriteString(mask(h.Secret))
		last = h.end
	}
	b.WriteString(cmd[last:])
	return b.String()
}

func mask(s string) string {
	keep := 4
	if len(s) <= 8 {
		keep = 1
	}
	return s[:keep] + strings.Repeat("*", 6)
}

func sortHits(hits []Hit) []Hit {
	out := append([]Hit(nil), hits...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].start < out[j-1].start; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
