package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Jev is TypeSafe's model that answers questions with probabilities
// (https://docs.typesafe.ai). With --jev, every candidate command is sent to
// it, as typed, with one yes/no ("noul") question.

const (
	jevBaseURL      = "https://api.typesafe.ai/v1"
	jevDefaultModel = "jev-latest"
	jevQuestion     = "Does this shell command contain a literal credential value (API key, password, token), rather than a $env reference or a `security find-generic-password` lookup?"
	jevMaxRetries   = 3
	jevMaxWait      = time.Minute
)

// jevKeyword picks commands worth asking about that no regex rule matched.
var jevKeyword = regexp.MustCompile(`(?i)(token|passw|secret|api[_-]?key|apikey|auth|bearer|credential|private|login|\s-p\S)`)

type jevClient struct {
	baseURL, key, model string
	http                *http.Client
}

func newJevClient(model string) (*jevClient, error) {
	key := os.Getenv("TYPESAFE_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("--jev needs TYPESAFE_API_KEY (keys are issued at https://console.typesafe.ai/keys)")
	}
	if model == "" {
		model = envOr("JEV_MODEL", jevDefaultModel)
	}
	return &jevClient{
		baseURL: strings.TrimRight(envOr("JEV_BASE_URL", jevBaseURL), "/"),
		key:     key,
		model:   model,
		http:    &http.Client{Timeout: 2 * time.Minute},
	}, nil
}

// InlineSecret returns the probability that cmd contains a literal credential.
func (c *jevClient) InlineSecret(cmd string) (float64, error) {
	body, _ := json.Marshal(map[string]any{
		"state": cmd,
		"model": c.model,
		"questions": map[string]any{
			"inline_secret": map[string]any{"type": "noul", "instructions": jevQuestion},
		},
	})
	for attempt := 0; ; attempt++ {
		req, _ := http.NewRequest("POST", c.baseURL+"/systemone", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return 0, err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var out struct {
				Answers map[string]struct {
					Noul *float64 `json:"noul"`
				} `json:"answers"`
			}
			if err := json.Unmarshal(data, &out); err != nil {
				return 0, fmt.Errorf("typesafe: bad response: %v", err)
			}
			a, ok := out.Answers["inline_secret"]
			if !ok || a.Noul == nil {
				return 0, fmt.Errorf("typesafe: response has no inline_secret answer")
			}
			return *a.Noul, nil
		}
		retryable := resp.StatusCode == 429 || resp.StatusCode == 529
		if !retryable || attempt == jevMaxRetries {
			return 0, fmt.Errorf("typesafe %d: %s (request id %s)", resp.StatusCode,
				strings.TrimSpace(string(data)), orUnknown(resp.Header.Get("x-typesafe-request-id")))
		}
		time.Sleep(retryWait(resp.Header.Get("retry-after"), attempt))
	}
}

// retryWait honours retry-after (capped), else backs off 1s, 2s, 4s with jitter.
func retryWait(after string, attempt int) time.Duration {
	if s, err := strconv.ParseFloat(after, 64); err == nil {
		return min(time.Duration(s*float64(time.Second)), jevMaxWait)
	}
	return time.Duration(1<<attempt)*time.Second + time.Duration(rand.Float64()*float64(time.Second/2))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// judgeAll asks Jev about every command, `workers` at a time. Failed commands
// are left out of the result and counted.
func judgeAll(c *jevClient, cmds []string, workers int, progress io.Writer) (map[string]float64, int, error) {
	scores := make(map[string]float64, len(cmds))
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failed   int
		firstErr error
		done     int
	)
	jobs := make(chan string)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cmd := range jobs {
				p, err := c.InlineSecret(cmd)
				mu.Lock()
				if err != nil {
					failed++
					if firstErr == nil {
						firstErr = err
					}
				} else {
					scores[cmd] = p
				}
				done++
				if progress != nil {
					fmt.Fprintf(progress, "\rjev: %d/%d", done, len(cmds))
				}
				mu.Unlock()
			}
		}()
	}
	for _, cmd := range cmds {
		jobs <- cmd
	}
	close(jobs)
	wg.Wait()
	if progress != nil && len(cmds) > 0 {
		fmt.Fprint(progress, "\r\033[K")
	}
	return scores, failed, firstErr
}

// maskValues hides likely secret values in a command Jev flagged but no rule
// located: any word of 8+ characters that mixes letters and digits or has high
// entropy, unless it is a flag, path, URL host or variable.
var wordRe = regexp.MustCompile(`[^\s=:'"@,;(){}\[\]]+`)

func maskValues(cmd string) string {
	return wordRe.ReplaceAllStringFunc(cmd, func(w string) string {
		if len(w) < 8 || strings.ContainsAny(w[:1], "-$/.~%<") || strings.Contains(w, "/") || strings.Contains(w, ".") {
			return w
		}
		hasDigit := strings.ContainsAny(w, "0123456789")
		hasLetter := strings.IndexFunc(w, func(r rune) bool { return r >= 'A' && r <= 'z' }) >= 0
		if (hasDigit && hasLetter) || entropy(w) >= 3.5 {
			return mask(w)
		}
		return w
	})
}
