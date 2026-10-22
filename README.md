# sanity-check

Find API keys, passwords and tokens that were typed straight into a shell and
are now sitting in your history files.

```console
$ sanity-check
HIGH    github-token             zsh:1832
        gh auth login --with-token ghp_******
MEDIUM  url-credentials          atuin:20411 (+2 more)
        psql postgres://admin:S3cr******@db.internal/app
2 command(s) with secrets, from 48213 commands in 5 history file(s). Rotate these credentials, then remove the lines from history.
```

A single static binary with no runtime dependencies. It runs on macOS, Linux
and Windows, and reads every history it finds:

| Source | Files |
|---|---|
| zsh | `$ZDOTDIR/.zsh_history`, `~/.zhistory`, `~/.histfile`, `~/.zsh_sessions/*.history` (extended format, multi-line and metafied entries) |
| bash | `~/.bash_history` (timestamp lines skipped), `~/.bash_sessions/*.history` |
| fish | `$XDG_DATA_HOME/fish/*_history` |
| nushell | `history.txt` and `history.sqlite3` in `~/.config/nushell`, `~/Library/Application Support/nushell`, `%APPDATA%\nushell` |
| atuin | `$ATUIN_DB_PATH` or `$XDG_DATA_HOME/atuin/history.db` (deleted entries skipped) |
| PowerShell | PSReadLine `*_history.txt` on every OS |
| ksh, tcsh | `~/.sh_history`, `~/.history` |
| REPLs | psql, mysql, python, node, sqlite3, redis-cli, irb, mongosh |
| `$HISTFILE` | if exported |

## Install

```sh
brew install softway-solutions/tap/sanity-check
```

Or with Go, or by downloading a binary from
[Releases](https://github.com/softway-solutions/sanity-check/releases):

```sh
go install github.com/softway-solutions/sanity-check@latest
```

## Usage

```sh
sanity-check                      # scan everything found
sanity-check --list               # show which history files would be scanned
sanity-check --source zsh,atuin   # only these sources
sanity-check --high-only          # only vendor-format tokens, fewest false positives
sanity-check --json               # machine-readable output
sanity-check --format fish FILE   # scan a specific file
history | sanity-check -          # scan stdin
```

Secrets are masked in the output. `--reveal` prints them in full.

The command exits with `0` when it finds nothing, `1` when it finds secrets
and `2` on error, so you can use it in scripts and CI.

## What it detects

**High confidence:** documented token formats from AWS, GitHub, GitLab,
Anthropic, OpenAI, Stripe, Slack, Google, npm, PyPI, Hugging Face, SendGrid
and DigitalOcean, plus JWTs and private-key headers.

**Medium confidence:** a credential-shaped name, flag or header followed by a
literal value:

- `export DB_PASSWORD=...` and `$env.API_TOKEN = '...'`
- `set -x API_KEY ...` (fish)
- `--password ...` and `--token=...`
- `Authorization: Bearer ...`
- `curl -u user:pass`
- `scheme://user:pass@host`
- `mysql -p...`
- `sshpass -p ...`

References never count as findings. These are all ignored:

- variables: `$VAR`, `${VAR}`, `$env.X`, `%VAR%`
- command substitution: `$(...)`, `(security find-generic-password ...)`
- files and stdin: `@file`, `/path`, `< file`, `--password-stdin`
- placeholders: `<token>`, `[AuthToken]`, `your_api_key_here`, `xxxxxx`

## Judging with Jev (optional)

`--jev` asks [Jev](https://typesafe.ai) to judge each command as well.
Jev is TypeSafe's model, and it answers questions with a probability. It
needs `TYPESAFE_API_KEY`, which you can get at
https://console.typesafe.ai/keys.

```sh
TYPESAFE_API_KEY=... sanity-check --jev
```

> **Commands are sent to `api.typesafe.ai` exactly as typed, secrets
> included.** Only use `--jev` if you're comfortable with TypeSafe seeing them.

Jev answers one yes/no question for each command: *"Does this shell command
contain a literal credential value (API key, password, token), rather than a
$env reference or a `security find-generic-password` lookup?"*

| Command | Sent to Jev? | Result |
|---|---|---|
| Matches a vendor token format | no | always reported |
| Matches a medium-confidence rule | yes | reported only if Jev scores ≥ `--jev-threshold` (default 0.7) |
| Matches no rule but mentions token, password, secret, key, auth, login and similar | yes, the most recent `--jev-limit` (default 200) | reported as rule `jev` if Jev scores ≥ threshold |
| Anything else | no | not reported |

If a Jev request fails, that command keeps the rule-based verdict and a
warning is printed. The command exits with `2` only if every request fails.

Other flags:
- `--jev-model` picks the model. The default is `$JEV_MODEL`, or
  `jev-latest`.
- `--jev-workers` sets how many requests run at once. The default is 20.
- `JEV_BASE_URL` overrides the API endpoint.

## Fixing a finding

1. **Rotate the credential.** It has been on disk in plain text.
2. Remove the line from history. For example:
   - zsh/bash: edit the file.
   - atuin: `atuin search --delete '<text>'`.
   - fish: `history delete`.
3. Store the new value in a secret manager, such as the macOS Keychain,
   `pass`, 1Password's `op` or Vault, and read it in when you need it:
   `export TOKEN=$(security find-generic-password -s tool -a me -w)`.

## Releasing

```sh
scripts/release.sh v0.1.0
```

The script tags the version, builds the binaries, publishes a GitHub release
and updates the formula in
[softway-solutions/homebrew-tap](https://github.com/softway-solutions/homebrew-tap).
