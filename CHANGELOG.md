# Changelog

## v0.1.2 — 2026-03-10

### Added

- **Per-profile environment variables** — attach env vars to a profile and export them to the shell via `eval $(authbear env <profile>)`.
  - Plain (non-sensitive) env vars stored in `profiles.json` via `authbear profile add --env KEY=VALUE` (repeatable).
  - Secret env vars stored in the OS keychain via `authbear env set <profile> <KEY>` (prompts for value).
  - `authbear env unset <profile> <KEY>` removes a secret env var from keychain and the profile.
  - `authbear env <profile>` prints `export KEY=VALUE` lines for all attached env vars (plain + secret).

### Storage

Secret env vars use keychain key `profile:<name>:env:<KEY>`. The profile config tracks which secret key names exist under `secret_env` so exports know what to fetch.

---

## v0.1.1 — 2026-02-24

### Added

- `authbear health` command with `--json` output, `--expect`, `--no-auth`, `--timeout`, `--header`, `--query` flags.
- `--response-json` flag on `authbear call` for machine-readable response envelopes.
- Homebrew tap automation via GitHub Actions (`update-homebrew-tap.yml`).

---

## v0.1.0 — 2026-02-24

### Added

- Initial release.
- Profile management (`add`, `list`, `show`, `remove`) with `profiles.json` config.
- Keychain-backed credential storage via `go-keyring`.
- Auth types: `bearer`, `api-key`, `oauth-device`.
- OAuth 2.0 device authorization grant with automatic access token refresh.
- `authbear call` with headers, query params, JSON body, file body, raw/pretty output.
- `authbear token` to print auth header value.
- `authbear login` / `authbear logout`.
- `authbear doctor` for config and keychain diagnostics.
- Homebrew formula (`Formula/authbear.rb`).
