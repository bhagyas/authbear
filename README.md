# authbear

`authbear` is a local CLI auth broker for API tooling.

It manages credentials for multiple services and stores secrets in your OS keychain, then uses those credentials to call endpoints directly from the CLI.

## Features

- Profile-based auth configuration (`dev`, `staging`, `prod`, etc.)
- Keychain-backed secret storage (no plaintext tokens in config files)
- Auth modes:
  - `bearer`
  - `api-key`
  - `oauth-device` (OAuth 2.0 device authorization grant)
- Automatic OAuth token refresh when calling APIs
- Built-in API caller with headers/query/body options

## Install

Build from source:

```bash
go build -o authbear ./cmd/authbear
```

Optional local install:

```bash
go install ./cmd/authbear
```

Install with Homebrew (tap):

```bash
brew tap bhagyas/authbear
brew install authbear
```

## Quickstart

### 1) Create a profile

Bearer token example:

```bash
authbear profile add github \
  --base-url https://api.github.com \
  --auth-type bearer
```

API key example:

```bash
authbear profile add stripe \
  --base-url https://api.stripe.com \
  --auth-type api-key \
  --api-key-header Authorization
```

OAuth device code example:

```bash
authbear profile add my-idp \
  --base-url https://api.example.com \
  --auth-type oauth-device \
  --device-code-url https://id.example.com/oauth/device/code \
  --token-url https://id.example.com/oauth/token \
  --client-id YOUR_CLIENT_ID \
  --scopes "openid,profile,offline_access"
```

### 2) Log in and store credentials in keychain

```bash
authbear login github
```

For OAuth device flow:

```bash
authbear login my-idp
```

If your provider requires a confidential client secret:

```bash
authbear login my-idp --client-secret YOUR_CLIENT_SECRET
```

### 3) Call an endpoint

```bash
authbear call github GET /user
```

With JSON body:

```bash
authbear call github POST /repos/owner/repo/issues \
  --json '{"title":"Bug","body":"details"}'
```

With extra headers and query params:

```bash
authbear call my-idp GET /v1/items \
  --header "X-Tenant: acme" \
  --query "limit=20" \
  --query "sort=created_at"

# Machine-readable call output
authbear call github GET /user --response-json
```

Health check example:

```bash
authbear health github
authbear health github --path /rate_limit --expect 200 --timeout 5
authbear health github --json
```

## Commands

- `authbear profile add <name> [flags]`
- `authbear profile list`
- `authbear profile show <name>`
- `authbear profile remove <name>`
- `authbear login <name> [--client-secret ...]`
- `authbear token <name>`
- `authbear call <name> <METHOD> <path-or-url> [flags]`
- `authbear health <name> [flags]`
- `authbear logout <name>`
- `authbear doctor`

See full command docs in `docs/USAGE.md`.

## Storage model

- Non-secret profile config: `~/.config/authbear/profiles.json`
- Secrets: OS keychain via `go-keyring`

Key names:

- `profile:<name>:bearer`
- `profile:<name>:api-key`
- `profile:<name>:oauth`
- `profile:<name>:client-secret`

## Security notes

- Secret prompts use hidden terminal input.
- Auth data is stored in keychain, not plaintext config.
- OAuth access tokens are refreshed automatically when near expiry.
- Avoid printing raw tokens in logs and scripts unless necessary.

## Development

Run tests:

```bash
go test ./...
```

Run the CLI directly:

```bash
go run ./cmd/authbear --help
```

Release automation notes are in `docs/RELEASING.md`.
