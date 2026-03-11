# Usage

## profile add

Create or update a named profile.

```bash
authbear profile add <name> [flags]
```

Flags:

- `--base-url` API base URL used by `call` when path is relative
- `--health-path` default path used by `health` (default runtime fallback is `/health`)
- `--auth-type` `bearer`, `api-key`, `oauth-device`, or `jwt-p8`
- `--api-key-header` header name used for `api-key` auth (default `X-API-Key`)
- `--device-code-url` OAuth device authorization endpoint
- `--token-url` OAuth token endpoint
- `--client-id` OAuth client id
- `--scopes` comma-separated OAuth scopes
- `--audience` OAuth audience (if required by provider)
- `--key-id` Apple key ID (jwt-p8)
- `--issuer-id` Apple issuer ID / team ID (jwt-p8)
- `--jwt-audience` JWT audience claim (jwt-p8, default `appstoreconnect-v1`)
- `--env KEY=VALUE` plain (non-secret) env var attached to the profile (repeatable)

## profile list / show / remove

```bash
authbear profile list
authbear profile show <name>
authbear profile remove <name>
```

`remove` deletes profile config only. Use `logout` to remove credentials from keychain.

## login

Authenticate a profile and persist credentials in keychain.

```bash
authbear login <name> [--client-secret ...]
```

Behavior by auth type:

- `bearer`: prompts for bearer token (hidden input)
- `api-key`: prompts for API key (hidden input)
- `oauth-device`: starts device flow, prints verification URL/code, polls token endpoint, stores access and refresh token
- `jwt-p8`: reads, validates, and stores the EC private key from `--key-file` into the OS keychain

For `oauth-device`, `--client-secret` is optional and only needed by providers that require confidential clients.

### jwt-p8 login flags

- `--key-file <path>` path to the Apple `.p8` private key file (required for `jwt-p8`)
- `--delete-after-store` delete the key file from disk after it has been stored in the keychain

## token

Print the auth header payload for a profile.

```bash
authbear token <name>
```

Notes:

- For `bearer`/`oauth-device`, output includes scheme (`Bearer ...`)
- For `api-key`, output is the key value

## call

Call an endpoint using stored auth.

```bash
authbear call <name> <METHOD> <path-or-url> [flags]
```

Flags:

- `--header "Key: Value"` repeatable
- `--query "key=value"` repeatable
- `--json '{...}'` inline JSON body
- `--data <file>` request body from file
- `--raw` do not pretty-print JSON response
- `--response-json` print machine-readable response envelope as JSON
- `--status` print status line and response headers
- `--timeout <seconds>` request timeout (default `30`)

Auth behavior:

- `bearer` and `oauth-device`: injects `Authorization` header
- `api-key`: injects configured API key header
- `oauth-device`: refreshes access token automatically if near expiry

## health

Check an endpoint health/readiness with optional auth.

```bash
authbear health <name> [flags]
```

Flags:

- `--path /health` endpoint path or absolute URL
- `--expect 200` expected status code
- `--timeout 5` request timeout seconds
- `--no-auth` skip auth header injection
- `--json` print machine-readable JSON output
- `--header "Key: Value"` repeatable
- `--query "key=value"` repeatable

Exit code is `0` when status matches `--expect`, else `1`.

## logout

Delete stored credentials for a profile from keychain.

```bash
authbear logout <name>
```

## env

Manage environment variables attached to a profile and export them to the shell.

Profiles support two kinds of env vars:

- **Plain** — stored in `profiles.json` alongside other profile config. Set via `profile add --env KEY=VALUE`. Suitable for non-sensitive values like `API_VERSION`, `REGION`, etc.
- **Secret** — stored in the OS keychain. Set via `env set`. Suitable for sensitive values like API keys or tokens used by other tools (e.g. `REVENUECAT_API_KEY`, `STRIPE_SECRET_KEY`).

### env set

Store a secret env var for a profile in keychain (prompts for the value):

```bash
authbear env set <profile> <KEY>
```

Example:

```bash
authbear env set myprofile REVENUECAT_API_KEY
```

### env unset

Remove a secret env var from keychain:

```bash
authbear env unset <profile> <KEY>
```

### env \<profile\>

Print `export KEY=VALUE` lines for all env vars (plain + secret) attached to a profile:

```bash
authbear env <profile>
```

Use with `eval` to load them into the current shell session:

```bash
eval $(authbear env myprofile)
```

Or source into a script:

```bash
eval $(authbear env myprofile)
curl -H "Authorization: Bearer $REVENUECAT_API_KEY" https://api.revenuecat.com/v1/subscribers/...
```

## doctor

Verify local configuration path and keychain availability.

```bash
authbear doctor
```

## Common flows

Apple App Store Connect (jwt-p8):

```bash
authbear profile add appstore \
  --base-url https://api.appstoreconnect.apple.com \
  --auth-type jwt-p8 \
  --key-id XXXXXXXXXX \
  --issuer-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Store key; optionally delete from disk
authbear login appstore --key-file ~/Downloads/AuthKey_XXXXXXXXXX.p8 --delete-after-store

# JWT is generated fresh on every call (20-minute lifetime)
authbear call appstore GET /v1/apps

# Inspect the generated JWT
authbear token appstore
```

Bearer:

```bash
authbear profile add github --base-url https://api.github.com --auth-type bearer
authbear login github
authbear call github GET /user
```

OAuth device:

```bash
authbear profile add internal \
  --base-url https://api.internal.example \
  --auth-type oauth-device \
  --device-code-url https://auth.internal.example/oauth/device/code \
  --token-url https://auth.internal.example/oauth/token \
  --client-id cli-tool \
  --scopes "openid,offline_access,profile"

authbear login internal
authbear call internal GET /v1/me
```
