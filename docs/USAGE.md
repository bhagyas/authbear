# Usage

## profile add

Create or update a named profile.

```bash
authbear profile add <name> [flags]
```

Flags:

- `--base-url` API base URL used by `call` when path is relative
- `--auth-type` `bearer`, `api-key`, or `oauth-device`
- `--api-key-header` header name used for `api-key` auth (default `X-API-Key`)
- `--device-code-url` OAuth device authorization endpoint
- `--token-url` OAuth token endpoint
- `--client-id` OAuth client id
- `--scopes` comma-separated OAuth scopes
- `--audience` OAuth audience (if required by provider)

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

For `oauth-device`, `--client-secret` is optional and only needed by providers that require confidential clients.

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
- `--status` print status line and response headers
- `--timeout <seconds>` request timeout (default `30`)

Auth behavior:

- `bearer` and `oauth-device`: injects `Authorization` header
- `api-key`: injects configured API key header
- `oauth-device`: refreshes access token automatically if near expiry

## logout

Delete stored credentials for a profile from keychain.

```bash
authbear logout <name>
```

## doctor

Verify local configuration path and keychain availability.

```bash
authbear doctor
```

## Common flows

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
