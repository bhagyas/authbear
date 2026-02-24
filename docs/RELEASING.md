# Releasing

## One-time setup

Set a repository secret in `bhagyas/authbear`:

- Name: `TAP_GITHUB_TOKEN`
- Value: GitHub personal access token that can push to `bhagyas/homebrew-authbear`
- Scope: `repo`

This token is used by `.github/workflows/update-homebrew-tap.yml` to update the tap formula.

## Release flow

1. Push code changes to `main`.
2. Create and push a semver tag:

```bash
git tag v0.1.1
git push origin v0.1.1
```

3. Publish the GitHub release for that tag.

When the release is published, the workflow will:

- download `https://github.com/bhagyas/authbear/archive/refs/tags/<tag>.tar.gz`
- compute sha256
- update `Formula/authbear.rb` in `bhagyas/homebrew-authbear`
- commit and push the formula update to `main`

## Manual retry

If needed, run the workflow manually from Actions using `workflow_dispatch` and pass a tag like `v0.1.1`.
