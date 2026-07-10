# Homebrew Formula For Chio

Chio is pre-release and does not currently publish a Homebrew formula. Build
from source until a tagged release includes a `chio.rb` release asset.

## One-line Install After A Tagged Release

```bash
curl -fsSL -o /tmp/chio.rb https://github.com/backbay-labs/chio/releases/latest/download/chio.rb
brew install --formula /tmp/chio.rb
```

## About The Formula

The release-binaries workflow renders the installable formula from
[`packaging/homebrew/chio.rb.tmpl`](../../packaging/homebrew/chio.rb.tmpl) and
publishes the result as the `chio.rb` release asset alongside the platform
archives when a release is cut.

## Upgrading After A Tagged Release

```bash
curl -fsSL -o /tmp/chio.rb https://github.com/backbay-labs/chio/releases/latest/download/chio.rb
brew upgrade --formula /tmp/chio.rb
```

## Uninstalling

```bash
brew uninstall chio
```

## Verifying The Install

```bash
chio --version
which chio
```

For other install paths (Docker, curl), see
[`BINARY_DISTRIBUTION.md`](./BINARY_DISTRIBUTION.md).
