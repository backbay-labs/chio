# Homebrew Tap for Chio

## One-line install

```bash
curl -fsSL -o /tmp/chio.rb https://github.com/backbay-labs/chio/releases/latest/download/chio.rb
brew install --formula /tmp/chio.rb
```

## About the tap

The release-binaries workflow renders the installable formula from
[`Homebrew/chio.rb.tmpl`](../../Homebrew/chio.rb.tmpl) and publishes the
result as the `chio.rb` release asset alongside the platform archives.

## Upgrading

```bash
curl -fsSL -o /tmp/chio.rb https://github.com/backbay-labs/chio/releases/latest/download/chio.rb
brew upgrade --formula /tmp/chio.rb
```

## Uninstalling

```bash
brew uninstall chio
```

## Verifying the install

```bash
chio --version
which chio
```

For other install paths (Docker, curl), see
[`BINARY_DISTRIBUTION.md`](./BINARY_DISTRIBUTION.md).
