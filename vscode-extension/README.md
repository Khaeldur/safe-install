<p align="center">
  <img src="icon.svg" alt="Safe Install" width="128" height="128">
</p>

<h1 align="center">Safe Install - Supply Chain Defense</h1>

<p align="center">
  Protect against typosquatting, malicious packages, and supply chain attacks directly in VS Code.
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=safe-install.safe-install"><img src="https://img.shields.io/visual-studio-marketplace/v/safe-install.safe-install?label=VS%20Code%20Marketplace" alt="VS Code Marketplace Version"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=safe-install.safe-install"><img src="https://img.shields.io/visual-studio-marketplace/i/safe-install.safe-install" alt="Installs"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=safe-install.safe-install"><img src="https://img.shields.io/visual-studio-marketplace/r/safe-install.safe-install" alt="Rating"></a>
</p>

---

## Features

### Inline Risk Diagnostics

When you save a dependency file, Safe Install scans every package and highlights risky dependencies with red squiggly underlines. Each diagnostic includes the threat type (typosquat, new package, low maintainer count) and a severity level so you can triage quickly.

### Hover Intelligence

Hover over any package name to see a rich tooltip with:
- **Package age** -- how long the package has existed on the registry
- **Maintainer count** -- number of active maintainers
- **Download stats** -- weekly download volume
- **Typosquat risk** -- similarity score against popular packages

### Status Bar Indicator

A shield icon in the status bar shows your current protection status:
- **Green shield** -- protection active, last scan clean
- **Yellow shield** -- warnings detected in the last scan
- **Red shield** -- critical risks found
- **Grey shield** -- protection disabled

### Supported Ecosystems

| File | Ecosystem |
|---|---|
| `requirements.txt` | pip (Python) |
| `package.json` | npm (JavaScript) |
| `Cargo.toml` | cargo (Rust) |
| `go.mod` | go (Go) |
| `Gemfile` | gem (Ruby) |

## Requirements

The [safe-install](https://github.com/your-org/safe-install) CLI must be installed and available on your PATH:

```bash
pip install safe-install
```

Alternatively, set the path manually via the `safeInstall.cliPath` setting.

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `safeInstall.cliPath` | `safe-install` | Path to the safe-install CLI binary |
| `safeInstall.scanOnSave` | `true` | Automatically scan dependency files on save |
| `safeInstall.showHoverIntelligence` | `true` | Show package intelligence on hover |

## Commands

Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and type "Safe Install":

| Command | Description |
|---|---|
| `Safe Install: Scan Current File` | Run a full scan on the active dependency file |
| `Safe Install: Audit Package Under Cursor` | Get detailed intelligence for the package at your cursor position |
| `Safe Install: Toggle Protection` | Enable or disable on-save scanning |

## How It Works

The extension acts as a thin UI layer on top of the `safe-install` CLI:

1. When you open or save a supported dependency file, the extension invokes `safe-install audit --json` with the file path.
2. The CLI checks each package against registry metadata, typosquat databases, and risk heuristics.
3. Results are parsed and displayed as VS Code diagnostics (squiggly underlines), hover tooltips, and status bar updates.

No packages are installed or executed during scanning -- the CLI only queries registry APIs.

## Known Issues

- **First scan may be slow** -- the CLI fetches registry metadata on the first run. Subsequent scans use a local cache.
- **Private registries** -- packages from private registries may show as "unknown" if the CLI cannot reach the registry. Configure registry auth via the CLI directly.
- **Monorepo support** -- only the currently open file is scanned. Workspace-wide scanning is planned for a future release.

## Release Notes

See [CHANGELOG.md](CHANGELOG.md) for full release history.

## License

MIT
