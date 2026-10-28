# TreeGuard VS Code Extension

Official VS Code extension for **TreeGuard**, bringing real-time in-editor SAST security diagnostics, inline issue squiggles, and status bar findings counters natively into VS Code.

## Features

- **Native Security Diagnostics**: Scans files on save, on open, or on demand and reports vulnerabilities directly in the VS Code Problems panel with precise line/column positioning.
- **Status Bar Integration**: Real-time status bar indicator showing scan status (`TreeGuard: Scanning...`, `TreeGuard: Clean`, `TreeGuard: 3 Issue(s)`).
- **Active File & Workspace Scans**: Scan the entire workspace or focus exclusively on the currently open file.
- **Configurable Severity & Rules**: Filter by minimum severity threshold (`INFO`, `WARNING`, `ERROR`) or custom rule packs.

## Installation

1. Build or download the `treeguard` CLI binary and ensure it is available in your `$PATH` (or configure `treeguard.executablePath` in VS Code Settings).
2. Install the extension VSIX or copy the `editors/vscode` directory to `~/.vscode/extensions/treeguard-vscode`.

## Extension Commands

- `TreeGuard: Scan Active Workspace` (`treeguard.scan`): Triggers a full SAST scan across the active workspace directory.
- `TreeGuard: Scan Active File` (`treeguard.scanActiveFile`): Scans the active text editor document.

## Settings

- `treeguard.executablePath`: Path to the `treeguard` CLI binary (default: `treeguard`).
- `treeguard.rulesPath`: Path to custom Rego rule directory or pack alias.
- `treeguard.scanOnSave`: Automatically trigger SAST scan on file save (default: `true`).
- `treeguard.scanOnOpen`: Automatically trigger SAST scan on file open (default: `true`).
- `treeguard.severityThreshold`: Minimum severity filter for inline diagnostics (`INFO`, `WARNING`, `ERROR`).
