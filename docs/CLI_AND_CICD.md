# TreeGuard CLI Reference & CI/CD Integration Guide

Complete manual for the **TreeGuard** command-line interface and copy-paste pipeline configurations for **GitHub Actions**, **GitLab CI**, **Bitbucket Pipelines**, and **CircleCI**.

---

## 1. CLI Commands & Flags

### `treeguard scan [flags] <paths...>`
Scans source code files or directories for security vulnerabilities.

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config` | `-c` | `""` | Path to project configuration file (`.treeguard.yaml` / `.treeguard.yml`). |
| `--changed-only` | | `false` | Scan only modified/uncommitted files in local Git repository. |
| `--baseline` | | `""` | Scan files changed relative to Git reference (e.g. `main`, `origin/main`, `HEAD~1`). |
| `--rules` | `-r` | `./rules` | Path to rule `.rego` file(s), directory, remote URL (`https://...`), or pack alias (`pack:owasp-top10`). |
| `--update-rules` | | `false` | Force update/re-download remote rule packs before scanning. |
| `--format` | `-f` | `text` | Output report format: `text`, `json`, `sarif`, `html`. |
| `--output` | `-o` | `stdout` | Write report output directly to a file. |
| `--severity` | | `INFO` | Minimum severity filter: `INFO`, `WARNING`, `ERROR`. |
| `--lang` | `-l` | `""` | Filter targets by language (`python`, `javascript`, `go`, etc.). |
| `--threads` | `-j` | `auto` | Number of concurrent worker threads (`0` = CPU count). |
| `--no-color` | | `false` | Disable color formatting in terminal output. |
| `--dry-run` | | `false` | Preview proposed automated remediations as unified diffs without modifying files. |
| `--fix` | | `false` | Automatically apply rule remediations directly to source files on disk. |

#### Project Configuration File (`.treeguard.yaml`)
TreeGuard automatically discovers `.treeguard.yaml` or `.treeguard.yml` in the project target directory or current working directory. You can also explicitly specify a configuration file using `-c` or `--config`.

**Configuration Schema Example (`.treeguard.yaml`)**:
```yaml
# Rule paths and remote rule packs
rules:
  - rules/python
  - rules/go
  - pack:owasp-top10

# Directory ignore patterns
ignore:
  - vendor
  - node_modules
  - dist
  - temp

# Scan settings
format: html
output: treeguard-report.html
min_severity: WARNING
language: python
threads: 4
fix: false
```

**Precedence Rules**:
1. **CLI Flags**: Explicit command-line flags always take highest precedence (e.g., `--format text` overrides `format: json`).
2. **Config File**: Configuration file options in `.treeguard.yaml` take precedence over defaults.
3. **Defaults**: Hardcoded CLI defaults apply when options are omitted from both CLI and config.

#### Examples
```bash
# Scan src directory using default rules
./treeguard scan ./src

# Scan using a remote rule pack URL or registry alias
./treeguard scan -r pack:owasp-top10 ./src
./treeguard scan -r https://example.com/rules/custom-pack.tar.gz ./src

# Generate interactive standalone HTML security report
./treeguard scan --format html -o audit-report.html ./src

# Export SARIF report for GitHub Code Scanning
./treeguard scan --format sarif -o results.sarif ./src

# Preview proposed automated fixes
./treeguard scan --dry-run ./src

# Apply automated fixes to files
./treeguard scan --fix ./src
```

---

### `treeguard test <fixture-path>`
Runs Semgrep-style test suite verification against annotated test fixtures (`# ruleid:` / `# ok:`).

```bash
./treeguard test test/fixtures
```

---

### `treeguard dump-ast [flags] <file>`
Dumps the Tree-sitter AST JSON payload (`input.nodes`) passed to Rego rules.

```bash
# Dump full AST input
./treeguard dump-ast app.py

# Dump only flattened node list
./treeguard dump-ast --nodes-only app.py
```

---

### `treeguard query -e <expr> <file>`
Executes ad-hoc Rego query expression against a file's AST data model.

```bash
./treeguard query -e '[c.text | c := data.sast.find_calls[_]]' app.py
```

---

### `treeguard validate [flags] <rule-paths...>`
Validates and lints Rego rule files for syntax errors, standard package naming conventions (`package rules.<lang>.<rule>`), required metadata fields (`id`, `severity`, `message`), and policy entrypoints (`deny` or `findings`).

```bash
# Validate rules in rules/ directory
./treeguard validate rules

# Strict validation upgrading advisory warnings to errors
./treeguard validate --strict rules

# Output JSON validation report
./treeguard validate -f json rules
```

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--strict` | | `false` | Upgrade advisory warnings (like missing CWE reference) to validation errors. |
| `--format` | `-f` | `text` | Output report format: `text` or `json`. |

---

### `treeguard pack <subcommand>` (alias: `treeguard registry`)
Manages local cache of remote rule packs and registries.

```bash
# Pull and cache a remote rule pack or URL
./treeguard pack pull pack:owasp-top10
./treeguard pack pull https://example.com/rules.tar.gz

# List all cached rule packs and default registry aliases
./treeguard pack list

# Force update all cached rule packs
./treeguard pack update

# Clear local rule pack cache
./treeguard pack clean
```

---

### Inline Code Suppressions (`treeguard:ignore`)
Developers can suppress findings directly in source code using inline comments. Both same-line comments and preceding-line comments are supported across all languages (`//`, `#`, `/* ... */`, `--`).

```python
# Suppress a specific rule on the next line
# treeguard:ignore:py-eval-detected intentional CLI expression evaluator
eval(user_input)

# Suppress all rules on the same line
open(user_path)  # treeguard:ignore
```

```go
// Suppress multiple rules with justification
// treeguard:ignore:go-sql-injection,go-path-traversal trusted internal query
db.Query(rawQuery)
```

---

## 2. CI/CD Pipeline Integrations

### A. GitHub Actions (`.github/workflows/security.yml`)
Runs TreeGuard scan on push/PR and uploads SARIF findings to the **GitHub Security Tab**:

```yaml
name: "TreeGuard SAST Security Scan"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  treeguard-scan:
    name: "TreeGuard Security Scan"
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build TreeGuard
        run: go build -o treeguard ./cmd/treeguard

      - name: Run TreeGuard Scan
        run: |
          ./treeguard scan --format sarif -o treeguard-results.sarif ./
        continue-on-error: true

      - name: Upload SARIF Report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: treeguard-results.sarif
```

---

### B. GitLab CI (`.gitlab-ci.yml`)
Generates SAST report artifact for GitLab Security Dashboard:

```yaml
stages:
  - test

treeguard-sast:
  stage: test
  image: golang:1.22
  script:
    - go build -o treeguard ./cmd/treeguard
    - ./treeguard scan --format json -o gl-sast-report.json ./
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

### C. Bitbucket Pipelines (`bitbucket-pipelines.yml`)

```yaml
pipelines:
  default:
    - step:
        name: TreeGuard Security Scan
        image: golang:1.22
        script:
          - go build -o treeguard ./cmd/treeguard
          - ./treeguard scan ./src
```

---

## 3. VS Code IDE Extension Integration

The official TreeGuard VS Code extension lives in `editors/vscode/`. It brings live inline diagnostics, problem squiggles, and status bar findings counters natively into VS Code.

### Features
- **On-Save & On-Open SAST Diagnostics**: Real-time security findings displayed directly in the VS Code Problems tab and active editor lines with exact ranges.
- **Status Bar Integration**: Visual indicator showing real-time scanning status and total finding counts.
- **Commands**:
  - `TreeGuard: Scan Active Workspace`: Run a full repository scan and update inline problem markers.
  - `TreeGuard: Scan Active File`: Focus scan on the active editor file.
- **Configurable Settings**:
  - `treeguard.executablePath`: Custom binary path (defaults to `treeguard` in `PATH`).
  - `treeguard.rulesPath`: Path to custom rules directory or rule pack alias.
  - `treeguard.scanOnSave`: Enable/disable automatic scan on document save.
  - `treeguard.scanOnOpen`: Enable/disable automatic scan on document open.
  - `treeguard.severityThreshold`: Filter findings by minimum severity (`INFO`, `WARNING`, `ERROR`).

### Installation for Local Development
1. Copy `editors/vscode` to `~/.vscode/extensions/treeguard-vscode` (or link via symlink).
2. Ensure the `treeguard` binary is available in your `$PATH` or configured in VS Code `settings.json`.
3. Open VS Code and execute **TreeGuard: Scan Active Workspace** or **TreeGuard: Scan Active File** from the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`).

