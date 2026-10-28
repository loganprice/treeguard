# TreeGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)

`TreeGuard` is a fast, multi-language Static Application Security Testing (SAST) engine inspired by **Semgrep**, built using **Tree-sitter** for syntax parsing and **Open Policy Agent (OPA)** for declarative security policies written in **Rego**.

---

## 📚 Documentation Index

* **[Architecture & Technical Design](./opa_sast/docs/ARCHITECTURE.md)**: System design, Tree-sitter parsing pipeline, OPA evaluation engine, worker pool concurrency, and bottom-to-top autofix algorithm.
* **[Rule Writing & Rego Stdlib Reference](./opa_sast/docs/RULES_GUIDE.md)**: Guide for authoring security rules, metadata schemas, Rego stdlib API (`sast.rego`), and fixture test runner syntax.
* **[CLI Reference & CI/CD Guide](./opa_sast/docs/CLI_AND_CICD.md)**: Command-line flag reference, `--fix` / `--dry-run` usage, and copy-paste pipeline configs for GitHub Actions, GitLab CI, and Bitbucket.
* **[OWASP Top 10 Rule Catalog](./opa_sast/docs/RULE_CATALOG.md)**: Complete catalog of pre-packaged security rules across 13 languages with CWE IDs and automated remediation support.

---

## Key Features

- **Multi-Language Support**: Accurate parsing powered by Tree-sitter for **13 languages**:
  - **Python** (`.py`, `.pyi`)
  - **JavaScript** (`.js`, `.jsx`, `.mjs`, `.cjs`)
  - **TypeScript** (`.ts`, `.mts`, `.cts`)
  - **TSX** (`.tsx`)
  - **Go** (`.go`)
  - **Java** (`.java`)
  - **Rust** (`.rs`)
  - **Ruby** (`.rb`, `.rake`, `.gemspec`)
  - **C** (`.c`, `.h`)
  - **C++** (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`)
  - **PHP** (`.php`)
  - **JSON** (`.json`)
  - **Dockerfile / Containerfile** (`Dockerfile`, `Containerfile`, `*.dockerfile`)
- **Expressive Rego Rules**: Write declarative security rules using Rego with rule metadata, CWE, OWASP tags, and custom severities (`ERROR`, `WARNING`, `INFO`).
- **Rich AST Data Model**: Exposes both a flattened, indexed node list (`input.nodes`) for $O(1)$/$O(N)$ matching and a hierarchical CST tree (`input.ast`).
- **Embedded Standard Library (`sast.rego`)**: Helper functions for function calls (`sast.find_calls`), argument inspection (`sast.arg`), ancestry checks (`sast.has_ancestor`), string literals, and finding construction.
- **Tree-sitter Query Built-in**: Direct support for native Tree-sitter S-expression pattern matching inside Rego via `sast.ts_query("(call ...) @call")`.
- **Semgrep-style Rule Testing**: Built-in `treeguard test` runner verifying `# ruleid: <id>` and `# ok: <id>` annotations in fixture files.
- **Rule Linting & Validation**: Validate rule syntax and metadata schemas ahead of time using `treeguard validate`.
- **Rule Packaging**: Bundle rule libraries into redistributable `.tar.gz` packages via `treeguard pack`.
- **Multiple Output Formats**:
  - **Text**: Colorized terminal output with exact line indicators and code snippets.
  - **JSON**: Structured machine-readable schema for custom integrations.
  - **SARIF 2.1.0**: Industry-standard OASIS SARIF output for GitHub Advanced Security and CI/CD pipelines.
  - **HTML**: Self-contained interactive vulnerability reports with charts and code previews.
- **High Concurrency**: Parallel file parsing and evaluation using Go worker pools.

---

## Installation & Build

### Option A: Prebuilt Docker Container
Run TreeGuard instantly with bundled security rules without installing Go or a C compiler:

```bash
# Scan current repository (mounts workspace into non-root container)
docker run --rm -v $(pwd):/workspace ghcr.io/loganprice/treeguard:latest scan .
```

### Option B: Precompiled Release Binaries
Download precompiled `.tar.gz` release archives with bundled security rules and SHA-256 checksums from [GitHub Releases](https://github.com/loganprice/treeguard/releases) for:
- Linux (x86_64)
- macOS (Apple Silicon / arm64)
- macOS (Intel / x86_64)

### Option C: Build from Source
Requires Go 1.22+ and a C compiler (for Tree-sitter Cgo bindings):

```bash
# Clone repository
git clone https://github.com/loganprice/treeguard.git
cd treeguard

# Build using Makefile (injects dynamic git commit, date, and version metadata)
make build

# Move to PATH (optional)
sudo mv treeguard /usr/local/bin/
```

---

## Quick Start

### 1. Scan a Project
```bash
# Scan a directory using default rules in ./rules
./treeguard scan ./src

# Fail CI only on CRITICAL or HIGH findings (allowing warnings through)
./treeguard scan --fail-on high ./src

# Run scans without breaking CI on findings
./treeguard scan --fail-on none ./src

# Scan with custom file size limits and per-file evaluation timeouts
./treeguard scan --max-file-size 10485760 --timeout 45s ./src

# Scan with JSON, SARIF, or HTML output
./treeguard scan --format json -o results.json ./src
./treeguard scan --format sarif -o results.sarif ./src
./treeguard scan --format html -o audit-report.html ./src

# Filter by language and minimum severity
./treeguard scan -l python --severity ERROR ./src

# Preview proposed automated remediations (dry-run)
./treeguard scan --dry-run ./src

# Automatically apply remediations to source files on disk
./treeguard scan --fix ./src
```

### 2. Print Version & Build Metadata
```bash
./treeguard version
# TreeGuard version v1.0.0 (commit: abcdef1, built at: 2026-09-18T12:00:00Z, go: go1.26.1, platform: darwin/arm64)

./treeguard version --json
```

### 3. Validate Rule Definitions

```bash
# Lint and validate rule syntax and metadata across a rules directory
./treeguard validate rules/

# Validate and fail on warnings as well as errors
./treeguard validate --strict rules/
```

### 3. Test Rules against Annotated Fixtures
```bash
# Run Semgrep-style rule tests
./treeguard test test/fixtures
```

### 4. Inspect a File's AST Representation
```bash
# Dump the exact JSON input provided to Rego
./treeguard dump-ast app.py

# Dump only the flattened node list
./treeguard dump-ast --nodes-only app.py
```

### 5. Run an Ad-hoc Rego Query
```bash
# Find all calls in a file
./treeguard query -e '[n.text | n := input.nodes[_]; n.type == "call"]' app.py
```

### 6. Package Rules into Distributable Bundles
```bash
# Create a tarball bundle containing rules and stdlib
./treeguard pack --dir rules/ --out treeguard-rules-v1.0.0.tar.gz
```

---

## Rule Writing Guide

Rules are written in `.rego` files under `rules/`. Every rule defines a package, optional rule `metadata`, and one or more `deny[finding]` or `findings[finding]` evaluation blocks.

### Rule Data Model (`input`)

When evaluating a rule against a source file, `input` provides:

```json
{
  "file": {
    "path": "app.py",
    "language": "python",
    "lines_count": 42,
    "lines": ["..."]
  },
  "nodes": [
    {
      "id": 14,
      "parent_id": 12,
      "type": "call",
      "field": "body",
      "range": {
        "start": { "line": 8, "column": 5, "byte": 120 },
        "end": { "line": 8, "column": 45, "byte": 160 }
      },
      "text": "db.execute(\"SELECT ... %s\" % user_id)",
      "fields": {
        "function": { "id": 15, "type": "attribute", "text": "db.execute" },
        "arguments": { "id": 16, "type": "argument_list", "text": "(...)" }
      },
      "ancestors": [12, 5, 0],
      "children": [15, 16]
    }
  ],
  "ast": { ... }
}
```

### Example 1: Python SQL Injection Rule

```rego
package rules.python.sql_injection

import data.sast
import future.keywords.in

metadata := {
    "id": "py-sql-injection",
    "title": "SQL Injection via String Formatting",
    "message": "Untrusted formatted string passed to execute(). Use parameterized queries instead.",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "language": "python"
}

deny[finding] {
    input.file.language == "python"

    # Match calls to .execute(...)
    call := sast.find_calls_ending_with(".execute")[_]

    # Inspect first argument
    arg := sast.arg(call, 0)
    is_formatted_string(arg)

    finding := sast.new_finding(metadata, call, metadata.message)
}

is_formatted_string(node) {
    node.type == "binary_operator"
    sast.field_text(node, "operator") == "%"
}

is_formatted_string(node) {
    node.type == "call"
    endswith(sast.field_text(node, "function"), ".format")
}

is_formatted_string(node) {
    node.type == "string"
    child_id := node.children[_]
    input.nodes[child_id].type == "interpolation"
}
```

### Example 2: Tree-sitter Query Built-in (`sast.ts_query`)

You can execute native Tree-sitter S-expression queries inside Rego:

```rego
package rules.python.pattern_example

metadata := {
    "id": "py-system-exec",
    "severity": "ERROR"
}

deny[finding] {
    # Native Tree-sitter pattern query
    matches := sast.ts_query("(call function: (attribute object: (identifier) @obj attribute: (identifier) @attr))")
    m := matches[_]
    m.captures.obj.text == "os"
    m.captures.attr.text == "system"

    finding := {
        "rule_id": metadata.id,
        "message": "Use of os.system() detected",
        "severity": metadata.severity,
        "range": m.captures.attr.range,
        "code": m.captures.attr.text
    }
}
```

---

## Standard Library Reference (`sast.rego`)

The standard library is embedded automatically in every rule evaluation under `data.sast`:

| Function | Description |
|---|---|
| `sast.nodes_by_type(type)` | Returns all AST nodes matching `type` |
| `sast.get_node(id)` | Retrieves node by its integer ID |
| `sast.child(node, field)` | Returns child node mapped to `field` name |
| `sast.field_text(node, field)` | Returns text of child node mapped to `field` |
| `sast.children(node)` | Returns all direct child node objects |
| `sast.parent(node)` | Returns parent node object |
| `sast.ancestors(node)` | Returns array of all ancestor node objects |
| `sast.has_ancestor(node, type)` | Checks if any ancestor matches node `type` |
| `sast.has_ancestor_or_self(node, type)` | Checks if node or any ancestor matches `type` |
| `sast.is_descendant(node, parent)` | Checks if `node` is descendant of `parent` |
| `sast.find_calls` | Returns all call expressions |
| `sast.find_calls_by_name(name)` | Returns calls where callee matches `name` |
| `sast.find_calls_ending_with(suffix)` | Returns calls where callee ends with `suffix` |
| `sast.arguments(call_node)` | Returns argument nodes of a call |
| `sast.arg(call_node, index)` | Returns N-th argument node (0-indexed) |
| `sast.is_string_literal(node)` | Checks if node is a string literal |
| `sast.strip_quotes(text)` | Trims enclosing quotes from string |
| `sast.new_finding(meta, node, msg)` | Constructs a standardized Finding object |

---

## Semgrep-style Testing

Create a test file with comments indicating expected matches:

```python
# test_sql.py
def test_cases(user_id):
    # ruleid: py-sql-injection
    db.execute("SELECT * FROM users WHERE id = %s" % user_id)

    # ok: py-sql-injection
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

Run:
```bash
./treeguard test test_sql.py
```

The tester verifies:
1. Every `# ruleid:` has a finding on that line or the next line.
2. Every `# ok:` produces NO findings.
3. No unexpected findings appear without annotations.

---

## OWASP Top 10 Security Rule Catalog

`TreeGuard` includes comprehensive OWASP Top 10 (2021) rule coverage across all supported languages:

### 1. Python, JavaScript / TypeScript, and Go
| OWASP Category | Python Rule | JS / TS Rule | Go Rule |
|---|---|---|---|
| **A01: Broken Access Control** | `py-path-traversal` | `js-path-traversal` | `go-path-traversal` |
| **A02: Cryptographic Failures** | `py-weak-cryptography` | `js-weak-cryptography` | `go-weak-cryptography` |
| **A03: Injection** | `py-sql-injection`, `py-command-injection` | `js-dangerous-eval`, `js-command-injection` | `go-sql-injection`, `go-command-injection` |
| **A04: Insecure Design** | `py-hardcoded-secret` | `js-hardcoded-secret` | `go-hardcoded-secret` |
| **A05: Security Misconfiguration** | `py-debug-mode-enabled` | `js-cors-wildcard-credentials` | `go-insecure-tls` |
| **A06: Vulnerable Components** | `py-xxe-elementtree` | `js-prototype-pollution` | `go-ssh-insecure-ignore-host-key` |
| **A07: Auth Failures** | `py-insecure-cookie` | `js-insecure-cookie` | `go-insecure-cookie` |
| **A08: Software & Data Integrity** | `py-unsafe-deserialization` | `js-unsafe-deserialization` | `go-unsafe-gob-decoder` |
| **A09: Logging Failures** | `py-empty-except-pass` | `js-empty-catch-block` | `go-unhandled-security-error` |
| **A10: SSRF** | `py-ssrf-requests` | `js-ssrf-http-request` | `go-ssrf-http-client` |

### 2. Java, Ruby, PHP, C/C++, and Rust
| OWASP Category | Java Rule | Ruby Rule | PHP Rule | C / C++ Rule | Rust Rule |
|---|---|---|---|---|---|
| **A01: Broken Access Control** | `java-path-traversal` | `ruby-path-traversal` | `php-path-traversal` | `c-path-traversal` | `rust-path-traversal` |
| **A02: Cryptographic Failures** | `java-weak-cryptographic-hash` | `ruby-weak-cryptography` | `php-weak-cryptographic-hash` | `c-weak-prng-rand` | `rust-weak-cryptography` |
| **A03: Injection** | `java-sql-injection`, `java-command-injection` | `ruby-sql-injection`, `ruby-command-injection` | `php-sql-injection`, `php-command-injection` | `c-command-injection` | `rust-command-injection-shell` |
| **A04: Insecure Design** | `java-hardcoded-secret` | `ruby-hardcoded-secret` | `php-hardcoded-secret` | `c-hardcoded-secret` | `rust-hardcoded-secret` |
| **A05: Misconfiguration** | `java-spring-csrf-disabled` | `ruby-rails-debug-all-requests-local` | `php-display-errors-enabled` | `c-insecure-file-permissions` | `rust-tls-invalid-certs-allowed` |
| **A06: Vulnerable Components** | `java-xxe-xml-factory` | `ruby-rexml-xxe` | `php-xxe-simplexml` | `c-banned-memory-functions` | `rust-unsafe-block` |
| **A07: Auth Failures** | `java-insecure-cookie-flags` | `ruby-insecure-cookie` | `php-insecure-cookie` | `c-hardcoded-secret` | `rust-insecure-cookie` |
| **A08: Software & Data Integrity** | `java-unsafe-deserialization` | `ruby-unsafe-deserialization` | `php-unsafe-unserialize` | `c-integer-overflow-malloc` | `rust-mem-transmute-usage` |
| **A09: Logging Failures** | `java-empty-catch-block` | `ruby-empty-rescue-block` | `php-empty-catch-block` | `c-format-string-vulnerability` | `rust-unhandled-critical-error` |
| **A10: SSRF** | `java-ssrf-http-connection` | `ruby-ssrf-http-request` | `php-ssrf-curl` | `c-ssrf-libcurl` | `rust-ssrf-http-client` |

### 3. Dockerfile / Containerfile
| OWASP Category | Dockerfile Rule | CWE | Description |
|---|---|---|---|
| **A05: Security Misconfiguration** | `dockerfile-missing-user` | CWE-250 | Avoid running containers as root; specify a non-root `USER` |
| **A05: Security Misconfiguration** | `dockerfile-avoid-sudo` | CWE-250 | Avoid using `sudo` inside container `RUN` commands |
| **A05: Security Misconfiguration** | `dockerfile-avoid-latest-tag` | CWE-1188 | Pin specific base image versions instead of mutable `:latest` tag |
| **A05: Security Misconfiguration** | `dockerfile-avoid-add` | CWE-441 | Prefer `COPY` over `ADD` unless archive extraction is needed |

---

## Community & Contributing

We welcome contributions of all kinds: bug fixes, new security rules, parser enhancements, and documentation improvements!

* **[Contributing Guide](file:///Users/lprice/Workspace/opa_sast/CONTRIBUTING.md)**: Onboarding instructions, Cgo build prerequisites, code layout rules, new rule authoring guide, and PR checklist.
* **[Code of Conduct](file:///Users/lprice/Workspace/opa_sast/CODE_OF_CONDUCT.md)**: Community standards and enforcement guidelines (Contributor Covenant v2.1).
* **[Security Policy](file:///Users/lprice/Workspace/opa_sast/SECURITY.md)**: Vulnerability disclosure process and response SLAs.

---

## License

This project is licensed under the [MIT License](file:///Users/lprice/Workspace/opa_sast/LICENSE) - see the [LICENSE](file:///Users/lprice/Workspace/opa_sast/LICENSE) file for details.

