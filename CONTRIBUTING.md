# Contributing to TreeGuard

Thank you for your interest in contributing to TreeGuard! We welcome community contributions, bug reports, feature requests, and new security rules.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## Getting Started

### Prerequisites
* **Go**: Version 1.22 or higher.
* **C Compiler (Cgo)**: A working C99/C11 compiler (`gcc` or `clang`) is required to compile Tree-sitter grammar bindings (`CGO_ENABLED=1`).
* **Git**: For version control.

### Local Development Setup

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/<your-username>/treeguard.git
   cd treeguard
   ```

2. **Download Dependencies**:
   ```bash
   go mod download
   ```

3. **Build the CLI**:
   ```bash
   go build -o treeguard ./cmd/treeguard
   ./treeguard --help
   ```

4. **Run the Test Suite**:
   ```bash
   go test -v ./...
   ```

---

## Repository Architecture & Code Conventions

TreeGuard adheres to standard Go project conventions and the Uber Go Style Guide:

* **`cmd/`**: Contains the command entrypoints. Code in `cmd/treeguard/main.go` must remain minimal (~15 lines) and only wire up CLI execution.
* **`internal/`**: Contains private packages and core domain services:
  * `internal/cli/`: Cobra CLI commands and user input handling.
  * `internal/engine/`: Open Policy Agent (OPA) runtime, rule evaluation, and built-ins.
  * `internal/parser/`: Tree-sitter language grammar registration and AST generation.
  * `internal/query/`: Programmatic AST dumping and ad-hoc Rego query services.
  * `internal/runner/`: Concurrent scanning pipelines, autofix application, and fixture test runner.
  * `internal/registry/`: Rule pack client, remote caching, and registry aliases.
  * `internal/reporter/`: Output formatters (Console, JSON, SARIF 2.1.0, HTML).
  * `internal/validator/`: Static linter and metadata validator for Rego rule files.
* **Co-located Tests**: Every source file `foo.go` must have its corresponding unit tests in `foo_test.go` within the same package.

---

## Authoring New Security Rules

If you are contributing a new security rule to `rules/<language>/`:

1. **Rule File Structure**: Name rules descriptively (e.g. `rules/python/command_injection.rego`).
2. **Required Metadata**: Every rule must define a `metadata` object containing:
   ```rego
   package rules.python.command_injection

   import data.sast

   metadata := {
       "id": "py-command-injection",
       "title": "Command Injection via os.system",
       "message": "Direct execution of shell commands with untrusted input",
       "severity": "ERROR",           # ERROR, WARNING, or INFO
       "cwe": "CWE-78",
       "owasp": "A03:2021-Injection",
       "language": "python"
   }

   deny[finding] {
       # Rego rule logic...
       finding := sast.new_finding(metadata, target_node, metadata.message)
   }
   ```
3. **Add Test Fixtures**: Provide an annotated test fixture file under `test/fixtures/<language>/` using `# ruleid: <id>` and `# ok: <id>` annotations:
   ```python
   # ruleid: py-command-injection
   os.system(user_input)

   # ok: py-command-injection
   subprocess.run(["echo", "safe"], check=True)
   ```
4. **Validate & Test**:
   ```bash
   # Lint rule metadata and syntax
   ./treeguard validate rules/<language>

   # Run fixture tests
   ./treeguard test test/fixtures/<language> -r rules/<language>
   ```

---

## Adding a New Language Grammar

1. Add the Tree-sitter Go binding module to `go.mod`:
   ```bash
   go get github.com/tree-sitter/tree-sitter-<language>/bindings/go
   ```
2. Register the language in `internal/parser/registry.go` inside `init()`.
3. Add extension mappings and test cases in `internal/parser/registry_test.go` and `internal/parser/parser_test.go`.

---

## Pull Request Checklist

Before submitting your pull request:
- [ ] Code compiles without warnings: `go build ./cmd/treeguard`.
- [ ] All tests pass: `go test ./...`.
- [ ] Code is formatted and vet passes: `go fmt ./... && go vet ./...`.
- [ ] Tests are co-located in `*_test.go` matching the modified source files.
- [ ] Documentation or fixtures updated as needed.
