# TreeGuard Rule Writing & Rego Stdlib Reference

This guide provides a comprehensive tutorial and API reference for writing security rules and automated remediations in **TreeGuard** using **OPA Rego**.

---

## 1. Rule Structure & Conventions

Rules in TreeGuard are written in `.rego` files placed in `rules/<language>/`. 

### Mandatory Rule Structure
Every rule file must declare a `package`, import `data.sast`, define a `metadata` map, and produce findings inside `deny[finding]`:

```rego
package rules.python.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "py-weak-cryptography",
	"title": "Use of Broken or Weak Cryptographic Hash",
	"message": "Use of weak cryptographic hash (MD5/SHA1). Use hashlib.sha256 instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["hashlib.md5", "hashlib.sha1"]

	target := sast.callee_node(call)
	finding := sast.new_finding_on_node_with_fix(metadata, call, target, metadata.message, "hashlib.sha256")
}
```

---

## 2. Rule Metadata Schema

The `metadata` dictionary configures finding properties and reporting tags:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `string` | **Required**. Unique rule identifier (e.g. `c-weak-prng-rand`). |
| `title` | `string` | Short human-readable title. |
| `message` | `string` | **Required**. Detailed vulnerability explanation and remediation advice. |
| `severity` | `string` | Issue severity: `ERROR`, `WARNING`, or `INFO`. |
| `cwe` | `string` | Common Weakness Enumeration ID (e.g. `CWE-338`). |
| `owasp` | `string` | OWASP Top 10 category (e.g. `A02:2021-Cryptographic Failures`). |
| `language` | `string` | Primary target language (e.g. `c`, `python`, `go`). |
| `fix` | `string` | Optional global replacement string for automated remediation. |

---

## 3. Standard Library API (`sast.rego`)

TreeGuard embeds helper functions into every evaluation scope via `import data.sast`:

### Node Matching & Navigation

#### `sast.nodes_by_type(node_type)`
Returns an array of all AST nodes matching the given `node_type` string.

#### `sast.child(node, field_name)`
Retrieves the direct child node corresponding to the given field name (e.g. `function`, `arguments`, `left`, `right`).

#### `sast.field_text(node, field_name)`
Returns the source text string of the child node with the specified field name.

#### `sast.parent(node)`
Returns the direct parent node of `node`.

#### `sast.ancestors(node)`
Returns an array of all ancestor nodes up to root.

#### `sast.has_ancestor(node, ancestor_type)`
Evaluates to `true` if `node` has any ancestor of type `ancestor_type`.

---

### Function Call Inspection

#### `sast.find_calls`
Returns an array of all function/method call expressions across all 12 supported languages (`call`, `call_expression`, `method_invocation`, etc.).

#### `sast.call_name(call_node)`
Extracts the function or method name string from a call node across languages.

#### `sast.callee_node(call_node)`
Returns the exact AST node corresponding to the callee/function name (useful for targeting function names in autofixes).

#### `sast.arguments(call_node)`
Returns an array of all named argument AST nodes passed to a function call.

#### `sast.arg(call_node, index)`
Returns the `N`-th argument AST node (0-indexed) of a function call.

---

### String & Literal Helpers

#### `sast.is_string_literal(node)`
Evaluates to `true` if `node` is a string literal (`string`, `string_literal`, `raw_string_literal`, `template_string`, etc.).

#### `sast.strip_quotes(text)`
Strips enclosing single (`'`) or double (`"`) quotes from a string.

---

### Finding Construction & Autofix Helpers

#### `sast.new_finding(rule_meta, node, custom_message)`
Constructs a standard finding map reported on `node`.

#### `sast.new_finding_with_fix(rule_meta, node, custom_message, replacement)`
Constructs a finding reported on `node` with an automated code replacement string for `node`.

#### `sast.new_finding_on_node_with_fix(rule_meta, finding_node, target_node, custom_message, replacement)`
Constructs a finding reported on `finding_node` (for line snippet reporting), but targeting `target_node` for code replacement.

---

## 4. Intra-Procedural Taint Analysis (Sources → Sanitizers → Sinks)

TreeGuard supports intra-procedural data-flow taint tracking natively in Rego rules. Taint analysis traces data flowing from untrusted **Sources** to vulnerable **Sinks**, while respecting neutralizing **Sanitizers**.

### Taint Analysis API
- **`sast.find_taint_flows(sources, sinks, sanitizers)`**: Traces intra-procedural data flow from nodes in `sources` to nodes in `sinks`, ignoring flows blocked by `sanitizers`. Returns a list of flow objects `{"source": srcNode, "sink": snkNode}`.
- **`sast.has_taint_flow(source, sink, sanitizers)`**: Returns `true` if untrusted data flows from `source` to `sink` without passing through `sanitizers`.
- **`sast.new_taint_finding(rule_meta, source, sink, custom_message)`**: Constructs a finding attached to `sink` with metadata recording the origin source.

### Example Taint Rule (`rules/python/sql_injection_taint.rego`)
```rego
package rules.python.sql_injection_taint

import future.keywords.in
import data.sast

metadata := {
	"id": "py-sql-injection-taint",
	"title": "SQL Injection (Taint Tracking)",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection"
}

deny[finding] {
	input.file.language == "python"

	sources := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["request.args.get", "request.form.get", "sys.argv"]
	]

	sinks := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["cursor.execute", "db.execute", "engine.execute"]
	]

	sanitizers := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["shlex.quote", "sqlescape", "int"]
	]

	flow := sast.find_taint_flows(sources, sinks, sanitizers)[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "Untrusted input flows into SQL query execution")
}
```

---

## 4. Writing Tree-sitter S-Expression Queries (`sast.ts_query`)

For complex structural patterns, TreeGuard supports native S-expression queries inside Rego:

```rego
deny[finding] {
	input.file.language == "python"
	matches := sast.ts_query("(call function: (attribute attribute: (identifier) @attr (#eq? @attr \"execute\"))) @call")
	match := matches[_]
	
	finding := sast.new_finding(metadata, match.captures["call"], metadata.message)
}
```

---

## 5. Rule Testing Framework

TreeGuard includes a built-in test runner enforcing Semgrep-style test annotations in fixture files under `test/fixtures/`.

### Annotation Syntax

* **`# ruleid: <rule-id>`** or **`// ruleid: <rule-id>`**: Asserts that `<rule-id>` MUST produce a finding on this line or the next line.
* **`# ok: <rule-id>`** or **`// ok: <rule-id>`**: Asserts that `<rule-id>` MUST NOT produce any findings on this line or the next line.

### Test Fixture Example (`test/fixtures/c/c_security.c`)
```c
void test_a02_crypto() {
    // ruleid: c-weak-prng-rand
    int token = rand();
}
```

### Running Rule Tests
```bash
./treeguard test test/fixtures
```
