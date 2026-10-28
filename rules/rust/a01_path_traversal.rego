package rules.rust.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-path-traversal",
	"title": "Path Traversal in Rust File Operations",
	"message": "Potential path traversal: opening or reading file using dynamic path without canonicalization via std::fs::canonicalize().",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	is_file_read_call(fn_name)

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_file_read_call(name) {
	endswith(name, "open")
}

is_file_read_call(name) {
	endswith(name, "read")
}

is_file_read_call(name) {
	endswith(name, "read_to_string")
}
