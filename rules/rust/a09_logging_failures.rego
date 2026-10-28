package rules.rust.a09_logging_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-unhandled-critical-error",
	"title": "Silently Discarding Critical Operation Result with let _ =",
	"message": "Silently discarding the Result of critical I/O, crypto, or file removal operations can hide vulnerabilities and security failures.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	decl := input.nodes[_]
	decl.type == "let_declaration"

	pattern := sast.child(decl, "pattern")
	pattern.text == "_"

	val := sast.child(decl, "value")
	val.type == "call_expression"
	is_sensitive_rust_operation(val.text)

	finding := sast.new_finding(metadata, decl, metadata.message)
}

is_sensitive_rust_operation(text) {
	contains(text, "remove_file")
}

is_sensitive_rust_operation(text) {
	contains(text, "remove_dir")
}

is_sensitive_rust_operation(text) {
	contains(text, "set_permissions")
}
