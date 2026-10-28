package rules.c.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "c-path-traversal",
	"title": "Path Traversal via File Operations in C/C++",
	"message": "Potential path traversal: opening file using dynamic path without sanitization via realpath().",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["fopen", "open", "freopen"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
