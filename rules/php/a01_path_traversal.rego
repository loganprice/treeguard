package rules.php.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "php-path-traversal",
	"title": "Path Traversal in PHP File Operations",
	"message": "Potential path traversal: file read operation using dynamic path without sanitization via realpath() or basename().",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"file_get_contents",
		"readfile",
		"fopen",
		"file",
		"highlight_file",
		"show_source"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
