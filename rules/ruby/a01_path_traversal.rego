package rules.ruby.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-path-traversal",
	"title": "Path Traversal via File Operations in Ruby",
	"message": "Potential path traversal: opening or reading file using dynamic path without sanitization",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["read", "open", "binread", "readlines"]

	# Receiver is File or IO
	receiver := sast.child(call, "receiver")
	receiver.text in ["File", "IO"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
