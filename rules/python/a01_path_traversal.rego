package rules.python.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "py-path-traversal",
	"title": "Path Traversal in File Operations",
	"message": "Potential path traversal vulnerability: opening file using dynamic path without sanitization",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["open", "send_file", "flask.send_file"]

	arg := sast.arg(call, 0)
	is_dynamic_path(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_dynamic_path(node) {
	node.type in ["identifier", "attribute"]
}

is_dynamic_path(node) {
	node.type == "binary_operator"
	sast.field_text(node, "operator") in ["+", "%"]
}

is_dynamic_path(node) {
	node.type == "string"
	child_id := node.children[_]
	input.nodes[child_id].type == "interpolation"
}
