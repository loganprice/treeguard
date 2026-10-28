package rules.java.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "java-path-traversal",
	"title": "Path Traversal via File Operations in Java",
	"message": "Potential path traversal: opening file stream using dynamic unvalidated path. Use path normalization and validate against a base directory.",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "java"
}

# Match new FileInputStream(path), new File(path), new FileReader(path)
deny[finding] {
	input.file.language == "java"
	creation := input.nodes[_]
	creation.type == "object_creation_expression"

	type_name := sast.field_text(creation, "type")
	type_name in ["FileInputStream", "FileReader", "File", "FileOutputStream"]

	args := sast.child(creation, "arguments")
	arg_id := args.children[_]
	arg := input.nodes[arg_id]
	arg.is_named == true
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, creation, metadata.message)
}

# Match Paths.get(dynamicPath)
deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "get"

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
