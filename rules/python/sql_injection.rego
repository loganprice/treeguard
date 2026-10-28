package rules.python.sql_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "py-sql-injection",
	"title": "SQL Injection via String Formatting",
	"message": "Potential SQL injection detected: untrusted formatted string passed to execute(). Use parameterized queries instead.",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"

	# Match calls to .execute(...)
	call := sast.find_calls_ending_with(".execute")[_]

	# First argument to execute
	arg := sast.arg(call, 0)

	# Check if argument is formatted string:
	# 1. Binary operator % ("SELECT ... %s" % var)
	# 2. Call to .format() ("SELECT ... {}".format(var))
	# 3. Formatted string literal / f-string (f"SELECT ... {var}")
	is_formatted_string(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_formatted_string(node) {
	node.type == "binary_operator"
	sast.field_text(node, "operator") == "%"
}

is_formatted_string(node) {
	node.type == "call"
	sast.field_text(node, "function") == "format"
}

is_formatted_string(node) {
	node.type == "call"
	endswith(sast.field_text(node, "function"), ".format")
}

is_formatted_string(node) {
	node.type in ["formatted_string", "format_expression"]
}

is_formatted_string(node) {
	node.type == "string"
	child_id := node.children[_]
	input.nodes[child_id].type == "interpolation"
}
