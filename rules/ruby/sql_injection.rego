package rules.ruby.sql_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-sql-injection",
	"title": "SQL Injection in ActiveRecord Query",
	"message": "Potential SQL injection: raw SQL query built using string interpolation. Use parameterized queries (where('id = ?', id)) instead.",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["where", "find_by_sql", "select"]

	arg := sast.arg(call, 0)
	is_interpolated_string(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_interpolated_string(node) {
	node.type == "string"
	child_id := node.children[_]
	input.nodes[child_id].type == "interpolation"
}
