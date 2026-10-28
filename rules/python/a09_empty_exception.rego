package rules.python.a09_empty_exception

import data.sast

metadata := {
	"id": "py-empty-except-pass",
	"title": "Silent Exception Suppression via Empty Except Block",
	"message": "Empty exception handler with 'pass' suppresses all errors, obscuring security-critical failures and vulnerabilities.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	clause := input.nodes[_]
	clause.type == "except_clause"

	# Get body block directly from children
	child_id := clause.children[_]
	body := input.nodes[child_id]
	body.type == "block"

	# Check if sole statement in body is a pass statement
	pass_stmt_id := body.children[_]
	input.nodes[pass_stmt_id].type == "pass_statement"

	finding := sast.new_finding(metadata, clause, metadata.message)
}
