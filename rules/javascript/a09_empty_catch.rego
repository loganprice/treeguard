package rules.javascript.a09_empty_catch

import data.sast

metadata := {
	"id": "js-empty-catch-block",
	"title": "Silent Error Suppression via Empty Catch Block",
	"message": "Empty catch block silently ignores exceptions, obscuring security-critical failures and system errors.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	clause := input.nodes[_]
	clause.type == "catch_clause"

	body := sast.child(clause, "body")
	body.type == "statement_block"

	# Check that body has no named child statements
	named_children := [cid |
		cid := body.children[_]
		input.nodes[cid].is_named == true
	]
	count(named_children) == 0

	finding := sast.new_finding(metadata, clause, metadata.message)
}
