package rules.java.a09_empty_catch

import data.sast

metadata := {
	"id": "java-empty-catch-block",
	"title": "Silent Exception Suppression via Empty Catch Block",
	"message": "Empty catch block silently ignores exceptions, masking security-critical errors or security exceptions.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	clause := input.nodes[_]
	clause.type == "catch_clause"

	body := sast.child(clause, "body")
	body.type == "block"

	named_children := [cid |
		cid := body.children[_]
		input.nodes[cid].is_named == true
	]
	count(named_children) == 0

	finding := sast.new_finding(metadata, clause, metadata.message)
}
