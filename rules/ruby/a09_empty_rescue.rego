package rules.ruby.a09_empty_rescue

import data.sast

metadata := {
	"id": "ruby-empty-rescue-block",
	"title": "Silent Error Suppression via Empty Rescue in Ruby",
	"message": "Empty rescue block silently suppresses exceptions, obscuring security-critical failures and operational errors.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	clause := input.nodes[_]
	clause.type == "rescue"

	# Check if rescue has no statements inside body
	body := sast.child(clause, "body")
	body.type == "body_statement"

	named_children := [cid |
		cid := body.children[_]
		input.nodes[cid].is_named == true
	]
	count(named_children) == 0

	finding := sast.new_finding(metadata, clause, metadata.message)
}
