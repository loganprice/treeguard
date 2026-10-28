package rules.php.a09_empty_catch

import data.sast

metadata := {
	"id": "php-empty-catch-block",
	"title": "Silent Error Suppression via Empty Catch Block in PHP",
	"message": "Empty catch block silently suppresses exceptions, hiding critical errors and security exceptions.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	clause := input.nodes[_]
	clause.type == "catch_clause"

	body := sast.child(clause, "body")
	body.type == "compound_statement"

	named_children := [cid |
		cid := body.children[_]
		input.nodes[cid].is_named == true
	]
	count(named_children) == 0

	finding := sast.new_finding(metadata, clause, metadata.message)
}
