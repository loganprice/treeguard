package rules.javascript.dom_xss

import data.sast
import future.keywords.in

metadata := {
	"id": "js-dom-xss-innerhtml",
	"title": "DOM-based Cross-Site Scripting via innerHTML",
	"message": "Assignment to innerHTML or outerHTML can cause DOM-based Cross-Site Scripting (XSS). Use textContent or safe DOM APIs instead.",
	"severity": "WARNING",
	"cwe": "CWE-79",
	"owasp": "A03:2021-Injection",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	assign := input.nodes[_]
	assign.type == "assignment_expression"

	left_id := assign.fields.left.id
	left := input.nodes[left_id]
	left.type == "member_expression"
	sast.field_text(left, "property") in ["innerHTML", "outerHTML"]

	finding := sast.new_finding(metadata, assign, metadata.message)
}
