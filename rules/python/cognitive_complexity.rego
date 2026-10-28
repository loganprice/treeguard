package rules.python.cognitive_complexity

import future.keywords.in
import data.sast

metadata := {
	"id": "py-cognitive-complexity",
	"title": "Function Exceeds Cognitive Complexity Threshold",
	"message": "Function has high Cognitive Complexity, indicating code that is hard to understand, maintain, and audit.",
	"severity": "WARNING",
	"cwe": "CWE-1075",
	"owasp": "A04:2021-Insecure Design",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	func := input.nodes[_]
	func.type == "function_definition"

	control_types := [
		"if_statement",
		"for_statement",
		"while_statement",
		"else_clause",
		"try_statement",
		"except_clause"
	]

	costs := [cost |
		n := input.nodes[_]
		func.id in n.ancestors
		n.type in control_types

		nesting_ancestors := [a_id |
			a_id := n.ancestors[_]
			func.id in input.nodes[a_id].ancestors
			input.nodes[a_id].type in control_types
		]

		cost := 1 + count(nesting_ancestors)
	]

	total_complexity := sum(costs)
	total_complexity > 10

	func_name := func.fields.name.text
	msg := sprintf("Function '%s' has Cognitive Complexity score of %d (threshold: 10).", [func_name, total_complexity])

	finding := sast.new_finding(metadata, func, msg)
}
