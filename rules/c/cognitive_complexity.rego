package rules.c.cognitive_complexity

import future.keywords.in
import data.sast

metadata := {
	"id": "c-cognitive-complexity",
	"title": "Function Exceeds Cognitive Complexity Threshold",
	"message": "C/C++ function has high Cognitive Complexity, increasing maintainability risks and audit effort.",
	"severity": "WARNING",
	"cwe": "CWE-1075",
	"owasp": "A04:2021-Insecure Design",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	func := input.nodes[_]
	func.type == "function_definition"

	control_types := [
		"if_statement",
		"for_statement",
		"while_statement",
		"do_statement",
		"switch_statement"
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

	msg := sprintf("C/C++ function has Cognitive Complexity score of %d (threshold: 10).", [total_complexity])

	finding := sast.new_finding(metadata, func, msg)
}
