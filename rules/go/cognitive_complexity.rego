package rules.go.cognitive_complexity

import future.keywords.in
import data.sast

metadata := {
	"id": "go-cognitive-complexity",
	"title": "Function Exceeds Cognitive Complexity Threshold",
	"message": "Function or method has high Cognitive Complexity, making it difficult to comprehend and maintain.",
	"severity": "WARNING",
	"cwe": "CWE-1075",
	"owasp": "A04:2021-Insecure Design",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	func := input.nodes[_]
	func.type in ["function_declaration", "method_declaration"]

	control_types := [
		"if_statement",
		"for_statement",
		"expression_switch_statement",
		"type_switch_statement",
		"select_statement"
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
