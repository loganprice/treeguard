package rules.javascript.cognitive_complexity

import future.keywords.in
import data.sast

metadata := {
	"id": "js-cognitive-complexity",
	"title": "Function Exceeds Cognitive Complexity Threshold",
	"message": "Function has high Cognitive Complexity, making it prone to bugs and difficult to audit.",
	"severity": "WARNING",
	"cwe": "CWE-1075",
	"owasp": "A04:2021-Insecure Design",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	func := input.nodes[_]
	func.type in ["function_declaration", "function_expression", "arrow_function", "method_definition"]

	control_types := [
		"if_statement",
		"for_statement",
		"for_in_statement",
		"for_of_statement",
		"while_statement",
		"do_statement",
		"switch_statement",
		"catch_clause",
		"ternary_expression"
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

	func_name := sast.call_name(func)
	name_str := object.get(func.fields, "name", {"text": "anonymous"}).text
	msg := sprintf("Function '%s' has Cognitive Complexity score of %d (threshold: 10).", [name_str, total_complexity])

	finding := sast.new_finding(metadata, func, msg)
}
