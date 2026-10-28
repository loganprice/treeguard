package rules.javascript.a06_prototype_pollution

import data.sast
import future.keywords.in

metadata := {
	"id": "js-prototype-pollution",
	"title": "Prototype Pollution via __proto__ Assignment",
	"message": "Direct assignment or modification of __proto__ can lead to Prototype Pollution, altering Object behavior globally and enabling RCE.",
	"severity": "ERROR",
	"cwe": "CWE-1321",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	assign := input.nodes[_]
	assign.type == "assignment_expression"

	left_id := assign.fields.left.id
	left := input.nodes[left_id]

	is_proto_access(left)

	finding := sast.new_finding(metadata, assign, metadata.message)
}

is_proto_access(node) {
	node.type == "member_expression"
	sast.field_text(node, "property") == "__proto__"
}

is_proto_access(node) {
	node.type == "subscript_expression"
	index_node := sast.child(node, "index")
	sast.strip_quotes(index_node.text) == "__proto__"
}
