package rules.go.a04_hardcoded_secret

import data.sast
import future.keywords.in

metadata := {
	"id": "go-hardcoded-secret",
	"title": "Hardcoded Secret in Token Operations",
	"message": "Hardcoded secret string passed to JWT token signing or verification. Store secrets in environment variables.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	endswith(sast.field_text(call, "function"), "SignedString")

	arg := sast.arg(call, 0)
	is_byte_string_literal(arg)

	finding := sast.new_finding(metadata, arg, metadata.message)
}

is_byte_string_literal(node) {
	node.type == "type_conversion_expression"
	sast.field_text(node, "type") == "[]byte"
	operand := sast.child(node, "operand")
	sast.is_string_literal(operand)
	sast.strip_quotes(operand.text) != ""
}
