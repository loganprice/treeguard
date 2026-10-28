package rules.java.a04_hardcoded_secret

import data.sast
import future.keywords.in

metadata := {
	"id": "java-hardcoded-secret",
	"title": "Hardcoded Secret Key in Java",
	"message": "Hardcoded cryptographic secret key or password in source code. Retrieve secrets from environment variables or vault.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	creation := input.nodes[_]
	creation.type == "object_creation_expression"
	sast.field_text(creation, "type") == "SecretKeySpec"

	# First argument is key bytes
	args := sast.child(creation, "arguments")
	arg_id := args.children[_]
	arg := input.nodes[arg_id]
	arg.is_named == true
	is_literal_bytes(arg)

	finding := sast.new_finding(metadata, creation, metadata.message)
}

is_literal_bytes(node) {
	node.type == "method_invocation"
	sast.call_name(node) == "getBytes"
	receiver := sast.child(node, "object")
	sast.is_string_literal(receiver)
}
