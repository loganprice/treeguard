package rules.java.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "java-ssrf-http-connection",
	"title": "Server-Side Request Forgery (SSRF) via Dynamic URL in Java",
	"message": "Opening connection to dynamic URL without validation allows attackers to target internal microservices or cloud metadata services.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	creation := input.nodes[_]
	creation.type == "object_creation_expression"
	sast.field_text(creation, "type") == "URL"

	args := sast.child(creation, "arguments")
	arg_id := args.children[_]
	arg := input.nodes[arg_id]
	arg.is_named == true
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, creation, metadata.message)
}
