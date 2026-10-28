package rules.c.a04_hardcoded_secret

import data.sast
import future.keywords.in

metadata := {
	"id": "c-hardcoded-secret",
	"title": "Hardcoded Secret Key or Password in C/C++",
	"message": "Hardcoded secret or password literal in source code. Retrieve secrets securely from environment variables or a configuration vault.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	init := input.nodes[_]
	init.type == "init_declarator"

	declarator := sast.child(init, "declarator")
	is_sensitive_identifier(declarator.text)

	val := sast.child(init, "value")
	sast.is_string_literal(val)

	finding := sast.new_finding(metadata, init, metadata.message)
}

is_sensitive_identifier(name) {
	name_upper := upper(name)
	contains_sensitive_term(name_upper)
}

contains_sensitive_term(u) {
	contains(u, "PASSWORD")
}
contains_sensitive_term(u) {
	contains(u, "SECRET")
}
contains_sensitive_term(u) {
	contains(u, "API_KEY")
}
