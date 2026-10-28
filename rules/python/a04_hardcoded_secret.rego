package rules.python.a04_hardcoded_secret

import data.sast
import future.keywords.in

metadata := {
	"id": "py-hardcoded-secret",
	"title": "Hardcoded Secret or Cryptographic Key",
	"message": "Hardcoded secret key or password detected in source code. Store secrets in environment variables or a secret vault.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "python"
}

# Match hardcoded key argument in jwt.encode/decode
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["jwt.encode", "jwt.decode"]

	# Second argument is secret key
	key_arg := sast.arg(call, 1)
	sast.is_string_literal(key_arg)
	sast.strip_quotes(key_arg.text) != ""

	finding := sast.new_finding(metadata, key_arg, metadata.message)
}

# Match sensitive variable assignment with string literal
deny[finding] {
	input.file.language == "python"
	assign := input.nodes[_]
	assign.type == "assignment"

	left := sast.child(assign, "left")
	is_secret_identifier(left.text)

	right := sast.child(assign, "right")
	sast.is_string_literal(right)
	val := sast.strip_quotes(right.text)
	count(val) >= 4

	finding := sast.new_finding(metadata, assign, metadata.message)
}

is_secret_identifier(name) {
	name_upper := upper(name)
	name_upper in [
		"SECRET_KEY",
		"JWT_SECRET",
		"API_KEY",
		"PRIVATE_KEY",
		"ADMIN_PASSWORD",
		"DB_PASSWORD"
	]
}
