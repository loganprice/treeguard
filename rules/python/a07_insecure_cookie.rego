package rules.python.a07_insecure_cookie

import data.sast

metadata := {
	"id": "py-insecure-cookie",
	"title": "Insecure Cookie Settings",
	"message": "Cookie is configured without HttpOnly or Secure flags, making it vulnerable to theft via XSS or network sniffing.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "python"
}

# Match set_cookie with httponly=False or secure=False
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	endswith(sast.field_text(call, "function"), ".set_cookie")

	args_container := sast.child(call, "arguments")
	arg_id := args_container.children[_]
	arg := input.nodes[arg_id]
	arg.type == "keyword_argument"

	param_name := sast.field_text(arg, "name")
	param_val := sast.field_text(arg, "value")

	is_insecure_flag(param_name, param_val)

	finding := sast.new_finding(metadata, arg, metadata.message)
}

is_insecure_flag(name, val) {
	name == "httponly"
	val == "False"
}

is_insecure_flag(name, val) {
	name == "secure"
	val == "False"
}
