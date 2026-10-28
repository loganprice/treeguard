package rules.javascript.a04_hardcoded_secret

import data.sast
import future.keywords.in

metadata := {
	"id": "js-hardcoded-secret",
	"title": "Hardcoded JWT Secret or Sensitive Token",
	"message": "Hardcoded secret string used in JWT signing or authentication. Use environment variables to supply secrets.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["jwt.sign", "jwt.verify"]

	key_arg := sast.arg(call, 1)
	sast.is_string_literal(key_arg)
	sast.strip_quotes(key_arg.text) != ""

	finding := sast.new_finding(metadata, key_arg, metadata.message)
}
