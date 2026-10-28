package rules.php.a04_hardcoded_secret

import data.sast

metadata := {
	"id": "php-hardcoded-secret",
	"title": "Hardcoded JWT Secret in PHP",
	"message": "Hardcoded secret string passed to JWT::encode/decode. Retrieve secrets from environment variables (getenv) or vault.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) == "encode"

	key_arg := sast.arg(call, 1)
	sast.is_string_literal(key_arg)
	sast.strip_quotes(key_arg.text) != ""

	finding := sast.new_finding(metadata, key_arg, metadata.message)
}
