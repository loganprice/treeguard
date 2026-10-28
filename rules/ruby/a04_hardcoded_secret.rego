package rules.ruby.a04_hardcoded_secret

import data.sast

metadata := {
	"id": "ruby-hardcoded-secret",
	"title": "Hardcoded JWT Secret Key in Ruby",
	"message": "Hardcoded secret string passed to JWT.encode/decode. Store secret keys in environment variables or credentials vault.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	sast.call_name(call) == "encode"

	receiver := sast.child(call, "receiver")
	receiver.text == "JWT"

	key_arg := sast.arg(call, 1)
	sast.is_string_literal(key_arg)
	sast.strip_quotes(key_arg.text) != ""

	finding := sast.new_finding(metadata, key_arg, metadata.message)
}
