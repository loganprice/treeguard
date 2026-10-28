package rules.javascript.a08_unsafe_deserialization

import data.sast
import future.keywords.in

metadata := {
	"id": "js-unsafe-deserialization",
	"title": "Insecure Deserialization via node-serialize",
	"message": "Deserialization of untrusted data using node-serialize unserialize() allows arbitrary code execution via IIFE function expressions.",
	"severity": "ERROR",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in [
		"serialize.unserialize",
		"nodeSerialize.unserialize",
		"unserialize"
	]

	finding := sast.new_finding(metadata, call, metadata.message)
}
