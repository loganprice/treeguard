package rules.php.a08_unsafe_deserialization

import data.sast

metadata := {
	"id": "php-unsafe-unserialize",
	"title": "Insecure Deserialization via PHP unserialize()",
	"message": "Deserialization of untrusted input using unserialize() allows arbitrary object injection, property-oriented programming (POP chains), and remote code execution. Use json_decode() instead.",
	"severity": "ERROR",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) == "unserialize"

	finding := sast.new_finding(metadata, call, metadata.message)
}
