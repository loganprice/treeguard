package rules.c.a09_format_string

import data.sast
import future.keywords.in

metadata := {
	"id": "c-format-string-vulnerability",
	"title": "Format String Vulnerability in printf",
	"message": "Passing dynamic non-literal format string to printf() or fprintf() allows attackers to read/write process memory via %x and %n specifiers. Use printf(\"%s\", buf) instead.",
	"severity": "ERROR",
	"cwe": "CWE-134",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "c"
}

# printf(buf) with dynamic argument
deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	sast.call_name(call) == "printf"

	args := sast.arguments(call)
	count(args) == 1

	arg := args[0]
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
