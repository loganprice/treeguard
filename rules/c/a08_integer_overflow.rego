package rules.c.a08_integer_overflow

import data.sast
import future.keywords.in

metadata := {
	"id": "c-integer-overflow-malloc",
	"title": "Potential Integer Overflow in Memory Allocation",
	"message": "Performing arithmetic multiplication directly inside malloc() argument can cause integer overflow, leading to undersized buffer allocation and heap overflow. Use calloc() or safe checked multiplication.",
	"severity": "WARNING",
	"cwe": "CWE-190",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	sast.call_name(call) in ["malloc", "alloca"]

	arg := sast.arg(call, 0)
	arg.type == "binary_expression"
	contains(arg.text, "*")

	finding := sast.new_finding(metadata, call, metadata.message)
}
