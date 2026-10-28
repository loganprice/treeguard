package rules.c.a03_command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "c-command-injection",
	"title": "Command Injection via system() or popen() in C/C++",
	"message": "Potential command injection: executing command using system() or popen() with unvalidated input. Use fork() + execve() with explicit arguments.",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["system", "popen"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
