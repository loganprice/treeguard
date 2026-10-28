package rules.ruby.command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-command-injection",
	"title": "Command Injection via Shell Execution in Ruby",
	"message": "Potential command injection: executing command via system() or exec() with dynamic arguments",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["system", "exec", "popen"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
