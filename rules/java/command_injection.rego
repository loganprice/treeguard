package rules.java.command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "java-command-injection",
	"title": "Command Injection via Runtime.exec()",
	"message": "Executing command with Runtime.getRuntime().exec() can lead to remote command injection. Use ProcessBuilder with explicit tokenized argument list.",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "exec"

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
