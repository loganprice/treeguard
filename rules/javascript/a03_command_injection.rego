package rules.javascript.a03_command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "js-command-injection",
	"title": "Command Injection via Child Process Execution",
	"message": "Potential command injection: executing command string in shell via child_process.exec(). Use execFile or spawn with argument array instead.",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in [
		"child_process.exec",
		"child_process.execSync",
		"exec",
		"execSync"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
