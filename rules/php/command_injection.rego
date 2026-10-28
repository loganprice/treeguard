package rules.php.command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "php-command-injection",
	"title": "Command Injection via Shell Execution in PHP",
	"message": "Potential command injection: executing command using system(), exec(), shell_exec(), or passthru() with unescaped input. Use escapeshellarg() or escapeshellcmd().",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["system", "exec", "shell_exec", "passthru", "popen"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
