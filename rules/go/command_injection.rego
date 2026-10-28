package rules.go.command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "go-command-injection",
	"title": "Command Injection via Shell Invocation",
	"message": "Invoking shell interpreter ('sh -c' or 'bash -c') with exec.Command may lead to command injection vulnerabilities",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["exec.Command", "exec.CommandContext"]

	# Check arguments for shell invocation
	arg0 := sast.arg(call, 0)
	sast.strip_quotes(arg0.text) in ["sh", "bash", "/bin/sh", "/bin/bash"]

	arg1 := sast.arg(call, 1)
	sast.strip_quotes(arg1.text) == "-c"

	finding := sast.new_finding(metadata, call, metadata.message)
}
