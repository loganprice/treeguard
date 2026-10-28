package rules.python.command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "py-command-injection",
	"title": "Command Injection via Shell Execution",
	"message": "Potential command injection: executing command with shell=True or os.system()",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "python"
}

# Match os.system or os.popen
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["os.system", "os.popen"]

	finding := sast.new_finding(metadata, call, metadata.message)
}

# Match subprocess with shell=True
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in [
		"subprocess.Popen",
		"subprocess.run",
		"subprocess.call",
		"subprocess.check_call",
		"subprocess.check_output"
	]

	# Check if shell=True is passed as keyword argument
	args_container := sast.child(call, "arguments")
	arg_id := args_container.children[_]
	arg := input.nodes[arg_id]
	arg.type == "keyword_argument"
	sast.field_text(arg, "name") == "shell"
	sast.field_text(arg, "value") == "True"

	finding := sast.new_finding(metadata, call, metadata.message)
}
