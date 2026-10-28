package rules.python.a05_debug_enabled

import data.sast

metadata := {
	"id": "py-debug-mode-enabled",
	"title": "Debug Mode Enabled in Production",
	"message": "Debug mode is enabled. This exposes interactive debuggers, stack traces, and environment secrets.",
	"severity": "ERROR",
	"cwe": "CWE-489",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "python"
}

# Match app.run(..., debug=True)
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	endswith(sast.field_text(call, "function"), ".run")

	args_container := sast.child(call, "arguments")
	arg_id := args_container.children[_]
	arg := input.nodes[arg_id]
	arg.type == "keyword_argument"
	sast.field_text(arg, "name") == "debug"
	val := sast.child(arg, "value")
	val.text == "True"

	finding := sast.new_finding_on_node_with_fix(metadata, arg, val, metadata.message, "False")
}

# Match DEBUG = True
deny[finding] {
	input.file.language == "python"
	assign := input.nodes[_]
	assign.type == "assignment"

	left := sast.child(assign, "left")
	left.text == "DEBUG"

	right := sast.child(assign, "right")
	right.text == "True"

	finding := sast.new_finding_on_node_with_fix(metadata, assign, right, metadata.message, "False")
}
