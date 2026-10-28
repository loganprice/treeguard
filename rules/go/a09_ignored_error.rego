package rules.go.a09_ignored_error

import data.sast
import future.keywords.in

metadata := {
	"id": "go-unhandled-security-error",
	"title": "Unhandled Error in Critical Security Operation",
	"message": "Silently discarding errors with '_' on critical database or transaction operations can mask security vulnerabilities.",
	"severity": "WARNING",
	"cwe": "CWE-391",
	"owasp": "A09:2021-Security Logging and Monitoring Failures",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	assign := input.nodes[_]
	assign.type in ["assignment_statement", "short_var_declaration"]

	# Left side is blank identifier _
	sast.field_text(assign, "left") == "_"

	# Right side contains sensitive call
	call := sast.find_calls[_]
	call.parent_id == assign.fields.right.id
	is_sensitive_call(sast.field_text(call, "function"))

	finding := sast.new_finding(metadata, assign, metadata.message)
}

is_sensitive_call(name) {
	endswith(name, ".Commit")
}
is_sensitive_call(name) {
	endswith(name, ".Rollback")
}
is_sensitive_call(name) {
	name in ["os.RemoveAll", "os.Chmod"]
}
