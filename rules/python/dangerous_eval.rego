package rules.python.dangerous_eval

import data.sast
import future.keywords.in

metadata := {
	"id": "py-dangerous-eval",
	"title": "Use of Dangerous Dynamic Evaluation",
	"message": "Dangerous dynamic execution using eval() or exec() can allow arbitrary remote code execution",
	"severity": "ERROR",
	"cwe": "CWE-95",
	"owasp": "A03:2021-Injection",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["eval", "exec"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
