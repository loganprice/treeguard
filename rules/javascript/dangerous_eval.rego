package rules.javascript.dangerous_eval

import data.sast
import future.keywords.in

metadata := {
	"id": "js-dangerous-eval",
	"title": "Dangerous Code Evaluation",
	"message": "Use of eval() or Function constructor allows dynamic code execution and Cross-Site Scripting (XSS)",
	"severity": "ERROR",
	"cwe": "CWE-95",
	"owasp": "A03:2021-Injection",
	"language": "javascript"
}

# Match eval(...) or window.eval(...)
deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["eval", "window.eval", "global.eval"]

	finding := sast.new_finding(metadata, call, metadata.message)
}

# Match new Function(...)
deny[finding] {
	sast.is_js_family(input.file.language)
	new_expr := input.nodes[_]
	new_expr.type == "new_expression"
	sast.field_text(new_expr, "constructor") == "Function"

	finding := sast.new_finding(metadata, new_expr, metadata.message)
}
