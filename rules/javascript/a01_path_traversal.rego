package rules.javascript.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "js-path-traversal",
	"title": "Path Traversal in File Operations",
	"message": "Potential path traversal: file read operation using dynamic path without sanitization",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"fs.readFile",
		"fs.readFileSync",
		"fs.createReadStream",
		"res.sendFile",
		"response.sendFile"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
