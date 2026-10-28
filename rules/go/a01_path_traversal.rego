package rules.go.a01_path_traversal

import data.sast
import future.keywords.in

metadata := {
	"id": "go-path-traversal",
	"title": "Path Traversal in File Operations",
	"message": "Potential path traversal: opening file using dynamic path without sanitization via filepath.Clean",
	"severity": "ERROR",
	"cwe": "CWE-22",
	"owasp": "A01:2021-Broken Access Control",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"os.Open",
		"os.OpenFile",
		"os.ReadFile",
		"os.Create",
		"ioutil.ReadFile"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
