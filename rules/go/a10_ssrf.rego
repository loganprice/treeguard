package rules.go.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "go-ssrf-http-client",
	"title": "Server-Side Request Forgery (SSRF) via Dynamic URL",
	"message": "Dynamic URL passed to HTTP client without validation. An attacker could force the server to make requests to internal resources.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"http.Get",
		"http.Post",
		"http.PostForm",
		"http.Head"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
