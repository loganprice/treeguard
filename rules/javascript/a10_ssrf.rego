package rules.javascript.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "js-ssrf-http-request",
	"title": "Server-Side Request Forgery (SSRF) via Dynamic URL",
	"message": "Dynamic URL passed to HTTP request client without validation.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"fetch",
		"axios.get",
		"axios.post",
		"http.get",
		"https.get"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
