package rules.c.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "c-ssrf-libcurl",
	"title": "Server-Side Request Forgery (SSRF) via libcurl",
	"message": "Setting dynamic URL in curl_easy_setopt(CURLOPT_URL) without validation can allow Server-Side Request Forgery (SSRF) to internal services.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	sast.call_name(call) == "curl_easy_setopt"

	opt_arg := sast.arg(call, 1)
	opt_arg.text == "CURLOPT_URL"

	url_arg := sast.arg(call, 2)
	not sast.is_string_literal(url_arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
