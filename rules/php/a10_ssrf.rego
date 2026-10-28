package rules.php.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "php-ssrf-curl",
	"title": "Server-Side Request Forgery (SSRF) via cURL in PHP",
	"message": "Dynamic URL passed to curl_init() without validation allows attackers to force the server into performing requests against internal resources.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) == "curl_init"

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
