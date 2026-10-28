package rules.python.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "py-ssrf-requests",
	"title": "Server-Side Request Forgery (SSRF) via Dynamic URL",
	"message": "Dynamic URL passed to HTTP client without validation. An attacker could force the server to make requests to internal resources or cloud metadata.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in [
		"requests.get",
		"requests.post",
		"requests.put",
		"requests.delete",
		"requests.head",
		"urllib.request.urlopen",
		"httpx.get",
		"httpx.post"
	]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
