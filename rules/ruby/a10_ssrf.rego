package rules.ruby.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-ssrf-http-request",
	"title": "Server-Side Request Forgery (SSRF) via Dynamic URL in Ruby",
	"message": "Dynamic URL passed to HTTP client (Net::HTTP / URI.open) without validation. An attacker can force the server to contact internal services or cloud metadata endpoints.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	sast.call_name(call) in ["get", "post", "open"]

	receiver := sast.child(call, "receiver")
	contains(receiver.text, "HTTP")

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
