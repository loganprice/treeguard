package rules.rust.a10_ssrf

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-ssrf-http-client",
	"title": "Server-Side Request Forgery (SSRF) via HTTP Client in Rust",
	"message": "Passing dynamic unvalidated URL to HTTP client (reqwest/ureq) allows attackers to initiate malicious requests to internal microservices or cloud metadata endpoints.",
	"severity": "ERROR",
	"cwe": "CWE-918",
	"owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	is_rust_http_client(fn.text)

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_rust_http_client(name) {
	name in ["reqwest::get", "ureq::get", "reqwest::Client::new().get"]
}
