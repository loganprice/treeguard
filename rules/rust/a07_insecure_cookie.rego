package rules.rust.a07_insecure_cookie

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-insecure-cookie",
	"title": "Insecure Cookie Configuration in Rust",
	"message": "Cookie configured with http_only(false) or secure(false), exposing cookie to XSS theft or cleartext transmission.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	is_insecure_cookie_method(fn.text)

	arg := sast.arg(call, 0)
	arg.text == "false"

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_insecure_cookie_method(name) {
	endswith(name, "http_only")
}

is_insecure_cookie_method(name) {
	endswith(name, "secure")
}
