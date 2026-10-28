package rules.java.a07_insecure_cookie

import data.sast
import future.keywords.in

metadata := {
	"id": "java-insecure-cookie-flags",
	"title": "Insecure Cookie Settings in Java Servlet",
	"message": "Cookie configured with setHttpOnly(false) or setSecure(false), exposing sensitive session cookies to XSS or transmission over cleartext HTTP.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["setHttpOnly", "setSecure"]

	arg := sast.arg(call, 0)
	arg.text == "false"

	finding := sast.new_finding(metadata, call, metadata.message)
}
