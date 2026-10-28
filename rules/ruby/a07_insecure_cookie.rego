package rules.ruby.a07_insecure_cookie

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-insecure-cookie",
	"title": "Insecure Cookie Settings in Ruby",
	"message": "Cookie set with httponly: false or secure: false, exposing cookie to XSS theft or transmission over insecure channels.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	pair := input.nodes[_]
	pair.type == "pair"

	key := sast.field_text(pair, "key")
	val := sast.field_text(pair, "value")

	is_insecure_cookie_key(key, val)

	finding := sast.new_finding(metadata, pair, metadata.message)
}

is_insecure_cookie_key(k, v) {
	k in ["httponly", ":httponly"]
	v == "false"
}

is_insecure_cookie_key(k, v) {
	k in ["secure", ":secure"]
	v == "false"
}
