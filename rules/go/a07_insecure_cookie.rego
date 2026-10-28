package rules.go.a07_insecure_cookie

import data.sast

metadata := {
	"id": "go-insecure-cookie",
	"title": "Insecure Cookie Settings",
	"message": "Cookie set with HttpOnly: false or Secure: false, exposing it to theft via XSS or insecure transmission.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	elem := input.nodes[_]
	elem.type == "keyed_element"

	key := sast.field_text(elem, "key")
	val := sast.field_text(elem, "value")

	is_insecure_cookie_key(key, val)

	finding := sast.new_finding(metadata, elem, metadata.message)
}

is_insecure_cookie_key(k, v) {
	k == "HttpOnly"
	v == "false"
}

is_insecure_cookie_key(k, v) {
	k == "Secure"
	v == "false"
}
