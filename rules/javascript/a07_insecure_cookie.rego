package rules.javascript.a07_insecure_cookie

import data.sast
import future.keywords.in

metadata := {
	"id": "js-insecure-cookie",
	"title": "Insecure Cookie Settings",
	"message": "Cookie set with httpOnly: false or secure: false, making it vulnerable to XSS theft or transmission over unencrypted connections.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["res.cookie", "response.cookie"]

	# Third argument is cookie options object
	opt_arg := sast.arg(call, 2)
	opt_arg.type == "object"

	pair_id := opt_arg.children[_]
	pair := input.nodes[pair_id]
	pair.type == "pair"

	key := sast.field_text(pair, "key")
	val := sast.field_text(pair, "value")

	is_insecure_cookie_opt(key, val)

	finding := sast.new_finding(metadata, pair, metadata.message)
}

is_insecure_cookie_opt(k, v) {
	k == "httpOnly"
	v == "false"
}

is_insecure_cookie_opt(k, v) {
	k == "secure"
	v == "false"
}
