package rules.javascript.a05_misconfiguration

import data.sast

metadata := {
	"id": "js-cors-wildcard-credentials",
	"title": "CORS Misconfiguration: Wildcard with Credentials",
	"message": "Configuring CORS with origin '*' and credentials: true allows any third-party website to make authenticated requests to this server.",
	"severity": "ERROR",
	"cwe": "CWE-942",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	obj := input.nodes[_]
	obj.type == "object"

	has_origin_star(obj)
	has_credentials_true(obj)

	finding := sast.new_finding(metadata, obj, metadata.message)
}

has_origin_star(obj) {
	prop_id := obj.children[_]
	prop := input.nodes[prop_id]
	prop.type == "pair"
	sast.field_text(prop, "key") == "origin"
	sast.strip_quotes(sast.field_text(prop, "value")) == "*"
}

has_credentials_true(obj) {
	prop_id := obj.children[_]
	prop := input.nodes[prop_id]
	prop.type == "pair"
	sast.field_text(prop, "key") == "credentials"
	sast.field_text(prop, "value") == "true"
}
