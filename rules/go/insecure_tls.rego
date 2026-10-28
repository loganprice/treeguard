package rules.go.insecure_tls

import data.sast

metadata := {
	"id": "go-insecure-tls",
	"title": "TLS InsecureSkipVerify Enabled",
	"message": "TLS verification is disabled with InsecureSkipVerify: true, allowing Man-in-the-Middle (MitM) attacks",
	"severity": "ERROR",
	"cwe": "CWE-295",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	elem := input.nodes[_]
	elem.type == "keyed_element"

	# Check key is InsecureSkipVerify
	sast.field_text(elem, "key") == "InsecureSkipVerify"

	# Check value is true
	sast.field_text(elem, "value") == "true"

	finding := sast.new_finding(metadata, elem, metadata.message)
}
