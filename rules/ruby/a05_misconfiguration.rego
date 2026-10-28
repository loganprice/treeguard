package rules.ruby.a05_misconfiguration

import data.sast

metadata := {
	"id": "ruby-rails-debug-all-requests-local",
	"title": "Rails Debug Mode Enabled (consider_all_requests_local)",
	"message": "Enabling consider_all_requests_local in production exposes detailed stack traces and system environment variables.",
	"severity": "ERROR",
	"cwe": "CWE-489",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	node := input.nodes[_]
	node.type == "assignment"

	left := sast.child(node, "left")
	contains(left.text, "consider_all_requests_local")

	right := sast.child(node, "right")
	right.text == "true"

	finding := sast.new_finding(metadata, node, metadata.message)
}
