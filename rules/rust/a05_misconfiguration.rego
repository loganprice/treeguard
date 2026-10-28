package rules.rust.a05_misconfiguration

import data.sast

metadata := {
	"id": "rust-tls-invalid-certs-allowed",
	"title": "TLS Certificate Validation Disabled in Rust",
	"message": "Enabling danger_accept_invalid_certs(true) disables TLS certificate verification, leaving connections open to Man-in-the-Middle (MitM) attacks.",
	"severity": "ERROR",
	"cwe": "CWE-295",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	endswith(fn.text, "danger_accept_invalid_certs")

	arg := sast.arg(call, 0)
	arg.text == "true"

	finding := sast.new_finding(metadata, call, metadata.message)
}
