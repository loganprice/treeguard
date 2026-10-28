package rules.rust.a04_hardcoded_secret

import data.sast

metadata := {
	"id": "rust-hardcoded-secret",
	"title": "Hardcoded Secret Key in Rust",
	"message": "Hardcoded secret byte string used in cryptographic key construction. Read secrets from environment variables or a secrets manager.",
	"severity": "ERROR",
	"cwe": "CWE-798",
	"owasp": "A04:2021-Insecure Design",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	endswith(fn.text, "from_secret")

	arg := sast.arg(call, 0)
	startswith(arg.text, `b"`)

	finding := sast.new_finding(metadata, arg, metadata.message)
}
