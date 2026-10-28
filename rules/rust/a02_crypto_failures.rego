package rules.rust.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-weak-cryptography",
	"title": "Use of Broken Cryptographic Hash in Rust",
	"message": "Use of weak cryptographic hash (MD5/SHA1). Use sha2::Sha256 or ring for cryptographic operations.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	is_weak_rust_crypto(fn.text)

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_weak_rust_crypto(name) {
	startswith(name, "md5::")
}

is_weak_rust_crypto(name) {
	startswith(name, "sha1::")
}
