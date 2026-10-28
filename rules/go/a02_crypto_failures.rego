package rules.go.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "go-weak-cryptography",
	"title": "Use of Broken Cryptographic Hash (MD5/SHA1)",
	"message": "Use of weak cryptographic hash (MD5/SHA1). Use sha256.New() or sha512.New() instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "go"
}

go_hash_replacements := {
	"md5.New": "sha256.New",
	"md5.Sum": "sha256.Sum",
	"sha1.New": "sha256.New",
	"sha1.Sum": "sha256.Sum"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	repl := go_hash_replacements[fn_text]

	target := sast.callee_node(call)
	finding := sast.new_finding_on_node_with_fix(metadata, call, target, metadata.message, repl)
}
