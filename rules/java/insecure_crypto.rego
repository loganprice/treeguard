package rules.java.insecure_crypto

import data.sast
import future.keywords.in

metadata := {
	"id": "java-weak-cryptographic-hash",
	"title": "Use of Broken Cryptographic Hash in Java",
	"message": "Use of weak cryptographic hash algorithm (MD5/SHA-1). Use SHA-256 or SHA-512 instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "getInstance"

	arg := sast.arg(call, 0)
	sast.is_string_literal(arg)
	hash_name := upper(sast.strip_quotes(arg.text))
	hash_name in ["MD5", "SHA-1", "SHA1"]

	finding := sast.new_finding_on_node_with_fix(metadata, call, arg, metadata.message, `"SHA-256"`)
}
