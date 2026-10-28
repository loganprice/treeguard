package rules.c.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "c-weak-prng-rand",
	"title": "Use of Insecure Pseudo-Random Number Generator (rand/srand)",
	"message": "Use of predictable PRNG (rand/srand) in C/C++. For security or cryptographic tokens, use getrandom(), arc4random(), or OpenSSL RAND_bytes().",
	"severity": "WARNING",
	"cwe": "CWE-338",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "c"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["rand", "srand"]

	target := sast.callee_node(call)
	finding := sast.new_finding_on_node_with_fix(metadata, call, target, metadata.message, "arc4random")
}
