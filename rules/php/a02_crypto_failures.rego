package rules.php.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "php-weak-cryptographic-hash",
	"title": "Use of Broken Cryptographic Hash in PHP (MD5/SHA1)",
	"message": "Use of weak cryptographic hash (md5 or sha1). Use password_hash() for passwords or hash('sha256', ...) for general hashing.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["md5", "sha1"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
