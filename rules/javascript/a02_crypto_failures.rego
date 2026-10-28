package rules.javascript.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "js-weak-cryptography",
	"title": "Use of Broken or Weak Cryptographic Hash",
	"message": "Use of weak cryptographic hash (MD5/SHA1). Use SHA-256 or SHA-512 instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "javascript"
}

deny[finding] {
	sast.is_js_family(input.file.language)
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["crypto.createHash", "createHash"]

	arg := sast.arg(call, 0)
	sast.is_string_literal(arg)
	hash_name := lower(sast.strip_quotes(arg.text))
	hash_name in ["md5", "sha1"]

	finding := sast.new_finding_on_node_with_fix(metadata, call, arg, metadata.message, "'sha256'")
}
