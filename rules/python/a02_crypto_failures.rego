package rules.python.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "py-weak-cryptography",
	"title": "Use of Broken or Weak Cryptographic Algorithm",
	"message": "Use of broken cryptographic hash (MD5/SHA1) or insecure pseudo-random generator (random) for security contexts. Use hashlib.sha256 or secrets module instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "python"
}

hash_replacements := {
	"hashlib.md5": "hashlib.sha256",
	"hashlib.sha1": "hashlib.sha256"
}

# Match hashlib.md5 or hashlib.sha1
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	repl := hash_replacements[fn_text]

	target := sast.callee_node(call)
	finding := sast.new_finding_on_node_with_fix(metadata, call, target, metadata.message, repl)
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new"]

	finding := sast.new_finding(metadata, call, metadata.message)
}

# Match insecure random in sensitive token generation
deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["random.random", "random.randint", "random.choice"]

	# Check if assigned to token, secret, password, key, or session
	parent_node := sast.parent(call)
	parent_node.type == "assignment"
	left := sast.child(parent_node, "left")
	is_sensitive_name(left.text)

	finding := sast.new_finding(metadata, call, "Insecure PRNG (random) used to generate security-sensitive token/key. Use secrets module instead.")
}

is_sensitive_name(name) {
	name_lower := lower(name)
	name_lower in ["token", "secret", "password", "key", "session_id", "auth_token", "api_key"]
}
