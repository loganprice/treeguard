package rules.ruby.a02_crypto_failures

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-weak-cryptography",
	"title": "Use of Broken Cryptographic Hash in Ruby (MD5/SHA1)",
	"message": "Use of weak cryptographic hash (Digest::MD5 or Digest::SHA1). Use Digest::SHA256 or Digest::SHA512 instead.",
	"severity": "ERROR",
	"cwe": "CWE-327",
	"owasp": "A02:2021-Cryptographic Failures",
	"language": "ruby"
}

ruby_digest_replacements := {
	"Digest::MD5": "Digest::SHA256",
	"Digest::SHA1": "Digest::SHA256"
}

deny[finding] {
	input.file.language == "ruby"
	node := input.nodes[_]
	node.type == "scope_resolution"
	repl := ruby_digest_replacements[node.text]

	finding := sast.new_finding_on_node_with_fix(metadata, node, node, metadata.message, repl)
}
