package rules.rust.unsafe_block

import data.sast

metadata := {
	"id": "rust-unsafe-block",
	"title": "Use of Unsafe Code Block in Rust",
	"message": "Unsafe code blocks bypass Rust's memory safety and concurrency guarantees. Ensure strict invariants and document safety requirements.",
	"severity": "WARNING",
	"cwe": "CWE-119",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	node := input.nodes[_]
	node.type == "unsafe_block"

	finding := sast.new_finding(metadata, node, metadata.message)
}
