package rules.rust.a08_data_integrity

import data.sast

metadata := {
	"id": "rust-mem-transmute-usage",
	"title": "Unsafe Type Transmutation via mem::transmute",
	"message": "Use of std::mem::transmute() reinterprets the bits of a value as another type without type checking, easily causing undefined behavior, memory corruption, and type confusion.",
	"severity": "WARNING",
	"cwe": "CWE-843",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	endswith(fn.text, "transmute")

	finding := sast.new_finding(metadata, call, metadata.message)
}
