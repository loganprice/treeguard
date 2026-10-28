package rules.ruby.a08_unsafe_deserialization

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-unsafe-deserialization",
	"title": "Unsafe Object Deserialization in Ruby (Marshal/YAML)",
	"message": "Deserialization of untrusted data with Marshal.load or YAML.load allows arbitrary remote code execution via Ruby gadget chains. Use JSON or YAML.safe_load instead.",
	"severity": "ERROR",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	sast.call_name(call) == "load"

	receiver := sast.child(call, "receiver")
	receiver.text in ["Marshal", "YAML"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
