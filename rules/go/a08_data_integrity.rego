package rules.go.a08_data_integrity

import data.sast
import future.keywords.in

metadata := {
	"id": "go-unsafe-gob-decoder",
	"title": "Insecure Deserialization via gob Decoder",
	"message": "Decoding untrusted data using gob.NewDecoder can lead to arbitrary memory corruption or unexpected type execution.",
	"severity": "WARNING",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["gob.NewDecoder"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
