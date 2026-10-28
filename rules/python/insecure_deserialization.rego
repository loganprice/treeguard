package rules.python.insecure_deserialization

import data.sast
import future.keywords.in

metadata := {
	"id": "py-unsafe-deserialization",
	"title": "Insecure Deserialization via Pickle",
	"message": "Unsafe deserialization using pickle can lead to arbitrary code execution",
	"severity": "ERROR",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in ["pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
