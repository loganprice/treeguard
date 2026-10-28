package rules.java.a08_unsafe_deserialization

import data.sast

metadata := {
	"id": "java-unsafe-deserialization",
	"title": "Unsafe Object Deserialization via ObjectInputStream",
	"message": "Deserialization of untrusted streams using ObjectInputStream.readObject() allows arbitrary remote code execution via gadget chains.",
	"severity": "ERROR",
	"cwe": "CWE-502",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "readObject"

	finding := sast.new_finding(metadata, call, metadata.message)
}
