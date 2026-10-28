package rules.go.a06_vulnerable_components

import data.sast

metadata := {
	"id": "go-ssh-insecure-ignore-host-key",
	"title": "SSH InsecureIgnoreHostKey Disables Host Key Checking",
	"message": "Use of ssh.InsecureIgnoreHostKey() disables SSH host key verification, exposing connections to Man-in-the-Middle (MitM) attacks.",
	"severity": "ERROR",
	"cwe": "CWE-295",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	sast.field_text(call, "function") == "ssh.InsecureIgnoreHostKey"

	finding := sast.new_finding(metadata, call, metadata.message)
}
