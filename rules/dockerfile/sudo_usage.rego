package rules.dockerfile.sudo_usage

import data.sast
import future.keywords.in

metadata := {
	"id": "docker-sudo-usage",
	"title": "Use of sudo in RUN Instruction",
	"message": "Avoid using sudo in RUN instructions as it can introduce unexpected privilege escalation risks",
	"severity": "ERROR",
	"cwe": "CWE-250",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "dockerfile"
}

deny[finding] {
	input.file.language == "dockerfile"
	node := input.nodes[_]
	node.type == "run_instruction"
	re_match(`(?i)\bsudo\b`, node.text)
	finding := sast.new_finding(metadata, node, metadata.message)
}
