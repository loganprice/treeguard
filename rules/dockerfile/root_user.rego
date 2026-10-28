package rules.dockerfile.root_user

import data.sast
import future.keywords.in

metadata := {
	"id": "docker-root-user",
	"title": "Container Running as Root User",
	"message": "Explicitly running container as root (USER root or USER 0) poses security risks",
	"severity": "ERROR",
	"cwe": "CWE-250",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "dockerfile"
}

deny[finding] {
	input.file.language == "dockerfile"
	node := input.nodes[_]
	node.type == "user_instruction"
	contains(lower(node.text), "root")
	finding := sast.new_finding(metadata, node, metadata.message)
}

deny[finding] {
	input.file.language == "dockerfile"
	node := input.nodes[_]
	node.type == "user_instruction"
	re_match(`(?i)^\s*user\s+0\s*$`, node.text)
	finding := sast.new_finding(metadata, node, metadata.message)
}
