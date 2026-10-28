package rules.dockerfile.latest_tag

import data.sast
import future.keywords.in

metadata := {
	"id": "docker-latest-tag",
	"title": "Use of :latest Tag in Base Image",
	"message": "Using ':latest' tag in FROM instruction can cause non-deterministic builds",
	"severity": "WARNING",
	"cwe": "CWE-1188",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "dockerfile"
}

deny[finding] {
	input.file.language == "dockerfile"
	node := input.nodes[_]
	node.type == "from_instruction"
	contains(lower(node.text), ":latest")
	finding := sast.new_finding(metadata, node, metadata.message)
}
