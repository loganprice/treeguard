package rules.dockerfile.add_usage

import data.sast
import future.keywords.in

metadata := {
	"id": "docker-add-usage",
	"title": "Use of ADD Instruction Instead of COPY",
	"message": "Use COPY instead of ADD unless auto-extraction of tar archives or fetching URLs is required",
	"severity": "WARNING",
	"cwe": "CWE-829",
	"owasp": "A08:2021-Software and Data Integrity Failures",
	"language": "dockerfile"
}

deny[finding] {
	input.file.language == "dockerfile"
	node := input.nodes[_]
	node.type == "add_instruction"
	finding := sast.new_finding(metadata, node, metadata.message)
}
