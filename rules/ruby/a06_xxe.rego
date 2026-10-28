package rules.ruby.a06_xxe

import data.sast
import future.keywords.in

metadata := {
	"id": "ruby-rexml-xxe",
	"title": "XML External Entity (XXE) Vulnerability in Ruby REXML",
	"message": "Parsing XML using REXML::Document without entity restrictions can lead to XML External Entity (XXE) expansion and file disclosure.",
	"severity": "WARNING",
	"cwe": "CWE-611",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "ruby"
}

deny[finding] {
	input.file.language == "ruby"
	call := sast.find_calls[_]
	sast.call_name(call) == "new"

	receiver := sast.child(call, "receiver")
	receiver.text in ["REXML::Document"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
