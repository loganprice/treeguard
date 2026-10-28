package rules.python.a06_xxe

import data.sast
import future.keywords.in

metadata := {
	"id": "py-xxe-elementtree",
	"title": "XML External Entity (XXE) Vulnerability",
	"message": "Standard xml.etree.ElementTree is vulnerable to XML External Entity (XXE) and entity expansion attacks. Use defusedxml instead.",
	"severity": "WARNING",
	"cwe": "CWE-611",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "python"
}

deny[finding] {
	input.file.language == "python"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	fn_text in [
		"ET.parse",
		"ET.fromstring",
		"xml.etree.ElementTree.parse",
		"xml.etree.ElementTree.fromstring"
	]

	finding := sast.new_finding(metadata, call, metadata.message)
}
