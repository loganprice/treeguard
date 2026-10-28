package rules.java.a06_xxe

import data.sast
import future.keywords.in

metadata := {
	"id": "java-xxe-xml-factory",
	"title": "XML External Entity (XXE) Vulnerability in Java XML Parser",
	"message": "Default XML parsers (DocumentBuilderFactory / SAXParserFactory) resolve external entities by default, exposing the system to XXE and SSRF attacks.",
	"severity": "ERROR",
	"cwe": "CWE-611",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "newInstance"

	receiver := sast.child(call, "object")
	receiver_name := receiver.text
	receiver_name in ["DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
