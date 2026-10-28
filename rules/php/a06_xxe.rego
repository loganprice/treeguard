package rules.php.a06_xxe

import data.sast
import future.keywords.in

metadata := {
	"id": "php-xxe-simplexml",
	"title": "XML External Entity (XXE) Vulnerability in PHP SimpleXML",
	"message": "Parsing untrusted XML with simplexml_load_string without disabling external entity loaders exposes files and internal services to XXE attacks.",
	"severity": "WARNING",
	"cwe": "CWE-611",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) in ["simplexml_load_string", "simplexml_load_file"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
