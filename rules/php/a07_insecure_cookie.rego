package rules.php.a07_insecure_cookie

import data.sast
import future.keywords.in

metadata := {
	"id": "php-insecure-cookie",
	"title": "Insecure Cookie Configuration in PHP",
	"message": "Cookie created with httponly or secure set to false, exposing session tokens to XSS or cleartext interception.",
	"severity": "WARNING",
	"cwe": "CWE-1004",
	"owasp": "A07:2021-Identification and Authentication Failures",
	"language": "php"
}

# Match array options: ['httponly' => false]
deny[finding] {
	input.file.language == "php"
	element := input.nodes[_]
	element.type == "array_element_initializer"

	key := input.nodes[element.children[0]]
	sast.strip_quotes(key.text) in ["httponly", "secure"]

	val := input.nodes[element.children[2]]
	val.text == "false"

	finding := sast.new_finding(metadata, element, metadata.message)
}
