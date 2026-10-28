package rules.java.a05_misconfiguration

import data.sast

metadata := {
	"id": "java-spring-csrf-disabled",
	"title": "Spring Security CSRF Protection Disabled",
	"message": "Disabling Cross-Site Request Forgery (CSRF) protection in Spring Security leaves endpoints vulnerable to unauthorized state-changing attacks.",
	"severity": "ERROR",
	"cwe": "CWE-352",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	sast.call_name(call) == "disable"

	# Receiver is csrf()
	receiver := sast.child(call, "object")
	receiver.type == "method_invocation"
	sast.call_name(receiver) == "csrf"

	finding := sast.new_finding(metadata, call, metadata.message)
}
