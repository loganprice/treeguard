package rules.java.sql_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "java-sql-injection",
	"title": "SQL Injection in JDBC Statement Execution",
	"message": "Potential SQL injection: executing SQL query dynamically built with string concatenation. Use PreparedStatement with placeholders (?) instead.",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection",
	"language": "java"
}

deny[finding] {
	input.file.language == "java"
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	fn_name in ["executeQuery", "executeUpdate", "execute"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
