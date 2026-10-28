package rules.go.sql_injection

import data.sast

metadata := {
	"id": "go-sql-injection",
	"title": "SQL Injection via Formatted String",
	"message": "Dynamic SQL query constructed with fmt.Sprintf passed to db query. Use parameterized placeholders instead ($1, ?)",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection",
	"language": "go"
}

deny[finding] {
	input.file.language == "go"
	call := sast.find_calls[_]
	fn_text := sast.field_text(call, "function")
	is_sql_method(fn_text)

	arg := sast.arg(call, 0)
	arg.type == "call_expression"
	sast.field_text(arg, "function") == "fmt.Sprintf"

	finding := sast.new_finding(metadata, call, metadata.message)
}

is_sql_method(name) {
	endswith(name, ".Query")
}
is_sql_method(name) {
	endswith(name, ".QueryRow")
}
is_sql_method(name) {
	endswith(name, ".Exec")
}
