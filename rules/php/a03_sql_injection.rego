package rules.php.a03_sql_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "php-sql-injection",
	"title": "SQL Injection in PHP Database Query",
	"message": "Potential SQL injection: executing SQL query with dynamic unparameterized input. Use prepared statements with PDO or mysqli_prepare.",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection",
	"language": "php"
}

# mysqli_query($conn, $sql)
deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) == "mysqli_query"

	arg := sast.arg(call, 1)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}

# PDO query($sql)
deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) in ["query", "exec"]

	arg := sast.arg(call, 0)
	not sast.is_string_literal(arg)

	finding := sast.new_finding(metadata, call, metadata.message)
}
