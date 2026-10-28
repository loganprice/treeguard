package rules.php.a05_misconfiguration

import data.sast
import future.keywords.in

metadata := {
	"id": "php-display-errors-enabled",
	"title": "PHP Display Errors Enabled in Runtime",
	"message": "Enabling display_errors in PHP reveals internal file paths, stack traces, and database error messages to attackers.",
	"severity": "ERROR",
	"cwe": "CWE-489",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "php"
}

deny[finding] {
	input.file.language == "php"
	call := sast.find_calls[_]
	sast.call_name(call) == "ini_set"

	arg0 := sast.arg(call, 0)
	sast.strip_quotes(arg0.text) == "display_errors"

	arg1 := sast.arg(call, 1)
	sast.strip_quotes(arg1.text) in ["1", "true", "on"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
