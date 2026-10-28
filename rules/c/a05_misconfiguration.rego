package rules.c.a05_misconfiguration

import data.sast
import future.keywords.in

metadata := {
	"id": "c-insecure-file-permissions",
	"title": "Overly Permissive File Permissions (umask(0) or 0777)",
	"message": "Setting umask(0) or chmod with 0777 grants world-writable permissions, allowing any local user to tamper with files.",
	"severity": "ERROR",
	"cwe": "CWE-732",
	"owasp": "A05:2021-Security Misconfiguration",
	"language": "c"
}

# Match umask(0)
deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	sast.call_name(call) == "umask"

	arg := sast.arg(call, 0)
	arg.text == "0"

	finding := sast.new_finding_on_node_with_fix(metadata, call, arg, metadata.message, "0027")
}

# Match chmod(..., 0777)
deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	sast.call_name(call) in ["chmod", "fchmod"]

	arg := sast.arg(call, 1)
	arg.text == "0777"

	finding := sast.new_finding_on_node_with_fix(metadata, call, arg, metadata.message, "0755")
}
