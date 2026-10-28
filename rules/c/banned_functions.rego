package rules.c.banned_functions

import data.sast
import future.keywords.in

metadata := {
	"id": "c-banned-memory-functions",
	"title": "Use of Banned or Insecure C/C++ Function",
	"message": "Use of insecure legacy memory/string function (gets/strcpy/sprintf) prone to buffer overflows. Use fgets, strncpy, or snprintf instead.",
	"severity": "ERROR",
	"cwe": "CWE-120",
	"owasp": "A06:2021-Vulnerable and Outdated Components",
	"language": "c"
}

banned_replacements := {
	"gets": "fgets",
	"strcpy": "strncpy",
	"sprintf": "snprintf",
	"strcat": "strncat"
}

deny[finding] {
	input.file.language in ["c", "cpp"]
	call := sast.find_calls[_]
	fn_name := sast.call_name(call)
	repl := banned_replacements[fn_name]

	target := sast.callee_node(call)
	finding := sast.new_finding_on_node_with_fix(metadata, call, target, metadata.message, repl)
}
