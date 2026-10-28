package rules.python.sql_injection_taint

import future.keywords.in
import data.sast

metadata := {
	"id": "py-sql-injection-taint",
	"title": "SQL Injection (Taint Tracking)",
	"description": "Untrusted HTTP input flows into database query execution without sanitization.",
	"severity": "ERROR",
	"cwe": "CWE-89",
	"owasp": "A03:2021-Injection"
}

deny[finding] {
	input.file.language == "python"

	sources := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["request.args.get", "request.form.get", "req.args.get", "sys.argv"]
	]

	sinks := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["cursor.execute", "db.execute", "engine.execute", "execute"]
	]

	sanitizers := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["shlex.quote", "sqlescape", "int"]
	]

	flow := sast.find_taint_flows(sources, sinks, sanitizers)[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "Untrusted input flows into SQL query execution")
}
