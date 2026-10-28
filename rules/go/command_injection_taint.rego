package rules.go.command_injection_taint

import future.keywords.in
import data.sast

metadata := {
	"id": "go-command-injection-taint",
	"title": "Command Injection (Taint Tracking)",
	"description": "Untrusted input flows directly into OS command execution without sanitization.",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection"
}

deny[finding] {
	input.file.language == "go"

	sources := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["r.FormValue", "r.URL.Query().Get", "req.FormValue", "os.Getenv"]
	]

	sinks := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["exec.Command", "exec.CommandContext"]
	]

	sanitizers := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["strconv.Atoi", "filepath.Clean"]
	]

	flow := sast.find_taint_flows(sources, sinks, sanitizers)[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "Untrusted HTTP/environment input flows into exec.Command")
}
