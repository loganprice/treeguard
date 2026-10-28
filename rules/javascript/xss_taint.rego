package rules.javascript.xss_taint

import future.keywords.in
import data.sast

metadata := {
	"id": "js-xss-taint",
	"title": "Cross-Site Scripting (XSS Taint Tracking)",
	"description": "Untrusted request data flows directly into HTTP response output without HTML sanitization.",
	"severity": "ERROR",
	"cwe": "CWE-79",
	"owasp": "A03:2021-Injection"
}

deny[finding] {
	sast.is_js_family(input.file.language)

	sources := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["req.query.get", "req.params.get", "url.searchParams.get"]
	]

	sinks := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["res.send", "res.write", "response.write"]
	]

	sanitizers := [c |
		c := sast.find_calls[_]
		sast.call_name(c) in ["DOMPurify.sanitize", "escapeHTML", "encodeURIComponent"]
	]

	flow := sast.find_taint_flows(sources, sinks, sanitizers)[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "Untrusted request data flows into response output without sanitization")
}
