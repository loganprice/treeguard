package rules.rust.a03_command_injection

import data.sast
import future.keywords.in

metadata := {
	"id": "rust-command-injection-shell",
	"title": "Command Execution via Shell in Rust",
	"message": "Spawning shell (/bin/sh, /bin/bash, cmd.exe) via std::process::Command can lead to command injection. Invoke binaries directly with tokenized arguments.",
	"severity": "ERROR",
	"cwe": "CWE-78",
	"owasp": "A03:2021-Injection",
	"language": "rust"
}

deny[finding] {
	input.file.language == "rust"
	call := sast.find_calls[_]
	fn := sast.child(call, "function")
	endswith(fn.text, "Command::new")

	arg := sast.arg(call, 0)
	sast.is_string_literal(arg)
	shell := sast.strip_quotes(arg.text)
	shell in ["sh", "bash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe"]

	finding := sast.new_finding(metadata, call, metadata.message)
}
