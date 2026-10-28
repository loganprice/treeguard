package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
)

func TestEngineLoadAndCompileTableDriven(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func(t *testing.T) string
		loadAction   func(eng *engine.Engine, path string) error
		wantCompile  bool
		compileError bool
	}{
		{
			name: "Load valid rule file and compile",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				f := filepath.Join(dir, "valid.rego")
				content := `package rules.test.valid
metadata := { "id": "test-rule", "severity": "ERROR" }
deny[finding] { finding := { "id": metadata.id, "message": "found" } }`
				if err := os.WriteFile(f, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
				return f
			},
			loadAction: func(eng *engine.Engine, path string) error {
				return eng.LoadRuleFile(path)
			},
			wantCompile:  true,
			compileError: false,
		},
		{
			name: "Load non-existent rule file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "non_existent.rego")
			},
			loadAction: func(eng *engine.Engine, path string) error {
				return eng.LoadRuleFile(path)
			},
			wantCompile:  false,
			compileError: false,
		},
		{
			name: "Load directory with valid and test rego files",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				valid := filepath.Join(dir, "valid.rego")
				if err := os.WriteFile(valid, []byte("package rules.test.dirvalid\ndeny[f] { f := \"ok\" }"), 0644); err != nil {
					t.Fatal(err)
				}
				testFile := filepath.Join(dir, "rule_test.rego")
				if err := os.WriteFile(testFile, []byte("package rules.test.dirvalid_test"), 0644); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			loadAction: func(eng *engine.Engine, path string) error {
				return eng.LoadRuleDir(path)
			},
			wantCompile:  true,
			compileError: false,
		},
		{
			name: "Load non-existent directory",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing_dir")
			},
			loadAction: func(eng *engine.Engine, path string) error {
				return eng.LoadRuleDir(path)
			},
			wantCompile:  false,
			compileError: false,
		},
		{
			name: "Compile invalid Rego syntax",
			setup: func(t *testing.T) string {
				return "package rules.test.invalid syntax error ==="
			},
			loadAction: func(eng *engine.Engine, content string) error {
				eng.AddRuleModule("invalid.rego", content)
				return nil
			},
			wantCompile:  true,
			compileError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathOrContent := tt.setup(t)
			eng := engine.New()
			err := tt.loadAction(eng, pathOrContent)
			if err != nil {
				if tt.wantCompile {
					t.Fatalf("loadAction unexpectedly failed: %v", err)
				}
				return
			}

			if tt.wantCompile {
				err := eng.Compile(ctx)
				if (err != nil) != tt.compileError {
					t.Fatalf("Compile() error = %v, compileError %v", err, tt.compileError)
				}
			}
		})
	}
}

func TestEngineEvalTableDriven(t *testing.T) {
	ctx := context.Background()
	p := parser.New()

	pySource := `
def calculate(expr):
    return eval(expr)

def message():
    return "hello"
`
	parsedPy, err := p.ParseSource("calc.py", []byte(pySource), "python")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	defer parsedPy.Close()

	tests := []struct {
		name          string
		ruleContent   string
		isCompiled    bool
		wantFindings  int
		wantRuleID    string
		wantSeverity  string
		wantFixString string
		wantErr       bool
	}{
		{
			name:       "Uncompiled engine error",
			isCompiled: false,
			wantErr:    true,
		},
		{
			name: "Rule with deny collection, metadata defaults, and AST node finding",
			ruleContent: `
package rules.python.eval

metadata := {
	"id": "py-eval-detected",
	"title": "Dangerous Eval",
	"message": "eval() call detected",
	"severity": "ERROR",
	"cwe": "CWE-95",
	"owasp": "A03:2021"
}

deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`,
			isCompiled:   true,
			wantFindings: 1,
			wantRuleID:   "py-eval-detected",
			wantSeverity: engine.SeverityError,
			wantErr:      false,
		},
		{
			name: "Rule with findings collection and explicit fix",
			ruleContent: `
package rules.python.fix_test

metadata := {
	"id": "py-fix-test",
	"severity": "WARN"
}

findings[f] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	f := {
		"rule_id": "custom-id",
		"title": "Custom Title",
		"message": "Custom Message",
		"severity": "HIGH",
		"cwe": "CWE-123",
		"owasp": "A01:2021",
		"code": "eval(expr)",
		"file": "calc.py",
		"range": call.range,
		"fix": {
			"replacement": "ast.literal_eval(expr)",
			"range": call.range
		}
	}
}
`,
			isCompiled:    true,
			wantFindings:  1,
			wantRuleID:    "custom-id",
			wantSeverity:  engine.SeverityError,
			wantFixString: "ast.literal_eval(expr)",
			wantErr:       false,
		},
		{
			name: "Rule returning simple string finding",
			ruleContent: `
package rules.python.str_finding

metadata := {
	"id": "str-rule",
	"severity": "INFO"
}

deny[msg] {
	input.file.language == "python"
	msg := "Simple string finding message"
}
`,
			isCompiled:   true,
			wantFindings: 1,
			wantRuleID:   "str-rule",
			wantSeverity: engine.SeverityInfo,
			wantErr:      false,
		},
		{
			name: "Rule with fix as raw string replacement",
			ruleContent: `
package rules.python.fix_string

metadata := { "id": "fix-str-rule", "severity": "WARN" }

deny[f] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	f := {
		"node": call,
		"fix": "safe_eval(expr)"
	}
}
`,
			isCompiled:    true,
			wantFindings:  1,
			wantRuleID:    "fix-str-rule",
			wantSeverity:  engine.SeverityWarning,
			wantFixString: "safe_eval(expr)",
			wantErr:       false,
		},
		{
			name: "Rule returning non-matching query (0 findings)",
			ruleContent: `
package rules.python.none

metadata := { "id": "no-match", "severity": "ERROR" }

deny[finding] {
	input.file.language == "non_existent_language"
	finding := "none"
}
`,
			isCompiled:   true,
			wantFindings: 0,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := engine.New()
			if tt.ruleContent != "" {
				eng.AddRuleModule("rule.rego", tt.ruleContent)
			}
			if tt.isCompiled {
				if err := eng.Compile(ctx); err != nil {
					t.Fatalf("Compile() failed: %v", err)
				}
			}

			findings, err := eng.EvalFile(ctx, parsedPy)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EvalFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(findings) != tt.wantFindings {
				t.Fatalf("EvalFile() returned %d findings, want %d", len(findings), tt.wantFindings)
			}

			if tt.wantFindings > 0 {
				f := findings[0]
				if f.RuleID != tt.wantRuleID {
					t.Errorf("RuleID = %q, want %q", f.RuleID, tt.wantRuleID)
				}
				if f.Severity != tt.wantSeverity {
					t.Errorf("Severity = %q, want %q", f.Severity, tt.wantSeverity)
				}
				if tt.wantFixString != "" {
					if f.Fix == nil || f.Fix.Replacement != tt.wantFixString {
						t.Errorf("Fix replacement = %v, want %q", f.Fix, tt.wantFixString)
					}
				}
			}
		})
	}
}

func TestTreeSitterQueryBuiltinTableDriven(t *testing.T) {
	ctx := context.Background()
	p := parser.New()

	pySource := `
insecure_func()
safe_func()
`
	parsed, err := p.ParseSource("test.py", []byte(pySource), "python")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	defer parsed.Close()

	tests := []struct {
		name         string
		ruleContent  string
		wantFindings int
		wantErr      bool
	}{
		{
			name: "Valid tree-sitter query builtin",
			ruleContent: `
package rules.python.ts_query_test

metadata := { "id": "py-ts-query-call", "severity": "WARNING" }

deny[finding] {
	matches := sast.ts_query("(call function: (identifier) @fn)")
	m := matches[_]
	fn := m.captures.fn
	fn.text == "insecure_func"
	finding := {
		"rule_id": metadata.id,
		"message": "found call",
		"code": fn.text,
		"range": fn.range
	}
}
`,
			wantFindings: 1,
			wantErr:      false,
		},
		{
			name: "Invalid tree-sitter query yields no matches",
			ruleContent: `
package rules.python.ts_invalid

deny[finding] {
	matches := sast.ts_query("(non_existent_node_type_abc_123)")
	m := matches[_]
	finding := "invalid"
}
`,
			wantFindings: 0,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := engine.New()
			eng.AddRuleModule("ts.rego", tt.ruleContent)
			if err := eng.Compile(ctx); err != nil {
				t.Fatalf("Compile() failed: %v", err)
			}

			findings, err := eng.EvalFile(ctx, parsed)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EvalFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(findings) != tt.wantFindings {
				t.Errorf("findings count = %d, want %d", len(findings), tt.wantFindings)
			}
		})
	}
}

func TestSeverityHelpersTableDriven(t *testing.T) {
	normTests := []struct {
		input string
		want  string
	}{
		{"ERROR", engine.SeverityError},
		{"error", engine.SeverityError},
		{"CRITICAL", engine.SeverityError},
		{"HIGH", engine.SeverityError},
		{"WARNING", engine.SeverityWarning},
		{"warn", engine.SeverityWarning},
		{"MEDIUM", engine.SeverityWarning},
		{"INFO", engine.SeverityInfo},
		{"note", engine.SeverityInfo},
		{"unknown", engine.SeverityInfo},
		{"", engine.SeverityInfo},
	}

	for _, tt := range normTests {
		t.Run("NormalizeSeverity_"+tt.input, func(t *testing.T) {
			got := engine.NormalizeSeverity(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDeduplicateAndFilterTableDriven(t *testing.T) {
	f1 := engine.Finding{
		RuleID:   "rule-1",
		File:     "test.py",
		Severity: engine.SeverityError,
		Range: parser.Range{
			Start: parser.Point{Line: 1, Column: 1},
			End:   parser.Point{Line: 1, Column: 10},
		},
	}
	f1Dup := f1
	f2 := engine.Finding{
		RuleID:   "rule-2",
		File:     "test.py",
		Severity: engine.SeverityWarning,
		Range: parser.Range{
			Start: parser.Point{Line: 5, Column: 1},
			End:   parser.Point{Line: 5, Column: 10},
		},
	}
	f3 := engine.Finding{
		RuleID:   "rule-3",
		File:     "test.py",
		Severity: engine.SeverityInfo,
		Range: parser.Range{
			Start: parser.Point{Line: 10, Column: 1},
			End:   parser.Point{Line: 10, Column: 10},
		},
	}

	dedupTests := []struct {
		name     string
		input    []engine.Finding
		wantLen  int
		wantKeys []string
	}{
		{
			name:    "Empty input",
			input:   nil,
			wantLen: 0,
		},
		{
			name:    "Single finding",
			input:   []engine.Finding{f1},
			wantLen: 1,
		},
		{
			name:    "With duplicate findings",
			input:   []engine.Finding{f1, f1Dup, f2, f3},
			wantLen: 3,
		},
	}

	for _, tt := range dedupTests {
		t.Run("Deduplicate_"+tt.name, func(t *testing.T) {
			got := engine.DeduplicateFindings(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("DeduplicateFindings() returned %d findings, want %d", len(got), tt.wantLen)
			}
		})
	}

	filterTests := []struct {
		name        string
		minSeverity string
		wantLen     int
	}{
		{"Filter ERROR", engine.SeverityError, 1},
		{"Filter WARNING", engine.SeverityWarning, 2},
		{"Filter INFO", engine.SeverityInfo, 3},
		{"Filter empty severity defaults to INFO", "", 3},
	}

	allFindings := []engine.Finding{f1, f2, f3}
	for _, tt := range filterTests {
		t.Run("Filter_"+tt.name, func(t *testing.T) {
			got := engine.FilterBySeverity(allFindings, tt.minSeverity)
			if len(got) != tt.wantLen {
				t.Errorf("FilterBySeverity(%q) returned %d findings, want %d", tt.minSeverity, len(got), tt.wantLen)
			}
		})
	}
}

func TestContextHelpers(t *testing.T) {
	t.Run("GetActiveContext with nil context", func(t *testing.T) {
		ctx := context.Background()
		if act := engine.GetActiveContext(ctx); act != nil {
			t.Errorf("expected nil ActiveContext, got %v", act)
		}
	})

	t.Run("WithActiveContext and GetActiveContext roundtrip", func(t *testing.T) {
		act := &engine.ActiveContext{
			Source: []byte("test source"),
		}
		ctx := engine.WithActiveContext(context.Background(), act)
		got := engine.GetActiveContext(ctx)
		if got == nil || string(got.Source) != "test source" {
			t.Errorf("GetActiveContext roundtrip mismatch: got %v", got)
		}
	})
}

func TestIntraProceduralTaintAnalysisTableDriven(t *testing.T) {
	ctx := context.Background()
	p := parser.New()

	pySourceTainted := `
def vulnerable(req):
    user_data = req.args.get("user")
    query = "SELECT * FROM users WHERE id = " + user_data
    cursor.execute(query)

def sanitized(req):
    user_data = req.args.get("user")
    clean_data = shlex.quote(user_data)
    query = "SELECT * FROM users WHERE id = " + clean_data
    cursor.execute(query)
`

	parsedPy, err := p.ParseSource("taint_test.py", []byte(pySourceTainted), "python")
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	defer parsedPy.Close()

	ruleContent := `
package rules.python.sql_taint

import data.sast

metadata := {
	"id": "py-sql-taint",
	"severity": "ERROR"
}

deny[finding] {
	sources := sast.find_calls_ending_with(".get")
	sinks := sast.find_calls_ending_with(".execute")
	sanitizers := sast.find_calls_by_name("shlex.quote")

	flow := sast.find_taint_flows(sources, sinks, sanitizers)[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "SQL Taint Violation")
}
`

	eng := engine.New()
	eng.AddRuleModule("taint_rule.rego", ruleContent)
	if err := eng.Compile(ctx); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	findings, err := eng.EvalFile(ctx, parsedPy)
	if err != nil {
		t.Fatalf("EvalFile failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 taint finding (vulnerable function), got %d", len(findings))
	}

	if findings[0].RuleID != "py-sql-taint" {
		t.Errorf("RuleID = %q, want 'py-sql-taint'", findings[0].RuleID)
	}
	if findings[0].Range.Start.Line != 5 {
		t.Errorf("Finding line = %d, want line 5 (cursor.execute in vulnerable func)", findings[0].Range.Start.Line)
	}
}

func TestInterproceduralTaintFlowTableDriven(t *testing.T) {
	ctx := context.Background()
	p := parser.New()

	ruleContent := `
package rules.python.sql_taint_interproc

import data.sast

metadata := {
	"id": "py-sql-taint-interproc",
	"severity": "ERROR"
}

deny[finding] {
	sources := sast.find_calls_ending_with(".get")
	sinks := sast.find_calls_ending_with(".execute")

	flow := sast.find_taint_flows(sources, sinks, [])[_]
	finding := sast.new_taint_finding(metadata, flow.source, flow.sink, "Interprocedural SQL Taint Violation")
}
`

	tests := []struct {
		name         string
		sources      map[string]string
		wantFindings int
		wantRuleID   string
	}{
		{
			name: "Cross-function taint within same file",
			sources: map[string]string{
				"main.py": `
def execute_query(query_str):
    cursor.execute(query_str)

func_safe = lambda x: x

def process_request(request):
    user_input = request.args.get('id')
    execute_query(user_input)
`,
			},
			wantFindings: 1,
			wantRuleID:   "py-sql-taint-interproc",
		},
		{
			name: "Cross-file taint across two files",
			sources: map[string]string{
				"db_helper.py": `
def run_db_op(sql_text):
    cursor.execute(sql_text)
`,
				"api_handler.py": `
def handle_api(req):
    val = req.args.get('q')
    run_db_op(val)
`,
			},
			wantFindings: 1,
			wantRuleID:   "py-sql-taint-interproc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callGraph := engine.NewProjectCallGraph()
			var parsedList []*parser.ParsedFile

			for filePath, src := range tt.sources {
				pf, err := p.ParseSource(filePath, []byte(src), "python")
				if err != nil {
					t.Fatalf("ParseSource failed for %s: %v", filePath, err)
				}
				defer pf.Close()
				callGraph.IndexFile(pf)
				parsedList = append(parsedList, pf)
			}

			eng := engine.New()
			eng.AddRuleModule("interproc_rule.rego", ruleContent)
			if err := eng.Compile(ctx); err != nil {
				t.Fatalf("Compile failed: %v", err)
			}

			var totalFindings []engine.Finding
			for _, pf := range parsedList {
				findings, err := eng.EvalFileWithCallGraph(ctx, pf, callGraph)
				if err != nil {
					t.Fatalf("EvalFileWithCallGraph failed for %s: %v", pf.Input.File.Path, err)
				}
				totalFindings = append(totalFindings, findings...)
			}

			totalFindings = engine.DeduplicateFindings(totalFindings)
			if len(totalFindings) != tt.wantFindings {
				t.Fatalf("Got %d findings, want %d", len(totalFindings), tt.wantFindings)
			}
			if tt.wantFindings > 0 && totalFindings[0].RuleID != tt.wantRuleID {
				t.Errorf("RuleID = %q, want %q", totalFindings[0].RuleID, tt.wantRuleID)
			}
		})
	}
}
