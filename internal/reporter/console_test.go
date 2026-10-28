package reporter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/reporter"
)

func TestConsoleReporterTableDriven(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "app.py")
	fileContent := `import os
def run(cmd):
    # DANGEROUS
    os.system(cmd)
`
	if err := os.WriteFile(sampleFile, []byte(fileContent), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		noColor      bool
		findings     []engine.Finding
		wantSubstrs  []string
		unwantSubstr []string
	}{
		{
			name:     "No findings success message",
			noColor:  true,
			findings: nil,
			wantSubstrs: []string{
				"No security issues found",
				"Scanned 5 file(s)",
			},
		},
		{
			name:    "Error finding with snippet, metadata, and autofix",
			noColor: true,
			findings: []engine.Finding{
				{
					RuleID:   "py-os-system",
					Title:    "Command Injection",
					Message:  "Use of os.system is unsafe",
					Severity: engine.SeverityError,
					File:     sampleFile,
					Range: parser.Range{
						Start: parser.Point{Line: 4, Column: 5},
						End:   parser.Point{Line: 4, Column: 19},
					},
					Code:  "os.system(cmd)",
					CWE:   "CWE-78",
					OWASP: "A03:2021-Injection",
					Fix: &engine.Fix{
						Replacement: "subprocess.run(cmd)",
					},
				},
			},
			wantSubstrs: []string{
				"[ERROR]",
				"py-os-system",
				"Message: Use of os.system is unsafe",
				"CWE: CWE-78",
				"OWASP: A03:2021-Injection",
				"Autofix available: subprocess.run(cmd)",
				"os.system(cmd)",
				"Found 1 issue(s): 1 errors, 0 warnings, 0 infos",
			},
		},
		{
			name:    "Warning and Info findings with missing snippet file",
			noColor: false,
			findings: []engine.Finding{
				{
					RuleID:   "warn-rule",
					Message:  "Warning issue",
					Severity: engine.SeverityWarning,
					File:     filepath.Join(tmpDir, "missing.py"),
					Range: parser.Range{
						Start: parser.Point{Line: 10, Column: 1},
					},
				},
				{
					RuleID:   "info-rule",
					Message:  "Info issue",
					Severity: engine.SeverityInfo,
					File:     filepath.Join(tmpDir, "missing.py"),
					Range: parser.Range{
						Start: parser.Point{Line: 20, Column: 1},
					},
				},
			},
			wantSubstrs: []string{
				"[WARNING]",
				"[INFO]",
				"warn-rule",
				"info-rule",
				"Found 2 issue(s): 0 errors, 1 warnings, 1 infos",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := reporter.NewConsoleReporter(tt.noColor)
			var buf bytes.Buffer
			err := rep.Render(&buf, tt.findings, sampleStats())
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			out := buf.String()
			for _, want := range tt.wantSubstrs {
				if !strings.Contains(out, want) {
					t.Errorf("ConsoleReporter output missing expected substring %q\nFull output:\n%s", want, out)
				}
			}
		})
	}
}
