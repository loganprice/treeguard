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

func TestHTMLReporterTableDriven(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "app.py")
	os.WriteFile(sampleFile, []byte("eval('1+1')\n"), 0644)

	tests := []struct {
		name        string
		findings    []engine.Finding
		wantSubstrs []string
	}{
		{
			name: "HTML report with finding and code snippet",
			findings: []engine.Finding{
				{
					RuleID:   "py-eval",
					Title:    "Eval Execution",
					Message:  "Use of eval is unsafe",
					Severity: engine.SeverityError,
					File:     sampleFile,
					CWE:      "CWE-95",
					OWASP:    "A03:2021-Injection",
					Range: parser.Range{
						Start: parser.Point{Line: 1, Column: 1},
						End:   parser.Point{Line: 1, Column: 11},
					},
					Fix: &engine.Fix{
						Replacement: "literal_eval('1+1')",
					},
				},
			},
			wantSubstrs: []string{
				"<!DOCTYPE html>",
				"TreeGuard SAST Report",
				"py-eval",
				"Use of eval is unsafe",
				"CWE-95",
				"A03:2021-Injection",
				"literal_eval('1+1')",
			},
		},
		{
			name:     "HTML report with empty findings",
			findings: nil,
			wantSubstrs: []string{
				"<!DOCTYPE html>",
				"TreeGuard SAST Report",
				"\"files_scanned\":5",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := reporter.NewHTMLReporter()
			var buf bytes.Buffer
			err := rep.Render(&buf, tt.findings, sampleStats())
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			out := buf.String()
			for _, want := range tt.wantSubstrs {
				if !strings.Contains(out, want) {
					t.Errorf("HTMLReporter output missing expected substring %q\nGot:\n%s", want, out)
				}
			}
		})
	}
}
