package reporter_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/reporter"
)

func TestSARIFReporterTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		pretty       bool
		findings     []engine.Finding
		wantLevel    string
		wantRuleProp bool
		wantFix      bool
	}{
		{
			name:   "Error finding with CWE/OWASP and fix",
			pretty: true,
			findings: []engine.Finding{
				{
					RuleID:   "sarif-rule-1",
					Title:    "SARIF Title",
					Message:  "SARIF Message",
					Severity: engine.SeverityError,
					File:     "main.go",
					CWE:      "CWE-89",
					OWASP:    "A03:2021",
					Range: parser.Range{
						Start: parser.Point{Line: 10, Column: 5},
						End:   parser.Point{Line: 10, Column: 20},
					},
					Fix: &engine.Fix{
						Replacement: "safe_code()",
						Range: parser.Range{
							Start: parser.Point{Line: 10, Column: 5},
							End:   parser.Point{Line: 10, Column: 20},
						},
					},
				},
			},
			wantLevel:    "error",
			wantRuleProp: true,
			wantFix:      true,
		},
		{
			name:   "Warning and Info findings without fix",
			pretty: false,
			findings: []engine.Finding{
				{
					RuleID:   "warn-rule",
					Message:  "Warn message",
					Severity: engine.SeverityWarning,
					File:     "app.py",
				},
				{
					RuleID:   "info-rule",
					Message:  "Info message",
					Severity: engine.SeverityInfo,
					File:     "app.py",
				},
			},
			wantLevel:    "warning",
			wantRuleProp: false,
			wantFix:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := reporter.NewSARIFReporter(tt.pretty)
			var buf bytes.Buffer
			err := rep.Render(&buf, tt.findings, sampleStats())
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			var sarif map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
				t.Fatalf("SARIF unmarshal error = %v", err)
			}

			if sarif["version"] != "2.1.0" {
				t.Errorf("SARIF version = %v, want 2.1.0", sarif["version"])
			}

			runs, ok := sarif["runs"].([]interface{})
			if !ok || len(runs) != 1 {
				t.Fatalf("expected 1 run in SARIF report")
			}

			runMap := runs[0].(map[string]interface{})
			results, ok := runMap["results"].([]interface{})
			if !ok || len(results) != len(tt.findings) {
				t.Fatalf("results count = %d, want %d", len(results), len(tt.findings))
			}

			if len(results) > 0 {
				res0 := results[0].(map[string]interface{})
				if res0["level"] != tt.wantLevel {
					t.Errorf("result level = %v, want %q", res0["level"], tt.wantLevel)
				}
				if tt.wantFix {
					if _, hasFixes := res0["fixes"]; !hasFixes {
						t.Errorf("expected fixes array in SARIF result")
					}
				}
			}
		})
	}
}
