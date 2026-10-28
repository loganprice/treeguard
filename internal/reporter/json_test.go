package reporter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/reporter"
)

func TestJSONReporterTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		pretty   bool
		findings []engine.Finding
	}{
		{
			name:   "Pretty formatted JSON report",
			pretty: true,
			findings: []engine.Finding{
				{
					RuleID:   "rule-1",
					Message:  "Test issue",
					Severity: engine.SeverityError,
					File:     "test.py",
				},
			},
		},
		{
			name:     "Compact JSON report with empty findings",
			pretty:   false,
			findings: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := reporter.NewJSONReporter(tt.pretty)
			var buf bytes.Buffer
			err := rep.Render(&buf, tt.findings, sampleStats())
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			var report map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
				t.Fatalf("JSON unmarshal error = %v", err)
			}

			if report["version"] != "1.0.0" {
				t.Errorf("version = %v, want 1.0.0", report["version"])
			}

			statsMap, ok := report["stats"].(map[string]interface{})
			if !ok || statsMap["files_scanned"] != float64(5) {
				t.Errorf("stats.files_scanned = %v, want 5", statsMap["files_scanned"])
			}

			if tt.pretty && !strings.Contains(buf.String(), "\n  \"version\"") {
				t.Errorf("expected pretty printed JSON with indentations")
			}
		})
	}
}
