package reporter

import (
	"encoding/json"
	"io"

	"github.com/loganprice/treeguard/internal/engine"
)

// JSONReport represents the top-level structure of a JSON scan report.
type JSONReport struct {
	Version  string           `json:"version"`
	Stats    ReportStats      `json:"stats"`
	Findings []engine.Finding `json:"findings"`
}

// JSONReporter formats scan findings as structured JSON.
type JSONReporter struct {
	Pretty bool
}

// NewJSONReporter creates a new JSONReporter.
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{Pretty: pretty}
}

// Render writes JSON-formatted results to the given writer.
func (j *JSONReporter) Render(w io.Writer, findings []engine.Finding, stats ReportStats) error {
	stats.DurationMs = stats.Duration.Milliseconds()

	report := JSONReport{
		Version:  "1.0.0",
		Stats:    stats,
		Findings: findings,
	}

	encoder := json.NewEncoder(w)
	if j.Pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(report)
}
