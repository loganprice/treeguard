package reporter

import (
	"io"
	"time"

	"github.com/loganprice/treeguard/internal/engine"
)

// ReportStats summarizes execution statistics.
type ReportStats struct {
	FilesScanned    int           `json:"files_scanned"`
	RulesCount      int           `json:"rules_count"`
	Duration        time.Duration `json:"duration"`
	DurationMs      int64         `json:"duration_ms"`
	SuppressedCount int           `json:"suppressed_count,omitempty"`
}

// Reporter defines the rendering interface for scan findings.
type Reporter interface {
	Render(w io.Writer, findings []engine.Finding, stats ReportStats) error
}
