package reporter_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/loganprice/treeguard/internal/reporter"
)

func sampleStats() reporter.ReportStats {
	return reporter.ReportStats{
		FilesScanned: 5,
		RulesCount:   10,
		Duration:     50 * time.Millisecond,
	}
}

func TestReporterInterface(t *testing.T) {
	reporters := []reporter.Reporter{
		reporter.NewConsoleReporter(true),
		reporter.NewJSONReporter(true),
		reporter.NewSARIFReporter(true),
		reporter.NewHTMLReporter(),
	}

	for _, r := range reporters {
		var buf bytes.Buffer
		if err := r.Render(&buf, nil, sampleStats()); err != nil {
			t.Errorf("Render() error with empty findings on %T: %v", r, err)
		}
	}
}
