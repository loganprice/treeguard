package runner_test

import (
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/runner"
)

func TestParseSourceSuppressionsTableDriven(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		targetLine     int
		ruleID         string
		wantSuppressed bool
	}{
		{
			name:           "Same line Python comment suppress all",
			source:         "eval('1+1') # treeguard:ignore\n",
			targetLine:     1,
			ruleID:         "py-eval-detected",
			wantSuppressed: true,
		},
		{
			name:           "Same line Go comment suppress specific rule",
			source:         "exec.Command(cmd) // treeguard:ignore:go-command-injection\n",
			targetLine:     1,
			ruleID:         "go-command-injection",
			wantSuppressed: true,
		},
		{
			name:           "Same line Go comment rule mismatch",
			source:         "exec.Command(cmd) // treeguard:ignore:go-other-rule\n",
			targetLine:     1,
			ruleID:         "go-command-injection",
			wantSuppressed: false,
		},
		{
			name:           "Preceding line comment suppress specific rule with justification",
			source:         "// treeguard:ignore:go-sql-injection intentional internal query\ndb.Query(rawSql)\n",
			targetLine:     2,
			ruleID:         "go-sql-injection",
			wantSuppressed: true,
		},
		{
			name:           "Preceding line C comment block",
			source:         "/* treeguard:ignore:c-banned-memory-functions */\ngets(buf);\n",
			targetLine:     2,
			ruleID:         "c-banned-memory-functions",
			wantSuppressed: true,
		},
		{
			name:           "Comma separated rule IDs",
			source:         "# treeguard:ignore:rule-a,rule-b\nsome_code()\n",
			targetLine:     2,
			ruleID:         "rule-b",
			wantSuppressed: true,
		},
		{
			name:           "Normal comment without suppression directive",
			source:         "// This is a normal comment\ncode()\n",
			targetLine:     2,
			ruleID:         "any-rule",
			wantSuppressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := runner.ParseSourceSuppressions(tt.source)
			got := fs.IsSuppressed(tt.ruleID, tt.targetLine)
			if got != tt.wantSuppressed {
				t.Errorf("IsSuppressed(%q, line %d) = %v, want %v", tt.ruleID, tt.targetLine, got, tt.wantSuppressed)
			}
		})
	}
}

func TestFilterSuppressedFindingsTableDriven(t *testing.T) {
	f1 := engine.Finding{
		RuleID: "rule-1",
		File:   "app.py",
		Range:  parser.Range{Start: parser.Point{Line: 2}},
	}
	f2 := engine.Finding{
		RuleID: "rule-2",
		File:   "app.py",
		Range:  parser.Range{Start: parser.Point{Line: 5}},
	}

	suppressions := map[string]runner.FileSuppressions{
		"app.py": runner.ParseSourceSuppressions("# treeguard:ignore:rule-1\ncode_line_2()\n\ncode_line_5()\n"),
	}

	filtered, count := runner.FilterSuppressedFindings([]engine.Finding{f1, f2}, suppressions)
	if count != 1 {
		t.Errorf("Suppressed count = %d, want 1", count)
	}
	if len(filtered) != 1 || filtered[0].RuleID != "rule-2" {
		t.Errorf("Filtered findings mismatch: %v", filtered)
	}
}
