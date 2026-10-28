package runner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/runner"
)

func TestApplyFixesTableDriven(t *testing.T) {
	tmpDir := t.TempDir()

	sampleFile := filepath.Join(tmpDir, "test.c")
	origContent := `#include <stdio.h>
#include <stdlib.h>

int main() {
    int r1 = rand();
    int r2 = rand();
    return 0;
}
`
	if err := os.WriteFile(sampleFile, []byte(origContent), 0644); err != nil {
		t.Fatal(err)
	}

	p := parser.New()
	parsed, err := p.ParseSource(sampleFile, []byte(origContent), "c")
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}

	var randNodes []parser.ASTNode
	for _, node := range parsed.Input.Nodes {
		if node.Text == "rand" && node.Type == "identifier" {
			randNodes = append(randNodes, node)
		}
	}

	if len(randNodes) < 2 {
		t.Fatalf("Expected at least 2 rand identifier nodes, got %d", len(randNodes))
	}

	validFindings := []engine.Finding{
		{
			RuleID: "c-weak-prng-rand",
			File:   sampleFile,
			Fix: &engine.Fix{
				Replacement: "arc4random",
				Range:       randNodes[0].Range,
			},
		},
		{
			RuleID: "c-weak-prng-rand",
			File:   sampleFile,
			Fix: &engine.Fix{
				Replacement: "arc4random",
				Range:       randNodes[1].Range,
			},
		},
	}

	outOfBoundsFinding := []engine.Finding{
		{
			RuleID: "invalid-range",
			File:   sampleFile,
			Fix: &engine.Fix{
				Replacement: "invalid",
				Range: parser.Range{
					Start: parser.Point{Byte: 99999},
					End:   parser.Point{Byte: 100000},
				},
			},
		},
	}

	overlappingFindings := []engine.Finding{
		{
			RuleID: "overlap-1",
			File:   sampleFile,
			Fix: &engine.Fix{
				Replacement: "first",
				Range: parser.Range{
					Start: parser.Point{Byte: randNodes[0].Range.Start.Byte},
					End:   parser.Point{Byte: randNodes[0].Range.End.Byte + 5},
				},
			},
		},
		{
			RuleID: "overlap-2",
			File:   sampleFile,
			Fix: &engine.Fix{
				Replacement: "second",
				Range: parser.Range{
					Start: parser.Point{Byte: randNodes[0].Range.Start.Byte + 2},
					End:   parser.Point{Byte: randNodes[0].Range.End.Byte + 2},
				},
			},
		},
	}

	tests := []struct {
		name           string
		dryRun         bool
		findings       []engine.Finding
		wantFilesFixed int
		wantApplied    int
		checkContent   bool
		expectedSubstr string
	}{
		{
			name:           "Dry-run mode with valid findings",
			dryRun:         true,
			findings:       validFindings,
			wantFilesFixed: 1,
			wantApplied:    2,
			checkContent:   true,
			expectedSubstr: "rand()", // Unchanged on disk
		},
		{
			name:           "Live fix mode with valid findings",
			dryRun:         false,
			findings:       validFindings,
			wantFilesFixed: 1,
			wantApplied:    2,
			checkContent:   true,
			expectedSubstr: "arc4random()", // Updated on disk
		},
		{
			name:           "Out of bounds byte range finding",
			dryRun:         true,
			findings:       outOfBoundsFinding,
			wantFilesFixed: 0,
			wantApplied:    0,
			checkContent:   false,
		},
		{
			name:           "Overlapping findings (skips second edit)",
			dryRun:         true,
			findings:       overlappingFindings,
			wantFilesFixed: 1,
			wantApplied:    1,
			checkContent:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := runner.ApplyFixes(tt.findings, tt.dryRun)
			if err != nil {
				t.Fatalf("ApplyFixes error = %v", err)
			}

			if res.FilesFixed != tt.wantFilesFixed {
				t.Errorf("FilesFixed = %d, want %d", res.FilesFixed, tt.wantFilesFixed)
			}
			if res.FixesApplied != tt.wantApplied {
				t.Errorf("FixesApplied = %d, want %d", res.FixesApplied, tt.wantApplied)
			}

			if tt.checkContent {
				content, _ := os.ReadFile(sampleFile)
				if !strings.Contains(string(content), tt.expectedSubstr) {
					t.Errorf("File content missing expected substring %q\nContent:\n%s", tt.expectedSubstr, string(content))
				}
			}
		})
	}
}
